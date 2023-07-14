//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    export_event::{
        EventExporter, ExporterInternalImplementation, InternalBufferValueEventProcessor,
        InternalSampleMapProcessor,
    },
    meta::MapSampleMeta,
};
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use libbpf_rs::{Map, MapFlags, PerfBuffer, PerfBufferBuilder, RingBuffer, RingBufferBuilder};
use log::error;

use super::BpfSkeleton;
#[macro_export]
macro_rules! program_poll_loop {
    ($handle: expr, $blk: block) => {{
        use log::info;
        use std::time::Duration;
        info!("Running ebpf program...");
        while !$handle.should_terminate() {
            while $handle.should_pause() {
                std::hint::spin_loop();
                std::thread::sleep(Duration::from_millis(1));
            }
            if $handle.should_terminate() {
                info!("Program terminated");
                break;
            }
            $blk;
        }
    }};
}
#[ouroboros::self_referencing]
pub(crate) struct RingBufPollerContext {
    exporter: Arc<EventExporter>,
    #[borrows(exporter)]
    event_processor: &'this dyn InternalBufferValueEventProcessor,
    #[borrows(event_processor)]
    #[covariant]
    ringbuf: RingBuffer<'this>,
    poll_timeout_ms: u64,
}

#[ouroboros::self_referencing]
pub(crate) struct PerfEventPollerContext {
    exporter: Arc<EventExporter>,
    #[borrows(exporter)]
    event_processor: &'this dyn InternalBufferValueEventProcessor,
    error_flag: AtomicBool,
    #[borrows(event_processor, error_flag)]
    #[covariant]
    perf: PerfBuffer<'this>,
    poll_timeout_ms: u64,
}
#[ouroboros::self_referencing]
pub(crate) struct SampleMapPollerContext<'a> {
    map: &'a Map,
    exporter: Arc<EventExporter>,
    sample_config: &'a MapSampleMeta,
    #[borrows(exporter)]
    event_processor: &'this dyn InternalSampleMapProcessor,
}

pub(crate) enum Poller<'a> {
    RingBuf(RingBufPollerContext),
    PerfEvent(PerfEventPollerContext),
    SampleMap(SampleMapPollerContext<'a>),
}

impl<'a> Drop for Poller<'a> {
    fn drop(&mut self) {
        if let Poller::SampleMap(ctx) = self {
            if ctx.borrow_sample_config().clear_map {
                // Clean up the map
                let keys = ctx.borrow_map().keys().collect::<Vec<_>>();
                for key in keys.into_iter() {
                    ctx.borrow_map().delete(&key).ok();
                }
            }
        }
    }
}

impl<'a> Poller<'a> {
    pub(crate) fn poll(&self) -> Result<()> {
        match self {
            Poller::RingBuf(rb) => {
                rb.borrow_ringbuf()
                    .poll(Duration::from_millis(*rb.borrow_poll_timeout_ms()))
                    .map_err(|e| anyhow!("Failed to poll ringbuf: {}, see logs for details", e))?;
            }
            Poller::PerfEvent(ctx) => {
                ctx.borrow_perf()
                    .poll(Duration::from_millis(*ctx.borrow_poll_timeout_ms()))
                    .map_err(|e| anyhow!("Failed to poll perf event: {}", e))?;
                if ctx.borrow_error_flag().load(Ordering::Relaxed) {
                    bail!("Failed to poll perf event. See log for details");
                }
            }
            Poller::SampleMap(ctx) => {
                for key in ctx.borrow_map().keys() {
                    let value = ctx
                        .borrow_map()
                        .lookup(&key, MapFlags::empty())
                        .map_err(|e| {
                            anyhow!("Failed to lookup value of the key `{:?}`: {}", key, e)
                        })?
                        .ok_or_else(|| anyhow!("Value of key `{:?}` should exist", key))?;
                    ctx.borrow_event_processor()
                        .handle_event(&key, &value)
                        .with_context(|| anyhow!("Failed to handle event"))?;
                }
                std::thread::sleep(Duration::from_millis(
                    ctx.borrow_sample_config().interval as u64,
                ));
            }
        };
        Ok(())
    }
}

impl BpfSkeleton {
    #[inline]
    pub(crate) fn wait_for_no_export_program(&self) -> Result<()> {
        program_poll_loop!(self.handle, {
            std::hint::spin_loop();
            std::thread::sleep(Duration::from_millis(1));
        });
        Ok(())
    }

    pub(crate) fn build_ringbuf_poller(
        &self,
        map: &Map,
        exporter: Arc<EventExporter>,
    ) -> Result<RingBufPollerContext> {
        let ctx = RingBufPollerContextTryBuilder {
            exporter,
            event_processor_builder: |v: &Arc<EventExporter>| {
                let event_processor = match &v.internal_impl {
                    ExporterInternalImplementation::BufferValueProcessor {
                        event_processor, ..
                    } => &**event_processor,
                    _ => bail!("Expected the exporter uses ringbuf processor"),
                };
                Ok(event_processor)
            },
            ringbuf_builder: |event_processor| {
                let mut builder = RingBufferBuilder::new();
                builder
                    .add(map, |data: &[u8]| {
                        if let Err(e) = event_processor.handle_event(data) {
                            error!("Failed to process event: {}", e);
                            -1
                        } else {
                            0
                        }
                    })
                    .with_context(|| anyhow!("Failed to add ringbuf callback"))?;

                let ringbuf = builder
                    .build()
                    .with_context(|| anyhow!("Failed to build ringbuf poller"))?;
                Ok(ringbuf)
            },
            poll_timeout_ms: self.meta.poll_timeout_ms as u64,
        }
        .try_build()?;

        Ok(ctx)
    }
    #[inline]
    pub(crate) fn build_perfevent_poller(
        &self,
        map: &Map,
        exporter: Arc<EventExporter>,
    ) -> Result<PerfEventPollerContext> {
        let ctx = PerfEventPollerContextTryBuilder {
            exporter,
            error_flag: AtomicBool::new(false),
            event_processor_builder: |v: &Arc<EventExporter>| {
                let event_processor = match &v.internal_impl {
                    ExporterInternalImplementation::BufferValueProcessor {
                        event_processor, ..
                    } => &**event_processor,
                    _ => bail!("Expected the exporter uses ringbuf processor"),
                };
                Ok(event_processor)
            },
            perf_builder: |processor, error_flag: &AtomicBool| {
                let perf = PerfBufferBuilder::new(map)
                    .sample_cb(|_cpu: i32, data: &[u8]| {
                        if let Err(e) = processor.handle_event(data) {
                            error!("Failed to handle event for perf array: {}", e);
                            error_flag.store(true, Ordering::Relaxed);
                        }
                    })
                    .build()
                    .with_context(|| anyhow!("Failed to build perf event"))?;
                Ok(perf)
            },
            poll_timeout_ms: self.meta.poll_timeout_ms as u64,
        }
        .try_build()?;
        Ok(ctx)
    }
    #[inline]
    pub(crate) fn build_sample_map_poller<'a>(
        &self,
        map: &'a Map,
        exporter: Arc<EventExporter>,
        sample_config: &'a MapSampleMeta,
    ) -> Result<SampleMapPollerContext<'a>> {
        let ctx = SampleMapPollerContextTryBuilder {
            exporter,
            event_processor_builder: |v| {
                let event_processor = match &v.internal_impl {
                    ExporterInternalImplementation::KeyValueMapProcessor {
                        event_processor,
                        ..
                    } => &**event_processor,
                    _ => bail!("Expected the exporter uses key-value processor"),
                };
                Ok(event_processor)
            },
            map,
            sample_config,
        }
        .try_build()?;
        Ok(ctx)
    }
}
