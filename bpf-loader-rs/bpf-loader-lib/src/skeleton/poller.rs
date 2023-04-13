use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{
    export_event::{EventExporter, ExporterInternalImplementation},
    meta::MapSampleMeta,
};
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use libbpf_rs::{Map, MapFlags, PerfBufferBuilder, RingBufferBuilder};
use log::error;

use super::BpfSkeleton;
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
impl BpfSkeleton {
    #[inline]
    pub(crate) fn wait_for_no_export_program(&self) -> Result<()> {
        program_poll_loop!(self.handle, {
            std::hint::spin_loop();
        });
        Ok(())
    }
    #[inline]
    pub(crate) fn wait_and_poll_from_ringbuf(
        &self,
        map: &Map,
        exporter: Arc<EventExporter>,
    ) -> Result<()> {
        let event_processor = match &exporter.internal_impl {
            ExporterInternalImplementation::RingBufProcessor {
                event_processor, ..
            } => event_processor,
            _ => bail!("Expected the exporter uses ringbuf processor"),
        };
        let mut builder = RingBufferBuilder::new();
        builder
            .add(map, |data: &[u8]| {
                if let Err(e) = event_processor.handle_event(data) {
                    error!("Failed to process event: {}", e);
                    1
                } else {
                    0
                }
            })
            .with_context(|| anyhow!("Failed to add ringbuf callback"))?;

        let ringbuf = builder
            .build()
            .with_context(|| anyhow!("Failed to build ringbuf poller"))?;
        program_poll_loop!(self.handle, {
            ringbuf
                .poll(Duration::from_millis(self.meta.poll_timeout_ms as u64))
                .map_err(|e| anyhow!("Failed to poll ringbuf: {}, see logs for details", e))?;
        });
        Ok(())
    }
    #[inline]
    pub(crate) fn wait_and_poll_from_perf_event_array(
        &self,
        map: &Map,
        exporter: Arc<EventExporter>,
    ) -> Result<()> {
        let event_processor = match &exporter.internal_impl {
            ExporterInternalImplementation::RingBufProcessor {
                event_processor, ..
            } => event_processor,
            _ => bail!("Expected the exporter uses ringbuf processor"),
        };
        let error_flag = AtomicBool::new(false);
        let perf = PerfBufferBuilder::new(map)
            .sample_cb(|_cpu: i32, data: &[u8]| {
                if let Err(e) = event_processor.handle_event(data) {
                    error!("Failed to handle event for perf array: {}", e);
                    error_flag.store(true, Ordering::Relaxed);
                }
            })
            .build()
            .with_context(|| anyhow!("Failed to build perf event"))?;
        program_poll_loop!(self.handle, {
            perf.poll(Duration::from_millis(self.meta.poll_timeout_ms as u64))
                .map_err(|e| anyhow!("Failed to poll perf event: {}", e))?;
            if error_flag.load(Ordering::Relaxed) {
                bail!("Failed to poll perf event. See log for details");
            }
        });
        Ok(())
    }
    #[inline]
    pub(crate) fn wait_and_sample_map(
        &self,
        map: &Map,
        exporter: Arc<EventExporter>,
        sample_config: &MapSampleMeta,
    ) -> Result<()> {
        let event_processor = match &exporter.internal_impl {
            ExporterInternalImplementation::KeyValueMapProcessor {
                event_processor, ..
            } => event_processor,
            _ => bail!("Expected the exporter uses key-value processor"),
        };
        program_poll_loop!(self.handle, {
            for key in map.keys() {
                let value = map
                    .lookup(&key, MapFlags::empty())
                    .map_err(|e| anyhow!("Failed to lookup value of the key `{:?}`: {}", key, e))?
                    .ok_or_else(|| anyhow!("Value of key `{:?}` should exist", key))?;
                event_processor
                    .handle_event(&key, &value)
                    .with_context(|| anyhow!("Failed to handle event"))?;
            }
            std::thread::sleep(Duration::from_millis(sample_config.interval as u64));
        });
        if sample_config.clear_map {
            // Clean up the map
            let keys = map.keys().collect::<Vec<_>>();
            for key in keys.into_iter() {
                map.delete(&key)?;
            }
        }
        Ok(())
    }
}
