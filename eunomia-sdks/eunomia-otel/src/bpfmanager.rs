use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    bpfprog::BPFProgramState,
    config::{ExporterConfig, ProgramConfig},
    state::AppState,
};

/// a mutex wrapper for BPFProgram manager
/// use for interacting with BPFProgram
#[derive(Clone)]
pub struct BPFManagerGuard<'a> {
    guard: Arc<Mutex<BPFProgramManager<'a>>>,
}

impl<'a> BPFManagerGuard<'a> {
    /// create a new BPFManager
    pub fn new(config: &ExporterConfig, state: Arc<AppState>) -> Result<BPFManagerGuard<'a>> {
        let mut program_manager = BPFProgramManager::new();
        program_manager.start_programs_for_exporter(config, state)?;
        Ok(BPFManagerGuard {
            guard: Arc::new(Mutex::new(program_manager)),
        })
    }
    /// start a new BPFProgram
    pub async fn start(&self, config: ProgramConfig, state: Arc<AppState>) -> Result<u32> {
        let mut guard = self.guard.lock().await;
        guard.add_bpf_prog(&config, state)
    }
    /// stop a BPFProgram with given id
    pub async fn stop(&self, id: u32) -> Result<()> {
        let mut guard = self.guard.lock().await;
        guard.remove_bpf_prog(id)
    }
    /// get all BPFPrograms list
    pub async fn list(&self) -> Vec<BPFListItem> {
        let guard = self.guard.lock().await;
        guard.list_all_progs()
    }
}

/// The list item return by list in manager
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct BPFListItem {
    /// the id of the program in manager
    id: u32,
    /// the name of the program
    name: String,
}

struct BPFProgramManager<'a> {
    states: HashMap<u32, BPFProgramState<'a>>,
    id: u32,
}

impl<'a> BPFProgramManager<'a> {
    pub fn new() -> BPFProgramManager<'a> {
        BPFProgramManager {
            states: HashMap::new(),
            id: 0,
        }
    }
    fn insert_bpf_prog(&mut self, prog: BPFProgramState<'a>) -> u32 {
        self.states.insert(self.id, prog);
        let id = self.id;
        self.id += 1;
        id
    }
    pub fn list_all_progs(&self) -> Vec<BPFListItem> {
        let mut result = Vec::new();
        for (id, prog) in self.states.iter() {
            result.push(BPFListItem {
                id: *id,
                name: prog.get_name(),
            });
        }
        result
    }
    pub fn remove_bpf_prog(&mut self, id: u32) -> Result<()> {
        if let Some(prog) = self.states.remove(&id) {
            prog.stop();
        }
        self.states.remove(&id);
        Ok(())
    }
    pub fn add_bpf_prog(&mut self, config: &ProgramConfig, state: Arc<AppState>) -> Result<u32> {
        let prog = BPFProgramState::run_and_wait(config, state)?;
        Ok(self.insert_bpf_prog(prog))
    }
    pub fn start_programs_for_exporter(
        &mut self,
        config: &ExporterConfig,
        state: Arc<AppState>,
    ) -> Result<()> {
        for program in &config.programs {
            self.add_bpf_prog(program, state.clone())?;
        }
        Ok(())
    }
}
