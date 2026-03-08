#![allow(deprecated)]

use ecli_lib::runner::{
    client::{AbstractClient, ProgramDesc, ProgramStatus},
    ProgramHandle,
};

fn _assert_trait_in_scope<T: AbstractClient>() {}

fn main() {
    let handle: ProgramHandle = 7;
    let desc = ProgramDesc {
        id: handle,
        name: "prog".to_string(),
        status: ProgramStatus::Running,
    };

    let _ = desc;
    let _ = ProgramStatus::Paused;
    let _ = handle;
}
