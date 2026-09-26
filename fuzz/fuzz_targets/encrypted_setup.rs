#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use stogas_verifier::{
    approvals::Environment,
    channel::{record_size, setup::PendingSetup},
};

fuzz_target!(|data: &[u8]| {
    static SETUP: OnceLock<PendingSetup> = OnceLock::new();
    let setup = SETUP.get_or_init(|| PendingSetup::new(Environment::Staging).unwrap());
    let _ = setup.inspect(data);
    let _ = record_size(data);
});
