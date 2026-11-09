#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|bytes: &[u8]| {
    let _ = fedup_protocol::read_frame(&mut Cursor::new(bytes));
});
