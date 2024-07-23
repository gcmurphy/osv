#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _dontcare: Result<osv::schema::Vulnerability, serde_json::Error> = serde_json::from_str(s);
    }
});
