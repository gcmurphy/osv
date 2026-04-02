//! Example: Loading a single OSV vulnerability from a local file.
//!
//! Requires the `local` feature to be enabled.
//!
//! Usage:
//! 1. Create a dummy OSV JSON file (e.g., `test_vuln.json`):
//!    ```json
//!    {
//!        "schema_version": "1.0.0",
//!        "id": "TEST-VULN-001",
//!        "modified": "2023-01-01T00:00:00Z",
//!        "published": "2023-01-01T00:00:00Z",
//!        "summary": "A test vulnerability",
//!        "details": "Details about the test vulnerability.",
//!        "affected": [
//!            {
//!                "package": {
//!                    "name": "test-package",
//!                    "ecosystem": "PyPI"
//!                },
//!                "ranges": [
//!                    {
//!                        "type": "SEMVER",
//!                        "events": [
//!                            { "introduced": "1.0.0" },
//!                            { "fixed": "1.0.1" }
//!                        ]
//!                    }
//!                ]
//!            }
//!        ]
//!    }
//!    ```
//! 2. Run the example: `cargo run --example load_file --features local -- test_vuln.json`
//! 3. Remember to delete `test_vuln.json` afterwards.

#[cfg(feature = "local")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use osv::local::load_vulnerability;
    use std::env;
    use std::path::Path;

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: cargo run --example load_file --features local -- <path_to_osv_json_file>");
        std::process::exit(1);
    }

    let file_path_str = &args[1];
    let file_path = Path::new(file_path_str);

    println!("Attempting to load vulnerability from: {:?}", file_path);

    match load_vulnerability(file_path) {
        Ok(vulnerability) => {
            println!("Successfully loaded vulnerability:");
            println!("ID: {}", vulnerability.id);
            println!("Modified: {}", vulnerability.modified);
            if let Some(summary) = &vulnerability.summary {
                println!("Summary: {}", summary);
            }
            if let Some(details) = &vulnerability.details {
                println!("Details: {}", details);
            }
        }
        Err(e) => {
            eprintln!("Error loading vulnerability: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(not(feature = "local"))]
fn main() {
    println!("This example requires the 'local' feature to be enabled.");
    println!("Run with: cargo run --example load_file --features local -- <path>");
}
