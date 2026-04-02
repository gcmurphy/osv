//! Example: Loading multiple OSV vulnerabilities from a local directory.
//!
//! Requires the `local` feature to be enabled.
//!
//! Usage:
//! 1. Create a directory (e.g., `test_vuln_dir`).
//! 2. Create multiple dummy OSV JSON files inside it (e.g., `vuln1.json`, `vuln2.json`).
//!    Use the format from the `load_file` example, changing the "id" for each.
//! 3. Optionally create subdirectories with more `.json` files if testing recursion.
//! 4. Run the example:
//!    - Non-recursive: `cargo run --example load_dir --features local -- test_vuln_dir`
//!    - Recursive: `cargo run --example load_dir --features local -- test_vuln_dir recursive`
//! 5. Remember to delete `test_vuln_dir` afterwards.

#[cfg(feature = "local")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use osv::local::load_directory;
    use std::env;
    use std::path::Path;

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: cargo run --example load_dir --features local -- <path_to_directory> [recursive]");
        std::process::exit(1);
    }

    let dir_path_str = &args[1];
    let dir_path = Path::new(dir_path_str);
    let recursive = args.len() == 3 && args[2] == "recursive";

    println!(
        "Attempting to load vulnerabilities from directory: {:?} (recursive: {})",
        dir_path, recursive
    );

    match load_directory(dir_path, recursive) {
        Ok(vulnerabilities) => {
            println!(
                "Successfully loaded {} vulnerabilities:",
                vulnerabilities.len()
            );
            for (i, vulnerability) in vulnerabilities.iter().enumerate() {
                println!(
                    "  {}: ID = {}, Modified = {}",
                    i + 1,
                    vulnerability.id,
                    vulnerability.modified
                    // add more properties here to print
                );
            }
        }
        Err(e) => {
            eprintln!("Error loading directory: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(not(feature = "local"))]
fn main() {
    println!("This example requires the 'local' feature to be enabled.");
    println!("Run with: cargo run --example load_dir --features local -- <path> [recursive]");
}
