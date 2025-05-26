//! # Local File Loading
//!
//! Provides functionality to load OSV vulnerability data from local JSON files.

use crate::schema;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LoadError {
    #[error("IO error accessing path {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse JSON from file {path:?}: {source}")]
    JsonParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("Path {0:?} is not a file")]
    NotAFile(PathBuf),
    #[error("Path {0:?} is not a directory")]
    NotADirectory(PathBuf),
    #[error("Error walking directory {path:?}: {source}")]
    WalkDir {
        path: PathBuf,
        #[source]
        source: walkdir::Error,
    },
}

/// Loads a single OSV vulnerability from a JSON file at the specified path.
///
/// # Arguments
///
/// * `path` - A path reference that points to the vulnerability JSON file.
///
/// # Errors
///
/// Returns `LoadError` if the file cannot be read, is not a valid file,
/// or contains invalid JSON.
pub fn load_vulnerability(
    path: impl AsRef<Path>,
) -> Result<schema::Vulnerability, LoadError> {
    let path = path.as_ref();
    if !path.is_file() {
        if !path.exists() {
             return Err(LoadError::Io { path: path.to_path_buf(), source: std::io::Error::new(std::io::ErrorKind::NotFound, "File not found") });
        }
        return Err(LoadError::NotAFile(path.to_path_buf()));
    }

    let content = fs::read_to_string(path).map_err(|e| LoadError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    serde_json::from_str::<schema::Vulnerability>(&content).map_err(|e| LoadError::JsonParse {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Loads all OSV vulnerabilities from JSON files found within a specified directory.
///
/// # Arguments
///
/// * `path` - A path reference to the directory containing vulnerability JSON files.
/// * `recursive` - If `true`, searches for `.json` files in subdirectories as well.
///
/// # Errors
///
/// Returns `LoadError` if the directory cannot be read, is not a directory,
/// or if any file encountered causes an I/O or JSON parsing error during loading.
/// The function currently fails on the first error encountered.
pub fn load_directory(
    path: impl AsRef<Path>,
    recursive: bool,
) -> Result<Vec<schema::Vulnerability>, LoadError> {
    let path = path.as_ref();
    if !path.is_dir() {
        if !path.exists() {
             return Err(LoadError::Io { path: path.to_path_buf(), source: std::io::Error::new(std::io::ErrorKind::NotFound, "Directory not found") });
        }
        return Err(LoadError::NotADirectory(path.to_path_buf()));
    }

    let mut vulnerabilities = Vec::new();
    let walker = WalkDir::new(path).max_depth(if recursive { usize::MAX } else { 1 });

    for entry_result in walker {
        let entry = entry_result.map_err(|e| LoadError::WalkDir {
            path: path.to_path_buf(),
            source: e,
        })?;
        let entry_path = entry.path();

        if entry_path.is_file() {
            if let Some(ext) = entry_path.extension() {
                if ext == "json" {
                    let vulnerability = load_vulnerability(entry_path)?;
                    vulnerabilities.push(vulnerability);
                }
            }
        }
    }

    Ok(vulnerabilities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::tempdir;

    fn create_valid_osv_json(id: &str) -> String {
        format!(
            r#"{{
                "schema_version": "1.0.0",
                "id": "{}",
                "modified": "2021-01-01T00:00:00Z",
                "affected": []
            }}"#,
            id
        )
    }

    #[test]
    fn test_load_vulnerability_success() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("vuln.json");
        let json_content = create_valid_osv_json("TEST-001");
        fs::write(&file_path, json_content).unwrap();

        let result = load_vulnerability(&file_path);
        assert!(result.is_ok());
        let vuln = result.unwrap();
        assert_eq!(vuln.id, "TEST-001");
    }

    #[test]
    fn test_load_vulnerability_not_a_file() {
        let dir = tempdir().unwrap();
        let result = load_vulnerability(dir.path());
        assert!(matches!(result, Err(LoadError::NotAFile(_))));
    }
    
    #[test]
    fn test_load_vulnerability_file_not_found() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent.json");
        let result = load_vulnerability(&file_path);
        assert!(matches!(result, Err(LoadError::Io { .. })));
        if let Err(LoadError::Io { source, .. }) = result {
             assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
    }


    #[test]
    fn test_load_vulnerability_invalid_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("invalid.json");
        fs::write(&file_path, "{ invalid json ").unwrap();

        let result = load_vulnerability(&file_path);
        assert!(matches!(result, Err(LoadError::JsonParse { .. })));
    }

    #[test]
    fn test_load_directory_success_non_recursive() {
        let dir = tempdir().unwrap();
        let sub_dir = dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();

        fs::write(dir.path().join("vuln1.json"), create_valid_osv_json("TEST-001")).unwrap();
        fs::write(dir.path().join("vuln2.json"), create_valid_osv_json("TEST-002")).unwrap();
        fs::write(dir.path().join("not_json.txt"), "hello").unwrap();
        fs::write(sub_dir.join("vuln3.json"), create_valid_osv_json("TEST-003")).unwrap();

        let result = load_directory(dir.path(), false);
        assert!(result.is_ok());
        let vulns = result.unwrap();
        assert_eq!(vulns.len(), 2);
        assert!(vulns.iter().any(|v| v.id == "TEST-001"));
        assert!(vulns.iter().any(|v| v.id == "TEST-002"));
    }

    #[test]
    fn test_load_directory_success_recursive() {
        let dir = tempdir().unwrap();
        let sub_dir = dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let sub_sub_dir = sub_dir.join("subsubdir");
        fs::create_dir(&sub_sub_dir).unwrap();


        fs::write(dir.path().join("vuln1.json"), create_valid_osv_json("TEST-001")).unwrap();
        fs::write(sub_dir.join("vuln2.json"), create_valid_osv_json("TEST-002")).unwrap();
        fs::write(sub_sub_dir.join("vuln3.json"), create_valid_osv_json("TEST-003")).unwrap();
        fs::write(dir.path().join("not_json.txt"), "hello").unwrap();


        let result = load_directory(dir.path(), true);
        assert!(result.is_ok());
        let vulns = result.unwrap();
        assert_eq!(vulns.len(), 3);
        assert!(vulns.iter().any(|v| v.id == "TEST-001"));
        assert!(vulns.iter().any(|v| v.id == "TEST-002"));
        assert!(vulns.iter().any(|v| v.id == "TEST-003"));
    }
    
    #[test]
    fn test_load_directory_not_a_directory() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("some_file.txt");
        File::create(&file_path).unwrap();

        let result = load_directory(&file_path, false);
        assert!(matches!(result, Err(LoadError::NotADirectory(_))));
    }

    #[test]
    fn test_load_directory_dir_not_found() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().join("nonexistent_dir");
        let result = load_directory(&dir_path, false);
         assert!(matches!(result, Err(LoadError::Io { .. })));
        if let Err(LoadError::Io { source, .. }) = result {
             assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
    }

    #[test]
    fn test_load_directory_fails_on_first_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("vuln1.json"), create_valid_osv_json("TEST-001")).unwrap();
        fs::write(dir.path().join("invalid.json"), "{ invalid json ").unwrap();
        fs::write(dir.path().join("vuln2.json"), create_valid_osv_json("TEST-002")).unwrap();

        let result = load_directory(dir.path(), false);
        assert!(matches!(result, Err(LoadError::JsonParse { .. })));
        if let Err(LoadError::JsonParse{ path, ..}) = result {
            assert!(path.ends_with("invalid.json"));
        }
    }
}
