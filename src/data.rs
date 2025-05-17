use futures::TryStreamExt;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::ObjectStore;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DataError {
    #[error("failed to access requested resource")]
    ObjectStoreError(#[from] object_store::Error),

    #[error("invalid file path")]
    ServiceAccountError(String),

    #[error("cache access error")]
    CacheFileError(#[from] std::io::Error),

    #[error("unexpected error has occurred")]
    Unexpected,
}

pub async fn download(
    service_account: &Path,
    output_directory: &Path,
    prefix: Option<&object_store::path::Path>,
) -> Result<(), DataError> {
    let sa_path = service_account
        .to_str()
        .ok_or_else(|| DataError::ServiceAccountError("Invalid UTF-8 path".to_string()))?;

    let osv_data = GoogleCloudStorageBuilder::new()
        .with_service_account_path(sa_path)
        .with_url("gs://osv-vulnerabilities")
        .build()?;

    let stream = osv_data.list(prefix);
    stream
        .try_filter(|meta| {
            let json_file = meta.location.extension() == Some("json");
            async move { json_file }
        })
        .map_err(DataError::ObjectStoreError)
        .try_for_each_concurrent(16, |meta| {
            let objects = osv_data.clone();
            async move {
                let remote_path = meta.location.as_ref();
                let local_path = output_directory.to_path_buf().join(remote_path);
                let cached = if local_path.exists() {
                    let metadata = std::fs::metadata(&local_path)?;
                    let modified = metadata.modified()?;
                    let remote_modified = meta.last_modified;
                    let local_modified = chrono::DateTime::<chrono::Utc>::from(modified);
                    remote_modified <= local_modified
                } else {
                    false
                };
                if !cached {
                    if let Some(parent) = local_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|_| DataError::Unexpected)?;
                    }
                    let object_path = meta.location.clone();
                    let data = objects.get(&object_path).await?.bytes().await?.to_vec();
                    std::fs::write(&local_path, data).map_err(|_| DataError::Unexpected)?;
                }
                Ok(())
            }
        })
        .await?;

    Ok(())
}
