use osv::data;
use std::path::PathBuf;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), data::DataError> {
    let service_account = PathBuf::from(r"./credentials.json");
    let output_directory = PathBuf::from(r"./data");
    //let prefix = Path::from(r"Ubuntu");

    println!("Starting download of vulnerability data...");
    let start = Instant::now();

    data::download(&service_account, &output_directory, None).await?;

    let duration = start.elapsed();
    println!("Download completed in {:.2?}", duration);

    Ok(())
}
