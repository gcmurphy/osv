use comfy_table::Table;
use osv::client;
use osv::schema::Ecosystem::PyPI;
use textwrap::termwidth;

#[tokio::main]
async fn main() -> Result<(), client::ApiError> {
    if let Some(vulns) = client::query_package("jinja2", "2.4.1", PyPI).await? {
        let default = String::from("-");
        let linewrap = (termwidth() as f32 / 3.0 * 2.0).round() as usize;
        let mut table = Table::new();
        table.set_header(vec!["Vulnerability ID", "Details"]);
        for vuln in &vulns {
            let details = vuln.details.as_ref().unwrap_or(&default);
            let details = textwrap::wrap(details, linewrap).join("\n");
            table.add_row(vec![&vuln.id, &details]);
        }
        println!("{table}");
    }

    Ok(())
}
