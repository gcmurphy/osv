//!
//! # Overview
//!
//! The osv client library provides a thin layer of abstraction
//! over the open source vulnerability (osv) database API. The osv database is
//! an open, precise and distributed approach to producing and consuming
//! vulnerability information for open source projects.
//!
//! This library currently provides a mean to find out whether a particular package
//! version is affected by any vulnerabilities and to fetch specific information
//! about a vulnerability within a number of different package ecosystems. It
//! is the intention to follow along with osv evolution and provide quality
//! type safe bindings to API for rust clients.
//!
//! The models and endpoints are derived from the documentation
//! published on <https://osv.dev/> directly.
//!
//!
//! # Examples
//!
//! ```
//! use comfy_table::Table;
//! use osv::schema::Ecosystem::PyPI;
//! use textwrap::termwidth;
//!
//! #[async_std::main]
//! async fn main() -> Result<(), osv::client::ApiError> {
//!
//!    if let Some(vulns) = osv::client::query_package("jinja2", "2.4.1", PyPI).await? {
//!        let default = String::from("-");
//!        let linewrap = (termwidth() as f32 / 3.0 * 2.0).round() as usize;
//!        let mut table = Table::new();
//!        table.set_header(vec!["Vulnerability ID", "Details"]);
//!        for vuln in &vulns {
//!            let details = vuln.details.as_ref().unwrap_or(&default);
//!            let details = textwrap::wrap(details, linewrap).join("\n");
//!            table.add_row(vec![&vuln.id, &details]);
//!        }
//!        println!("{table}");
//!    }
//!    Ok(())
//!}
//! ```
//!
//! There are more examples [here](https://github.com/gcmurphy/osv/tree/master/examples) that demonstrate usage.

#[cfg(feature = "schema")]
pub mod schema;

#[cfg(feature = "client")]
pub mod client;
