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
//! # Examples
//!
//! ```
//! use comfy_table::Table;
//! use osv::schema::Ecosystem::PyPI;
//! use textwrap::termwidth;
//!
//! #[tokio::main]
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

use super::schema::*;
use serde::{Deserialize, Serialize};
use reqwest::StatusCode;
use thiserror::Error;
use url::Url;

/// A Request encapsulates the different payloads that will be accepted by the
/// osv.dev API server. You can either submit a query to the server using a
/// commit hash or alternatively a package and version pair.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Request {
    /// Query the vulnerability sources by commit ID
    CommitQuery { commit: Commit },

    /// Query the vulnerability sources by package and version pair.
    PackageQuery { version: Version, package: Package },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Response {
    Vulnerabilities { vulns: Vec<Vulnerability> },
    NoResult(serde_json::Value),
}

/// ApiError is the common error type when a request is rejected
/// by the api.osv.dev endpoint, the response is not understood
/// by the client or there is an underlying connection
/// problem.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ApiError {
    #[error("requested resource {0} not found")]
    NotFound(String),

    #[error("invalid request url: {0:?}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("serialization failure: {0:?}")]
    SerializationError(#[from] serde_json::Error),

    #[error("request to osv endpoint failed: {0:?}")]
    RequestFailed(reqwest::Error),

    #[error("unexpected error has occurred")]
    Unexpected,
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::RequestFailed(err)
    }
}

///
/// Query the underlying Open Source Vulnerability (osv) database for
/// any vulnerabilities associated with either a package or a commit.
///
/// The request can either be based on a commit or package and version
/// tuple. When querying a package you also need to specify the package
/// ecosystem the package belongs to.
///
/// Note that - [`query_commit`](query_commit) and [`query_package`](query_package) are convenience wrappers
/// for this function and should be favoured over calling [`query`](query) directly.
///
///
/// # Examples
///
/// ```
/// # use tokio::task;
/// # task::block_on(async {
/// let ver = osv::schema::Version::from("2.4.1");
/// let pkg = "jinja2".to_string();
/// let req = osv::client::Request::PackageQuery {
///             version: ver,
///             package: osv::schema::Package {
///                name: pkg,
///                ecosystem: osv::schema::Ecosystem::PyPI,
///                purl: None,
///            }
///     };
///
/// let resp = osv::client::query(&req).await.expect("vulnerabilities expected");
/// println!("{:#?}", resp.unwrap());
/// # });
/// ```
///
///
pub async fn query(q: &Request) -> Result<Option<Vec<Vulnerability>>, ApiError> {
    let client = reqwest::Client::new();
    let res = client.post("https://api.osv.dev/v1/query")
        .json(q)
        .send()
        .await?;

    match res.status() {
        StatusCode::NOT_FOUND => {
            let err = match q {
                Request::PackageQuery {
                    version: _,
                    package: pkg,
                } => {
                    format!("package - `{}`", pkg.name)
                }
                Request::CommitQuery { commit: c } => {
                    format!("commit - `{}`", c)
                }
            };
            Err(ApiError::NotFound(err))
        }
        _ => {
            let vulns: Response = res.json().await?;
            match vulns {
                Response::Vulnerabilities { vulns: vs } => Ok(Some(vs)),
                _ => Ok(None),
            }
        }
    }
}

///
/// Query the Open Source Vulnerability (osv) database for
/// vulnerabilities associated with the specified package
/// and version.
///
/// See <https://osv.dev/docs/#operation/OSV_QueryAffected> for more
/// details.
///
/// # Examples
///
/// ```
/// use osv::client::query_package;
/// use osv::schema::Ecosystem::PyPI;
/// # use tokio::task;
/// # task::block_on(async {
///     let pkg = "jinja2";
///     let ver = "2.4.1";
///     if let Some(vulns) = query_package(pkg, ver, PyPI).await.unwrap() {
///         for vuln in &vulns {
///             println!("{:#?} - {:#?}", vuln.id, vuln.details);
///             for affected in &vuln.affected {
///                 println!("    {:#?}", affected.ranges);
///             }
///         }
///     } else {
///         println!("no known vulnerabilities for {} v{}", pkg, ver);
///     }
/// # });
/// ```
pub async fn query_package(
    name: &str,
    version: &str,
    ecosystem: Ecosystem,
) -> Result<Option<Vec<Vulnerability>>, ApiError> {
    let req = Request::PackageQuery {
        version: Version::from(version),
        package: Package {
            name: name.to_string(),
            ecosystem,
            purl: None,
        },
    };

    query(&req).await
}

///
/// Query the Open Source Vulnerability (osv) database for
/// vulnerabilities based on a Git commit SHA1.
///
/// See <https://osv.dev/docs/#operation/OSV_QueryAffected> for more details
/// and examples.
///
/// # Examples
///
/// ```
/// # use async_std::task;
/// # use osv::client::query_commit;
/// # task::block_on(async {
/// let vulnerable = query_commit("6879efc2c1596d11a6a6ad296f80063b558d5e0f")
///         .await
///         .expect("api error");
///
/// match vulnerable {
///     Some(affected) => println!("{:#?}", affected),
///     None => println!("all clear!"),
/// }
/// # });
/// ```
///
pub async fn query_commit(commit: &str) -> Result<Option<Vec<Vulnerability>>, ApiError> {
    let req = Request::CommitQuery {
        commit: Commit::from(commit),
    };
    query(&req).await
}

///
/// Query the osv database for vulnerability by ID.
///
/// # Examples
///
/// ```
/// # use async_std::task;
/// use osv::client::vulnerability;
/// # task::block_on(async {
/// let vuln = vulnerability("OSV-2020-484").await.unwrap();
/// assert!(vuln.id.eq("OSV-2020-484"));
///
/// # });
/// ```
pub async fn vulnerability(vuln_id: &str) -> Result<Vulnerability, ApiError> {
    let base = Url::parse("https://api.osv.dev/v1/vulns/")?;
    let req = base.join(vuln_id)?;
    let res = reqwest::get(req.as_str()).await?;
    if res.status() == StatusCode::NOT_FOUND {
        Err(ApiError::NotFound(vuln_id.to_string()))
    } else {
        let vuln: Vulnerability = res.json().await?;
        Ok(vuln)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_package_query() {
        let req = Request::PackageQuery {
            version: Version::from("2.4.1"),
            package: Package {
                name: "jinja2".to_string(),
                ecosystem: Ecosystem::PyPI,
                purl: None,
            },
        };
        let res = query(&req).await.unwrap();
        assert!(res.is_some());
    }

    #[async_std::test]
    async fn test_package_query_wrapper() {
        let res = query_package("jinja2", "2.4.1", Ecosystem::PyPI)
            .await
            .unwrap();
        assert!(res.is_some());
    }

    #[async_std::test]
    async fn test_invalid_packagename() {
        let res = query_package(
            "asdfasdlfkjlksdjfklsdjfklsdjfklds",
            "0.0.1",
            Ecosystem::PyPI,
        )
        .await
        .unwrap();
        assert!(res.is_none());
    }

    #[async_std::test]
    async fn test_commit_query() {
        let req = Request::CommitQuery {
            commit: Commit::from("6879efc2c1596d11a6a6ad296f80063b558d5e0f"),
        };
        let res = query(&req).await.unwrap();
        assert!(res.is_some());
    }

    #[async_std::test]
    async fn test_commit_query_wrapper() {
        let res = query_commit("6879efc2c1596d11a6a6ad296f80063b558d5e0f")
            .await
            .unwrap();
        assert!(res.is_some());
    }

    #[async_std::test]
    async fn test_invalid_commit() {
        let res = query_commit("zzzz").await.unwrap();
        assert!(res.is_none());
    }

    #[async_std::test]
    async fn test_vulnerability() {
        let res = vulnerability("OSV-2020-484").await;
        assert!(res.is_ok());
    }

    #[async_std::test]
    async fn test_get_missing_cve() {
        let res = vulnerability("CVE-2014-0160").await;
        assert!(res.is_err());
    }
}
