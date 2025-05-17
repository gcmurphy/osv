use chrono::{DateTime, Utc};
use lazy_regex::regex_switch;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Package identifies the code library or command that
/// is potentially affected by a particular vulnerability.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Package {
    /// The name of the package or dependency.
    pub name: String,

    /// The ecosystem identifies the overall library ecosystem that this
    /// package can be obtained from.
    pub ecosystem: Ecosystem,

    /// The purl field is a string following the [Package URL
    /// specification](https://github.com/package-url/purl-spec) that identifies the
    /// package. This field is optional but recommended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// A commit is a full SHA1 Git hash in hex format.
pub type Commit = String;

/// Version is arbitrary string representing the version of a package.
pub type Version = String;

/// The package ecosystem that the vulnerabilities in the OSV database
/// are associated with.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Clone)]
#[non_exhaustive]
pub enum Ecosystem {
    AlmaLinux(Option<String>),
    Alpine(Option<String>),
    Android,
    Bioconductor,
    Bitnami,
    Chainguard,
    ConanCenter,
    CRAN,
    CratesIO,
    Debian(Option<String>),
    DWF,
    GHC,
    GSD,
    GitHubActions,
    Go,
    Hackage,
    Hex,
    JavaScript,
    Linux,
    Mageia(String),
    Maven(String),
    Npm,
    NuGet,
    OpenSUSE(Option<String>),
    OssFuzz,
    Packagist,
    PhotonOS(Option<String>),
    Pub,
    PyPI,
    Python,
    RedHat(Option<String>),
    RockyLinux(Option<String>),
    RubyGems,
    SUSE(Option<String>),
    SwiftURL,
    Ubuntu {
        version: String,
        metadata: Option<String>,
        fips: Option<String>,
        pro: bool,
        lts: bool,
    },
    UVI,
    Wolfi,
}

impl Serialize for Ecosystem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Ecosystem::AlmaLinux(None) => serializer.serialize_str("AlmaLinux"),
            Ecosystem::AlmaLinux(Some(release)) => {
                serializer.serialize_str(&format!("AlmaLinux:{}", release))
            }
            Ecosystem::Alpine(None) => serializer.serialize_str("Alpine"),
            Ecosystem::Alpine(Some(version)) => {
                serializer.serialize_str(&format!("Alpine:{}", version))
            }
            Ecosystem::Android => serializer.serialize_str("Android"),
            Ecosystem::Bioconductor => serializer.serialize_str("Bioconductor"),
            Ecosystem::Bitnami => serializer.serialize_str("Bitnami"),
            Ecosystem::Chainguard => serializer.serialize_str("Chainguard"),
            Ecosystem::ConanCenter => serializer.serialize_str("ConanCenter"),
            Ecosystem::CRAN => serializer.serialize_str("CRAN"),
            Ecosystem::CratesIO => serializer.serialize_str("crates.io"),
            Ecosystem::Debian(None) => serializer.serialize_str("Debian"),
            Ecosystem::Debian(Some(version)) => {
                serializer.serialize_str(&format!("Debian:{}", version))
            }
            Ecosystem::DWF => serializer.serialize_str("DWF"),
            Ecosystem::GHC => serializer.serialize_str("GHC"),
            Ecosystem::GSD => serializer.serialize_str("GSD"),
            Ecosystem::GitHubActions => serializer.serialize_str("GitHub Actions"),
            Ecosystem::Go => serializer.serialize_str("Go"),
            Ecosystem::Hackage => serializer.serialize_str("Hackage"),
            Ecosystem::Hex => serializer.serialize_str("Hex"),
            Ecosystem::JavaScript => serializer.serialize_str("JavaScript"),
            Ecosystem::Linux => serializer.serialize_str("Linux"),
            Ecosystem::Mageia(release) => serializer.serialize_str(&format!("Mageia:{}", release)),
            Ecosystem::Maven(repository) => {
                let mvn: String = match repository.as_str() {
                    "https://repo.maven.apache.org/maven2" => "Maven".to_string(),
                    _ => format!("Maven:{}", repository),
                };
                serializer.serialize_str(&mvn)
            }
            Ecosystem::Npm => serializer.serialize_str("npm"),
            Ecosystem::NuGet => serializer.serialize_str("NuGet"),
            Ecosystem::OpenSUSE(None) => serializer.serialize_str("openSUSE"),
            Ecosystem::OpenSUSE(Some(release)) => {
                serializer.serialize_str(&format!("openSUSE:{}", release))
            }
            Ecosystem::OssFuzz => serializer.serialize_str("OSS-Fuzz"),
            Ecosystem::Packagist => serializer.serialize_str("Packagist"),
            Ecosystem::PhotonOS(None) => serializer.serialize_str("Photon OS"),
            Ecosystem::PhotonOS(Some(release)) => {
                serializer.serialize_str(&format!("Photon OS:{}", release))
            }
            Ecosystem::Pub => serializer.serialize_str("Pub"),
            Ecosystem::PyPI => serializer.serialize_str("PyPI"),
            Ecosystem::Python => serializer.serialize_str("Python"),
            Ecosystem::RedHat(None) => serializer.serialize_str("Red Hat"),
            Ecosystem::RedHat(Some(release)) => {
                serializer.serialize_str(&format!("Red Hat:{}", release))
            }
            Ecosystem::RockyLinux(None) => serializer.serialize_str("Rocky Linux"),
            Ecosystem::RockyLinux(Some(release)) => {
                serializer.serialize_str(&format!("Rocky Linux:{}", release))
            }
            Ecosystem::RubyGems => serializer.serialize_str("RubyGems"),
            Ecosystem::SUSE(None) => serializer.serialize_str("SUSE"),
            Ecosystem::SUSE(Some(release)) => {
                serializer.serialize_str(&format!("SUSE:{}", release))
            }
            Ecosystem::SwiftURL => serializer.serialize_str("SwiftURL"),
            Ecosystem::Ubuntu {
                version,
                pro,
                lts,
                metadata,
                fips,
            } => {
                let mut parts: Vec<String> = vec!["Ubuntu".to_string()];
                if *pro {
                    parts.push("Pro".to_string());
                }
                if let Some(stream) = fips {
                    parts.push(stream.clone());
                }
                parts.push(version.clone());
                if *lts {
                    parts.push("LTS".to_string());
                }
                if let Some(meta) = metadata {
                    parts.push(meta.clone());
                }
                let serialized = parts.join(":");
                serializer.serialize_str(&serialized)
            }
            Ecosystem::UVI => serializer.serialize_str("UVI"),
            Ecosystem::Wolfi => serializer.serialize_str("Wolfi"),
        }
    }
}

impl<'de> Deserialize<'de> for Ecosystem {
    fn deserialize<D>(deserializer: D) -> Result<Ecosystem, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EcosystemVisitor;

        impl Visitor<'_> for EcosystemVisitor {
            type Value = Ecosystem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid string representing an ecosystem")
            }

            fn visit_str<E>(self, value: &str) -> Result<Ecosystem, E>
            where
                E: de::Error,
            {
                match value {
                    "AlmaLinux" | "AlmaLinux:" => Ok(Ecosystem::AlmaLinux(None)),
                    _ if value.starts_with("AlmaLinux:") => Ok(Ecosystem::AlmaLinux(
                        value.strip_prefix("AlmaLinux:").map(|v| v.to_string()),
                    )),
                    "Alpine" => Ok(Ecosystem::Alpine(None)),
                    _ if value.starts_with("Alpine:") => Ok(Ecosystem::Alpine(
                        value.strip_prefix("Alpine:").map(|v| v.to_string()),
                    )),
                    "Android" => Ok(Ecosystem::Android),
                    "Bioconductor" => Ok(Ecosystem::Bioconductor),
                    "Bitnami" => Ok(Ecosystem::Bitnami),
                    "Chainguard" => Ok(Ecosystem::Chainguard),
                    "ConanCenter" => Ok(Ecosystem::ConanCenter),
                    "CRAN" => Ok(Ecosystem::CRAN),
                    "crates.io" => Ok(Ecosystem::CratesIO),
                    "Debian" => Ok(Ecosystem::Debian(None)),
                    _ if value.starts_with("Debian:") => Ok(Ecosystem::Debian(
                        value.strip_prefix("Debian:").map(|v| v.to_string()),
                    )),
                    "DWF" => Ok(Ecosystem::DWF),
                    "GHC" => Ok(Ecosystem::GHC),
                    "GitHub Actions" => Ok(Ecosystem::GitHubActions),
                    "Go" => Ok(Ecosystem::Go),
                    "GSD" => Ok(Ecosystem::GSD),
                    "Hackage" => Ok(Ecosystem::Hackage),
                    "Hex" => Ok(Ecosystem::Hex),
                    "JavaScript" => Ok(Ecosystem::JavaScript),
                    "Linux" => Ok(Ecosystem::Linux),
                    _ if value.starts_with("Mageia:") => Ok(Ecosystem::Mageia(
                        value
                            .strip_prefix("Mageia:")
                            .map(|v| v.to_string())
                            .unwrap(),
                    )),
                    "Maven" | "Maven:" => Ok(Ecosystem::Maven(
                        "https://repo.maven.apache.org/maven2".to_string(),
                    )),
                    _ if value.starts_with("Maven:") => Ok(Ecosystem::Maven(
                        value.strip_prefix("Maven:").map(|v| v.to_string()).unwrap(),
                    )),
                    "npm" => Ok(Ecosystem::Npm),
                    "NuGet" => Ok(Ecosystem::NuGet),
                    "openSUSE" => Ok(Ecosystem::OpenSUSE(None)),
                    _ if value.starts_with("openSUSE:") => Ok(Ecosystem::OpenSUSE(
                        value.strip_prefix("openSUSE:").map(|v| v.to_string()),
                    )),
                    "OSS-Fuzz" => Ok(Ecosystem::OssFuzz),
                    "Packagist" => Ok(Ecosystem::Packagist),
                    "Photon OS" | "Photon OS:" => Ok(Ecosystem::PhotonOS(None)),
                    _ if value.starts_with("Photon OS:") => Ok(Ecosystem::PhotonOS(
                        value.strip_prefix("Photon OS:").map(|v| v.to_string()),
                    )),
                    "Pub" => Ok(Ecosystem::Pub),
                    "PyPI" => Ok(Ecosystem::PyPI),
                    "Python" => Ok(Ecosystem::Python),
                    "Red Hat" => Ok(Ecosystem::RedHat(None)),
                    _ if value.starts_with("Red Hat:") => Ok(Ecosystem::RedHat(
                        value.strip_prefix("Red Hat:").map(|v| v.to_string()),
                    )),
                    "Rocky Linux" | "Rocky Linux:" => Ok(Ecosystem::RockyLinux(None)),
                    _ if value.starts_with("Rocky Linux:") => Ok(Ecosystem::RockyLinux(
                        value.strip_prefix("Rocky Linux:").map(|v| v.to_string()),
                    )),
                    "RubyGems" => Ok(Ecosystem::RubyGems),
                    "SUSE" => Ok(Ecosystem::SUSE(None)),
                    _ if value.starts_with("SUSE:") => Ok(Ecosystem::SUSE(
                        value.strip_prefix("SUSE:").map(|v| v.to_string()),
                    )),
                    "SwiftURL" => Ok(Ecosystem::SwiftURL),
                    _ if value.starts_with("Ubuntu:") => {
                        regex_switch!(value,
                            r#"^Ubuntu(?::Pro)?(?::(?<fips>FIPS(?:-preview|-updates)?))?:(?<version>\d+\.\d+)(?::LTS)?(?::for:(?<specialized>.+))?$"# => {
                                Ecosystem::Ubuntu {
                                    version: version.to_string(),
                                    metadata: (!specialized.is_empty()).then_some(specialized.to_string()),
                                    fips: (!fips.is_empty()).then_some(fips.to_string()),
                                    pro: value.contains(":Pro"),
                                    lts: value.contains(":LTS"),
                                }
                            }
                        ).ok_or(de::Error::unknown_variant(value, &["Ecosystem"]))
                    }
                    "UVI" => Ok(Ecosystem::UVI),
                    "Wolfi" => Ok(Ecosystem::Wolfi),
                    _ => Err(de::Error::unknown_variant(value, &["Ecosystem"])),
                }
            }
        }
        deserializer.deserialize_str(EcosystemVisitor)
    }
}

/// Type of the affected range supplied. This can be an ecosystem
/// specific value, semver, or a git commit hash.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum RangeType {
    /// The versions introduced and fixed are arbitrary, uninterpreted strings specific to the
    /// package ecosystem
    Ecosystem,

    /// The versions introduced and fixed are full-length Git commit hashes.
    Git,

    /// The versions introduced and fixed are semantic versions as defined by SemVer 2.0.0.
    Semver,

    /// Default for the case where a range type is omitted.
    Unspecified,
}

/// The event captures information about the how and when
/// the package was affected by the vulnerability.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Event {
    /// The version or commit in which the vulnerability was
    /// introduced.
    Introduced(String),

    /// The version which the vulnerability was fixed.
    Fixed(String),

    /// Describes the last known affected version
    #[serde(rename = "last_affected")]
    LastAffected(String),

    /// The upper limit on the range being described.
    Limit(String),
}

/// The range of versions of a package for which
/// it is affected by the vulnerability.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Range {
    /// The format that the range events are specified in, for
    /// example SEMVER or GIT.
    #[serde(rename = "type")]
    pub range_type: RangeType,

    /// The ranges object’s repo field is the URL of the package’s code repository. The value
    /// should be in a format that’s directly usable as an argument for the version control
    /// system’s clone command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,

    /// Represent a status timeline for how the vulnerability affected the package. For
    /// example when the vulnerability was first introduced into the codebase.
    pub events: Vec<Event>,
}

/// The versions of the package that are affected
/// by a particular vulnerability. The affected ranges can include
/// when the vulnerability was first introduced and also when it
/// was fixed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Affected {
    /// The package that is affected by the vulnerability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,

    /// This `severity` field applies to a specific package, in cases where affected
    /// packages have differing severities for the same vulnerability. If any package
    /// level `severity` fields are set, the top level [`severity`](#severity-field)
    /// must not be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Vec<Severity>>,

    /// The range of versions or git commits that this vulnerability
    /// was first introduced and/or version that it was fixed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Range>>,

    /// Each string is a single affected version in whatever version syntax is
    /// used by the given package ecosystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,

    /// A JSON object that holds any additional information about the
    /// vulnerability as defined by the ecosystem for which the record applies.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<serde_json::Value>,

    /// A JSON object to hold any additional information about the range
    /// from which this record was obtained. The meaning of the values within
    /// the object is entirely defined by the database.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

/// The type of reference information that has been provided. Examples include
/// links to the original report, external advisories, or information about the
/// fix.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum ReferenceType {
    /// A published security advisory for the vulnerability.
    Advisory,

    /// An article or blog post describing the vulnerability.
    Article,

    /// A tool, script, scanner, or other mechanism that allows for detection
    /// of the vulnerability in production environments
    Detection,

    /// A social media discussion regarding the vulnerability.
    Discussion,

    /// A demonstration of the validity of a vulnerability claim
    Evidence,

    /// A source code browser link to the fix.
    Fix,

    /// Git commit hash or range where the issue occurred
    Git,

    /// A source code browser link to the introduction of the vulnerability.
    Introduced,

    /// A home web page for the package.
    Package,

    /// A report, typically on a bug or issue tracker, of the vulnerability.
    Report,

    #[serde(rename = "NONE")]
    Undefined,

    /// A web page of some unspecified kind.
    Web,
}

/// Reference to additional information about the vulnerability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reference {
    /// The type of reference this URL points to.
    #[serde(rename = "type")]
    pub reference_type: ReferenceType,

    /// The url where more information can be obtained about
    /// the vulnerability or associated the fix.
    pub url: String,
}

/// The [`SeverityType`](SeverityType) describes the quantitative scoring method used to rate the
/// severity of the vulnerability.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeverityType {
    /// A CVSS vector string representing the unique characteristics and severity of the vulnerability
    /// using a version of the [Common Vulnerability Scoring System notation](https://www.first.org/cvss/v2/)
    /// that is == 2.0 (e.g.`"AV:L/AC:M/Au:N/C:N/I:P/A:C"`).
    #[serde(rename = "CVSS_V2")]
    CVSSv2,

    /// A CVSS vector string representing the unique characteristics and severity of the
    /// vulnerability using a version of the Common Vulnerability Scoring System notation that is
    /// >= 3.0 and < 4.0 (e.g.`"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"`).
    #[serde(rename = "CVSS_V3")]
    CVSSv3,

    /// A CVSS vector string representing the unique characterictics and severity of the vulnerability
    /// using a version on the [Common Vulnerability Scoring System notation](https://www.first.org/cvss/)
    /// that is >= 4.0 and < 5.0 (e.g. `"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"`).
    #[serde(rename = "CVSS_V4")]
    CVSSv4,

    /// The severity score was arrived at by using an unspecified
    /// scoring method.
    #[serde(rename = "UNSPECIFIED")]
    Unspecified,
}

/// The type and score used to describe the severity of a vulnerability using one
/// or more quantitative scoring methods.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Severity {
    /// The severity type property must be a [`SeverityType`](SeverityType), which describes the
    /// quantitative method used to calculate the associated score.
    #[serde(rename = "type")]
    pub severity_type: SeverityType,

    /// The score property is a string representing the severity score based on the
    /// selected severity type.
    pub score: String,
}

/// The [`CreditType`](CreditType) this optional field should specify
/// the type or role of the individual or entity being credited.
///
/// These values and their definitions correspond directly to the [MITRE CVE specification](https://cveproject.github.io/cve-schema/schema/v5.0/docs/#collapseDescription_oneOf_i0_containers_cna_credits_items_type).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum CreditType {
    /// Validated the vulnerability to ensure accruacy or severity.
    Analyst,

    /// Facilitated the corredinated response process.
    Coordinator,

    /// Identified the vulnerability
    Finder,

    /// Any other type or role that does not fall under the categories
    /// described above.
    Other,

    /// Prepared a code change or other remediation plans.
    RemediationDeveloper,

    /// Reviewed vulnerability remediation plans or code changes
    /// for effectiveness and completeness.
    RemediationReviewer,

    /// Tested and verified the vulnerability or its remediation.
    RemediationVerifier,

    /// Notified the vendor of the vulnerability to a CNA.
    Reporter,

    /// Supported the vulnerability identification or remediation activities.
    Sponsor,

    /// Names of tools used in vulnerability discovery or identification.
    Tool,
}

/// Provides a way to give credit for the discovery, confirmation, patch or other events in the
/// life cycle of a vulnerability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credit {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_type: Option<CreditType>,
}

/// A vulnerability is the standard exchange format that is
/// defined by the OSV schema <https://ossf.github.io/osv-schema/>.
///
/// This is the entity that is returned when vulnerable data exists for
/// a given package or when requesting information about a specific vulnerability
/// by unique identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    /// The schema_version field is used to indicate which version of the OSV schema a particular
    /// vulnerability was exported with.
    pub schema_version: Option<String>,
    /// The id field is a unique identifier for the vulnerability entry. It is a string of the
    /// format <DB>-<ENTRYID>, where DB names the database and ENTRYID is in the format used by the
    /// database. For example: “OSV-2020-111”, “CVE-2021-3114”, or “GHSA-vp9c-fpxx-744v”.
    pub id: String,

    /// The published field gives the time the entry should be considered to have been published,
    /// as an RFC3339-formatted time stamp in UTC (ending in “Z”).
    pub published: Option<DateTime<Utc>>,

    /// The modified field gives the time the entry was last modified, as an RFC3339-formatted
    /// timestamptime stamp in UTC (ending in “Z”).
    pub modified: DateTime<Utc>,

    /// The withdrawn field gives the time the entry should be considered to have been withdrawn,
    /// as an RFC3339-formatted timestamp in UTC (ending in “Z”). If the field is missing, then the
    /// entry has not been withdrawn. Any rationale for why the vulnerability has been withdrawn
    /// should go into the summary text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<DateTime<Utc>>,

    /// The aliases field gives a list of IDs of the same vulnerability in other databases, in the
    /// form of the id field. This allows one database to claim that its own entry describes the
    /// same vulnerability as one or more entries in other databases. Or if one database entry has
    /// been deduplicated into another in the same database, the duplicate entry could be written
    /// using only the id, modified, and aliases field, to point to the canonical one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// The related field gives a list of IDs of closely related vulnerabilities, such as the same
    /// problem in alternate ecosystems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<String>>,

    /// The summary field gives a one-line, English textual summary of the vulnerability. It is
    /// recommended that this field be kept short, on the order of no more than 120 characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// The details field gives additional English textual details about the vulnerability. The
    /// details field is CommonMark markdown (a subset of GitHub-Flavored Markdown). Display code
    /// may at its discretion sanitize the input further, such as stripping raw HTML and links that
    /// do not start with http:// or https://. Databases are encouraged not to include those in the
    /// first place. (The goal is to balance flexibility of presentation with not exposing
    /// vulnerability database display sites to unnecessary vulnerabilities.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Indicates the specific package ranges that are affected by this vulnerability.
    pub affected: Option<Vec<Affected>>,

    /// An optional list of external reference's that provide more context about this
    /// vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Reference>>,

    /// The severity field is a JSON array that allows generating systems to describe the severity
    /// of a vulnerability using one or more quantitative scoring methods. Each severity item is a
    /// object specifying a type and score property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Vec<Severity>>,

    /// Provides a way to give credit for the discovery, confirmation, patch or other events in the
    /// life cycle of a vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits: Option<Vec<Credit>>,

    /// Top level field to hold any additional information about the vulnerability as defined
    /// by the database from which the record was obtained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_serialize_null_fields() {
        let vuln = Vulnerability {
            schema_version: Some("1.3.0".to_string()),
            id: "OSV-2020-484".to_string(),
            published: Some(chrono::Utc::now()),
            modified: chrono::Utc::now(),
            withdrawn: None,
            aliases: None,
            related: None,
            summary: None,
            details: None,
            affected: None,
            references: None,
            severity: None,
            credits: None,
            database_specific: None,
        };

        let as_json = serde_json::json!(vuln);
        let str_json = as_json.to_string();
        assert!(!str_json.contains("withdrawn"));
        assert!(!str_json.contains("aliases"));
        assert!(!str_json.contains("related"));
        assert!(!str_json.contains("summary"));
        assert!(!str_json.contains("details"));
        assert!(!str_json.contains("references"));
        assert!(!str_json.contains("severity"));
        assert!(!str_json.contains("credits"));
        assert!(!str_json.contains("database_specific"));
    }

    #[test]
    fn test_maven_ecosystem() {
        let maven = Ecosystem::Maven("https://repo.maven.apache.org/maven2".to_string());
        let as_json = serde_json::json!(maven);
        assert_eq!(as_json, serde_json::json!("Maven"));

        let maven = Ecosystem::Maven("https://repo1.example.com/maven2".to_string());
        let as_json = serde_json::json!(maven);
        assert_eq!(
            as_json,
            serde_json::json!("Maven:https://repo1.example.com/maven2")
        );

        let json_str = r#""Maven""#;
        let maven: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            maven,
            Ecosystem::Maven("https://repo.maven.apache.org/maven2".to_string())
        );

        let json_str = r#""Maven:""#;
        let maven: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            maven,
            Ecosystem::Maven("https://repo.maven.apache.org/maven2".to_string())
        );
    }

    #[test]
    fn test_ubuntu_ecosystem() {
        let ubuntu = Ecosystem::Ubuntu {
            version: "20.04".to_string(),
            pro: true,
            lts: true,
            fips: None,
            metadata: None,
        };
        let as_json = serde_json::json!(ubuntu);
        assert_eq!(as_json, serde_json::json!("Ubuntu:Pro:20.04:LTS"));

        let ubuntu = Ecosystem::Ubuntu {
            version: "20.04".to_string(),
            pro: true,
            lts: false,
            fips: None,
            metadata: None,
        };
        let as_json = serde_json::json!(ubuntu);
        assert_eq!(as_json, serde_json::json!("Ubuntu:Pro:20.04"));

        let ubuntu = Ecosystem::Ubuntu {
            version: "20.04".to_string(),
            pro: false,
            lts: true,
            fips: None,
            metadata: None,
        };
        let as_json = serde_json::json!(ubuntu);
        assert_eq!(as_json, serde_json::json!("Ubuntu:20.04:LTS"));

        let ubuntu = Ecosystem::Ubuntu {
            version: "20.04".to_string(),
            pro: false,
            lts: false,
            fips: None,
            metadata: None,
        };
        let as_json = serde_json::json!(ubuntu);
        assert_eq!(as_json, serde_json::json!("Ubuntu:20.04"));

        let json_str = r#""Ubuntu:Pro:20.04:LTS""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "20.04".to_string(),
                pro: true,
                lts: true,
                fips: None,
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:Pro:20.04""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "20.04".to_string(),
                pro: true,
                lts: false,
                fips: None,
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:20.04:LTS""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "20.04".to_string(),
                pro: false,
                lts: true,
                fips: None,
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:20.04""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "20.04".to_string(),
                pro: false,
                lts: false,
                fips: None,
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:22.04:LTS:for:NVIDIA:BlueField""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "22.04".to_string(),
                pro: false,
                lts: true,
                fips: None,
                metadata: Some("NVIDIA:BlueField".to_string()),
            }
        );

        let json_str = r#""Ubuntu:Pro:FIPS-preview:22.04:LTS""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "22.04".to_string(),
                pro: true,
                lts: true,
                fips: Some("FIPS-preview".to_string()),
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:Pro:FIPS-updates:18.04:LTS""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "18.04".to_string(),
                pro: true,
                lts: true,
                fips: Some("FIPS-updates".to_string()),
                metadata: None,
            }
        );

        let json_str = r#""Ubuntu:Pro:FIPS:16.04:LTS""#;
        let ubuntu: Ecosystem = serde_json::from_str(json_str).unwrap();

        assert_eq!(
            ubuntu,
            Ecosystem::Ubuntu {
                version: "16.04".to_string(),
                pro: true,
                lts: true,
                fips: Some("FIPS".to_string()),
                metadata: None,
            }
        );
    }
}
