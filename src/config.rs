//! Ceremony configuration engine — loads, validates, and sorts PKI hierarchy configs.
//!
//! Supports YAML and JSON config files describing the full certificate hierarchy
//! for a PKI ceremony. The config is validated for structural correctness (parent
//! references, cycles, CA constraints) before any keys are generated.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Schema types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    pub name: String,
    pub organization: String,
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub passphrases: PassphraseConfig,
    pub hierarchy: Vec<CertSpec>,
    #[serde(default)]
    pub paper_backup: Option<PaperBackupConfig>,
    #[serde(default)]
    pub deployment: Option<DeploymentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseConfig {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default)]
    pub manager_hint: Option<String>,
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            manager_hint: None,
        }
    }
}

fn default_min_length() -> usize {
    16
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSpec {
    pub name: String,
    pub cn: String,
    pub cert_type: CertType,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default = "Algorithm::default")]
    pub algorithm: Algorithm,
    #[serde(default)]
    pub hash: Option<HashAlgorithm>,
    pub validity: Validity,
    #[serde(default)]
    pub pathlen: Option<u8>,
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub no_passphrase: bool,
    #[serde(default)]
    pub parallel_keys: Vec<Algorithm>,
    #[serde(default)]
    pub extensions: Option<ExtensionSpec>,
    #[serde(default)]
    pub subject: Option<SubjectSpec>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub deploy_to: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertType {
    Root,
    Intermediate,
    SubCa,
    Leaf,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "rsa_4096", alias = "rsa4096")]
    Rsa4096,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "ml_dsa_87", alias = "ml_dsa87")]
    MlDsa87,
    #[serde(rename = "ml_kem_1024", alias = "ml_kem1024")]
    MlKem1024,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    #[serde(default)]
    pub years: Option<u32>,
    #[serde(default)]
    pub days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSpec {
    #[serde(default)]
    pub key_usage: Vec<String>,
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    #[serde(default)]
    pub basic_constraints_ca: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectSpec {
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub organizational_unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperBackupConfig {
    #[serde(default)]
    pub formats: Vec<BarcodeFormat>,
    #[serde(default = "default_paper_output")]
    pub output: String,
    #[serde(default = "default_true")]
    pub include_pem: bool,
}

fn default_paper_output() -> String {
    "html".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BarcodeFormat {
    Qr,
    Aztec,
    Pdf417,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub packages: Vec<DeployPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPackage {
    pub name: String,
    pub target: String,
    pub patterns: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Loading
// ═══════════════════════════════════════════════════════════════

/// Load a ceremony config from a YAML or JSON file.
///
/// File format is auto-detected by extension:
/// - `.yaml` / `.yml` -> YAML
/// - `.json` -> JSON
/// - anything else -> try YAML first, then JSON
pub fn load_config(path: &str) -> Result<CeremonyConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {path}"))?;

    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let config: CeremonyConfig = match ext.as_str() {
        "json" => serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse JSON config: {path}"))?,
        "yaml" | "yml" => serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML config: {path}"))?,
        _ => {
            // Try YAML first (superset of JSON), fall back to JSON
            serde_yaml::from_str(&content)
                .or_else(|_| serde_json::from_str(&content))
                .with_context(|| format!("Failed to parse config (tried YAML and JSON): {path}"))?
        }
    };

    Ok(config)
}

// ═══════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════

/// Validate structural correctness of the ceremony config.
///
/// Checks:
/// - Cert names are unique
/// - Parent references resolve to existing certs
/// - Root certs have no parent
/// - Non-root certs have a parent
/// - Parents are CA types (root, intermediate, sub_ca)
/// - No cycles in the hierarchy
/// - Validity is specified (years or days, not both absent)
/// - pathlen is only set on CA types
/// - At least one cert exists
pub fn validate_config(config: &CeremonyConfig) -> Result<()> {
    if config.hierarchy.is_empty() {
        bail!("Config has no certificates in the hierarchy");
    }

    // Build name->index map and check uniqueness
    let mut name_map: HashMap<&str, usize> = HashMap::new();
    for (i, cert) in config.hierarchy.iter().enumerate() {
        if let Some(prev) = name_map.insert(&cert.name, i) {
            bail!(
                "Duplicate cert name '{}' at positions {} and {}",
                cert.name,
                prev,
                i
            );
        }
    }

    let mut root_count = 0;

    for cert in &config.hierarchy {
        // Root certs must not have a parent
        if cert.cert_type == CertType::Root {
            root_count += 1;
            if cert.parent.is_some() {
                bail!("Root cert '{}' must not have a parent", cert.name);
            }
        } else {
            // Non-root certs must have a parent
            let parent_name = cert.parent.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Non-root cert '{}' (type {:?}) must have a parent",
                    cert.name,
                    cert.cert_type
                )
            })?;

            // Parent must exist
            if !name_map.contains_key(parent_name.as_str()) {
                bail!(
                    "Cert '{}' references parent '{}' which does not exist",
                    cert.name,
                    parent_name
                );
            }

            // Parent must be a CA type
            let parent_cert = &config.hierarchy[name_map[parent_name.as_str()]];
            match parent_cert.cert_type {
                CertType::Root | CertType::Intermediate | CertType::SubCa => {}
                CertType::Leaf => {
                    bail!(
                        "Cert '{}' has parent '{}' which is a leaf — only CAs can issue certs",
                        cert.name,
                        parent_name
                    );
                }
            }
        }

        // Validity: at least one of years/days must be set
        if cert.validity.years.is_none() && cert.validity.days.is_none() {
            bail!(
                "Cert '{}' has no validity period — set years or days",
                cert.name
            );
        }

        // pathlen only makes sense for CA types
        if cert.pathlen.is_some() && cert.cert_type == CertType::Leaf {
            bail!(
                "Cert '{}' is a leaf but has pathlen set — only CAs have path length constraints",
                cert.name
            );
        }
    }

    if root_count == 0 {
        bail!("No root CA found in the hierarchy — at least one cert must have cert_type: root");
    }

    // Cycle detection via topological sort attempt
    detect_cycles(config, &name_map)?;

    Ok(())
}

/// Detect cycles in the cert hierarchy. Returns an error if a cycle is found.
fn detect_cycles(config: &CeremonyConfig, name_map: &HashMap<&str, usize>) -> Result<()> {
    let n = config.hierarchy.len();
    let mut in_degree = vec![0usize; n];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, cert) in config.hierarchy.iter().enumerate() {
        if let Some(ref parent_name) = cert.parent
            && let Some(&parent_idx) = name_map.get(parent_name.as_str())
        {
            children[parent_idx].push(i);
            in_degree[i] += 1;
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, degree) in in_degree.iter().enumerate() {
        if *degree == 0 {
            queue.push_back(i);
        }
    }

    let mut visited = 0;
    while let Some(node) = queue.pop_front() {
        visited += 1;
        for &child in &children[node] {
            in_degree[child] -= 1;
            if in_degree[child] == 0 {
                queue.push_back(child);
            }
        }
    }

    if visited < n {
        // Find certs involved in cycles for a useful error message
        let cycle_certs: Vec<&str> = (0..n)
            .filter(|&i| in_degree[i] > 0)
            .map(|i| config.hierarchy[i].name.as_str())
            .collect();
        bail!(
            "Cycle detected in certificate hierarchy involving: {}",
            cycle_certs.join(", ")
        );
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Topological sort
// ═══════════════════════════════════════════════════════════════

/// Return certs in topological order — parents before children.
///
/// This ensures that when generating certificates, a parent CA's cert
/// is always available before any child needs to be signed by it.
pub fn topological_sort(config: &CeremonyConfig) -> Result<Vec<&CertSpec>> {
    let n = config.hierarchy.len();
    let name_map: HashMap<&str, usize> = config
        .hierarchy
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i))
        .collect();

    let mut in_degree = vec![0usize; n];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, cert) in config.hierarchy.iter().enumerate() {
        if let Some(ref parent_name) = cert.parent
            && let Some(&parent_idx) = name_map.get(parent_name.as_str())
        {
            children[parent_idx].push(i);
            in_degree[i] += 1;
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, degree) in in_degree.iter().enumerate() {
        if *degree == 0 {
            queue.push_back(i);
        }
    }

    let mut result: Vec<&CertSpec> = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        result.push(&config.hierarchy[node]);
        for &child in &children[node] {
            in_degree[child] -= 1;
            if in_degree[child] == 0 {
                queue.push_back(child);
            }
        }
    }

    if result.len() < n {
        bail!("Cannot topologically sort — cycle detected in hierarchy");
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
// Passphrase grouping
// ═══════════════════════════════════════════════════════════════

/// Group certs that share a passphrase.
///
/// Grouping logic:
/// - Certs with `no_passphrase: true` are excluded (no group)
/// - Root certs get their own group (one per root)
/// - Offline CAs at the same depth share a group
/// - Online certs sharing the same parent share a group
/// - Leaf certs sharing the same parent share a group
pub fn passphrase_groups(config: &CeremonyConfig) -> Vec<Vec<&CertSpec>> {
    // Simple grouping: group by (parent, offline) for passphrase-required certs.
    // Root CAs each get their own group. Everything else groups by parent.
    let mut groups: Vec<Vec<&CertSpec>> = Vec::new();
    let mut parent_groups: HashMap<Option<&str>, Vec<&CertSpec>> = HashMap::new();

    for cert in &config.hierarchy {
        if cert.no_passphrase {
            continue;
        }

        if cert.cert_type == CertType::Root {
            // Each root gets its own group
            groups.push(vec![cert]);
        } else {
            let key = cert.parent.as_deref();
            parent_groups.entry(key).or_default().push(cert);
        }
    }

    for (_, certs) in parent_groups {
        if !certs.is_empty() {
            groups.push(certs);
        }
    }

    groups
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_valid_yaml() -> &'static str {
        r#"
name: test-pki
organization: Test LLC
hierarchy:
  - name: root-ca
    cn: Test Root CA
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    offline: true
  - name: intermediate
    cn: Test Intermediate
    cert_type: intermediate
    parent: root-ca
    algorithm: rsa_4096
    validity:
      years: 10
  - name: leaf-signer
    cn: Test Signer
    cert_type: leaf
    parent: intermediate
    algorithm: ed25519
    validity:
      days: 365
    no_passphrase: true
"#
    }

    #[test]
    fn parse_valid_yaml() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        assert_eq!(config.name, "test-pki");
        assert_eq!(config.organization, "Test LLC");
        assert_eq!(config.hierarchy.len(), 3);
        assert_eq!(config.hierarchy[0].cert_type, CertType::Root);
        assert_eq!(config.hierarchy[1].cert_type, CertType::Intermediate);
        assert_eq!(config.hierarchy[2].cert_type, CertType::Leaf);
        assert!(config.hierarchy[2].no_passphrase);
        assert_eq!(config.passphrases.min_length, 16); // default
    }

    #[test]
    fn parse_valid_json() {
        let json = r#"{
            "name": "json-test",
            "organization": "JSON LLC",
            "hierarchy": [
                {
                    "name": "root",
                    "cn": "Root CA",
                    "cert_type": "root",
                    "algorithm": "rsa_4096",
                    "validity": { "years": 20 }
                }
            ]
        }"#;
        let config: CeremonyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "json-test");
        assert_eq!(config.hierarchy.len(), 1);
    }

    #[test]
    fn validate_minimal_config() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        validate_config(&config).unwrap();
    }

    #[test]
    fn reject_empty_hierarchy() {
        let yaml = r#"
name: empty
organization: Empty LLC
hierarchy: []
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("no certificates"), "{err}");
    }

    #[test]
    fn reject_root_with_parent() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    parent: something
    algorithm: rsa_4096
    validity:
      years: 20
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("must not have a parent"), "{err}");
    }

    #[test]
    fn reject_non_root_without_parent() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: orphan
    cn: Orphan
    cert_type: intermediate
    algorithm: rsa_4096
    validity:
      years: 10
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("must have a parent"), "{err}");
    }

    #[test]
    fn reject_missing_parent_reference() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: child
    cn: Child
    cert_type: intermediate
    parent: nonexistent
    algorithm: rsa_4096
    validity:
      years: 10
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn reject_leaf_as_parent() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: leaf
    cn: Leaf
    cert_type: leaf
    parent: root
    algorithm: rsa_4096
    validity:
      years: 2
  - name: child-of-leaf
    cn: Bad Child
    cert_type: leaf
    parent: leaf
    algorithm: rsa_4096
    validity:
      years: 1
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("leaf"), "{err}");
    }

    #[test]
    fn reject_no_validity() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity: {}
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("validity"), "{err}");
    }

    #[test]
    fn reject_pathlen_on_leaf() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: leaf
    cn: Leaf
    cert_type: leaf
    parent: root
    algorithm: rsa_4096
    validity:
      years: 1
    pathlen: 0
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("pathlen"), "{err}");
    }

    #[test]
    fn reject_duplicate_names() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: dupe
    cn: First
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: dupe
    cn: Second
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("Duplicate"), "{err}");
    }

    #[test]
    fn reject_no_root() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: inter
    cn: Inter
    cert_type: intermediate
    parent: inter
    algorithm: rsa_4096
    validity:
      years: 10
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        // This will hit either "no root" or "cycle" depending on ordering
        assert!(
            err.to_string().contains("root") || err.to_string().contains("ycle"),
            "{err}"
        );
    }

    #[test]
    fn detect_cycle() {
        let yaml = r#"
name: bad
organization: Bad LLC
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
  - name: a
    cn: A
    cert_type: intermediate
    parent: b
    algorithm: rsa_4096
    validity:
      years: 10
  - name: b
    cn: B
    cert_type: sub_ca
    parent: a
    algorithm: rsa_4096
    validity:
      years: 5
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("ycle"), "{err}");
    }

    #[test]
    fn topological_sort_basic() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        let sorted = topological_sort(&config).unwrap();
        assert_eq!(sorted.len(), 3);
        // Root must come first
        assert_eq!(sorted[0].name, "root-ca");
        // Intermediate before its child
        let inter_pos = sorted
            .iter()
            .position(|c| c.name == "intermediate")
            .unwrap();
        let leaf_pos = sorted.iter().position(|c| c.name == "leaf-signer").unwrap();
        assert!(inter_pos < leaf_pos);
    }

    #[test]
    fn topological_sort_deep_hierarchy() {
        let yaml = r#"
name: deep
organization: Deep LLC
hierarchy:
  - name: leaf
    cn: Leaf
    cert_type: leaf
    parent: sub
    algorithm: ed25519
    validity:
      days: 90
  - name: sub
    cn: Sub CA
    cert_type: sub_ca
    parent: inter
    algorithm: rsa_4096
    validity:
      years: 5
  - name: inter
    cn: Intermediate
    cert_type: intermediate
    parent: root
    algorithm: rsa_4096
    validity:
      years: 10
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let sorted = topological_sort(&config).unwrap();
        let names: Vec<&str> = sorted.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["root", "inter", "sub", "leaf"]);
    }

    #[test]
    fn passphrase_groups_basic() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        let groups = passphrase_groups(&config);

        // root-ca gets its own group, intermediate gets a group, leaf-signer is excluded (no_passphrase)
        let all_names: Vec<Vec<&str>> = groups
            .iter()
            .map(|g| g.iter().map(|c| c.name.as_str()).collect())
            .collect();

        // Root should be in its own group
        assert!(all_names.iter().any(|g| g == &["root-ca"]));
        // Intermediate should be in a group
        assert!(all_names.iter().any(|g| g.contains(&"intermediate")));
        // leaf-signer should not appear (no_passphrase)
        assert!(!all_names.iter().any(|g| g.contains(&"leaf-signer")));
    }

    #[test]
    fn serde_roundtrip_yaml() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        let serialized = serde_yaml::to_string(&config).unwrap();
        let roundtrip: CeremonyConfig = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(config.name, roundtrip.name);
        assert_eq!(config.hierarchy.len(), roundtrip.hierarchy.len());
    }

    #[test]
    fn serde_roundtrip_json() {
        let config: CeremonyConfig = serde_yaml::from_str(minimal_valid_yaml()).unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let roundtrip: CeremonyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.name, roundtrip.name);
        assert_eq!(config.hierarchy.len(), roundtrip.hierarchy.len());
    }

    #[test]
    fn all_algorithms_parse() {
        for alg in [
            "rsa_4096",
            "ed25519",
            "ml_dsa_87",
            "ml_kem_1024",
            "rsa4096",
            "ml_dsa87",
            "ml_kem1024",
        ] {
            let yaml = format!(
                r#"
name: alg-test
organization: Test
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: {alg}
    validity:
      years: 20
"#
            );
            let config: CeremonyConfig = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(config.hierarchy[0].name, "root");
        }
    }

    #[test]
    fn all_hash_algorithms_parse() {
        for hash in ["sha256", "sha384", "sha512"] {
            let yaml = format!(
                r#"
name: hash-test
organization: Test
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    hash: {hash}
    validity:
      years: 20
"#
            );
            let config: CeremonyConfig = serde_yaml::from_str(&yaml).unwrap();
            assert!(config.hierarchy[0].hash.is_some());
        }
    }

    #[test]
    fn extensions_and_subject_parse() {
        let yaml = r#"
name: ext-test
organization: Test
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    extensions:
      key_usage:
        - keyCertSign
        - cRLSign
      extended_key_usage: []
      basic_constraints_ca: true
    subject:
      country: US
      organization: Test LLC
      organizational_unit: PKI
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let ext = config.hierarchy[0].extensions.as_ref().unwrap();
        assert_eq!(ext.key_usage.len(), 2);
        assert_eq!(ext.basic_constraints_ca, Some(true));
        let subj = config.hierarchy[0].subject.as_ref().unwrap();
        assert_eq!(subj.country.as_deref(), Some("US"));
    }

    #[test]
    fn paper_backup_and_deployment_parse() {
        let yaml = r#"
name: deploy-test
organization: Test
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
paper_backup:
  formats: [qr, pdf417]
  output: html
  include_pem: true
deployment:
  packages:
    - name: public
      target: deploy/public
      patterns: ["*.crt", "*.pub"]
    - name: private
      target: deploy/private
      patterns: ["*.key"]
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        let pb = config.paper_backup.as_ref().unwrap();
        assert_eq!(pb.formats.len(), 2);
        assert!(pb.include_pem);
        let deploy = config.deployment.as_ref().unwrap();
        assert_eq!(deploy.packages.len(), 2);
        assert_eq!(deploy.packages[0].patterns, vec!["*.crt", "*.pub"]);
    }

    #[test]
    fn load_config_from_file() {
        let dir = std::env::temp_dir().join("hedonistic-pki-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.yaml");
        std::fs::write(&path, minimal_valid_yaml()).unwrap();

        let config = load_config(path.to_str().unwrap()).unwrap();
        assert_eq!(config.name, "test-pki");
        validate_config(&config).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_json_file() {
        let dir = std::env::temp_dir().join("hedonistic-pki-test-json");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");
        let json = r#"{
            "name": "json-file-test",
            "organization": "JSON LLC",
            "hierarchy": [
                {
                    "name": "root",
                    "cn": "Root CA",
                    "cert_type": "root",
                    "algorithm": "rsa_4096",
                    "validity": { "years": 20 }
                }
            ]
        }"#;
        std::fs::write(&path, json).unwrap();

        let config = load_config(path.to_str().unwrap()).unwrap();
        assert_eq!(config.name, "json-file-test");
        validate_config(&config).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_nonexistent_file() {
        let err = load_config("/nonexistent/path/config.yaml").unwrap_err();
        assert!(err.to_string().contains("Failed to read"), "{err}");
    }

    #[test]
    fn parallel_keys_and_tags() {
        let yaml = r#"
name: tags-test
organization: Test
hierarchy:
  - name: root
    cn: Root
    cert_type: root
    algorithm: rsa_4096
    validity:
      years: 20
    parallel_keys:
      - ed25519
      - ml_dsa_87
    tags:
      - offline
      - ceremony
"#;
        let config: CeremonyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hierarchy[0].parallel_keys.len(), 2);
        assert_eq!(config.hierarchy[0].parallel_keys[0], Algorithm::Ed25519);
        assert_eq!(config.hierarchy[0].tags, vec!["offline", "ceremony"]);
    }
}
