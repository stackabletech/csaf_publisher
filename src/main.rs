use color_eyre::eyre::Context;
use csaf::definitions::Note;
use csaf::document::Revision;
use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use sha2::{Digest, Sha256, Sha512};
use std::{env, fs};

use chrono::{Datelike, SecondsFormat};
use color_eyre::eyre::{bail, ContextCompat, Result};
use csaf::{
    definitions::{Branch, BranchCategory, BranchesT},
    Csaf,
};
use regex::Regex;

const SECOBSERVE_API_BASE: &str = "https://secobserve-backend.stackable.tech/api";

fn main() -> Result<()> {
    color_eyre::install()?;

    let secobserve_api_token =
        env::var("SECOBSERVE_API_TOKEN").context("Missing SecObserve API token!")?;

    // The TLP label (https://www.first.org/tlp/) controls how the published
    // documents may be distributed, e.g. WHITE for the public advisories and
    // AMBER for the customer-only advisories.
    let tlp_label = env::var("TLP_LABEL").unwrap_or_else(|_| "WHITE".to_string());
    if !["WHITE", "GREEN", "AMBER", "RED"].contains(&tlp_label.as_str()) {
        bail!("invalid TLP label {tlp_label:?}, expected WHITE, GREEN, AMBER or RED");
    }

    // The first argument selects the publishing mode, the remaining arguments
    // are the documents to publish (one CSAF document per argument, so that
    // the filename can be derived from the document tracking id).
    let mut arguments = env::args().skip(1);
    let mode = arguments
        .next()
        .context("no mode given, expected \"cve\" or \"product-version\"")?;
    let names: Vec<String> = arguments.collect();
    if names.is_empty() {
        bail!("no names given after mode {mode:?}");
    }

    match mode.as_str() {
        "cve" => {
            for vulnerability_name in &names {
                publish_vulnerability_advisory(
                    vulnerability_name,
                    &secobserve_api_token,
                    &tlp_label,
                )?;
            }
        }
        "product-version" => {
            // Product versions are given as `<product>:<branch>`, matching the
            // product ids used in the CSAF documents,
            // e.g. `airflow:3.1.6-stackable26.3.0-amd64`.
            for product_version in &names {
                publish_product_version_advisory(
                    product_version,
                    &secobserve_api_token,
                    &tlp_label,
                )?;
            }
        }
        _ => bail!("unknown mode {mode:?}, expected \"cve\" or \"product-version\""),
    }

    // Generate directory listings
    for year_directory in year_directories()? {
        generate_index_html(&year_directory)?;
    }
    generate_index_html(".")?;

    Ok(())
}

fn publish_vulnerability_advisory(
    vulnerability_name: &str,
    secobserve_api_token: &str,
    tlp_label: &str,
) -> Result<()> {
    // Retrieve CSAF document from SecObserve API
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{SECOBSERVE_API_BASE}/vex/csaf_document/create/"))
        .json(&serde_json::json!({
            "vulnerability_names": &[vulnerability_name],
            "document_id_prefix": "STACKSA",
            "title": format!("Stackable Security Advisory for: {}", vulnerability_name),
            "publisher_name": "Stackable GmbH",
            "publisher_category": "vendor",
            "publisher_namespace": "https://www.stackable.tech",
            "tracking_status": "final",
            "tlp_label": tlp_label
        }))
        .header(
            "Authorization",
            format!("APIToken {}", secobserve_api_token),
        )
        .header("User-Agent", "Stackable Security Advisory Generator")
        .send()?;

    // Fail with the response body, so that SecObserve errors (e.g.
    // "Vulnerability with name ... does not exist" for a mistyped
    // vulnerability id) show up in the output instead of a parse error.
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        bail!("SecObserve returned {status} for vulnerability {vulnerability_name:?}: {body}");
    }

    // The document tracking id is the vulnerability id, so that the filename
    // (the lowercased tracking id) is stable across republications and an
    // existing advisory can be updated in place.
    publish_csaf_document(&body, vulnerability_name, tlp_label)
}

/// Publishes a VEX document containing all vulnerability statements for a
/// single product version, given as `<product>:<branch>` with the SecObserve
/// product and branch names, e.g. `airflow:3.1.6-stackable26.3.0-amd64`.
fn publish_product_version_advisory(
    product_version: &str,
    secobserve_api_token: &str,
    tlp_label: &str,
) -> Result<()> {
    let (product_name, branch_name) = product_version.split_once(':').context(format!(
        "invalid product version {product_version:?}, expected <product>:<branch>, e.g. airflow:3.1.6-stackable26.3.0-amd64"
    ))?;

    let product_id = find_product_id(product_name, secobserve_api_token)?;

    // Retrieve CSAF document from SecObserve API. Restricting the document to
    // the given branch limits it to a single product version.
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{SECOBSERVE_API_BASE}/vex/csaf_document/create/"))
        .json(&serde_json::json!({
            "product": product_id,
            "branch_names": &[branch_name],
            "document_id_prefix": "STACKSA",
            "title": format!("Stackable Security Advisory for: {}", product_version),
            "publisher_name": "Stackable GmbH",
            "publisher_category": "vendor",
            "publisher_namespace": "https://www.stackable.tech",
            "tracking_status": "final",
            "tlp_label": tlp_label
        }))
        .header(
            "Authorization",
            format!("APIToken {}", secobserve_api_token),
        )
        .header("User-Agent", "Stackable Security Advisory Generator")
        .send()?;

    let status = response.status();
    // SecObserve returns 204 when there are no vulnerability statements for
    // the given product version, which would produce an empty VEX document.
    if status == reqwest::StatusCode::NO_CONTENT {
        bail!(
            "SecObserve returned no vulnerability statements for product version {product_version:?}"
        );
    }
    let body = response.text()?;
    if !status.is_success() {
        bail!("SecObserve returned {status} for product version {product_version:?}: {body}");
    }

    // The document tracking id is derived from the product version, so that
    // the filename is stable across republications and an existing advisory
    // can be updated in place. The `:` separator is replaced by `-` to keep
    // the tracking id readable.
    let tracking_id = format!("{}-{}", product_name, branch_name);
    publish_csaf_document(&body, &tracking_id, tlp_label)
}

/// Looks up the SecObserve product id for the given product name.
fn find_product_id(product_name: &str, secobserve_api_token: &str) -> Result<u64> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("{SECOBSERVE_API_BASE}/products/"))
        .query(&[("name", product_name)])
        .header(
            "Authorization",
            format!("APIToken {}", secobserve_api_token),
        )
        .header("User-Agent", "Stackable Security Advisory Generator")
        .send()?;

    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        bail!("SecObserve returned {status} when looking up product {product_name:?}: {body}");
    }

    // The `name` filter matches substrings, so search the results for an
    // exact match.
    let products: serde_json::Value = serde_json::from_str(&body)?;
    products
        .get("results")
        .and_then(serde_json::Value::as_array)
        .context("missing results in product list")?
        .iter()
        .find(|product| {
            product.get("name").and_then(serde_json::Value::as_str) == Some(product_name)
        })
        .and_then(|product| product.get("id"))
        .and_then(serde_json::Value::as_u64)
        .context(format!(
            "product {product_name:?} does not exist in SecObserve"
        ))
}

/// Applies the Stackable customizations to a CSAF document returned by
/// SecObserve and writes it to the advisory directory structure, together with
/// its PGP signature and hashes. The document tracking id determines the
/// filename (the lowercased tracking id), so it must be stable across republications:
/// an already published document is updated in place, keeping its initial release
/// date and revision history.
fn publish_csaf_document(body: &str, tracking_id: &str, tlp_label: &str) -> Result<()> {
    // Parse CSAF document from response. SecObserve can emit a `cpe` in the
    // product identification helper (often an empty string or a CPE 2.3 formatted
    // string). The `csaf` crate parses `cpe` via the `cpe` crate, which only
    // understands the CPE 2.2 URI binding and rejects everything else with
    // "invalid prefix". We do not use `cpe` downstream, so strip it before parsing.
    let mut csaf_value: serde_json::Value = serde_json::from_str(body)?;
    sanitize_product_identification_helpers(&mut csaf_value);
    let mut csaf: Csaf = serde_json::from_value(csaf_value)?;
    // let mut csaf: Csaf = serde_json::from_reader(File::open("csaf_in.json")?)?;
    csaf.document.lang = Some("en-US".to_string());
    csaf.document.publisher.issuing_authority = Some("The Stackable Security Team is responsible for vulnerability handling across all Stackable offerings.".to_string());
    csaf.document.publisher.contact_details = Some("product-security@stackable.tech".to_string());
    // Documents that may be distributed without restriction (TLP:WHITE) are
    // published under CC BY 4.0. Documents with a more restrictive TLP label
    // must not be redistributed beyond what the label permits, so an open
    // license would contradict the label.
    let terms_of_use = match tlp_label {
        "WHITE" => "This content is licensed under the Creative Commons Attribution 4.0 International License (https://creativecommons.org/licenses/by/4.0/). If you distribute this content, or a modified version of it, you must provide attribution to Stackable GmbH and provide a link to the original.".to_string(),
        _ => format!("This content is provided to customers of Stackable GmbH and is classified as TLP:{tlp_label} according to the Traffic Light Protocol (https://www.first.org/tlp/). It may only be shared as permitted by this TLP label."),
    };
    let disclaimer = Note {
        category: csaf::definitions::NoteCategory::LegalDisclaimer,
        text: terms_of_use,
        title: Some("Terms of Use".to_string()),
        audience: None,
    };
    csaf.document.notes = Some(vec![disclaimer]);

    let branches = csaf
        .product_tree
        .as_ref()
        .context("missing product tree")?
        .branches
        .as_ref()
        .context("missing branches in product tree")?
        .0
        .clone();

    let new_branches = rebuild_product_tree_branches(branches);

    csaf.product_tree.as_mut().unwrap().branches = Some(BranchesT(new_branches));

    csaf.document.tracking.id = tracking_id.to_string();
    let filename = format!("{}.json", sanitize_filename(tracking_id));

    // If an advisory for this vulnerability was already published, update it in
    // place: keep its location (the year directory of the initial release, see
    // CSAF requirement 11), its initial release date and its revision history.
    let csaf_filename = match find_existing_advisory(&filename)? {
        Some(existing_csaf_filename) => {
            let existing_csaf: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&existing_csaf_filename)?)?;
            let existing_tracking = existing_csaf
                .get("document")
                .and_then(|document| document.get("tracking"))
                .context("missing tracking data in existing advisory")?;

            let mut revision_history: Vec<Revision> =
                serde_json::from_value(existing_tracking["revision_history"].clone())?;
            let new_version = revision_history
                .iter()
                .map(|revision| revision.number.parse::<u64>().unwrap_or(0))
                .max()
                .unwrap_or(0)
                + 1;
            revision_history.push(Revision {
                date: csaf.document.tracking.current_release_date,
                legacy_version: None,
                number: new_version.to_string(),
                summary: "Updated advisory".to_string(),
            });

            csaf.document.tracking.initial_release_date =
                serde_json::from_value(existing_tracking["initial_release_date"].clone())?;
            csaf.document.tracking.revision_history = revision_history;
            csaf.document.tracking.version = new_version.to_string();

            existing_csaf_filename
        }
        None => {
            let current_year = chrono::Local::now().year().to_string();
            fs::create_dir_all(&current_year)?;
            format!("{}/{}", current_year, filename)
        }
    };
    // Create a value using `to_value` first, to sort the keys in the JSON output
    let csaf_as_string = serde_json::to_string_pretty(&serde_json::to_value(&csaf)?)?;
    fs::write(&csaf_filename, &csaf_as_string)?;

    let validator_result = std::process::Command::new("node")
        .arg("/csaf_validator/validate.js")
        .arg(format!(
            "{}/{}",
            env::current_dir()?.to_string_lossy(),
            &csaf_filename
        ))
        .output()?;
    if !validator_result.status.success() {
        eprintln!("CSAF validation failed:");
        eprintln!("{}", String::from_utf8_lossy(&validator_result.stdout));
        eprintln!("{}", String::from_utf8_lossy(&validator_result.stderr));
        println!("CSAF content:\n{}", csaf_as_string);
        std::process::exit(1);
    }

    // Generate detached PGP signature
    let key_string = env::var("PGP_SECRET_KEY").context("Missing PGP secret key!")?;
    let (secret_key, _headers) = SignedSecretKey::from_string(&key_string)?;
    let passphrase =
        env::var("PGP_SECRET_KEY_PASSPHRASE").context("Missing PGP secret key passphrase!")?;
    let signature = DetachedSignature::sign_binary_data(
        rand::thread_rng(),
        &secret_key.primary_key,
        &Password::from(passphrase),
        HashAlgorithm::Sha256,
        csaf_as_string.as_bytes(),
    )?;
    let mut signature_filehandle = fs::File::create(format!("{}.asc", csaf_filename))?;
    signature.to_armored_writer(&mut signature_filehandle, ArmorOptions::default())?;

    // Read CSAF file into buffer
    let buffer = fs::read(&csaf_filename)?;

    // Generate hashes
    for hash_filename in ["sha512", "sha256"].into_iter() {
        let hash = match hash_filename {
            "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(&buffer);
                format!("{}  {}", hex::encode(hasher.finalize()), csaf_filename)
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(&buffer);
                format!("{}  {}", hex::encode(hasher.finalize()), csaf_filename)
            }
            _ => unreachable!(),
        };
        fs::write(format!("{}.{}", csaf_filename, hash_filename), hash)?;
    }

    // Prepend to changes.csv, like this: "2020/example_company_-_2020-yh4711.json","2020-07-01T10:09:07Z"
    // On updates, the old entry for this advisory is replaced.
    upsert_line(
        "changes.csv",
        &format!(
            "\"{}\",\"{}\"",
            csaf_filename,
            csaf.document
                .tracking
                .current_release_date
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
        &format!("\"{}\",", csaf_filename),
    )?;
    // Prepend the filename to index.txt, unless it is already listed
    upsert_line("index.txt", &csaf_filename, &csaf_filename)?;

    Ok(())
}

/// Rebuilds the product tree branches emitted by SecObserve (one
/// `ProductFamily` branch per product, with `ProductVersion` children) into a
/// vendor -> architecture -> product name -> product version hierarchy.
/// Non-`ProductFamily` branches are kept as they are.
///
/// Product versions usually follow the Stackable naming scheme, e.g.
/// `airflow:2.9.3-stackable25.3.0-arm64`. Some shipped images keep their
/// upstream version without a `-stackable<sdp-version>` part, e.g.
/// `git-sync:v4.6.0-arm64`; those are grouped in the same way. A product
/// version that matches neither pattern is dropped from the tree with a
/// warning. Its relationships survive, so the CSAF validator fails the
/// publication with test 6.1.1 instead of silently publishing an advisory
/// with incomplete product coverage.
fn rebuild_product_tree_branches(branches: Vec<Branch>) -> Vec<Branch> {
    let stackable_product_version_regex = Regex::new(r"^(?P<product_name>[a-zA-Z0-9\-_]+):(?P<full_version>((?P<product_version>.+)\-stackable)?(?P<sdp_version>\d+\.\d+\.\d+(\-dev)?)(\-(?P<architecture>arm64|amd64)?))$").unwrap();
    let upstream_product_version_regex = Regex::new(r"^(?P<product_name>[a-zA-Z0-9\-_]+):(?P<full_version>(?P<product_version>.+?)\-(?P<architecture>arm64|amd64))$").unwrap();

    let (sdp_branches, mut new_branches): (Vec<_>, Vec<_>) = branches
        .into_iter()
        .partition(|branch| matches!(branch.category, BranchCategory::ProductFamily));

    new_branches.insert(
        0,
        Branch {
            name: "Stackable".to_string(),
            category: BranchCategory::Vendor,
            product: None,
            branches: Some(BranchesT(vec![])),
        },
    );

    // Group products by architecture and product name
    sdp_branches.into_iter().for_each(|branch| {
        if let Some(subbranches) = branch.branches {
            subbranches
                .0
                .into_iter()
                // Loop over all product versions of the product family
                .filter(|subbranch| matches!(subbranch.category, BranchCategory::ProductVersion))
                .for_each(|mut subbranch| {
                    // Subbranch has a product
                    if let Some(product) = subbranch.product.as_ref() {
                        // That product has a name that matches one of the product version patterns
                        let captures = stackable_product_version_regex
                            .captures(&product.name)
                            .or_else(|| upstream_product_version_regex.captures(&product.name));
                        if let Some(captures) = captures {
                            let product_name = captures.name("product_name").unwrap().as_str();
                            let full_version = captures.name("full_version").unwrap().as_str();
                            let product_version = captures
                                .name("product_version")
                                .or_else(|| captures.name("sdp_version"))
                                .unwrap()
                                .as_str();

                            let product_architecture =
                                captures.name("architecture").map(|v| v.as_str()).unwrap();

                            let stackable_architecture_branches =
                                new_branches[0].branches.as_mut().unwrap();

                            // Find architecture branch in stackable_branches or create it
                            let architecture_idx = stackable_architecture_branches
                                .0
                                .iter()
                                .position(|b| b.name == product_architecture)
                                .unwrap_or_else(|| {
                                    let idx = stackable_architecture_branches.0.len();
                                    stackable_architecture_branches.0.push(Branch {
                                        name: product_architecture.to_string(),
                                        category: BranchCategory::Architecture,
                                        product: None,
                                        branches: Some(BranchesT(vec![])),
                                    });
                                    idx
                                });

                            let architecture_branch_subbranches = stackable_architecture_branches.0
                                [architecture_idx]
                                .branches
                                .as_mut()
                                .unwrap();

                            // Find product_name branch in architecture branch or create it
                            let product_name_idx = architecture_branch_subbranches
                                .0
                                .iter()
                                .position(|b| b.name == product_name)
                                .unwrap_or_else(|| {
                                    let idx = architecture_branch_subbranches.0.len();

                                    architecture_branch_subbranches.0.push(Branch {
                                        name: product_name.to_string(),
                                        category: BranchCategory::ProductName,
                                        product: None,
                                        branches: Some(BranchesT(vec![])),
                                    });
                                    idx
                                });

                            // Append product version branch to product_name branch if it does not exist
                            if !architecture_branch_subbranches.0[product_name_idx]
                                .branches
                                .as_ref()
                                .unwrap()
                                .0
                                .iter()
                                .any(|b| b.name == product_version)
                            {
                                subbranch.name = full_version.to_string();
                                subbranch.product = Some(product.clone());

                                architecture_branch_subbranches.0[product_name_idx]
                                    .branches
                                    .as_mut()
                                    .unwrap()
                                    .0
                                    .push(subbranch);
                            }
                        } else {
                            eprintln!(
                                "warning: product {:?} matches no known product version pattern, dropping it from the product tree",
                                product.name
                            );
                        }
                    }
                });
        }
    });

    new_branches
}

/// Removes `cpe` entries and empty `purl` entries from every
/// `product_identification_helper` in a CSAF document.
///
/// The `csaf` crate parses `cpe` through the `cpe` crate, which only supports
/// the CPE 2.2 URI binding (`cpe:/...`) and rejects empty strings and CPE 2.3
/// formatted strings with an "invalid prefix" error. As we do not use `cpe`
/// downstream, dropping it keeps the tool working regardless of what SecObserve
/// emits. Empty `purl` strings are dropped for the same reason.
fn sanitize_product_identification_helpers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(helper)) =
                map.get_mut("product_identification_helper")
            {
                helper.remove("cpe");
                if let Some(serde_json::Value::String(purl)) = helper.get("purl") {
                    if purl.is_empty() {
                        helper.remove("purl");
                    }
                }
            }
            for nested in map.values_mut() {
                sanitize_product_identification_helpers(nested);
            }
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .for_each(sanitize_product_identification_helpers),
        _ => {}
    }
}

/// Converts a document tracking id into the corresponding CSAF filename
/// (without the `.json` suffix)
fn sanitize_filename(tracking_id: &str) -> String {
    let mut filename = String::new();
    for character in tracking_id.to_lowercase().chars() {
        if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '+'
            || character == '-'
        {
            filename.push(character);
        } else if !filename.ends_with('_') {
            filename.push('_');
        }
    }
    filename
}

/// Returns all year directories (e.g. `2024`) in the current directory.
fn year_directories() -> Result<Vec<String>> {
    let mut directories = vec![];
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        if let Ok(name) = entry.file_name().into_string() {
            if entry.file_type()?.is_dir()
                && name.len() == 4
                && name.chars().all(|c| c.is_ascii_digit())
            {
                directories.push(name);
            }
        }
    }
    Ok(directories)
}

/// Looks for an already published advisory with the given filename in all year
/// directories and returns its relative path (e.g. `2024/cve-2024-2961.json`).
fn find_existing_advisory(filename: &str) -> Result<Option<String>> {
    for year_directory in year_directories()? {
        let candidate = format!("{}/{}", year_directory, filename);
        if fs::exists(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Prepends `line` to the file, removing any previous line that starts with
/// `match_prefix` first.
fn upsert_line(filename: &str, line: &str, match_prefix: &str) -> Result<()> {
    let contents = fs::read_to_string(filename)?;
    let mut new_contents = format!("{}\n", line);
    for existing_line in contents.lines() {
        if !existing_line.starts_with(match_prefix) {
            new_contents.push_str(existing_line);
            new_contents.push('\n');
        }
    }
    fs::write(filename, new_contents)?;
    Ok(())
}

fn generate_index_html(directory: &str) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name());

    let mut index_content = String::new();
    index_content.push_str("<html><head><title>Stackable Security Advisories</title></head><body><h1>Stackable Security Advisories</h1><ul>");

    for entry in entries {
        let entry_name = entry.file_name().into_string().unwrap();
        if entry_name != "index.html" {
            index_content.push_str(&format!(
                "<li><a href=\"{}\">{}</a></li>",
                entry_name, entry_name
            ));
        }
    }

    index_content.push_str("</ul></body></html>");
    fs::write(format!("{}/index.html", directory), index_content)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        rebuild_product_tree_branches, sanitize_filename, sanitize_product_identification_helpers,
        upsert_line,
    };
    use csaf::definitions::{Branch, BranchCategory, BranchesT, FullProductName, ProductIdT};
    use serde_json::json;

    fn product_family(name: &str, version_names: &[&str]) -> Branch {
        Branch {
            name: name.to_string(),
            category: BranchCategory::ProductFamily,
            product: None,
            branches: Some(BranchesT(
                version_names
                    .iter()
                    .map(|version_name| Branch {
                        name: version_name.to_string(),
                        category: BranchCategory::ProductVersion,
                        product: Some(FullProductName {
                            name: version_name.to_string(),
                            product_id: ProductIdT(version_name.to_string()),
                            product_identification_helper: None,
                        }),
                        branches: None,
                    })
                    .collect(),
            )),
        }
    }

    /// Collects the product ids of all products in the given branches.
    fn product_ids(branches: &[Branch]) -> Vec<String> {
        let mut ids = vec![];
        for branch in branches {
            if let Some(product) = &branch.product {
                ids.push(product.product_id.0.clone());
            }
            if let Some(subbranches) = &branch.branches {
                ids.extend(product_ids(&subbranches.0));
            }
        }
        ids.sort();
        ids
    }

    #[test]
    fn rebuilds_stackable_and_upstream_versioned_products() {
        let branches = vec![
            product_family(
                "airflow",
                &[
                    "airflow:2.9.3-stackable25.3.0-arm64",
                    "airflow:2.9.3-stackable25.3.0-amd64",
                ],
            ),
            product_family(
                "git-sync",
                &["git-sync:v4.6.0-arm64", "git-sync:v4.5.1-amd64"],
            ),
            product_family("unparseable", &["unparseable-without-version-or-arch"]),
        ];

        let new_branches = rebuild_product_tree_branches(branches);

        // A single vendor branch containing everything
        assert_eq!(new_branches.len(), 1);
        assert_eq!(new_branches[0].name, "Stackable");
        assert!(matches!(new_branches[0].category, BranchCategory::Vendor));

        let architecture_names: Vec<_> = new_branches[0]
            .branches
            .as_ref()
            .expect("vendor branch must have subbranches")
            .0
            .iter()
            .map(|branch| branch.name.clone())
            .collect();
        assert_eq!(architecture_names, ["arm64", "amd64"]);

        // All parseable products are kept, the unparseable one is dropped
        assert_eq!(
            product_ids(&new_branches),
            [
                "airflow:2.9.3-stackable25.3.0-amd64",
                "airflow:2.9.3-stackable25.3.0-arm64",
                "git-sync:v4.5.1-amd64",
                "git-sync:v4.6.0-arm64",
            ]
        );
    }

    #[test]
    fn sanitizes_tracking_ids_to_filenames() {
        assert_eq!(sanitize_filename("CVE-2026-8838"), "cve-2026-8838");
        assert_eq!(
            sanitize_filename("GHSA-mjmj-j48q-9wg2"),
            "ghsa-mjmj-j48q-9wg2"
        );
        assert_eq!(
            sanitize_filename("STACKSA_2026_0011  0001"),
            "stacksa_2026_0011_0001"
        );
    }

    #[test]
    fn upserts_lines_without_duplicates() {
        let directory = std::env::temp_dir().join("csaf_publisher_upsert_test");
        std::fs::create_dir_all(&directory).expect("failed to create test directory");
        let file = directory.join("index.txt");
        let file = file.to_str().expect("test path is not valid UTF-8");

        std::fs::write(file, "2024/cve-2024-2961.json\n").expect("failed to write test file");

        upsert_line(file, "2026/cve-2026-8838.json", "2026/cve-2026-8838.json")
            .expect("failed to prepend new line");
        assert_eq!(
            std::fs::read_to_string(file).expect("failed to read test file"),
            "2026/cve-2026-8838.json\n2024/cve-2024-2961.json\n"
        );

        upsert_line(file, "2024/cve-2024-2961.json", "2024/cve-2024-2961.json")
            .expect("failed to upsert existing line");
        assert_eq!(
            std::fs::read_to_string(file).expect("failed to read test file"),
            "2024/cve-2024-2961.json\n2026/cve-2026-8838.json\n"
        );
    }

    #[test]
    fn drops_cpe_and_empty_purl_while_keeping_valid_purl() {
        let mut value = json!({
            "product_tree": {
                "branches": [{
                    "product": {
                        "product_identification_helper": {
                            "cpe": "cpe:2.3:a:so:comp:1.0.0:*:*:*:*:*:*:*",
                            "purl": "pkg:maven/org.yaml/snakeyaml@1.30"
                        }
                    }
                }, {
                    "product": {
                        "product_identification_helper": {
                            "cpe": "",
                            "purl": ""
                        }
                    }
                }]
            }
        });

        sanitize_product_identification_helpers(&mut value);

        let first =
            &value["product_tree"]["branches"][0]["product"]["product_identification_helper"];
        assert!(first.get("cpe").is_none());
        assert_eq!(first["purl"], "pkg:maven/org.yaml/snakeyaml@1.30");

        let second =
            &value["product_tree"]["branches"][1]["product"]["product_identification_helper"];
        assert!(second.get("cpe").is_none());
        assert!(second.get("purl").is_none());
    }
}
