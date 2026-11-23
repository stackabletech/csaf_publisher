use color_eyre::eyre::Context;
use csaf::definitions::Note;
use csaf::document::Revision;
use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use sha2::{Digest, Sha256, Sha512};
use std::{collections::HashMap, env, fs, time::Duration};

use chrono::{Datelike, SecondsFormat};
use color_eyre::eyre::{bail, ContextCompat, Result};
use csaf::{
    definitions::{Branch, BranchCategory, BranchesT},
    Csaf,
};
use regex::Regex;

const SECOBSERVE_API_BASE: &str = "https://secobserve-backend.stackable.tech/api";

// The publisher must match the publisher in the provider-metadata.json of the
// advisories and protected-advisories repositories. The namespace carries a
// trailing slash, because the csaf crate parses it as a URL and serializes it
// with one, so this is what ends up in the published documents.
const PUBLISHER_NAME: &str = "Stackable Product Security Team";
const PUBLISHER_NAMESPACE: &str = "https://www.stackable.tech/";
const PUBLISHER_ISSUING_AUTHORITY: &str = "The Stackable Product Security Team is responsible for vulnerability handling across all Stackable offerings.";

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

    // The first argument selects the mode, the remaining arguments are the
    // documents to publish (one CSAF document per argument, so that the
    // filename can be derived from the document tracking id), or the releases
    // to list the product versions for.
    let mut arguments = env::args().skip(1);
    let mode = arguments.next().context(
        "no mode given, expected \"cve\", \"product-version\" or \"list-product-versions\"",
    )?;
    let names: Vec<String> = arguments.collect();
    if names.is_empty() {
        bail!("no names given after mode {mode:?}");
    }

    // Each argument is published on its own, so that a single failing document
    // (e.g. a product name that does not exist in SecObserve) does not block
    // the others. The failures are reported at the end.
    let mut failures = vec![];
    match mode.as_str() {
        "cve" => {
            for vulnerability_name in &names {
                let outcome = publish_vulnerability_advisory(
                    vulnerability_name,
                    &secobserve_api_token,
                    &tlp_label,
                );
                report_outcome(vulnerability_name, outcome, &mut failures);
            }
        }
        "product-version" => {
            // Product versions are given as `<product>:<branch>`, matching the
            // product ids used in the CSAF documents,
            // e.g. `airflow:3.1.6-stackable26.3.0-amd64`.
            for product_version in &names {
                let outcome = publish_product_version_advisory(
                    product_version,
                    &secobserve_api_token,
                    &tlp_label,
                );
                report_outcome(product_version, outcome, &mut failures);
            }
        }
        "list-product-versions" => {
            // Prints the product versions of the given SDP releases as a
            // comma-separated list, in the form the "product-version" mode
            // expects. Nothing is published, so the advisory directory
            // listings are left alone.
            let product_versions = list_product_versions(&names, &secobserve_api_token)?;
            println!("{}", product_versions.join(","));
            return Ok(());
        }
        _ => bail!(
            "unknown mode {mode:?}, expected \"cve\", \"product-version\" or \"list-product-versions\""
        ),
    }

    // Generate directory listings. The base path is the site-root-relative URL
    // of the advisory directory (e.g. `/by-cve/csaf/v2/advisories`), used to
    // build path-absolute hrefs so links resolve regardless of whether the
    // requested directory URL carries a trailing slash. When unset the links
    // fall back to relative paths.
    let base_path = env::var("ADVISORY_BASE_PATH").ok();
    for year_directory in year_directories()? {
        generate_index_html(&year_directory, base_path.as_deref())?;
    }
    generate_index_html(".", base_path.as_deref())?;

    if !failures.is_empty() {
        bail!(
            "failed to publish {} of {} advisories: {}",
            failures.len(),
            names.len(),
            failures.join(", ")
        );
    }

    Ok(())
}

/// The result of publishing a single advisory.
enum PublishOutcome {
    /// The advisory was published for the first time.
    Created,
    /// The content of the advisory changed, a new revision was published.
    Updated,
    /// The content of the advisory did not change, nothing was written.
    Unchanged,
    /// SecObserve has no vulnerability statements, so there is nothing to
    /// publish.
    NoStatements,
}

/// Prints the outcome of publishing the advisory `name` and records it in
/// `failures` if publishing failed.
fn report_outcome(name: &str, outcome: Result<PublishOutcome>, failures: &mut Vec<String>) {
    match outcome {
        Ok(PublishOutcome::Created) => println!("{name}: published new advisory"),
        Ok(PublishOutcome::Updated) => println!("{name}: published new revision"),
        Ok(PublishOutcome::Unchanged) => println!("{name}: unchanged"),
        Ok(PublishOutcome::NoStatements) => {
            println!("{name}: skipped, SecObserve has no vulnerability statements")
        }
        Err(error) => {
            eprintln!("{name}: failed to publish: {error:?}");
            failures.push(name.to_string());
        }
    }
}

fn publish_vulnerability_advisory(
    vulnerability_name: &str,
    secobserve_api_token: &str,
    tlp_label: &str,
) -> Result<PublishOutcome> {
    // Retrieve CSAF document from SecObserve API
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{SECOBSERVE_API_BASE}/vex/csaf_document/create/"))
        .json(&serde_json::json!({
            "vulnerability_names": &[vulnerability_name],
            "document_id_prefix": "STACKSA",
            "title": format!("Stackable Security Advisory for: {}", vulnerability_name),
            "publisher_name": PUBLISHER_NAME,
            "publisher_category": "vendor",
            "publisher_namespace": PUBLISHER_NAMESPACE,
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
) -> Result<PublishOutcome> {
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
            "publisher_name": PUBLISHER_NAME,
            "publisher_category": "vendor",
            "publisher_namespace": PUBLISHER_NAMESPACE,
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
        return Ok(PublishOutcome::NoStatements);
    }
    let body = response.text()?;
    if !status.is_success() {
        bail!("SecObserve returned {status} for product version {product_version:?}: {body}");
    }

    // Every call of the create endpoint stores a new CSAF document in
    // SecObserve. Product version advisories are republished regularly, so
    // without cleaning up, SecObserve would accumulate a document per product
    // version and run. The published advisory in the repository is the source of
    // truth for the revision history, so the SecObserve copy is not needed.
    // Failing to delete it only leaves a stale copy behind, which is no reason
    // to fail publishing.
    if let Err(error) =
        delete_secobserve_csaf_document(&body, product_id, branch_name, secobserve_api_token)
    {
        eprintln!(
            "{product_version}: failed to delete the CSAF document created in SecObserve: {error:?}"
        );
    }

    // Make the statements match the packages that scanners report for the image,
    // see the functions for details. This is only done for product version
    // documents, as they cover a single image, so a component is never ambiguous.
    let mut csaf_value: serde_json::Value = serde_json::from_str(&body)?;
    replace_relationships_with_components(&mut csaf_value);
    normalize_purls(&mut csaf_value);

    // The document tracking id is derived from the product version, so that
    // the filename is stable across republications and an existing advisory
    // can be updated in place. The `:` separator is replaced by `-` to keep
    // the tracking id readable.
    let tracking_id = format!("{}-{}", product_name, branch_name);
    publish_csaf_document(&csaf_value.to_string(), &tracking_id, tlp_label)
}

/// Removes the relationships from the product tree and replaces every
/// reference to a relationship product id with the id of its component.
///
/// SecObserve states each vulnerability for a `default_component_of`
/// relationship between the component (e.g. a Maven package) and the image.
/// Trivy only applies such a statement when the component is a direct child of
/// the image in its dependency graph, so statements for transitive packages
/// (e.g. libcurl-minimal, which is pulled in by curl-minimal) or packages from
/// SBOMs embedded in the image are ignored. Stating the vulnerability for the
/// component itself works for all of them.
fn replace_relationships_with_components(value: &mut serde_json::Value) {
    let relationships = value
        .get_mut("product_tree")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|product_tree| product_tree.remove("relationships"));
    let Some(serde_json::Value::Array(relationships)) = relationships else {
        return;
    };

    let components: std::collections::HashMap<String, String> = relationships
        .iter()
        .filter_map(|relationship| {
            let relationship_id = relationship
                .get("full_product_name")?
                .get("product_id")?
                .as_str()?;
            let component_id = relationship.get("product_reference")?.as_str()?;
            Some((relationship_id.to_string(), component_id.to_string()))
        })
        .collect();

    replace_product_ids(value, &components);
}

/// Replaces all strings that are keys of `components` with their value. Arrays
/// of strings are deduplicated afterwards, because several relationships can
/// refer to the same component.
fn replace_product_ids(
    value: &mut serde_json::Value,
    components: &std::collections::HashMap<String, String>,
) {
    match value {
        serde_json::Value::String(string) => {
            if let Some(component_id) = components.get(string.as_str()) {
                *string = component_id.clone();
            }
        }
        serde_json::Value::Array(items) => {
            items
                .iter_mut()
                .for_each(|item| replace_product_ids(item, components));
            if items.iter().all(serde_json::Value::is_string) {
                let mut seen = std::collections::HashSet::new();
                items.retain(|item| seen.insert(item.as_str().unwrap_or_default().to_string()));
            }
        }
        serde_json::Value::Object(map) => map
            .values_mut()
            .for_each(|nested| replace_product_ids(nested, components)),
        _ => {}
    }
}

/// Normalizes the purls in every `product_identification_helper`, so that they
/// match the purls Trivy reports, see [`normalize_purl`].
fn normalize_purls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(purl)) = map
                .get_mut("product_identification_helper")
                .and_then(|helper| helper.get_mut("purl"))
            {
                *purl = normalize_purl(purl);
            }
            map.values_mut().for_each(normalize_purls);
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(normalize_purls),
        _ => {}
    }
}

/// Converts a purl as emitted by SecObserve into the form Trivy reports.
///
/// Trivy matches a purl only if all of its qualifiers are present in the
/// package purl, so qualifiers that Trivy does not set must be dropped:
///
/// - RPM: SecObserve uses `distro=rhel-9.8` and an `upstream` qualifier,
///   Trivy uses `distro=redhat-9.8` and no `upstream`.
/// - Go standard library: SecObserve uses the version without the `v` prefix
///   (`pkg:golang/stdlib@1.25.7`), Trivy with it (`@v1.25.7`).
fn normalize_purl(purl: &str) -> String {
    if purl.starts_with("pkg:rpm/") {
        let Some((base, qualifiers)) = purl.split_once('?') else {
            return purl.to_string();
        };
        let qualifiers: Vec<String> = qualifiers
            .split('&')
            .filter(|qualifier| !qualifier.starts_with("upstream="))
            .map(|qualifier| match qualifier.strip_prefix("distro=rhel-") {
                Some(version) => format!("distro=redhat-{version}"),
                None => qualifier.to_string(),
            })
            .collect();
        if qualifiers.is_empty() {
            return base.to_string();
        }
        return format!("{base}?{}", qualifiers.join("&"));
    }

    if let Some(version) = purl.strip_prefix("pkg:golang/stdlib@") {
        if version.starts_with(|c: char| c.is_ascii_digit()) {
            return format!("pkg:golang/stdlib@v{version}");
        }
    }

    purl.to_string()
}

/// Looks up the SecObserve product id for the given product name.
fn find_product_id(product_name: &str, secobserve_api_token: &str) -> Result<u64> {
    // The `name` filter matches substrings, so search the results for an
    // exact match. All pages are retrieved, as short names like `opa` match
    // many products.
    secobserve_list("products/", &[("name", product_name)], secobserve_api_token)?
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

/// Retrieves all results of a paginated SecObserve list endpoint, e.g.
/// `products/`.
fn secobserve_list(
    path: &str,
    query: &[(&str, &str)],
    secobserve_api_token: &str,
) -> Result<Vec<serde_json::Value>> {
    // List endpoints can be slow, e.g. SecObserve counts the observations of
    // every branch in the branch list, so allow more than the default timeout
    // of 30 seconds.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?;
    let mut results = vec![];
    // Pages are requested by number instead of following the `next` links,
    // because SecObserve builds those from the request it received, so behind
    // a TLS terminating proxy they can point to plain HTTP.
    for page in 1.. {
        let page = page.to_string();
        let response = client
            .get(format!("{SECOBSERVE_API_BASE}/{path}"))
            .query(query)
            .query(&[("page", page.as_str()), ("page_size", "100")])
            .header(
                "Authorization",
                format!("APIToken {}", secobserve_api_token),
            )
            .header("User-Agent", "Stackable Security Advisory Generator")
            .send()?;

        let status = response.status();
        let body = response.text()?;
        if !status.is_success() {
            bail!("SecObserve returned {status} when listing {path:?} (page {page}): {body}");
        }

        let mut list: serde_json::Value = serde_json::from_str(&body)?;
        results.append(
            list.get_mut("results")
                .and_then(serde_json::Value::as_array_mut)
                .context(format!("missing results in list of {path:?}"))?,
        );
        if list.get("next").is_none_or(serde_json::Value::is_null) {
            break;
        }
    }
    Ok(results)
}

/// Deletes the CSAF document that SecObserve stored when its create endpoint
/// returned `body` for the given product and branch.
fn delete_secobserve_csaf_document(
    body: &str,
    product_id: u64,
    branch_name: &str,
    secobserve_api_token: &str,
) -> Result<()> {
    // SecObserve tracking ids are `<prefix>_<base id>_<version>`, with a base id
    // of `<year>_<counter>`, e.g. `STACKSA_2026_0123_0001`.
    let document: serde_json::Value = serde_json::from_str(body)?;
    let tracking_id = document
        .pointer("/document/tracking/id")
        .and_then(serde_json::Value::as_str)
        .context("missing tracking id in CSAF document")?;
    let (document_id_prefix, document_base_id) = tracking_id
        .rsplit_once('_')
        .and_then(|(prefix_and_base_id, _version)| prefix_and_base_id.split_once('_'))
        .context(format!("unexpected SecObserve tracking id {tracking_id:?}"))?;

    // The list endpoint has no filter for the base id, so narrow the list down
    // as far as possible and search the results.
    let product_id = product_id.to_string();
    let csaf_id = secobserve_list(
        "vex/csaf/",
        &[
            ("product", product_id.as_str()),
            ("document_id_prefix", document_id_prefix),
            ("branches__branch__name", branch_name),
        ],
        secobserve_api_token,
    )?
    .iter()
    .find(|csaf| {
        csaf.get("document_base_id")
            .and_then(serde_json::Value::as_str)
            == Some(document_base_id)
    })
    .and_then(|csaf| csaf.get("id"))
    .and_then(serde_json::Value::as_u64)
    .context(format!(
        "CSAF document {tracking_id:?} not found in SecObserve"
    ))?;

    let client = reqwest::blocking::Client::new();
    let response = client
        .delete(format!("{SECOBSERVE_API_BASE}/vex/csaf/{csaf_id}/"))
        .header(
            "Authorization",
            format!("APIToken {}", secobserve_api_token),
        )
        .header("User-Agent", "Stackable Security Advisory Generator")
        .send()?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text()?;
        bail!("SecObserve returned {status} when deleting CSAF document {tracking_id:?}: {body}");
    }
    Ok(())
}

/// Lists the product versions of the given SDP releases (e.g. `26.7.0`) that
/// exist as branches in SecObserve, as sorted `<product>:<branch>` strings.
fn list_product_versions(releases: &[String], secobserve_api_token: &str) -> Result<Vec<String>> {
    let pattern = product_version_branch_pattern(releases)?;

    let product_names: HashMap<u64, String> =
        secobserve_list("products/", &[], secobserve_api_token)?
            .iter()
            .filter_map(|product| {
                Some((
                    product.get("id")?.as_u64()?,
                    product.get("name")?.as_str()?.to_string(),
                ))
            })
            .collect();

    // Listing all branches takes too long, so only list the branches that
    // contain one of the releases in their name (the `name` filter matches
    // substrings) and match them exactly afterwards.
    let mut product_versions = vec![];
    for release in releases {
        for branch in secobserve_list("branches/", &[("name", release)], secobserve_api_token)? {
            let Some(branch_name) = branch.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if !pattern.is_match(branch_name) {
                continue;
            }
            let Some(product_name) = branch
                .get("product")
                .and_then(serde_json::Value::as_u64)
                .and_then(|product_id| product_names.get(&product_id))
            else {
                continue;
            };
            product_versions.push(format!("{product_name}:{branch_name}"));
        }
    }
    product_versions.sort();
    product_versions.dedup();
    Ok(product_versions)
}

/// Matches the SecObserve branch names of the images of the given releases:
/// `<product version>-stackable<release>-<architecture>` for product images
/// and `<release>-<architecture>` for operator images. Branches of other
/// releases (e.g. `0.0.0-dev` images built from main) never match.
fn product_version_branch_pattern(releases: &[String]) -> Result<Regex> {
    let release_pattern = Regex::new(r"^\d+\.\d+\.\d+$")?;
    for release in releases {
        if !release_pattern.is_match(release) {
            bail!("invalid release {release:?}, expected a release like 26.7.0");
        }
    }
    let alternatives = releases
        .iter()
        .map(|release| regex::escape(release))
        .collect::<Vec<_>>()
        .join("|");
    Ok(Regex::new(&format!(
        r"(?:^|-stackable)(?:{alternatives})-(?:amd64|arm64)$"
    ))?)
}

/// Applies the Stackable customizations to a CSAF document returned by
/// SecObserve and writes it to the advisory directory structure, together with
/// its PGP signature and hashes. The document tracking id determines the
/// filename (the lowercased tracking id), so it must be stable across republications:
/// an already published document is updated in place, keeping its initial release
/// date and revision history.
fn publish_csaf_document(body: &str, tracking_id: &str, tlp_label: &str) -> Result<PublishOutcome> {
    // Parse CSAF document from response. SecObserve can emit a `cpe` in the
    // product identification helper (often an empty string or a CPE 2.3 formatted
    // string). The `csaf` crate parses `cpe` via the `cpe` crate, which only
    // understands the CPE 2.2 URI binding and rejects everything else with
    // "invalid prefix". We do not use `cpe` downstream, so strip it before parsing.
    let mut csaf_value: serde_json::Value = serde_json::from_str(body)?;
    sanitize_product_identification_helpers(&mut csaf_value);
    remove_conflicting_flags(&mut csaf_value);
    let mut csaf: Csaf = serde_json::from_value(csaf_value)?;
    // let mut csaf: Csaf = serde_json::from_reader(File::open("csaf_in.json")?)?;
    csaf.document.lang = Some("en-US".to_string());
    csaf.document.publisher.issuing_authority = Some(PUBLISHER_ISSUING_AUTHORITY.to_string());
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
    let (csaf_filename, outcome) = match find_existing_advisory(&filename)? {
        Some(existing_csaf_filename) => {
            let existing_csaf: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&existing_csaf_filename)?)?;

            // Advisories are republished regularly, so only publish a new
            // revision if the content actually changed. Otherwise every run
            // would add a revision and update the advisory in changes.csv,
            // making consumers download all advisories again.
            if equal_except_tracking(&existing_csaf, &serde_json::to_value(&csaf)?) {
                return Ok(PublishOutcome::Unchanged);
            }

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

            (existing_csaf_filename, PublishOutcome::Updated)
        }
        None => {
            let current_year = chrono::Local::now().year().to_string();
            fs::create_dir_all(&current_year)?;
            (
                format!("{}/{}", current_year, filename),
                PublishOutcome::Created,
            )
        }
    };
    // Create a value using `to_value` first, to sort the keys in the JSON output
    let csaf_as_string = serde_json::to_string_pretty(&serde_json::to_value(&csaf)?)?;

    // Validate and sign the document before it replaces the published one, so
    // that an invalid document or one without a matching signature never ends
    // up in the repository. The validator loads the document with `require`,
    // which needs the `.json` extension.
    let pending_csaf_filename = format!("{csaf_filename}.pending.json");
    fs::write(&pending_csaf_filename, &csaf_as_string)?;
    let signature = validate_csaf_document(&pending_csaf_filename)
        .and_then(|()| sign_csaf_document(&csaf_as_string));
    let signature = match signature {
        Ok(signature) => signature,
        Err(error) => {
            fs::remove_file(&pending_csaf_filename)?;
            return Err(error);
        }
    };
    fs::rename(&pending_csaf_filename, &csaf_filename)?;
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

    Ok(outcome)
}

/// Returns whether the two CSAF documents are equal apart from their tracking
/// data (release dates, revision history, version and generator), which
/// changes on every export even if the vulnerability statements do not.
fn equal_except_tracking(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    fn without_tracking(csaf: &serde_json::Value) -> serde_json::Value {
        let mut csaf = csaf.clone();
        if let Some(document) = csaf
            .get_mut("document")
            .and_then(serde_json::Value::as_object_mut)
        {
            document.remove("tracking");
        }
        csaf
    }
    without_tracking(left) == without_tracking(right)
}

/// Creates a detached PGP signature of the CSAF document.
fn sign_csaf_document(csaf_as_string: &str) -> Result<DetachedSignature> {
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
    Ok(signature)
}

/// Validates the CSAF document in the given file (relative to the current
/// directory) with the CSAF validator.
fn validate_csaf_document(filename: &str) -> Result<()> {
    let validator_result = std::process::Command::new("node")
        .arg("/csaf_validator/validate.js")
        .arg(format!(
            "{}/{}",
            env::current_dir()?.to_string_lossy(),
            filename
        ))
        .output()?;
    if !validator_result.status.success() {
        bail!(
            "CSAF validation failed:\n{}{}",
            String::from_utf8_lossy(&validator_result.stdout),
            String::from_utf8_lossy(&validator_result.stderr)
        );
    }
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

/// VEX justification flag labels, from the strongest to the weakest statement.
const FLAG_PRIORITY: [&str; 5] = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

/// Ensures that every product has at most one flag per vulnerability, as CSAF
/// requires (mandatory test 6.1.33).
///
/// SecObserve has one observation per scanner (e.g. Grype and Trivy) for the
/// same package and vulnerability. When those are assessed with different
/// justifications, SecObserve emits one flag per justification for the same
/// product. The product is kept in the flag with the strongest justification
/// (see [`FLAG_PRIORITY`]) and removed from the others, with a warning so that
/// the assessments can be aligned. The impact statements of all assessments
/// are kept, as a product may have several threats.
fn remove_conflicting_flags(value: &mut serde_json::Value) {
    let Some(vulnerabilities) = value
        .get_mut("vulnerabilities")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };

    for vulnerability in vulnerabilities {
        let vulnerability_name = vulnerability
            .get("cve")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown vulnerability")
            .to_string();
        let Some(flags) = vulnerability
            .get_mut("flags")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };

        // Visit the flags from the strongest to the weakest justification, unknown
        // labels last. The sort is stable, so equal labels keep their order.
        let flag_label = |flag: &serde_json::Value| {
            flag.get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut flag_order: Vec<usize> = (0..flags.len()).collect();
        flag_order.sort_by_key(|&index| {
            let label = flag_label(&flags[index]);
            FLAG_PRIORITY
                .iter()
                .position(|priority_label| *priority_label == label)
                .unwrap_or(FLAG_PRIORITY.len())
        });

        let mut kept_labels: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for index in flag_order {
            let label = flag_label(&flags[index]);
            let Some(product_ids) = flags[index]
                .get_mut("product_ids")
                .and_then(serde_json::Value::as_array_mut)
            else {
                continue;
            };
            product_ids.retain(|product_id| {
                let Some(product_id) = product_id.as_str() else {
                    return true;
                };
                match kept_labels.get(product_id) {
                    Some(kept_label) => {
                        eprintln!(
                            "warning: {vulnerability_name}: product {product_id:?} has the flags {kept_label:?} and {label:?}, keeping {kept_label:?}"
                        );
                        false
                    }
                    None => {
                        kept_labels.insert(product_id.to_string(), label.clone());
                        true
                    }
                }
            });
        }

        // Drop flags that no longer apply to any product or group
        flags.retain(|flag| {
            let has_products = flag
                .get("product_ids")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|product_ids| !product_ids.is_empty());
            has_products || flag.get("group_ids").is_some()
        });
        if flags.is_empty() {
            if let Some(vulnerability) = vulnerability.as_object_mut() {
                vulnerability.remove("flags");
            }
        }
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

fn generate_index_html(directory: &str, base_path: Option<&str>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name());

    let mut index_content = String::new();
    index_content.push_str("<html><head><title>Stackable Security Advisories</title></head><body><h1>Stackable Security Advisories</h1><ul>");

    for entry in entries {
        let entry_name = entry.file_name().into_string().unwrap();
        if entry_name != "index.html" {
            let is_directory = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let href = build_href(directory, &entry_name, is_directory, base_path);
            index_content.push_str(&format!("<li><a href=\"{}\">{}</a></li>", href, entry_name));
        }
    }

    index_content.push_str("</ul></body></html>");
    fs::write(format!("{}/index.html", directory), index_content)?;

    Ok(())
}

/// Builds the href for a directory listing entry. When `base_path` is set, the
/// href is path-absolute (e.g. `/by-cve/csaf/v2/advisories/2026/`) so it
/// resolves independently of the request URL's trailing slash; directory
/// entries additionally get a trailing slash. Without `base_path` the href
/// stays relative to the current directory.
fn build_href(
    directory: &str,
    entry_name: &str,
    is_directory: bool,
    base_path: Option<&str>,
) -> String {
    let trailing_slash = if is_directory { "/" } else { "" };
    match base_path {
        Some(base) => {
            let base = base.trim_end_matches('/');
            let subdirectory = match directory.trim_start_matches("./").trim_matches('/') {
                "" | "." => String::new(),
                subdirectory => format!("/{subdirectory}"),
            };
            format!("{base}{subdirectory}/{entry_name}{trailing_slash}")
        }
        None => format!("{entry_name}{trailing_slash}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_href, equal_except_tracking, normalize_purl, normalize_purls,
        product_version_branch_pattern, rebuild_product_tree_branches, remove_conflicting_flags,
        replace_relationships_with_components, sanitize_filename,
        sanitize_product_identification_helpers, upsert_line,
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

    #[test]
    fn replaces_relationships_with_components() {
        let image = "pkg:oci/nifi@sha256%3Aabc?arch=amd64";
        let curl = "pkg:rpm/redhat/curl-minimal@7.76.1-40.el9?arch=x86_64";
        let libcurl = "pkg:rpm/redhat/libcurl-minimal@7.76.1-40.el9?arch=x86_64";
        let curl_in_image = format!("{curl}@{image}");
        let libcurl_in_image = format!("{libcurl}@{image}");
        let mut value = json!({
            "product_tree": {
                "branches": [],
                "relationships": [{
                    "category": "default_component_of",
                    "full_product_name": {"name": curl_in_image, "product_id": curl_in_image},
                    "product_reference": curl,
                    "relates_to_product_reference": image
                }, {
                    "category": "default_component_of",
                    "full_product_name": {"name": libcurl_in_image, "product_id": libcurl_in_image},
                    "product_reference": libcurl,
                    "relates_to_product_reference": image
                }]
            },
            "vulnerabilities": [{
                "cve": "CVE-2024-7264",
                "product_status": {"known_not_affected": [curl_in_image, libcurl_in_image, curl]},
                "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": [curl_in_image]}],
                "threats": [{"category": "impact", "details": curl_in_image, "product_ids": [libcurl_in_image]}]
            }]
        });

        replace_relationships_with_components(&mut value);

        assert!(value["product_tree"].get("relationships").is_none());
        let vulnerability = &value["vulnerabilities"][0];
        assert_eq!(
            vulnerability["product_status"]["known_not_affected"],
            json!([curl, libcurl])
        );
        assert_eq!(vulnerability["flags"][0]["product_ids"], json!([curl]));
        assert_eq!(vulnerability["threats"][0]["product_ids"], json!([libcurl]));
    }

    #[test]
    fn keeps_documents_without_relationships() {
        let mut value = json!({
            "product_tree": {"branches": []},
            "vulnerabilities": [{"product_status": {"known_affected": ["a"]}}]
        });
        let expected = value.clone();

        replace_relationships_with_components(&mut value);

        assert_eq!(value, expected);
    }

    #[test]
    fn keeps_only_the_strongest_flag_per_product() {
        let mut value = json!({
            "vulnerabilities": [{
                "cve": "CVE-2026-31789",
                "flags": [{
                    "label": "vulnerable_code_not_in_execute_path",
                    "product_ids": ["openssl", "openssl-libs", "curl"]
                }, {
                    "label": "vulnerable_code_not_present",
                    "product_ids": ["openssl", "openssl-libs"]
                }]
            }, {
                "cve": "CVE-2026-0001",
                "flags": [{
                    "label": "vulnerable_code_cannot_be_controlled_by_adversary",
                    "product_ids": ["zlib"]
                }, {
                    "label": "component_not_present",
                    "product_ids": ["zlib"]
                }]
            }]
        });

        remove_conflicting_flags(&mut value);

        assert_eq!(
            value["vulnerabilities"][0]["flags"],
            json!([{
                "label": "vulnerable_code_not_in_execute_path",
                "product_ids": ["curl"]
            }, {
                "label": "vulnerable_code_not_present",
                "product_ids": ["openssl", "openssl-libs"]
            }])
        );
        assert_eq!(
            value["vulnerabilities"][1]["flags"],
            json!([{
                "label": "component_not_present",
                "product_ids": ["zlib"]
            }])
        );
    }

    #[test]
    fn normalizes_purls_to_trivy_form() {
        assert_eq!(
            normalize_purl("pkg:rpm/redhat/openssl-libs@3.5.5-4.el9_8?arch=x86_64&distro=rhel-9.8&epoch=1&upstream=openssl-3.5.5-4.el9_8.src.rpm"),
            "pkg:rpm/redhat/openssl-libs@3.5.5-4.el9_8?arch=x86_64&distro=redhat-9.8&epoch=1"
        );
        assert_eq!(
            normalize_purl("pkg:rpm/redhat/glib2@2.68.4?upstream=glib2.src.rpm"),
            "pkg:rpm/redhat/glib2@2.68.4"
        );
        assert_eq!(
            normalize_purl("pkg:golang/stdlib@1.25.7"),
            "pkg:golang/stdlib@v1.25.7"
        );
        assert_eq!(
            normalize_purl("pkg:golang/stdlib@v1.25.7"),
            "pkg:golang/stdlib@v1.25.7"
        );
        assert_eq!(
            normalize_purl("pkg:maven/io.netty/netty-codec-http@4.2.6.Final?type=jar"),
            "pkg:maven/io.netty/netty-codec-http@4.2.6.Final?type=jar"
        );
    }

    #[test]
    fn normalizes_purls_only_in_identification_helpers() {
        let rpm = "pkg:rpm/redhat/curl-minimal@7.76.1-40.el9?arch=x86_64&distro=rhel-9.8";
        let mut value = json!({
            "product_tree": {
                "branches": [{
                    "product": {
                        "name": rpm,
                        "product_id": rpm,
                        "product_identification_helper": {"purl": rpm}
                    }
                }]
            }
        });

        normalize_purls(&mut value);

        let product = &value["product_tree"]["branches"][0]["product"];
        assert_eq!(
            product["product_identification_helper"]["purl"],
            "pkg:rpm/redhat/curl-minimal@7.76.1-40.el9?arch=x86_64&distro=redhat-9.8"
        );
        assert_eq!(product["product_id"], rpm);
    }

    #[test]
    fn build_href_absolute_from_root_directory() {
        let base = Some("/by-cve/csaf/v2/advisories");
        assert_eq!(
            build_href(".", "2026", true, base),
            "/by-cve/csaf/v2/advisories/2026/"
        );
        assert_eq!(
            build_href(".", "index.txt", false, base),
            "/by-cve/csaf/v2/advisories/index.txt"
        );
    }

    #[test]
    fn build_href_absolute_from_year_directory() {
        let base = Some("/by-cve/csaf/v2/advisories");
        assert_eq!(
            build_href("2026", "cve-2026-6100.json", false, base),
            "/by-cve/csaf/v2/advisories/2026/cve-2026-6100.json"
        );
    }

    #[test]
    fn build_href_trims_redundant_slashes_in_base() {
        let base = Some("/by-cve/csaf/v2/advisories/");
        assert_eq!(
            build_href("./2026", "index.html", false, base),
            "/by-cve/csaf/v2/advisories/2026/index.html"
        );
    }

    #[test]
    fn build_href_relative_without_base_path() {
        assert_eq!(build_href(".", "2026", true, None), "2026/");
        assert_eq!(
            build_href("2026", "cve-2026-6100.json", false, None),
            "cve-2026-6100.json"
        );
    }

    #[test]
    fn matches_branches_of_the_given_releases() {
        let pattern = product_version_branch_pattern(&["26.3.0".to_string(), "26.7.0".to_string()])
            .expect("releases are valid");

        for branch_name in [
            "2.9.3-stackable26.3.0-amd64",
            "3.1.6-stackable26.7.0-arm64",
            "26.3.0-amd64",
            "26.7.0-arm64",
        ] {
            assert!(pattern.is_match(branch_name), "{branch_name} must match");
        }
        for branch_name in [
            "2.9.3-stackable0.0.0-dev-amd64",
            "0.0.0-dev-amd64",
            "2.9.3-stackable25.11.0-amd64",
            "2.9.3-stackable26.3.0",
            "26.3.0",
            "2.9.3-stackable126.3.0-amd64",
            "126.3.0-amd64",
            "26.3.0-amd64-pr123",
        ] {
            assert!(
                !pattern.is_match(branch_name),
                "{branch_name} must not match"
            );
        }
    }

    #[test]
    fn rejects_invalid_releases() {
        assert!(product_version_branch_pattern(&["26.3".to_string()]).is_err());
        assert!(product_version_branch_pattern(&[".*".to_string()]).is_err());
    }

    #[test]
    fn ignores_tracking_data_when_comparing_documents() {
        let published = json!({
            "document": {
                "title": "Stackable Security Advisory for: airflow:3.1.6-stackable26.3.0-amd64",
                "tracking": {
                    "current_release_date": "2026-10-27T08:10:54.639265Z",
                    "revision_history": [{"date": "2026-10-27T08:10:54.639265Z", "number": "1", "summary": "Initial release"}],
                    "version": "1"
                }
            },
            "vulnerabilities": [{"cve": "CVE-2026-0001", "product_status": {"known_not_affected": ["a"]}}]
        });
        let mut republished = published.clone();
        republished["document"]["tracking"] = json!({
            "current_release_date": "2026-11-23T04:00:00Z",
            "revision_history": [{"date": "2026-11-23T04:00:00Z", "number": "1", "summary": "Initial release"}],
            "version": "1"
        });
        assert!(equal_except_tracking(&published, &republished));

        republished["vulnerabilities"][0]["product_status"] = json!({"known_affected": ["a"]});
        assert!(!equal_except_tracking(&published, &republished));
    }
}
