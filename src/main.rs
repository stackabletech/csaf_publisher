use color_eyre::eyre::Context;
use pgp::ArmorOptions;
use pgp::{Deserializable, Message, SignedSecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::{env, fs};

use chrono::{Datelike, SecondsFormat};
use color_eyre::eyre::{ContextCompat, Result};
use csaf::{
    definitions::{Branch, BranchCategory, BranchesT},
    Csaf,
};
use regex::Regex;

fn main() -> Result<()> {
    color_eyre::install()?;

    let stackable_product_version_regex = Regex::new(r"^(?P<productname>[a-zA-Z0-9\-_]+):(?P<prefix>(?P<productversion>.+)\-stackable)?(?P<sdpversion>\d+\.\d+\.\d+(\-dev)?(\-(?P<architecture>arm64|amd64))?)$").unwrap();

    let secobserve_api_token =
        env::var("SECOBSERVE_API_TOKEN").context("Missing SecObserve API token!")?;

    // Collect command-line arguments for vulnerability names
    let vulnerability_names: Vec<String> = env::args().skip(1).collect();

    // Retrieve CSAF document from SecObserve API
    let client = reqwest::blocking::Client::new();
    let response = client
        .post("https://secobserve-backend.stackable.tech/api/vex/csaf_document/create/")
        .json(&serde_json::json!({
            "vulnerability_names": &vulnerability_names,
            "document_id_prefix": "STACKSA",
            "title": format!("Stackable Security Advisory for: {}", vulnerability_names.join(", ")),
            "publisher_name": "Stackable GmbH",
            "publisher_category": "vendor",
            "publisher_namespace": "http://www.stackable.tech",
            "tracking_status": "final",
            "tlp_label": "WHITE"
        }))
        .header(
            "Authorization",
            format!("APIToken {}", secobserve_api_token),
        )
        .header("User-Agent", "Stackable Security Advisory Generator")
        .send()?;

    // Extract filename from response headers
    let filename = response
        .headers()
        .get("Content-Disposition")
        .context("missing Content-Disposition header")?
        .to_str()?
        .split("filename=")
        .last()
        .context("missing filename in Content-Disposition header")?
        .replace('"', "");

    // Parse CSAF document from response
    let mut csaf: Csaf = serde_json::from_str(&response.text()?)?;
    csaf.document.lang = Some("en".to_string());
    let mut branches = csaf
        .product_tree
        .as_ref()
        .context("missing product tree")?
        .branches
        .as_ref()
        .context("missing branches in product tree")?
        .0
        .clone();
    // Find branch with name "_components_", store it in "component_branch" and remove it from the vec
    let component_branch_idx = branches
        .iter()
        .position(|b| b.name == "_components_")
        .context("no branch named '_components_'")?;
    let component_branch = branches.remove(component_branch_idx);

    let mut sdp_branches: Vec<Branch> = vec![];

    // Group products by sdp version
    branches
        .into_iter()
        .filter(|branch| matches!(branch.category, BranchCategory::ProductFamily))
        .for_each(|branch| {
            if let Some(subbranches) = branch.branches {
                subbranches
                    .0
                    .into_iter()
                    // Loop over all product versions of the product family
                    .filter(|subbranch| {
                        matches!(subbranch.category, BranchCategory::ProductVersion)
                    })
                    .for_each(|subbranch| {
                        // Subbranch has a product
                        if let Some(product) = subbranch.product.as_ref() {
                            // That product has a name that matches the stackable product version regex
                            if let Some(captures) =
                                stackable_product_version_regex.captures(&product.name)
                            {
                                // Find sdp_version branch in sdp_branches or create it
                                let sdp_version = captures.name("sdpversion").unwrap().as_str();

                                let sdp_version_idx = sdp_branches
                                    .iter()
                                    .position(|b| b.name == sdp_version)
                                    .unwrap_or_else(|| {
                                        let idx = sdp_branches.len();
                                        sdp_branches.push(Branch {
                                            name: sdp_version.to_string(),
                                            category: BranchCategory::ProductVersion,
                                            product: None,
                                            branches: Some(BranchesT(vec![])),
                                        });
                                        idx
                                    });

                                // Find product_name branch in sdp_branches or create it
                                let product_name = captures.name("productname").unwrap().as_str();

                                let product_name_idx = sdp_branches[sdp_version_idx]
                                    .branches
                                    .as_mut()
                                    .unwrap()
                                    .0
                                    .iter()
                                    .position(|b| b.name == product_name)
                                    .unwrap_or_else(|| {
                                        let idx = sdp_branches[sdp_version_idx]
                                            .branches
                                            .as_ref()
                                            .unwrap()
                                            .0
                                            .len();
                                        sdp_branches[sdp_version_idx]
                                            .branches
                                            .as_mut()
                                            .unwrap()
                                            .0
                                            .push(Branch {
                                                name: product_name.to_string(),
                                                category: BranchCategory::ProductName,
                                                product: None,
                                                branches: Some(BranchesT(vec![])),
                                            });
                                        idx
                                    });

                                // Append product version branch to product_name branch
                                sdp_branches[sdp_version_idx].branches.as_mut().unwrap().0
                                    [product_name_idx]
                                    .branches
                                    .as_mut()
                                    .unwrap()
                                    .0
                                    .push(subbranch);
                            }
                        }
                    });
            }
        });

    let new_branches = vec![
        component_branch,
        Branch {
            name: "Stackable".to_string(),
            category: BranchCategory::Vendor,
            product: None,
            branches: Some(BranchesT(vec![Branch {
                name: "Stackable Data Platform".to_string(),
                category: BranchCategory::ProductFamily,
                product: None,
                branches: Some(BranchesT(sdp_branches)),
            }])),
        },
    ];

    csaf.product_tree.as_mut().unwrap().branches = Some(BranchesT(new_branches));

    // Prepare output directory and filenames
    let current_year = chrono::Local::now().year().to_string();
    fs::create_dir_all(&current_year)?;

    // Write CSAF to file
    let csaf_filename = format!("{}/{}", current_year, filename);
    let csaf_as_string = serde_json::to_string_pretty(&csaf)?;
    fs::write(&csaf_filename, &csaf_as_string)?;

    // Generate PGP signature
    let key_string = env::var("PGP_SECRET_KEY").context("Missing PGP secret key!")?;
    let (secret_key, _headers) = SignedSecretKey::from_string(&key_string).unwrap();
    let mut signature_filehandle = fs::File::create(format!("{}/{}.asc", current_year, filename))?;
    let pgp_message = Message::new_literal(csaf_filename.as_bytes(), &csaf_as_string).sign(
        &secret_key,
        || env::var("PGP_SECRET_KEY_PASSPHRASE").expect("Missing PGP secret key passphrase!"),
        pgp::crypto::hash::HashAlgorithm::SHA2_256,
    )?;
    pgp_message
        .into_signature()
        .to_armored_writer(&mut signature_filehandle, ArmorOptions::default())?;

    // Read CSAF file into buffer
    let buffer = fs::read(&csaf_filename)?;

    // Generate hashes
    for hash_filename in ["sha512", "sha256"].into_iter() {
        let hash = match hash_filename {
            "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(&buffer);
                format!("{:x}  {}", hasher.finalize(), csaf_filename)
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(&buffer);
                format!("{:x}  {}", hasher.finalize(), csaf_filename)
            }
            _ => unreachable!(),
        };
        fs::write(
            format!("{}/{}.{}", current_year, filename, hash_filename),
            hash,
        )?;
    }

    // Prepend to changes.csv, like this: "2020/example_company_-_2020-yh4711.json","2020-07-01T10:09:07Z"
    prepend_to_file(
        "changes.csv",
        &format!("{},\"{}\"\n", csaf_filename, csaf.document.tracking.current_release_date.to_rfc3339_opts(SecondsFormat::Secs, true)),
    )?;
    // Prepend the filename to index.txt
    prepend_to_file("index.txt", &format!("{}\n", csaf_filename))?;

    // Generate directory listings
    generate_index_html(&current_year)?;
    generate_index_html(".")?;

    Ok(())
}

fn prepend_to_file(filename: &str, line: &str) -> Result<()> {
    let mut contents = fs::read_to_string(filename)?;
    contents.insert_str(0, line);
    fs::write(filename, contents)?;
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
