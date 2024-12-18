use color_eyre::eyre::Context;
use csaf::definitions::Note;
use pgp::ArmorOptions;
use pgp::{Deserializable, Message, SignedSecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::Read;
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

    let stackable_product_version_regex = Regex::new(r"^(?P<product_name>[a-zA-Z0-9\-_]+):(?P<full_version>((?P<product_version>.+)\-stackable)?(?P<sdp_version>\d+\.\d+\.\d+(\-dev)?)(\-(?P<architecture>arm64|amd64)?))$").unwrap();

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
            "publisher_namespace": "https://www.stackable.tech",
            "tracking_status": "draft",
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
    // let mut csaf: Csaf = serde_json::from_reader(File::open("csaf_in.json")?)?;
    // let filename = "csaf_out.json";
    csaf.document.lang = Some("en-US".to_string());
    csaf.document.publisher.issuing_authority = Some("The Stackable Security Team is responsible for vulnerability handling across all Stackable offerings.".to_string());
    csaf.document.publisher.contact_details = Some("product-security@stackable.tech".to_string());
    let disclaimer = Note {
        category: csaf::definitions::NoteCategory::LegalDisclaimer,
        text: "This content is licensed under the Creative Commons Attribution 4.0 International License (https://creativecommons.org/licenses/by/4.0/). If you distribute this content, or a modified version of it, you must provide attribution to Stackable GmbH and provide a link to the original.".to_string(),
        title: Some("Terms of Use".to_string()),
        audience: None
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

    // Group products by sdp version
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
                        // That product has a name that matches the stackable product version regex
                        if let Some(captures) =
                            stackable_product_version_regex.captures(&product.name)
                        {
                            let sdp_version = captures.name("sdp_version").unwrap().as_str();
                            let product_name = captures.name("product_name").unwrap().as_str();
                            let full_version = captures.name("full_version").unwrap().as_str();
                            let product_version = captures
                                .name("product_version")
                                .map(|v| v.as_str())
                                .unwrap_or(sdp_version);

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
                        }
                    }
                });
        }
    });

    csaf.product_tree.as_mut().unwrap().branches = Some(BranchesT(new_branches));

    // Prepare output directory and filenames
    let current_year = chrono::Local::now().year().to_string();
    fs::create_dir_all(&current_year)?;

    // Write CSAF to file
    let csaf_filename = format!("{}/{}", current_year, filename);
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
        &format!(
            "\"{}\",\"{}\"\n",
            csaf_filename,
            csaf.document
                .tracking
                .current_release_date
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        ),
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
