use std::env;

use color_eyre::eyre::{ContextCompat, Result};
use csaf::{
    definitions::{Branch, BranchCategory, BranchesT},
    Csaf,
};
use regex::Regex;

fn main() -> Result<()> {
    color_eyre::install()?;
    let stackable_product_version_regex: Regex = Regex::new(r"^(?P<productname>[a-zA-Z0-9\-_]+):(?P<prefix>(?P<productversion>.+)\-stackable)?(?P<sdpversion>\d+\.\d+\.\d+(\-dev)?(\-(?P<architecture>arm64|amd64))?)$").unwrap();

    let input_file = env::args().nth(1).context("Missing input file!\nUsage: csaf_transformer <input-file> <output-file>")?;
    let output_file = env::args().nth(2).context("Missing output file!\nUsage: csaf_transformer <input-file> <output-file>")?;

    let file = &std::fs::read_to_string(input_file)?;
    let mut csaf: Csaf = serde_json::from_str(file)?;
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
    // find branch with name "_components_", store it in "component_branch" and remove it from the vec
    let component_branch_idx = branches
        .iter()
        .position(|b| b.name == "_components_")
        .context("no branch named '_components_'")?;
    let component_branch = branches.remove(component_branch_idx);

    let mut sdp_branches: Vec<Branch> = vec![];

    // group products by sdp version
    branches
        .into_iter()
        // loop over all product families
        .filter(|branch| matches!(branch.category, BranchCategory::ProductFamily))
        .for_each(|branch| {
            if let Some(subbranches) = branch.branches {
                subbranches
                    .0
                    .into_iter()
                    // loop over all product versions of the product family
                    .filter(|subbranch| {
                        matches!(subbranch.category, BranchCategory::ProductVersion)
                    })
                    .for_each(|subbranch| {
                        // subbranch has a product
                        if let Some(product) = subbranch.product.as_ref() {
                            // that product has a name that matches the stackable product version regex
                            if let Some(captures) =
                                stackable_product_version_regex.captures(&product.name)
                            {
                                // find sdp_version branch in sdp_branches or create it
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


                                // find product_name branch in sdp_branches or create it
                                let product_name = captures.name("productname").unwrap().as_str();

                                let product_name_idx = sdp_branches[sdp_version_idx].branches.as_mut().unwrap().0
                                    .iter()
                                    .position(|b| b.name == product_name)
                                    .unwrap_or_else(|| {
                                        let idx = sdp_branches[sdp_version_idx].branches.as_ref().unwrap().0.len();
                                        sdp_branches[sdp_version_idx].branches.as_mut().unwrap().0.push(Branch {
                                            name: product_name.to_string(),
                                            category: BranchCategory::ProductName,
                                            product: None,
                                            branches: Some(BranchesT(vec![])),
                                        });
                                        idx
                                    });

                                // append product version branch to product_name branch
                                sdp_branches[sdp_version_idx].branches.as_mut()
                                .unwrap().0[product_name_idx]
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

    std::fs::write(output_file, serde_json::to_string_pretty(&csaf)?)?;

    Ok(())
}
