use std::any::Any;

use anyhow::{Context, Result};
use csaf::{definitions::{Branch, BranchCategory, BranchesT}, Csaf};
use regex::Regex;

#[tokio::main]
async fn main() -> Result<()> {
    let stackable_product_version_regex: Regex = Regex::new(r"^(?P<productname>[a-zA-Z0-9\-_]+):(?P<prefix>(?P<productversion>.+)\-stackable)?(?P<sdpversion>\d+\.\d+\.\d+(\-dev)?(\-(?P<architecture>arm64|amd64))?)$").unwrap();

    let mut csaf: Csaf = serde_json::from_str(&std::fs::read_to_string("csaf_in.json")?)?;
    let mut branches = csaf
        .product_tree
        .context("missing product tree")?
        .branches
        .context("product tree has no branches")?
        .0;
    // find branch with name "_components_", store it in "component_branch" and remove it from the vec
    let component_branch_idx = branches
        .iter()
        .position(|b| b.name == "_components_")
        .context("no branch named '_components_'")?;
    let component_branch = branches.remove(component_branch_idx);

    let sdp_branches: Vec<Branch> = vec![];

    for branch in branches.into_iter() {
        if branch.category.type_id() == BranchCategory::ProductFamily.type_id() {
            if let Some(branches) = branch.branches {
                for branch in branches.0.into_iter() {
                    if branch.category.type_id() == BranchCategory::ProductVersion.type_id() {
                        if let Some(product) = branch.product {
                            if let Some(captures) = stackable_product_version_regex.captures(&product.name) {
                                println!("found {} in sdp version {}", captures.name("productname").unwrap().as_str(), captures.name("sdpversion").unwrap().as_str());
                            }
                        }
                    }
                }
            }
        }
    }

    // vec![
    //                     Branch {
    //                         name: "24.3.0".to_string(),
    //                         category: BranchCategory::ProductVersion,
    //                         product: None,
    //                         branches: vec![
    //                             Branch {
    //                                 name: "Stackable HBase".to_string(),
    //                                 category: BranchCategory::ProductFamily,
    //                                 product: None,
    //                                 branches: vec![
    //                                     Branch {
    //                                         name: "2.4.17-stackable24.3.0".to_string(),
    //                                         category: BranchCategory::ProductVersion,
    //                                         product: Some(FullProductName {
    //                                             name: "Stackable HBase 2.4.17-stackable24.3.0".to_string(),
    //                                             product_id: "pkg:docker/sdp/hbase:2.4.17-stackable24.3.0?repository_url=oci.stackable.tech".to_string(),
    //                                             product_identification_helper: None,
    //                                         }),
    //                                         branches: vec![],
    //                                     },
    //                                 ],
    //                             },
    //                         ],
    //                     },
    //                 ]


    let new_branches = vec![
        component_branch,
        Branch {
            name: "Stackable".to_string(),
            category: BranchCategory::Vendor,
            product: None,
            branches: Some(BranchesT(vec![
                Branch {
                    name: "Stackable Data Platform".to_string(),
                    category: BranchCategory::ProductFamily,
                    product: None,
                    branches: None,
                },
            ])),
        },
    ];

    Ok(())
}
