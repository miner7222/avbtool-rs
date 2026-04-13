use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crypto::{AvbPublicKey, lookup_algorithm_by_type};
use crate::error::{AvbToolError as DynoError, Result};
use crate::footer::{
    calc_hash_level_offsets, generate_hash_tree, hash_digest_size, hash_file_prefix,
};
use crate::image::{inspect_avb_image, load_vbmeta_blob};
use crate::info::DescriptorInfo;
use crate::parser::AVB_VBMETA_IMAGE_HEADER_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedChainPartition {
    pub partition_name: String,
    pub rollback_index_location: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyImageOptions {
    pub key_blob: Option<Vec<u8>>,
    pub expected_chain_partitions: Vec<ExpectedChainPartition>,
    pub follow_chain_partitions: bool,
    pub accept_zeroed_hashtree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyImageReport {
    pub root_image: PathBuf,
    pub verified_images: Vec<PathBuf>,
    pub messages: Vec<String>,
}

pub fn verify_image(image_filename: &Path, options: &VerifyImageOptions) -> Result<VerifyImageReport> {
    let mut report = VerifyImageReport {
        root_image: image_filename.to_path_buf(),
        verified_images: Vec::new(),
        messages: Vec::new(),
    };
    let expected_map = options
        .expected_chain_partitions
        .iter()
        .map(|entry| {
            (
                entry.partition_name.clone(),
                (entry.rollback_index_location, entry.public_key.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut visited = BTreeSet::new();
    verify_image_inner(
        image_filename,
        options,
        &expected_map,
        None,
        &mut visited,
        &mut report,
    )?;
    Ok(report)
}

fn verify_image_inner(
    image_filename: &Path,
    options: &VerifyImageOptions,
    expected_chain_partitions: &BTreeMap<String, (u32, Vec<u8>)>,
    expected_key: Option<&[u8]>,
    visited: &mut BTreeSet<PathBuf>,
    report: &mut VerifyImageReport,
) -> Result<()> {
    let canonical = std::fs::canonicalize(image_filename).unwrap_or_else(|_| image_filename.to_path_buf());
    if !visited.insert(canonical.clone()) {
        report.messages.push(format!(
            "Skipping already verified chained image {}",
            image_filename.display()
        ));
        return Ok(());
    }

    let info = inspect_avb_image(image_filename)?;
    let vbmeta_blob = load_vbmeta_blob(image_filename)?;
    let (algorithm_name, embedded_public_key) = verify_vbmeta_signature(&info, &vbmeta_blob)?;

    if let Some(expected) = options.key_blob.as_deref() {
        if expected != embedded_public_key.as_slice() {
            return Err(DynoError::Validation(format!(
                "Embedded public key does not match requested key in {}",
                image_filename.display()
            )));
        }
    }
    if let Some(expected) = expected_key {
        if expected != embedded_public_key.as_slice() {
            return Err(DynoError::Validation(format!(
                "Embedded public key in {} does not match chained descriptor key",
                image_filename.display()
            )));
        }
    }

    report.verified_images.push(canonical);
    report.messages.push(match info.footer {
        Some(_) => format!(
            "vbmeta: Successfully verified footer and {} vbmeta struct in {}",
            algorithm_name,
            image_filename.display()
        ),
        None => format!(
            "vbmeta: Successfully verified {} vbmeta struct in {}",
            algorithm_name,
            image_filename.display()
        ),
    });

    let image_dir = image_filename.parent().unwrap_or_else(|| Path::new("."));
    let image_ext = image_filename
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    for descriptor in &info.descriptors {
        match descriptor {
            DescriptorInfo::Property { .. }
            | DescriptorInfo::KernelCmdline { .. }
            | DescriptorInfo::Unknown { .. } => {}
            DescriptorInfo::Hash {
                image_size,
                hash_algorithm,
                partition_name,
                salt,
                digest,
                ..
            } => {
                let target = resolve_descriptor_target(image_filename, image_dir, &image_ext, partition_name);
                let actual_digest =
                    hash_file_prefix(&target, *image_size, hash_algorithm, salt)?;
                if !digest.is_empty() && actual_digest != *digest {
                    return Err(DynoError::Validation(format!(
                        "{} digest of {} does not match descriptor",
                        hash_algorithm,
                        target.display()
                    )));
                }
                report.messages.push(format!(
                    "{}: Successfully verified {} hash of {} for image of {} bytes",
                    partition_name,
                    hash_algorithm,
                    target.display(),
                    image_size
                ));
            }
            DescriptorInfo::Hashtree {
                image_size,
                tree_offset,
                tree_size,
                data_block_size,
                hash_algorithm,
                partition_name,
                salt,
                root_digest,
                fec_size,
                ..
            } => {
                let target = resolve_descriptor_target(image_filename, image_dir, &image_ext, partition_name);
                let digest_size = hash_digest_size(hash_algorithm)?;
                let digest_padding = crate::crypto::round_to_pow2(digest_size) - digest_size;
                let (hash_level_offsets, calculated_tree_size) = calc_hash_level_offsets(
                    *image_size,
                    *data_block_size as u64,
                    (digest_size + digest_padding) as u64,
                );
                let (actual_root, actual_tree) = generate_hash_tree(
                    &target,
                    *image_size,
                    *data_block_size,
                    hash_algorithm,
                    salt,
                    digest_padding,
                    &hash_level_offsets,
                    calculated_tree_size,
                )?;
                if !root_digest.is_empty() && actual_root != *root_digest {
                    return Err(DynoError::Validation(format!(
                        "hashtree of {} does not match descriptor root digest",
                        target.display()
                    )));
                }
                if *tree_size > 0 {
                    let mut file = File::open(&target)?;
                    file.seek(SeekFrom::Start(*tree_offset))?;
                    let mut on_disk_tree = vec![0u8; *tree_size as usize];
                    file.read_exact(&mut on_disk_tree)?;
                    let is_zeroed = on_disk_tree.starts_with(b"ZeRoHaSH");
                    if is_zeroed && options.accept_zeroed_hashtree {
                        report.messages.push(format!(
                            "{}: skipping verification since hashtree is zeroed",
                            partition_name
                        ));
                    } else if on_disk_tree != actual_tree[..*tree_size as usize] {
                        return Err(DynoError::Validation(format!(
                            "hashtree of {} contains invalid data",
                            target.display()
                        )));
                    } else {
                        report.messages.push(format!(
                            "{}: Successfully verified {} hashtree of {} for image of {} bytes",
                            partition_name,
                            hash_algorithm,
                            target.display(),
                            image_size
                        ));
                    }
                } else {
                    report.messages.push(format!(
                        "{}: Descriptor intentionally omits on-disk hashtree",
                        partition_name
                    ));
                }
                if *fec_size > 0 {
                    report.messages.push(format!(
                        "{}: FEC presence noted but FEC payload verification is skipped",
                        partition_name
                    ));
                }
            }
            DescriptorInfo::ChainPartition {
                rollback_index_location,
                partition_name,
                public_key,
                ..
            } => {
                match expected_chain_partitions.get(partition_name) {
                    Some((expected_slot, expected_public_key)) => {
                        if rollback_index_location != expected_slot {
                            return Err(DynoError::Validation(format!(
                                "Expected rollback_index_location {} does not match {} in descriptor for partition {}",
                                expected_slot, rollback_index_location, partition_name
                            )));
                        }
                        if public_key != expected_public_key {
                            return Err(DynoError::Validation(format!(
                                "Expected public key blob does not match descriptor for partition {}",
                                partition_name
                            )));
                        }
                        report.messages.push(format!(
                            "{}: Successfully verified chain partition descriptor matches expected data",
                            partition_name
                        ));
                    }
                    None if !options.follow_chain_partitions => {
                        return Err(DynoError::Validation(format!(
                            "No expected chain partition for {}. Provide expected data or enable follow_chain_partitions.",
                            partition_name
                        )));
                    }
                    None => {
                        report.messages.push(format!(
                            "{}: Chained but rollback slot {} and key sha1 not provided; following chain",
                            partition_name, rollback_index_location
                        ));
                    }
                }

                if options.follow_chain_partitions {
                    let chained_image = image_dir.join(format!("{partition_name}{image_ext}"));
                    verify_image_inner(
                        &chained_image,
                        options,
                        expected_chain_partitions,
                        Some(public_key),
                        visited,
                        report,
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn verify_vbmeta_signature(
    info: &crate::info::AvbImageInfo,
    vbmeta_blob: &[u8],
) -> Result<(String, Vec<u8>)> {
    let header = &info.header;
    let algorithm = lookup_algorithm_by_type(header.algorithm_type)?;
    let auth_start = AVB_VBMETA_IMAGE_HEADER_SIZE;
    let auth_end = auth_start + header.authentication_data_block_size as usize;
    let aux_start = auth_end;
    let aux_end = aux_start + header.auxiliary_data_block_size as usize;
    if aux_end > vbmeta_blob.len() {
        return Err(DynoError::Validation("VBMeta blob truncated.".into()));
    }

    let auth_blob = &vbmeta_blob[auth_start..auth_end];
    let aux_blob = &vbmeta_blob[aux_start..aux_end];
    let hash_end = header.hash_offset as usize + header.hash_size as usize;
    let signature_end = header.signature_offset as usize + header.signature_size as usize;
    let public_key_end = header.public_key_offset as usize + header.public_key_size as usize;
    if hash_end > auth_blob.len()
        || signature_end > auth_blob.len()
        || public_key_end > aux_blob.len()
    {
        return Err(DynoError::Validation(
            "VBMeta offsets exceed authentication or auxiliary block.".into(),
        ));
    }

    let embedded_public_key =
        aux_blob[header.public_key_offset as usize..public_key_end].to_vec();
    if algorithm.name == "NONE" {
        return Ok((algorithm.name.to_string(), embedded_public_key));
    }

    let data_to_verify = [&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE], aux_blob].concat();
    let computed_digest = crate::crypto::compute_hash_for_algorithm(algorithm, &data_to_verify)?;
    let expected_digest = &auth_blob[header.hash_offset as usize..hash_end];
    if computed_digest.as_slice() != expected_digest {
        return Err(DynoError::Validation(
            "VBMeta digest does not match authentication block.".into(),
        ));
    }

    let public_key = AvbPublicKey::decode(&embedded_public_key)?;
    let signature = &auth_blob[header.signature_offset as usize..signature_end];
    if !public_key.verify(algorithm, signature, &data_to_verify)? {
        return Err(DynoError::Validation(format!(
            "Signature check failed for {}",
            algorithm.name
        )));
    }

    Ok((algorithm.name.to_string(), embedded_public_key))
}

fn resolve_descriptor_target(
    current_image: &Path,
    image_dir: &Path,
    image_ext: &str,
    partition_name: &str,
) -> PathBuf {
    if partition_name.is_empty() {
        current_image.to_path_buf()
    } else {
        image_dir.join(format!("{partition_name}{image_ext}"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::footer::{HashFooterArgs, add_hash_footer};

    fn sample_hash_footer_args() -> HashFooterArgs {
        HashFooterArgs {
            partition_size: Some(12288),
            dynamic_partition_size: false,
            partition_name: "boot".to_string(),
            hash_algorithm: "sha256".to_string(),
            salt: Some(vec![0x11, 0x22]),
            chain_partitions: Vec::new(),
            algorithm_name: "SHA256_RSA2048".to_string(),
            key_spec: Some("testkey_rsa2048".to_string()),
            public_key_metadata: None,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            properties: Vec::new(),
            kernel_cmdlines: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            release_string: None,
            append_to_release_string: None,
            output_vbmeta_image: None,
            do_not_append_vbmeta_image: false,
            use_persistent_digest: false,
            do_not_use_ab: false,
        }
    }

    #[test]
    fn verify_hash_footer_round_trip() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let report = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(crate::crypto::extract_public_key("testkey_rsa2048").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();

        assert!(!report.verified_images.is_empty());
        assert!(report.messages.iter().any(|line| line.contains("Successfully verified")));
    }

    #[test]
    fn verify_hash_footer_detects_mutation() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let mut bytes = fs::read(&image).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&image, bytes).unwrap();

        let error = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(crate::crypto::extract_public_key("testkey_rsa2048").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("digest") || error.to_string().contains("VBMeta"));
    }
}
