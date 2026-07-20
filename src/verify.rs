use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crypto::{
    AvbMldsaPublicKey, AvbPublicKey, is_mldsa_algorithm, lookup_algorithm_by_type,
};
use crate::error::{AvbToolError as DynoError, Result};
use crate::footer::{
    calc_hash_level_offsets, generate_hash_tree, hash_digest_size, hash_file_prefix,
};
use crate::image::read_exact_at;
use crate::image::{inspect_avb_image, load_vbmeta_blob};
use crate::info::DescriptorInfo;
use crate::parser::AVB_VBMETA_IMAGE_HEADER_SIZE;
use crate::sparse::ImageHandler;

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

/// Optional presentation hooks for AOSP text parity and later CLI wiring.
///
/// Defaults preserve AOSP dense behavior (preamble + chain separators). These
/// stay out of `VerifyImageOptions` so existing call sites remain compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRenderOptions {
    /// Optional path label used only in preamble when a key blob is provided.
    pub key_path_label: Option<String>,
    /// Emit `--` before following a chain partition (AOSP style).
    pub chain_separator: bool,
}

impl Default for VerifyRenderOptions {
    fn default() -> Self {
        Self {
            key_path_label: None,
            chain_separator: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyImageReport {
    pub root_image: PathBuf,
    pub verified_images: Vec<PathBuf>,
    pub messages: Vec<String>,
}

pub fn verify_image(
    image_filename: &Path,
    options: &VerifyImageOptions,
) -> Result<VerifyImageReport> {
    verify_image_with_render(image_filename, options, &VerifyRenderOptions::default())
}

pub fn verify_image_with_render(
    image_filename: &Path,
    options: &VerifyImageOptions,
    render: &VerifyRenderOptions,
) -> Result<VerifyImageReport> {
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
        render,
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
    render: &VerifyRenderOptions,
    expected_chain_partitions: &BTreeMap<String, (u32, Vec<u8>)>,
    expected_key: Option<&[u8]>,
    visited: &mut BTreeSet<PathBuf>,
    report: &mut VerifyImageReport,
) -> Result<()> {
    let canonical =
        std::fs::canonicalize(image_filename).unwrap_or_else(|_| image_filename.to_path_buf());
    if !visited.insert(canonical.clone()) {
        report.messages.push(format!(
            "Skipping already verified chained image {}",
            image_filename.display()
        ));
        return Ok(());
    }

    // AOSP prints a verification preamble before parsing/signature checks.
    if options.key_blob.is_some() {
        if let Some(key_path) = render.key_path_label.as_deref() {
            report.messages.push(format!(
                "Verifying image {} using key at {key_path}",
                image_filename.display()
            ));
        } else {
            report.messages.push(format!(
                "Verifying image {} using provided public key",
                image_filename.display()
            ));
        }
    } else {
        report.messages.push(format!(
            "Verifying image {} using embedded public key",
            image_filename.display()
        ));
    }

    let info = inspect_avb_image(image_filename)?;
    let vbmeta_blob = load_vbmeta_blob(image_filename)?;
    let (algorithm_name, embedded_public_key) = verify_vbmeta_signature(&info, &vbmeta_blob)?;

    if options
        .key_blob
        .as_deref()
        .is_some_and(|expected| expected != embedded_public_key.as_slice())
    {
        return Err(DynoError::Validation(format!(
            "Embedded public key does not match requested key in {}",
            image_filename.display()
        )));
    }
    if expected_key.is_some_and(|expected| expected != embedded_public_key.as_slice()) {
        return Err(DynoError::Validation(format!(
            "Embedded public key in {} does not match chained descriptor key",
            image_filename.display()
        )));
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
                let target = resolve_descriptor_target(
                    image_filename,
                    image_dir,
                    &image_ext,
                    partition_name,
                );
                let actual_digest = hash_file_prefix(&target, *image_size, hash_algorithm, salt)?;
                if !digest.is_empty() && actual_digest != *digest {
                    return Err(DynoError::Validation(format!(
                        "{hash_algorithm} digest of {} does not match digest in descriptor",
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
                let target = resolve_descriptor_target(
                    image_filename,
                    image_dir,
                    &image_ext,
                    partition_name,
                );
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
                        "hashtree of {} does not match descriptor",
                        target.display()
                    )));
                }
                if *tree_size > 0 {
                    let mut image = ImageHandler::open(&target, true).map_err(|err| match err {
                        crate::sparse::SparseError::Io(io) => DynoError::Io(io),
                        other => DynoError::Tool(other.to_string()),
                    })?;
                    let on_disk_tree =
                        read_exact_at(&mut image, *tree_offset, *tree_size as usize)?;
                    let is_zeroed = on_disk_tree.starts_with(b"ZeRoHaSH");
                    if is_zeroed && options.accept_zeroed_hashtree {
                        report.messages.push(format!(
                            "{partition_name}: skipping verification since hashtree is zeroed and --accept_zeroed_hashtree was given"
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
                            "No expected chain partition for partition {partition_name}. Use --expected_chain_partition to specify expected contents or --follow_chain_partitions."
                        )));
                    }
                    None => {
                        report.messages.push(format!(
                            "{partition_name}: Chained but ROLLBACK_SLOT (which is {rollback_index_location}) and KEY (which has sha1 {}) not specified",
                            sha1_hex(public_key)
                        ));
                    }
                }

                if options.follow_chain_partitions {
                    if render.chain_separator {
                        report.messages.push("--".to_string());
                    }
                    let chained_image = image_dir.join(format!("{partition_name}{image_ext}"));
                    verify_image_inner(
                        &chained_image,
                        options,
                        render,
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

    let embedded_public_key = aux_blob[header.public_key_offset as usize..public_key_end].to_vec();
    if algorithm.name == "NONE" {
        return Ok((algorithm.name.to_string(), embedded_public_key));
    }

    // Enforce exact public-key blob size for both RSA and ML-DSA encodings.
    if embedded_public_key.len() != algorithm.public_key_num_bytes {
        return Err(DynoError::Validation(format!(
            "Embedded public key size mismatch for {}: expected {} bytes, got {}",
            algorithm.name,
            algorithm.public_key_num_bytes,
            embedded_public_key.len()
        )));
    }

    let data_to_verify = [&vbmeta_blob[..AVB_VBMETA_IMAGE_HEADER_SIZE], aux_blob].concat();
    // ML-DSA algorithms use an empty external hash (hash_num_bytes == 0).
    let computed_digest = crate::crypto::compute_hash_for_algorithm(algorithm, &data_to_verify)?;
    let expected_digest = &auth_blob[header.hash_offset as usize..hash_end];
    if computed_digest.as_slice() != expected_digest {
        return Err(DynoError::Validation(
            "VBMeta digest does not match authentication block.".into(),
        ));
    }
    if is_mldsa_algorithm(algorithm.name) && header.hash_size != 0 {
        return Err(DynoError::Validation(format!(
            "ML-DSA algorithm {} requires empty external hash, got hash_size {}",
            algorithm.name, header.hash_size
        )));
    }

    let signature = &auth_blob[header.signature_offset as usize..signature_end];
    if signature.len() != algorithm.signature_num_bytes {
        return Err(DynoError::Validation(format!(
            "Signature size mismatch for {}: expected {} bytes, got {}",
            algorithm.name,
            algorithm.signature_num_bytes,
            signature.len()
        )));
    }

    let verified = if is_mldsa_algorithm(algorithm.name) {
        let public_key = AvbMldsaPublicKey::decode(algorithm.name, &embedded_public_key)?;
        // AvbMldsaPublicKey::decode enforces exact be32 raw length + total size.
        public_key.verify(algorithm, signature, &data_to_verify)?
    } else {
        let public_key = AvbPublicKey::decode(&embedded_public_key)?;
        public_key.verify(algorithm, signature, &data_to_verify)?
    };
    if !verified {
        return Err(DynoError::Validation(format!(
            "Signature check failed for {}",
            algorithm.name
        )));
    }

    Ok((algorithm.name.to_string(), embedded_public_key))
}

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
            partition_size: Some(131072),
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
        assert!(
            report
                .messages
                .iter()
                .any(|line| line.contains("Successfully verified"))
        );
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

    #[test]
    fn verify_reports_aosp_preamble_and_success_messages() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let report = verify_image_with_render(
            &image,
            &VerifyImageOptions {
                key_blob: Some(crate::crypto::extract_public_key("testkey_rsa2048").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
            &VerifyRenderOptions {
                key_path_label: Some("testkey_rsa2048".to_string()),
                chain_separator: true,
            },
        )
        .unwrap();

        assert!(report.messages[0].starts_with("Verifying image "));
        assert!(report.messages[0].contains("using key at testkey_rsa2048"));
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.starts_with("vbmeta: Successfully verified footer and"))
        );
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.contains("Successfully verified sha256 hash"))
        );
    }

    #[test]
    fn verify_detects_key_mismatch() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let wrong_key =
            crate::crypto::extract_public_key("testkey_rsa4096").unwrap_or_else(|_| vec![0u8; 8]);
        let error = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(wrong_key),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Embedded public key does not match")
                || error.to_string().contains("Signature check failed")
                || error.to_string().contains("digest")
        );
    }

    #[test]
    fn verify_embedded_key_preamble_without_key_blob() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();
        add_hash_footer(&image, &sample_hash_footer_args()).unwrap();

        let report = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: None,
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();

        assert_eq!(
            report.messages[0],
            format!(
                "Verifying image {} using embedded public key",
                image.display()
            )
        );
    }

    #[test]
    fn verify_mldsa_vbmeta_round_trip_and_render() {
        use crate::builder::{PropertySpec, VbmetaImageArgs, make_vbmeta_image};
        use crate::crypto::extract_public_key;

        let temp = tempdir().unwrap();
        let image = temp.path().join("vbmeta_mldsa.img");
        let args = VbmetaImageArgs {
            algorithm_name: "MLDSA65".to_string(),
            key_spec: Some("testkey_mldsa65".to_string()),
            public_key_metadata: None,
            rollback_index: 3,
            flags: 0,
            rollback_index_location: 0,
            properties: vec![PropertySpec {
                key: "x".to_string(),
                value: b"y".to_vec(),
            }],
            kernel_cmdlines: Vec::new(),
            extra_descriptors: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            chain_partitions: Vec::new(),
            release_string: Some("verify-mldsa".to_string()),
            append_to_release_string: None,
            padding_size: 0,
        };
        make_vbmeta_image(&image, &args).unwrap();

        let report = verify_image_with_render(
            &image,
            &VerifyImageOptions {
                key_blob: Some(extract_public_key("testkey_mldsa65").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
            &VerifyRenderOptions {
                key_path_label: Some("testkey_mldsa65".to_string()),
                chain_separator: true,
            },
        )
        .unwrap();
        assert!(report.messages[0].contains("using key at testkey_mldsa65"));
        assert!(
            report
                .messages
                .iter()
                .any(|m| m.contains("Successfully verified MLDSA65 vbmeta struct"))
        );
    }

    #[test]
    fn verify_mldsa_rejects_wrong_key_and_tamper() {
        use crate::builder::{VbmetaImageArgs, make_vbmeta_image};
        use crate::crypto::extract_public_key;

        let temp = tempdir().unwrap();
        let image = temp.path().join("vbmeta_mldsa.img");
        let args = VbmetaImageArgs {
            algorithm_name: "MLDSA65".to_string(),
            key_spec: Some("testkey_mldsa65".to_string()),
            public_key_metadata: None,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            properties: Vec::new(),
            kernel_cmdlines: Vec::new(),
            extra_descriptors: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            chain_partitions: Vec::new(),
            release_string: None,
            append_to_release_string: None,
            padding_size: 0,
        };
        make_vbmeta_image(&image, &args).unwrap();

        let wrong = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(extract_public_key("testkey_mldsa87").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap_err();
        assert!(
            wrong
                .to_string()
                .contains("Embedded public key does not match"),
            "{wrong}"
        );

        let mut bytes = fs::read(&image).unwrap();
        bytes[256 + 16] ^= 0xff;
        fs::write(&image, bytes).unwrap();
        let tamper = verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: None,
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap_err();
        assert!(
            tamper.to_string().contains("Signature check failed")
                || tamper.to_string().contains("digest")
                || tamper.to_string().contains("VBMeta"),
            "{tamper}"
        );
    }
}
