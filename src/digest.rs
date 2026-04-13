use std::path::{Path, PathBuf};

use sha2::{Digest as Sha2Digest, Sha256, Sha512};

use crate::error::{AvbToolError as DynoError, Result};
use crate::image::{inspect_avb_image, load_vbmeta_blob};
use crate::info::DescriptorInfo;

const HASHTREE_USE_ONLY_IF_NOT_DISABLED: u32 = 1;
const HASHTREE_USE_ONLY_IF_DISABLED: u32 = 2;

pub fn calculate_vbmeta_digest(image_filename: &Path, hash_algorithm: &str) -> Result<Vec<u8>> {
    let mut blobs = Vec::new();
    collect_vbmeta_blobs_recursive(image_filename, &mut blobs)?;
    match hash_algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            for blob in blobs {
                hasher.update(blob);
            }
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            for blob in blobs {
                hasher.update(blob);
            }
            Ok(hasher.finalize().to_vec())
        }
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported vbmeta digest algorithm {}",
            other
        ))),
    }
}

pub fn calculate_kernel_cmdline(
    image_filename: &Path,
    hashtree_disabled: bool,
) -> Result<String> {
    let mut snippets = Vec::new();
    collect_kernel_cmdlines_recursive(image_filename, &mut snippets)?;
    let filtered = snippets
        .into_iter()
        .filter(|(flags, _)| {
            let use_only_if_not_disabled = (*flags & HASHTREE_USE_ONLY_IF_NOT_DISABLED) != 0;
            let use_only_if_disabled = (*flags & HASHTREE_USE_ONLY_IF_DISABLED) != 0;
            (!use_only_if_not_disabled || !hashtree_disabled)
                && (!use_only_if_disabled || hashtree_disabled)
        })
        .map(|(_, cmdline)| cmdline)
        .collect::<Vec<_>>();
    Ok(filtered.join(" "))
}

pub fn print_partition_digests(image_filename: &Path) -> Result<Vec<(String, String)>> {
    let mut entries = Vec::new();
    collect_partition_digests_recursive(image_filename, &mut entries)?;
    Ok(entries)
}

fn collect_vbmeta_blobs_recursive(path: &Path, blobs: &mut Vec<Vec<u8>>) -> Result<()> {
    let blob = load_vbmeta_blob(path)?;
    blobs.push(blob);
    let info = inspect_avb_image(path)?;
    for descriptor in info.descriptors {
        if let DescriptorInfo::ChainPartition { partition_name, .. } = descriptor {
            collect_vbmeta_blobs_recursive(&chained_image_path(path, &partition_name), blobs)?;
        }
    }
    Ok(())
}

fn collect_kernel_cmdlines_recursive(
    path: &Path,
    snippets: &mut Vec<(u32, String)>,
) -> Result<()> {
    let info = inspect_avb_image(path)?;
    for descriptor in info.descriptors {
        match descriptor {
            DescriptorInfo::KernelCmdline {
                flags,
                kernel_cmdline,
            } => snippets.push((flags, kernel_cmdline)),
            DescriptorInfo::ChainPartition { partition_name, .. } => {
                collect_kernel_cmdlines_recursive(&chained_image_path(path, &partition_name), snippets)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_partition_digests_recursive(
    path: &Path,
    entries: &mut Vec<(String, String)>,
) -> Result<()> {
    let info = inspect_avb_image(path)?;
    for descriptor in info.descriptors {
        match descriptor {
            DescriptorInfo::Hash {
                partition_name,
                digest,
                ..
            } => entries.push((partition_name, bytes_to_hex(&digest))),
            DescriptorInfo::Hashtree {
                partition_name,
                root_digest,
                ..
            } => entries.push((partition_name, bytes_to_hex(&root_digest))),
            DescriptorInfo::ChainPartition { partition_name, .. } => {
                collect_partition_digests_recursive(&chained_image_path(path, &partition_name), entries)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn chained_image_path(parent_image: &Path, partition_name: &str) -> PathBuf {
    let image_dir = parent_image.parent().unwrap_or_else(|| Path::new("."));
    let extension = parent_image
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext))
        .unwrap_or_else(|| ".img".to_string());
    image_dir.join(format!("{}{}", partition_name, extension))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{:02x}", byte);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{VbmetaImageArgs, make_vbmeta_image};
    use tempfile::tempdir;

    #[test]
    fn calculate_vbmeta_digest_returns_sha256() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("vbmeta.img");
        let args = VbmetaImageArgs {
            algorithm_name: "SHA256_RSA2048".to_string(),
            key_spec: Some("testkey_rsa2048".to_string()),
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
        make_vbmeta_image(&output, &args).unwrap();
        let digest = calculate_vbmeta_digest(&output, "sha256").unwrap();
        assert_eq!(digest.len(), 32);
    }
}
