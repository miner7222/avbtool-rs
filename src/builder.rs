use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use byteorder::{BigEndian, WriteBytesExt};

use crate::crypto::{
    compute_hash_for_algorithm, load_key_from_spec, lookup_algorithm_by_name, round_to_multiple,
};
use crate::error::{AvbToolError as DynoError, Result};
use crate::image::{
    default_vbmeta_header, encode_footer, encode_header, extract_public_key_metadata,
    inspect_avb_image, load_vbmeta_blob,
};
use crate::info::DescriptorInfo;
use crate::parser::{AVB_FOOTER_SIZE, AvbFooter, AvbImageType, detect_avb_image_type};

const DESCRIPTOR_HEADER_SIZE: usize = 16;
const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const HASHTREE_DESCRIPTOR_SIZE: usize = 180;
const HASH_DESCRIPTOR_SIZE: usize = 132;
const KERNEL_CMDLINE_DESCRIPTOR_SIZE: usize = 24;
const CHAIN_PARTITION_DESCRIPTOR_SIZE: usize = 92;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertySpec {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPartitionSpec {
    pub partition_name: String,
    pub rollback_index_location: u32,
    pub public_key: Vec<u8>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VbmetaImageArgs {
    pub algorithm_name: String,
    pub key_spec: Option<String>,
    pub public_key_metadata: Option<Vec<u8>>,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub properties: Vec<PropertySpec>,
    pub kernel_cmdlines: Vec<String>,
    pub extra_descriptors: Vec<DescriptorInfo>,
    pub include_descriptors_from_images: Vec<PathBuf>,
    pub chain_partitions: Vec<ChainPartitionSpec>,
    pub release_string: Option<String>,
    pub append_to_release_string: Option<String>,
    pub padding_size: u64,
}

pub fn make_vbmeta_image(output: &Path, args: &VbmetaImageArgs) -> Result<()> {
    let blob = build_vbmeta_blob(args)?;
    let mut file = File::create(output)?;
    file.write_all(&blob)?;
    if args.padding_size > 0 {
        let padded_size = round_to_multiple(blob.len() as u64, args.padding_size) as usize;
        if padded_size > blob.len() {
            file.write_all(&vec![0u8; padded_size - blob.len()])?;
        }
    }
    Ok(())
}

pub fn rebuild_vbmeta_image(
    output_path: &Path,
    original_vbmeta_path: &Path,
    chained_images: &[&Path],
    key_spec: &str,
    algorithm_name: Option<&str>,
) -> Result<()> {
    rebuild_vbmeta_image_with_overrides(
        output_path,
        original_vbmeta_path,
        chained_images,
        key_spec,
        algorithm_name,
        None,
        None,
    )
}

pub fn rebuild_vbmeta_image_with_overrides(
    output_path: &Path,
    original_vbmeta_path: &Path,
    chained_images: &[&Path],
    key_spec: &str,
    algorithm_name: Option<&str>,
    rollback_index: Option<u64>,
    flags: Option<u32>,
) -> Result<()> {
    let original_info = inspect_avb_image(original_vbmeta_path)?;
    let original_blob = load_vbmeta_blob(original_vbmeta_path)?;
    let pkmd = extract_public_key_metadata(&original_info.header, &original_blob)?;

    let mut descriptors = original_info.descriptors.clone();
    let replacement_map = build_descriptor_replacement_map(chained_images)?;
    replace_descriptors_from_images(&mut descriptors, &replacement_map);

    let args = VbmetaImageArgs {
        algorithm_name: algorithm_name.map(str::to_string).unwrap_or_else(|| {
            load_key_from_spec(key_spec)
                .and_then(|key| key.algorithm())
                .unwrap_or_else(|_| "SHA256_RSA2048".to_string())
        }),
        key_spec: Some(key_spec.to_string()),
        public_key_metadata: Some(pkmd),
        rollback_index: rollback_index.unwrap_or(original_info.header.rollback_index),
        flags: flags.unwrap_or(original_info.header.flags),
        rollback_index_location: original_info.header.rollback_index_location,
        properties: collect_properties(&descriptors),
        kernel_cmdlines: collect_kernel_cmdlines(&descriptors),
        extra_descriptors: collect_extra_descriptors(&descriptors),
        include_descriptors_from_images: Vec::new(),
        chain_partitions: collect_chain_partitions(&descriptors),
        release_string: Some(original_info.header.release_string.clone()),
        append_to_release_string: None,
        padding_size: 0,
    };

    let blob = build_vbmeta_blob_from_descriptors(&args, descriptors)?;
    fs::write(output_path, blob)?;
    Ok(())
}

pub fn append_vbmeta_image(
    image_filename: &Path,
    vbmeta_image_filename: &Path,
    partition_size: u64,
) -> Result<()> {
    let block_size = 4096u64;
    if partition_size % block_size != 0 {
        return Err(DynoError::Validation(format!(
            "Partition size of {} is not a multiple of the image block size {}.",
            partition_size, block_size
        )));
    }

    let vbmeta_blob = load_vbmeta_blob(vbmeta_image_filename)?;
    let mut image = OpenOptions::new().read(true).write(true).open(image_filename)?;

    let original_size = if image.metadata()?.len() >= AVB_FOOTER_SIZE {
        match detect_avb_image_type(image_filename)? {
            AvbImageType::Footer => {
                image.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
                let footer = AvbFooter::from_reader(&mut image)?;
                image.set_len(footer.original_image_size)?;
                footer.original_image_size
            }
            _ => image.metadata()?.len(),
        }
    } else {
        image.metadata()?.len()
    };

    let current_size = image.metadata()?.len();
    let aligned_size = round_to_multiple(current_size, block_size);
    if aligned_size != current_size {
        image.set_len(aligned_size)?;
    }

    let vbmeta_offset = aligned_size;
    let vbmeta_padded_size = round_to_multiple(vbmeta_blob.len() as u64, block_size);
    let footer_offset = partition_size
        .checked_sub(AVB_FOOTER_SIZE)
        .ok_or_else(|| DynoError::Validation("Partition size too small for AVB footer".into()))?;
    if vbmeta_offset + vbmeta_padded_size > footer_offset {
        return Err(DynoError::Validation(format!(
            "Partition too small: need {} bytes before footer, have {}",
            vbmeta_offset + vbmeta_padded_size,
            footer_offset
        )));
    }

    image.set_len(partition_size)?;
    image.seek(SeekFrom::Start(vbmeta_offset))?;
    image.write_all(&vbmeta_blob)?;
    if vbmeta_padded_size > vbmeta_blob.len() as u64 {
        image.write_all(&vec![0u8; (vbmeta_padded_size - vbmeta_blob.len() as u64) as usize])?;
    }

    let footer = AvbFooter {
        magic: *b"AVBf",
        version_major: 1,
        version_minor: 0,
        original_image_size: original_size,
        vbmeta_offset,
        vbmeta_size: vbmeta_blob.len() as u64,
    };
    image.seek(SeekFrom::Start(footer_offset))?;
    image.write_all(&encode_footer(&footer))?;
    Ok(())
}

pub fn build_vbmeta_blob(args: &VbmetaImageArgs) -> Result<Vec<u8>> {
    let descriptors = build_descriptor_list(args)?;
    build_vbmeta_blob_from_descriptors(args, descriptors)
}

fn build_vbmeta_blob_from_descriptors(
    args: &VbmetaImageArgs,
    mut descriptors: Vec<DescriptorInfo>,
) -> Result<Vec<u8>> {
    let algorithm = lookup_algorithm_by_name(&args.algorithm_name)?;
    let key = match algorithm.name {
        "NONE" => {
            if args.key_spec.is_some() {
                return Err(DynoError::Validation(
                    "Algorithm NONE cannot be used with a signing key.".into(),
                ));
            }
            None
        }
        _ => Some(load_key_from_spec(args.key_spec.as_deref().ok_or_else(|| {
            DynoError::Validation("Signing key required for selected algorithm.".into())
        })?)?),
    };

    descriptors.sort_by_key(descriptor_sort_key);
    let encoded_descriptors = descriptors
        .iter()
        .map(encode_descriptor)
        .collect::<Result<Vec<_>>>()?
        .concat();

    let encoded_public_key = key
        .as_ref()
        .map(|key| key.encode_public_key())
        .unwrap_or_default();
    let pkmd = args.public_key_metadata.clone().unwrap_or_default();

    let mut header = default_vbmeta_header();
    header.required_libavb_version_minor = required_libavb_minor(args);
    header.algorithm_type = algorithm.algorithm_type;
    header.hash_size = algorithm.hash_num_bytes as u64;
    header.signature_offset = algorithm.hash_num_bytes as u64;
    header.signature_size = algorithm.signature_num_bytes as u64;
    header.public_key_offset = encoded_descriptors.len() as u64;
    header.public_key_size = encoded_public_key.len() as u64;
    // Always set offset to computed position (matching AOSP avbtool.py behavior),
    // even when metadata is empty. libavb ignores offset when size=0.
    header.public_key_metadata_offset =
        (encoded_descriptors.len() + encoded_public_key.len()) as u64;
    header.public_key_metadata_size = pkmd.len() as u64;
    header.descriptors_size = encoded_descriptors.len() as u64;
    header.rollback_index = args.rollback_index;
    header.flags = args.flags;
    header.rollback_index_location = args.rollback_index_location;
    if let Some(release) = &args.release_string {
        header.release_string = release.clone();
    }
    if let Some(suffix) = &args.append_to_release_string {
        header.release_string.push(' ');
        header.release_string.push_str(suffix);
    }

    let mut aux = Vec::new();
    aux.extend_from_slice(&encoded_descriptors);
    aux.extend_from_slice(&encoded_public_key);
    aux.extend_from_slice(&pkmd);
    aux.resize(round_to_multiple(aux.len() as u64, 64) as usize, 0);
    header.auxiliary_data_block_size = aux.len() as u64;

    let auth_size = round_to_multiple(
        (algorithm.hash_num_bytes + algorithm.signature_num_bytes) as u64,
        64,
    ) as usize;
    header.authentication_data_block_size = auth_size as u64;
    let header_bytes = encode_header(&header);

    let mut data_to_sign = header_bytes.clone();
    data_to_sign.extend_from_slice(&aux);
    let hash = compute_hash_for_algorithm(algorithm, &data_to_sign)?;
    let signature = if let Some(key) = key {
        key.sign(&data_to_sign, algorithm.name)?
    } else {
        Vec::new()
    };

    let mut auth = Vec::new();
    auth.extend_from_slice(&hash);
    auth.extend_from_slice(&signature);
    auth.resize(auth_size, 0);

    let mut blob = header_bytes;
    blob.extend_from_slice(&auth);
    blob.extend_from_slice(&aux);
    Ok(blob)
}

fn build_descriptor_list(args: &VbmetaImageArgs) -> Result<Vec<DescriptorInfo>> {
    let mut descriptors = Vec::new();

    for property in &args.properties {
        descriptors.push(DescriptorInfo::Property {
            key: property.key.clone(),
            value: property.value.clone(),
        });
    }

    for cmdline in &args.kernel_cmdlines {
        descriptors.push(DescriptorInfo::KernelCmdline {
            flags: 0,
            kernel_cmdline: cmdline.clone(),
        });
    }

    descriptors.extend(args.extra_descriptors.clone());

    let mut chains = args.chain_partitions.clone();
    chains.sort_by(|left, right| left.partition_name.cmp(&right.partition_name));
    for chain in chains {
        descriptors.push(DescriptorInfo::ChainPartition {
            rollback_index_location: chain.rollback_index_location,
            partition_name: chain.partition_name,
            public_key: chain.public_key,
            flags: chain.flags,
        });
    }

    // Collect descriptors from included images with deduplication by partition_name.
    // Matches avbtool.py behavior: last image wins for same partition_name.
    // Descriptors without partition_name (e.g. Property) are always appended.
    let mut named_descriptors: std::collections::BTreeMap<String, DescriptorInfo> =
        std::collections::BTreeMap::new();
    let mut unnamed_descriptors: Vec<DescriptorInfo> = Vec::new();

    for path in &args.include_descriptors_from_images {
        let info = inspect_avb_image(path)?;
        for desc in info.descriptors {
            if let Some(key) = descriptor_dedup_key(&desc) {
                named_descriptors.insert(key, desc);
            } else {
                unnamed_descriptors.push(desc);
            }
        }
    }

    // Unnamed descriptors first (Property etc.), then named in sorted key order
    descriptors.extend(unnamed_descriptors);
    descriptors.extend(named_descriptors.into_values());

    Ok(descriptors)
}

/// Build dedup key matching avbtool.py: `TypeName_partition_name`.
/// Returns None for descriptors without partition_name (Property, KernelCmdline, Unknown).
fn descriptor_dedup_key(desc: &DescriptorInfo) -> Option<String> {
    match desc {
        DescriptorInfo::Hash { partition_name, .. } => Some(format!("Hash_{partition_name}")),
        DescriptorInfo::Hashtree { partition_name, .. } => {
            Some(format!("Hashtree_{partition_name}"))
        }
        DescriptorInfo::ChainPartition { partition_name, .. } => {
            Some(format!("ChainPartition_{partition_name}"))
        }
        DescriptorInfo::Property { .. }
        | DescriptorInfo::KernelCmdline { .. }
        | DescriptorInfo::Unknown { .. } => None,
    }
}

fn collect_properties(descriptors: &[DescriptorInfo]) -> Vec<PropertySpec> {
    descriptors
        .iter()
        .filter_map(|descriptor| match descriptor {
            DescriptorInfo::Property { key, value } => Some(PropertySpec {
                key: key.clone(),
                value: value.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn collect_kernel_cmdlines(descriptors: &[DescriptorInfo]) -> Vec<String> {
    descriptors
        .iter()
        .filter_map(|descriptor| match descriptor {
            DescriptorInfo::KernelCmdline { kernel_cmdline, .. } => Some(kernel_cmdline.clone()),
            _ => None,
        })
        .collect()
}

fn collect_chain_partitions(descriptors: &[DescriptorInfo]) -> Vec<ChainPartitionSpec> {
    descriptors
        .iter()
        .filter_map(|descriptor| match descriptor {
            DescriptorInfo::ChainPartition {
                rollback_index_location,
                partition_name,
                public_key,
                flags,
            } => Some(ChainPartitionSpec {
                partition_name: partition_name.clone(),
                rollback_index_location: *rollback_index_location,
                public_key: public_key.clone(),
                flags: *flags,
            }),
            _ => None,
        })
        .collect()
}

fn collect_extra_descriptors(descriptors: &[DescriptorInfo]) -> Vec<DescriptorInfo> {
    descriptors
        .iter()
        .filter_map(|descriptor| match descriptor {
            DescriptorInfo::Hash { .. }
            | DescriptorInfo::Hashtree { .. }
            | DescriptorInfo::Unknown { .. } => Some(descriptor.clone()),
            _ => None,
        })
        .collect()
}

fn build_descriptor_replacement_map(images: &[&Path]) -> Result<BTreeMap<String, DescriptorInfo>> {
    let mut map = BTreeMap::new();
    for image in images {
        let info = inspect_avb_image(image)?;
        for descriptor in info.descriptors {
            match &descriptor {
                DescriptorInfo::Hash { partition_name, .. }
                | DescriptorInfo::Hashtree { partition_name, .. } => {
                    map.insert(partition_name.clone(), descriptor.clone());
                }
                _ => {}
            }
        }
    }
    Ok(map)
}

fn replace_descriptors_from_images(
    descriptors: &mut [DescriptorInfo],
    replacements: &BTreeMap<String, DescriptorInfo>,
) {
    for descriptor in descriptors {
        match descriptor {
            DescriptorInfo::Hash { partition_name, .. }
            | DescriptorInfo::Hashtree { partition_name, .. } => {
                if let Some(replacement) = replacements.get(partition_name) {
                    *descriptor = replacement.clone();
                }
            }
            _ => {}
        }
    }
}

fn descriptor_sort_key(descriptor: &DescriptorInfo) -> (u8, String) {
    match descriptor {
        DescriptorInfo::ChainPartition { partition_name, .. } => (0, partition_name.clone()),
        DescriptorInfo::Hash { partition_name, .. } => (1, partition_name.clone()),
        DescriptorInfo::Hashtree { partition_name, .. } => (2, partition_name.clone()),
        DescriptorInfo::KernelCmdline { kernel_cmdline, .. } => (3, kernel_cmdline.clone()),
        DescriptorInfo::Property { key, .. } => (4, key.clone()),
        DescriptorInfo::Unknown { tag, .. } => (5, format!("{tag:020}")),
    }
}

fn encode_descriptor(descriptor: &DescriptorInfo) -> Result<Vec<u8>> {
    match descriptor {
        DescriptorInfo::Property { key, value } => encode_property_descriptor(key, value),
        DescriptorInfo::Hashtree {
            dm_verity_version,
            image_size,
            tree_offset,
            tree_size,
            data_block_size,
            hash_block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            flags,
        } => encode_hashtree_descriptor(
            *dm_verity_version,
            *image_size,
            *tree_offset,
            *tree_size,
            *data_block_size,
            *hash_block_size,
            *fec_num_roots,
            *fec_offset,
            *fec_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            *flags,
        ),
        DescriptorInfo::Hash {
            image_size,
            hash_algorithm,
            partition_name,
            salt,
            digest,
            flags,
        } => encode_hash_descriptor(
            *image_size,
            hash_algorithm,
            partition_name,
            salt,
            digest,
            *flags,
        ),
        DescriptorInfo::KernelCmdline {
            flags,
            kernel_cmdline,
        } => encode_kernel_cmdline_descriptor(*flags, kernel_cmdline),
        DescriptorInfo::ChainPartition {
            rollback_index_location,
            partition_name,
            public_key,
            flags,
        } => encode_chain_partition_descriptor(
            *rollback_index_location,
            partition_name,
            public_key,
            *flags,
        ),
        DescriptorInfo::Unknown {
            tag,
            num_bytes_following,
            body,
        } => {
            let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + body.len());
            out.write_u64::<BigEndian>(*tag)?;
            out.write_u64::<BigEndian>(*num_bytes_following)?;
            out.extend_from_slice(body);
            Ok(out)
        }
    }
}

fn encode_property_descriptor(key: &str, value: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = key.as_bytes();
    let body_size =
        PROPERTY_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE + key_bytes.len() + 1 + value.len() + 1;
    let padded = round_to_multiple(body_size as u64, 8) as usize;
    let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
    out.write_u64::<BigEndian>(0)?;
    out.write_u64::<BigEndian>(padded as u64)?;
    out.write_u64::<BigEndian>(key_bytes.len() as u64)?;
    out.write_u64::<BigEndian>(value.len() as u64)?;
    out.extend_from_slice(key_bytes);
    out.push(0);
    out.extend_from_slice(value);
    out.push(0);
    out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn encode_hashtree_descriptor(
    dm_verity_version: u32,
    image_size: u64,
    tree_offset: u64,
    tree_size: u64,
    data_block_size: u32,
    hash_block_size: u32,
    fec_num_roots: u32,
    fec_offset: u64,
    fec_size: u64,
    hash_algorithm: &str,
    partition_name: &str,
    salt: &[u8],
    root_digest: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    let partition_name_bytes = partition_name.as_bytes();
    let body_size = HASHTREE_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE
        + partition_name_bytes.len()
        + salt.len()
        + root_digest.len();
    let padded = round_to_multiple(body_size as u64, 8) as usize;
    let mut hash_algorithm_buf = [0u8; 32];
    let hash_algorithm_bytes = hash_algorithm.as_bytes();
    let copy_len = hash_algorithm_bytes.len().min(32);
    hash_algorithm_buf[..copy_len].copy_from_slice(&hash_algorithm_bytes[..copy_len]);

    let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
    out.write_u64::<BigEndian>(1)?;
    out.write_u64::<BigEndian>(padded as u64)?;
    out.write_u32::<BigEndian>(dm_verity_version)?;
    out.write_u64::<BigEndian>(image_size)?;
    out.write_u64::<BigEndian>(tree_offset)?;
    out.write_u64::<BigEndian>(tree_size)?;
    out.write_u32::<BigEndian>(data_block_size)?;
    out.write_u32::<BigEndian>(hash_block_size)?;
    out.write_u32::<BigEndian>(fec_num_roots)?;
    out.write_u64::<BigEndian>(fec_offset)?;
    out.write_u64::<BigEndian>(fec_size)?;
    out.extend_from_slice(&hash_algorithm_buf);
    out.write_u32::<BigEndian>(partition_name_bytes.len() as u32)?;
    out.write_u32::<BigEndian>(salt.len() as u32)?;
    out.write_u32::<BigEndian>(root_digest.len() as u32)?;
    out.write_u32::<BigEndian>(flags)?;
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(partition_name_bytes);
    out.extend_from_slice(salt);
    out.extend_from_slice(root_digest);
    out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
    Ok(out)
}

fn encode_hash_descriptor(
    image_size: u64,
    hash_algorithm: &str,
    partition_name: &str,
    salt: &[u8],
    digest: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    let partition_name_bytes = partition_name.as_bytes();
    let body_size = HASH_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE
        + partition_name_bytes.len()
        + salt.len()
        + digest.len();
    let padded = round_to_multiple(body_size as u64, 8) as usize;
    let mut hash_algorithm_buf = [0u8; 32];
    let hash_algorithm_bytes = hash_algorithm.as_bytes();
    let copy_len = hash_algorithm_bytes.len().min(32);
    hash_algorithm_buf[..copy_len].copy_from_slice(&hash_algorithm_bytes[..copy_len]);

    let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
    out.write_u64::<BigEndian>(2)?;
    out.write_u64::<BigEndian>(padded as u64)?;
    out.write_u64::<BigEndian>(image_size)?;
    out.extend_from_slice(&hash_algorithm_buf);
    out.write_u32::<BigEndian>(partition_name_bytes.len() as u32)?;
    out.write_u32::<BigEndian>(salt.len() as u32)?;
    out.write_u32::<BigEndian>(digest.len() as u32)?;
    out.write_u32::<BigEndian>(flags)?;
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(partition_name_bytes);
    out.extend_from_slice(salt);
    out.extend_from_slice(digest);
    out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
    Ok(out)
}

fn encode_kernel_cmdline_descriptor(flags: u32, kernel_cmdline: &str) -> Result<Vec<u8>> {
    let kernel_cmdline_bytes = kernel_cmdline.as_bytes();
    let body_size =
        KERNEL_CMDLINE_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE + kernel_cmdline_bytes.len();
    let padded = round_to_multiple(body_size as u64, 8) as usize;
    let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
    out.write_u64::<BigEndian>(3)?;
    out.write_u64::<BigEndian>(padded as u64)?;
    out.write_u32::<BigEndian>(flags)?;
    out.write_u32::<BigEndian>(kernel_cmdline_bytes.len() as u32)?;
    out.extend_from_slice(kernel_cmdline_bytes);
    out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
    Ok(out)
}

fn encode_chain_partition_descriptor(
    rollback_index_location: u32,
    partition_name: &str,
    public_key: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    let partition_name_bytes = partition_name.as_bytes();
    let body_size = CHAIN_PARTITION_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE
        + partition_name_bytes.len()
        + public_key.len();
    let padded = round_to_multiple(body_size as u64, 8) as usize;
    let mut out = Vec::with_capacity(DESCRIPTOR_HEADER_SIZE + padded);
    out.write_u64::<BigEndian>(4)?;
    out.write_u64::<BigEndian>(padded as u64)?;
    out.write_u32::<BigEndian>(rollback_index_location)?;
    out.write_u32::<BigEndian>(partition_name_bytes.len() as u32)?;
    out.write_u32::<BigEndian>(public_key.len() as u32)?;
    out.write_u32::<BigEndian>(flags)?;
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(partition_name_bytes);
    out.extend_from_slice(public_key);
    out.resize(DESCRIPTOR_HEADER_SIZE + padded, 0);
    Ok(out)
}

fn required_libavb_minor(args: &VbmetaImageArgs) -> u32 {
    let mut required_minor = 0u32;
    if args.rollback_index_location > 0 {
        required_minor = required_minor.max(2);
    }
    if args.chain_partitions.iter().any(|chain| (chain.flags & 1) != 0) {
        required_minor = required_minor.max(3);
    }
    for path in &args.include_descriptors_from_images {
        if let Ok(info) = inspect_avb_image(path) {
            required_minor = required_minor.max(info.header.required_libavb_version_minor);
        }
    }
    required_minor
}

pub fn required_libavb_minor_for_args(args: &VbmetaImageArgs) -> u32 {
    required_libavb_minor(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn make_vbmeta_image_writes_signed_blob() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("vbmeta.img");
        let args = VbmetaImageArgs {
            algorithm_name: "SHA256_RSA2048".to_string(),
            key_spec: Some("testkey_rsa2048".to_string()),
            public_key_metadata: None,
            rollback_index: 7,
            flags: 0,
            rollback_index_location: 0,
            properties: vec![PropertySpec {
                key: "com.android.test".to_string(),
                value: b"value".to_vec(),
            }],
            kernel_cmdlines: vec!["console=ttyS0".to_string()],
            extra_descriptors: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            chain_partitions: Vec::new(),
            release_string: Some("avbtool-rs test".to_string()),
            append_to_release_string: None,
            padding_size: 0,
        };

        make_vbmeta_image(&output, &args).unwrap();
        let info = inspect_avb_image(&output).unwrap();
        assert_eq!(info.header.algorithm_type, 1);
        assert_eq!(info.header.rollback_index, 7);
    }
}
