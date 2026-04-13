use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use blake2::Blake2bVar;
use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

use crate::builder::{ChainPartitionSpec, PropertySpec, VbmetaImageArgs, build_vbmeta_blob};
use crate::crypto::{round_to_multiple, round_to_pow2};
use crate::error::{AvbToolError as DynoError, Result};
use crate::image::inspect_avb_image;
use crate::info::DescriptorInfo;
use crate::parser::{AVB_FOOTER_SIZE, AvbFooter, AvbImageType, detect_avb_image_type};

const DEFAULT_BLOCK_SIZE: u64 = 4096;
const ZERO_HASHTREE_MAGIC: &[u8; 8] = b"ZeRoHaSH";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashFooterArgs {
    pub partition_size: Option<u64>,
    pub dynamic_partition_size: bool,
    pub partition_name: String,
    pub hash_algorithm: String,
    pub salt: Option<Vec<u8>>,
    pub chain_partitions: Vec<ChainPartitionSpec>,
    pub algorithm_name: String,
    pub key_spec: Option<String>,
    pub public_key_metadata: Option<Vec<u8>>,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub properties: Vec<PropertySpec>,
    pub kernel_cmdlines: Vec<String>,
    pub include_descriptors_from_images: Vec<PathBuf>,
    pub release_string: Option<String>,
    pub append_to_release_string: Option<String>,
    pub output_vbmeta_image: Option<PathBuf>,
    pub do_not_append_vbmeta_image: bool,
    pub use_persistent_digest: bool,
    pub do_not_use_ab: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashtreeFooterArgs {
    pub partition_size: Option<u64>,
    pub partition_name: String,
    pub hash_algorithm: String,
    pub block_size: u32,
    pub salt: Option<Vec<u8>>,
    pub chain_partitions: Vec<ChainPartitionSpec>,
    pub algorithm_name: String,
    pub key_spec: Option<String>,
    pub public_key_metadata: Option<Vec<u8>>,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub properties: Vec<PropertySpec>,
    pub kernel_cmdlines: Vec<String>,
    pub include_descriptors_from_images: Vec<PathBuf>,
    pub release_string: Option<String>,
    pub append_to_release_string: Option<String>,
    pub output_vbmeta_image: Option<PathBuf>,
    pub do_not_append_vbmeta_image: bool,
    pub use_persistent_root_digest: bool,
    pub do_not_use_ab: bool,
    pub no_hashtree: bool,
    pub check_at_most_once: bool,
    pub generate_fec: bool,
}

pub fn add_hash_footer(image_filename: &Path, args: &HashFooterArgs) -> Result<()> {
    if args.partition_size.is_none() && !args.dynamic_partition_size {
        return Err(DynoError::Validation(
            "partition_size or dynamic_partition_size is required.".into(),
        ));
    }

    let block_size = DEFAULT_BLOCK_SIZE;
    let mut file = OpenOptions::new()
        .read(true)
        .write(!args.do_not_append_vbmeta_image)
        .open(image_filename)?;
    let existing_footer = existing_footer(&mut file, image_filename)?;
    let original_size = existing_footer
        .as_ref()
        .map(|footer| footer.original_image_size)
        .unwrap_or(file.metadata()?.len());
    let digest_size = hash_digest_size(&args.hash_algorithm)? as u64;
    let salt = args
        .salt
        .clone()
        .unwrap_or(if args.use_persistent_digest {
            Vec::new()
        } else {
            random_bytes(digest_size as usize)?
        });
    let digest = if args.use_persistent_digest {
        Vec::new()
    } else {
        hash_file_prefix(image_filename, original_size, &args.hash_algorithm, &salt)?
    };

    let mut descriptor_flags = 0u32;
    if args.do_not_use_ab {
        descriptor_flags |= 1;
    }

    let vbmeta_args = VbmetaImageArgs {
        algorithm_name: args.algorithm_name.clone(),
        key_spec: args.key_spec.clone(),
        public_key_metadata: args.public_key_metadata.clone(),
        rollback_index: args.rollback_index,
        flags: args.flags,
        rollback_index_location: args.rollback_index_location,
        properties: args.properties.clone(),
        kernel_cmdlines: args.kernel_cmdlines.clone(),
        extra_descriptors: vec![DescriptorInfo::Hash {
            image_size: original_size,
            hash_algorithm: args.hash_algorithm.clone(),
            partition_name: args.partition_name.clone(),
            salt,
            digest,
            flags: descriptor_flags,
        }],
        include_descriptors_from_images: args.include_descriptors_from_images.clone(),
        chain_partitions: args.chain_partitions.clone(),
        release_string: args.release_string.clone(),
        append_to_release_string: args.append_to_release_string.clone(),
        padding_size: 0,
    };
    let vbmeta_blob = build_vbmeta_blob(&vbmeta_args)?;

    if let Some(path) = &args.output_vbmeta_image {
        write_blob(path, &vbmeta_blob)?;
    }
    if args.do_not_append_vbmeta_image {
        return Ok(());
    }

    let aligned_original_size = round_to_multiple(original_size, block_size);
    let vbmeta_padded_size = round_to_multiple(vbmeta_blob.len() as u64, block_size);
    let partition_size = if args.dynamic_partition_size {
        round_to_multiple(
            aligned_original_size + vbmeta_padded_size + block_size,
            block_size,
        )
    } else {
        args.partition_size.unwrap_or_default()
    };
    if partition_size % block_size != 0 {
        return Err(DynoError::Validation(format!(
            "Partition size {} is not a multiple of {}",
            partition_size, block_size
        )));
    }

    let footer_start = partition_size
        .checked_sub(AVB_FOOTER_SIZE)
        .ok_or_else(|| DynoError::Validation("Partition too small for footer".into()))?;
    let minimum_partition_size = aligned_original_size + vbmeta_padded_size + block_size;
    if partition_size < minimum_partition_size {
        return Err(DynoError::Validation(format!(
            "Partition size {} too small; need at least {} bytes",
            partition_size, minimum_partition_size
        )));
    }

    file.set_len(original_size)?;
    if aligned_original_size > original_size {
        zero_fill(&mut file, original_size, aligned_original_size - original_size)?;
    }

    let vbmeta_offset = aligned_original_size;
    write_padded_blob(&mut file, vbmeta_offset, &vbmeta_blob, vbmeta_padded_size)?;
    if footer_start > vbmeta_offset + vbmeta_padded_size {
        zero_fill(
            &mut file,
            vbmeta_offset + vbmeta_padded_size,
            footer_start - (vbmeta_offset + vbmeta_padded_size),
        )?;
    }
    file.set_len(partition_size)?;
    write_footer(
        &mut file,
        footer_start,
        original_size,
        vbmeta_offset,
        vbmeta_blob.len() as u64,
    )?;
    Ok(())
}

pub fn add_hashtree_footer(image_filename: &Path, args: &HashtreeFooterArgs) -> Result<()> {
    if args.generate_fec {
        return Err(DynoError::UnsupportedOperation(
            "Pure Rust FEC generation is not implemented yet.".into(),
        ));
    }
    let block_size = args.block_size as u64;
    let mut file = OpenOptions::new()
        .read(true)
        .write(!args.do_not_append_vbmeta_image)
        .open(image_filename)?;
    let existing_footer = existing_footer(&mut file, image_filename)?;
    let original_size = existing_footer
        .as_ref()
        .map(|footer| footer.original_image_size)
        .unwrap_or(file.metadata()?.len());
    let aligned_image_size = round_to_multiple(original_size, block_size);
    let digest_size = hash_digest_size(&args.hash_algorithm)?;
    let digest_padding = round_to_pow2(digest_size) - digest_size;
    let salt = args
        .salt
        .clone()
        .unwrap_or(if args.use_persistent_root_digest {
            Vec::new()
        } else {
            random_bytes(digest_size)?
        });
    let (hash_level_offsets, mut tree_size) =
        calc_hash_level_offsets(aligned_image_size, block_size, (digest_size + digest_padding) as u64);
    let (root_digest, mut hash_tree) = generate_hash_tree(
        image_filename,
        aligned_image_size,
        args.block_size,
        &args.hash_algorithm,
        &salt,
        digest_padding,
        &hash_level_offsets,
        tree_size,
    )?;
    let tree_offset = aligned_image_size;
    if args.no_hashtree {
        tree_size = 0;
        hash_tree.clear();
    }

    let mut descriptor_flags = 0u32;
    if args.do_not_use_ab {
        descriptor_flags |= 1;
    }
    if args.check_at_most_once {
        descriptor_flags |= 1 << 1;
    }

    let vbmeta_args = VbmetaImageArgs {
        algorithm_name: args.algorithm_name.clone(),
        key_spec: args.key_spec.clone(),
        public_key_metadata: args.public_key_metadata.clone(),
        rollback_index: args.rollback_index,
        flags: args.flags,
        rollback_index_location: args.rollback_index_location,
        properties: args.properties.clone(),
        kernel_cmdlines: args.kernel_cmdlines.clone(),
        extra_descriptors: vec![DescriptorInfo::Hashtree {
            dm_verity_version: 1,
            image_size: aligned_image_size,
            tree_offset,
            tree_size,
            data_block_size: args.block_size,
            hash_block_size: args.block_size,
            fec_num_roots: 0,
            fec_offset: 0,
            fec_size: 0,
            hash_algorithm: args.hash_algorithm.clone(),
            partition_name: args.partition_name.clone(),
            salt,
            root_digest: if args.use_persistent_root_digest {
                Vec::new()
            } else {
                root_digest
            },
            flags: descriptor_flags,
        }],
        include_descriptors_from_images: args.include_descriptors_from_images.clone(),
        chain_partitions: args.chain_partitions.clone(),
        release_string: args.release_string.clone(),
        append_to_release_string: args.append_to_release_string.clone(),
        padding_size: 0,
    };
    let vbmeta_blob = build_vbmeta_blob(&vbmeta_args)?;

    if let Some(path) = &args.output_vbmeta_image {
        write_blob(path, &vbmeta_blob)?;
    }
    if args.do_not_append_vbmeta_image {
        return Ok(());
    }

    let hash_tree_padded_size = round_to_multiple(hash_tree.len() as u64, DEFAULT_BLOCK_SIZE);
    let vbmeta_padded_size = round_to_multiple(vbmeta_blob.len() as u64, DEFAULT_BLOCK_SIZE);
    let partition_size = args.partition_size.unwrap_or(
        aligned_image_size + hash_tree_padded_size + vbmeta_padded_size + DEFAULT_BLOCK_SIZE,
    );
    if partition_size % DEFAULT_BLOCK_SIZE != 0 {
        return Err(DynoError::Validation(format!(
            "Partition size {} is not a multiple of {}",
            partition_size, DEFAULT_BLOCK_SIZE
        )));
    }
    let footer_start = partition_size
        .checked_sub(AVB_FOOTER_SIZE)
        .ok_or_else(|| DynoError::Validation("Partition too small for footer".into()))?;
    let minimum_partition_size =
        aligned_image_size + hash_tree_padded_size + vbmeta_padded_size + DEFAULT_BLOCK_SIZE;
    if partition_size < minimum_partition_size {
        return Err(DynoError::Validation(format!(
            "Partition size {} too small; need at least {} bytes",
            partition_size, minimum_partition_size
        )));
    }

    file.set_len(original_size)?;
    if aligned_image_size > original_size {
        zero_fill(&mut file, original_size, aligned_image_size - original_size)?;
    }

    if hash_tree_padded_size > 0 {
        write_padded_blob(&mut file, tree_offset, &hash_tree, hash_tree_padded_size)?;
    }
    let vbmeta_offset = tree_offset + hash_tree_padded_size;
    write_padded_blob(&mut file, vbmeta_offset, &vbmeta_blob, vbmeta_padded_size)?;
    if footer_start > vbmeta_offset + vbmeta_padded_size {
        zero_fill(
            &mut file,
            vbmeta_offset + vbmeta_padded_size,
            footer_start - (vbmeta_offset + vbmeta_padded_size),
        )?;
    }
    file.set_len(partition_size)?;
    write_footer(
        &mut file,
        footer_start,
        original_size,
        vbmeta_offset,
        vbmeta_blob.len() as u64,
    )?;
    Ok(())
}

pub fn erase_footer(image_filename: &Path, keep_hashtree: bool) -> Result<()> {
    let info = inspect_avb_image(image_filename)?;
    let footer = info
        .footer
        .ok_or_else(|| DynoError::Validation("Given image does not have a footer.".into()))?;
    let new_size = if !keep_hashtree {
        footer.original_image_size
    } else {
        info.descriptors
            .iter()
            .find_map(|descriptor| match descriptor {
                DescriptorInfo::Hashtree {
                    tree_offset,
                    tree_size,
                    fec_offset,
                    fec_size,
                    ..
                } => {
                    let mut keep_end = tree_offset + tree_size;
                    if *fec_offset > 0 {
                        keep_end = keep_end.max(fec_offset + fec_size);
                    }
                    Some(keep_end)
                }
                _ => None,
            })
            .ok_or_else(|| {
                DynoError::Validation(
                    "Requested to keep hashtree but no hashtree descriptor was found.".into(),
                )
            })?
    };

    OpenOptions::new()
        .write(true)
        .open(image_filename)?
        .set_len(new_size)?;
    Ok(())
}

pub fn zero_hashtree(image_filename: &Path) -> Result<()> {
    let info = inspect_avb_image(image_filename)?;
    if info.footer.is_none() {
        return Err(DynoError::Validation(
            "Given image does not have a footer.".into(),
        ));
    }

    let descriptor = info
        .descriptors
        .iter()
        .find_map(|descriptor| match descriptor {
            DescriptorInfo::Hashtree {
                tree_offset,
                tree_size,
                fec_offset,
                fec_size,
                ..
            } => Some((*tree_offset, *tree_size, *fec_offset, *fec_size)),
            _ => None,
        })
        .ok_or_else(|| DynoError::Validation("No hashtree descriptor was found.".into()))?;
    let (tree_offset, tree_size, fec_offset, fec_size) = descriptor;
    if fec_offset > 0 && fec_offset != tree_offset + tree_size {
        return Err(DynoError::Validation(
            "Hash-tree and FEC data must be adjacent.".into(),
        ));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(image_filename)?;
    write_zeroed_region(&mut file, tree_offset, tree_size)?;
    if fec_offset > 0 && fec_size > 0 {
        write_zeroed_region(&mut file, fec_offset, fec_size)?;
    }
    Ok(())
}

pub fn resize_image(image_filename: &Path, partition_size: u64) -> Result<()> {
    if partition_size % DEFAULT_BLOCK_SIZE != 0 {
        return Err(DynoError::Validation(format!(
            "Partition size {} is not a multiple of {}",
            partition_size, DEFAULT_BLOCK_SIZE
        )));
    }

    let info = inspect_avb_image(image_filename)?;
    let footer = info
        .footer
        .ok_or_else(|| DynoError::Validation("Given image does not have a footer.".into()))?;
    let vbmeta_end_offset = round_to_multiple(footer.vbmeta_offset + footer.vbmeta_size, DEFAULT_BLOCK_SIZE);
    let minimum_partition_size = vbmeta_end_offset + DEFAULT_BLOCK_SIZE;
    if partition_size < minimum_partition_size {
        return Err(DynoError::Validation(format!(
            "Requested size {} too small; need at least {} bytes",
            partition_size, minimum_partition_size
        )));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(image_filename)?;
    file.set_len(partition_size)?;
    let footer_start = partition_size - AVB_FOOTER_SIZE;
    write_footer(
        &mut file,
        footer_start,
        footer.original_image_size,
        footer.vbmeta_offset,
        footer.vbmeta_size,
    )?;
    Ok(())
}

pub fn calc_hash_level_offsets(
    image_size: u64,
    block_size: u64,
    digest_size: u64,
) -> (Vec<u64>, u64) {
    let mut level_sizes = Vec::new();
    let mut tree_size = 0u64;
    let mut size = image_size;

    while size > block_size {
        let num_blocks = size.div_ceil(block_size);
        let level_size = round_to_multiple(num_blocks * digest_size, block_size);
        level_sizes.push(level_size);
        tree_size += level_size;
        size = level_size;
    }

    let mut level_offsets = Vec::with_capacity(level_sizes.len());
    for n in 0..level_sizes.len() {
        let offset = level_sizes[(n + 1)..].iter().sum();
        level_offsets.push(offset);
    }

    (level_offsets, tree_size)
}

pub fn generate_hash_tree(
    image_filename: &Path,
    image_size: u64,
    block_size: u32,
    hash_algorithm: &str,
    salt: &[u8],
    digest_padding: usize,
    hash_level_offsets: &[u64],
    tree_size: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut image = File::open(image_filename)?;
    generate_hash_tree_from_reader(
        &mut image,
        image_size,
        block_size,
        hash_algorithm,
        salt,
        digest_padding,
        hash_level_offsets,
        tree_size,
    )
}

pub(crate) fn generate_hash_tree_from_reader<R>(
    image: &mut R,
    image_size: u64,
    block_size: u32,
    hash_algorithm: &str,
    salt: &[u8],
    digest_padding: usize,
    hash_level_offsets: &[u64],
    tree_size: u64,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    R: Read + Seek,
{
    let block_size = block_size as usize;
    let mut hash_ret = vec![0u8; tree_size as usize];
    let mut hash_src_size = image_size as usize;
    let mut level_num = 0usize;

    if hash_src_size == block_size {
        let data = read_padded_block(image, 0, block_size, image_size)?;
        return Ok((hash_bytes(hash_algorithm, salt, &data)?, hash_ret));
    }

    let mut last_level_output = Vec::new();
    while hash_src_size > block_size {
        let mut level_output = Vec::new();
        let mut remaining = hash_src_size;
        while remaining > 0 {
            let data = if level_num == 0 {
                let read_offset = (hash_src_size - remaining) as u64;
                read_padded_block(image, read_offset, block_size, image_size)?
            } else {
                let offset = hash_level_offsets[level_num - 1] as usize + hash_src_size - remaining;
                let end = (offset + block_size).min(hash_ret.len());
                let mut block = hash_ret[offset..end].to_vec();
                block.resize(block_size, 0);
                block
            };
            let digest = hash_bytes(hash_algorithm, salt, &data)?;
            level_output.extend_from_slice(&digest);
            if digest_padding > 0 {
                level_output.extend(std::iter::repeat_n(0u8, digest_padding));
            }
            remaining = remaining.saturating_sub(block_size);
        }

        let padded_len = round_to_multiple(level_output.len() as u64, block_size as u64) as usize;
        level_output.resize(padded_len, 0);
        let offset = hash_level_offsets
            .get(level_num)
            .copied()
            .ok_or_else(|| DynoError::Validation("Missing hash level offset.".into()))?
            as usize;
        hash_ret[offset..offset + level_output.len()].copy_from_slice(&level_output);
        hash_src_size = level_output.len();
        level_num += 1;
        last_level_output = level_output;
    }

    Ok((hash_bytes(hash_algorithm, salt, &last_level_output)?, hash_ret))
}

pub fn hash_digest_size(hash_algorithm: &str) -> Result<usize> {
    match hash_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => Ok(20),
        "sha256" => Ok(32),
        "sha512" => Ok(64),
        "blake2b-256" => Ok(32),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported hash algorithm {}",
            other
        ))),
    }
}

pub fn parse_hex_string(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() % 2 != 0 {
        return Err(DynoError::Validation(format!(
            "Hex string must contain an even number of characters: {}",
            trimmed
        )));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let mut iter = trimmed.as_bytes().chunks_exact(2);
    for pair in &mut iter {
        let text = std::str::from_utf8(pair)
            .map_err(|error| DynoError::Validation(format!("Invalid hex string: {}", error)))?;
        out.push(u8::from_str_radix(text, 16).map_err(|error| {
            DynoError::Validation(format!("Invalid hex byte '{}': {}", text, error))
        })?);
    }
    Ok(out)
}

pub(crate) fn hash_file_prefix(
    image_filename: &Path,
    size: u64,
    hash_algorithm: &str,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let mut file = File::open(image_filename)?;
    match hash_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => {
            let mut hasher = Sha1::new();
            Sha1Digest::update(&mut hasher, salt);
            hash_reader_prefix(&mut file, size, &mut |chunk| Sha1Digest::update(&mut hasher, chunk))?;
            Ok(hasher.finalize().to_vec())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hash_reader_prefix(&mut file, size, &mut |chunk| hasher.update(chunk))?;
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(salt);
            hash_reader_prefix(&mut file, size, &mut |chunk| hasher.update(chunk))?;
            Ok(hasher.finalize().to_vec())
        }
        "blake2b-256" => {
            let mut hasher = Blake2bVar::new(32)
                .map_err(|error| DynoError::Tool(format!("Failed to init blake2b: {}", error)))?;
            hasher.update(salt);
            hash_reader_prefix(&mut file, size, &mut |chunk| hasher.update(chunk))?;
            let mut out = vec![0u8; 32];
            hasher
                .finalize_variable(&mut out)
                .map_err(|error| DynoError::Tool(format!("Failed to finalize blake2b: {}", error)))?;
            Ok(out)
        }
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported hash algorithm {}",
            other
        ))),
    }
}

pub(crate) fn hash_bytes(hash_algorithm: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match hash_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => {
            let mut hasher = Sha1::new();
            Sha1Digest::update(&mut hasher, salt);
            Sha1Digest::update(&mut hasher, data);
            Ok(hasher.finalize().to_vec())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(salt);
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "blake2b-256" => {
            let mut hasher = Blake2bVar::new(32)
                .map_err(|error| DynoError::Tool(format!("Failed to init blake2b: {}", error)))?;
            hasher.update(salt);
            hasher.update(data);
            let mut out = vec![0u8; 32];
            hasher
                .finalize_variable(&mut out)
                .map_err(|error| DynoError::Tool(format!("Failed to finalize blake2b: {}", error)))?;
            Ok(out)
        }
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported hash algorithm {}",
            other
        ))),
    }
}

fn existing_footer(file: &mut File, image_filename: &Path) -> Result<Option<AvbFooter>> {
    if file.metadata()?.len() < AVB_FOOTER_SIZE {
        return Ok(None);
    }
    if detect_avb_image_type(image_filename)? != AvbImageType::Footer {
        return Ok(None);
    }
    file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
    Ok(Some(AvbFooter::from_reader(file)?))
}

fn hash_reader_prefix<F>(file: &mut File, size: u64, update: &mut F) -> Result<()>
where
    F: FnMut(&[u8]),
{
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = size;
    let mut buffer = [0u8; 1024 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..chunk])?;
        update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(())
}

fn read_padded_block<R>(
    reader: &mut R,
    offset: u64,
    block_size: usize,
    file_size: u64,
) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    reader.seek(SeekFrom::Start(offset))?;
    let readable = file_size.saturating_sub(offset).min(block_size as u64) as usize;
    let mut block = vec![0u8; block_size];
    if readable > 0 {
        reader.read_exact(&mut block[..readable])?;
    }
    Ok(block)
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes)
        .map_err(|error| DynoError::Tool(format!("Failed to obtain random bytes: {}", error)))?;
    Ok(bytes)
}

fn write_blob(path: &Path, blob: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, blob)?;
    Ok(())
}

fn write_padded_blob(file: &mut File, offset: u64, blob: &[u8], padded_size: u64) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(blob)?;
    if padded_size > blob.len() as u64 {
        zero_fill(file, offset + blob.len() as u64, padded_size - blob.len() as u64)?;
    }
    Ok(())
}

fn write_footer(
    file: &mut File,
    footer_start: u64,
    original_image_size: u64,
    vbmeta_offset: u64,
    vbmeta_size: u64,
) -> Result<()> {
    let footer = AvbFooter {
        magic: *b"AVBf",
        version_major: 1,
        version_minor: 0,
        original_image_size,
        vbmeta_offset,
        vbmeta_size,
    };
    file.seek(SeekFrom::Start(footer_start))?;
    file.write_all(&crate::image::encode_footer(&footer))?;
    Ok(())
}

fn write_zeroed_region(file: &mut File, start: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start))?;
    let block_size = DEFAULT_BLOCK_SIZE as usize;
    let mut remaining = size;
    let mut first_block = vec![0u8; block_size];
    first_block[..ZERO_HASHTREE_MAGIC.len()].copy_from_slice(ZERO_HASHTREE_MAGIC);
    let first_len = remaining.min(block_size as u64) as usize;
    file.write_all(&first_block[..first_len])?;
    remaining -= first_len as u64;
    let zeros = vec![0u8; block_size];
    while remaining > 0 {
        let chunk = remaining.min(block_size as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn zero_fill(file: &mut File, start: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start))?;
    let zeros = [0u8; 8192];
    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::inspect_avb_image;
    use tempfile::tempdir;

    #[test]
    fn add_hash_footer_creates_footer_image() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        fs::write(&image, vec![0x41; 4096]).unwrap();

        add_hash_footer(
            &image,
            &HashFooterArgs {
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
            },
        )
        .unwrap();

        let info = inspect_avb_image(&image).unwrap();
        assert!(info.footer.is_some());
        assert!(matches!(info.descriptors[0], DescriptorInfo::Hash { .. }));
    }

    #[test]
    fn calc_hash_level_offsets_matches_aosp_shape() {
        let (offsets, size) = calc_hash_level_offsets(16384, 4096, 32);
        assert_eq!(offsets, vec![0]);
        assert_eq!(size, 4096);
    }

    #[test]
    fn zero_hashtree_marks_region() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("system.img");
        fs::write(&image, vec![0x5a; 8192]).unwrap();

        add_hashtree_footer(
            &image,
            &HashtreeFooterArgs {
                partition_size: None,
                partition_name: "system".to_string(),
                hash_algorithm: "sha256".to_string(),
                block_size: 4096,
                salt: Some(vec![0xaa, 0xbb]),
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
                use_persistent_root_digest: false,
                do_not_use_ab: false,
                no_hashtree: false,
                check_at_most_once: false,
                generate_fec: false,
            },
        )
        .unwrap();

        let info = inspect_avb_image(&image).unwrap();
        let tree_offset = info
            .descriptors
            .iter()
            .find_map(|descriptor| match descriptor {
                DescriptorInfo::Hashtree { tree_offset, .. } => Some(*tree_offset),
                _ => None,
            })
            .unwrap();
        zero_hashtree(&image).unwrap();
        let mut file = File::open(&image).unwrap();
        file.seek(SeekFrom::Start(tree_offset)).unwrap();
        let mut marker = [0u8; 8];
        file.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, ZERO_HASHTREE_MAGIC);
    }
}
