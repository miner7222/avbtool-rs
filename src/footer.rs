use std::fs;
use std::path::{Path, PathBuf};

use blake2::Blake2bVar;
use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

use crate::builder::{
    BuildSignOptions, ChainPartitionSpec, PropertySpec, VbmetaImageArgs,
    build_vbmeta_blob_with_options,
};
use crate::cmdline::cmdline_descriptors_from_hashtree_descriptor;
use crate::crypto::{round_to_multiple, round_to_pow2};
use crate::error::{AvbToolError as DynoError, Result};
use crate::fec::{FEC_BLOCKSIZE, calc_fec_data_size, fec_size_for_input, generate_fec_from_image};
use crate::image::{encode_footer, inspect_avb_image};
use crate::info::DescriptorInfo;
use crate::parser::{AVB_FOOTER_SIZE, AvbFooter, sparse_err};
use crate::sparse::ImageHandler;

#[allow(dead_code)]
const DEFAULT_BLOCK_SIZE: u64 = 4096;
/// AOSP `MAX_VBMETA_SIZE`: conservative upper bound for a vbmeta blob (64 KiB).
pub const MAX_VBMETA_SIZE: u64 = 64 * 1024;
/// AOSP `MAX_FOOTER_SIZE`: one full block reserved for the footer.
pub const MAX_FOOTER_SIZE: u64 = 4096;
/// Default Reed-Solomon root count for AVB hashtree FEC (`--fec_num_roots 2`).
pub const AVB_DEFAULT_FEC_NUM_ROOTS: u32 = 2;
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
    /// Number of Reed-Solomon roots for FEC. AOSP default is 2.
    pub fec_num_roots: u32,
}

/// Additive footer-build options kept outside [`HashFooterArgs`]/ [`HashtreeFooterArgs`].
///
/// Defaults preserve existing `add_*_footer` behavior. Callers that need signing
/// helpers, extra descriptors, or rootfs cmdline synthesis use the `*_with_options`
/// entry points.
#[derive(Debug, Clone, Default)]
pub struct FooterBuildOptions {
    pub build: BuildSignOptions,
    pub extra_descriptors: Vec<DescriptorInfo>,
    pub setup_as_rootfs_from_kernel: bool,
}

pub fn add_hash_footer(image_filename: &Path, args: &HashFooterArgs) -> Result<()> {
    add_hash_footer_with_options(image_filename, args, &FooterBuildOptions::default())
}

pub fn add_hash_footer_with_options(
    image_filename: &Path,
    args: &HashFooterArgs,
    options: &FooterBuildOptions,
) -> Result<()> {
    if args.partition_size.is_none() && !args.dynamic_partition_size {
        return Err(DynoError::Validation(
            "partition_size or dynamic_partition_size is required.".into(),
        ));
    }

    let mut image =
        ImageHandler::open(image_filename, args.do_not_append_vbmeta_image).map_err(sparse_err)?;
    let block_size = u64::from(image.block_size());
    let original_size = truncate_to_existing_footer(&mut image)?;
    let digest_size = hash_digest_size(&args.hash_algorithm)? as u64;
    let salt = args.salt.clone().unwrap_or(if args.use_persistent_digest {
        Vec::new()
    } else {
        random_bytes(digest_size as usize)?
    });
    let digest = if args.use_persistent_digest {
        Vec::new()
    } else {
        hash_image_prefix(&mut image, original_size, &args.hash_algorithm, &salt)?
    };

    let mut descriptor_flags = 0u32;
    if args.do_not_use_ab {
        descriptor_flags |= 1;
    }

    let mut extra_descriptors = vec![DescriptorInfo::Hash {
        image_size: original_size,
        hash_algorithm: args.hash_algorithm.clone(),
        partition_name: args.partition_name.clone(),
        salt,
        digest,
        flags: descriptor_flags,
    }];
    extra_descriptors.extend(options.extra_descriptors.clone());

    let vbmeta_args = VbmetaImageArgs {
        algorithm_name: args.algorithm_name.clone(),
        key_spec: args.key_spec.clone(),
        public_key_metadata: args.public_key_metadata.clone(),
        rollback_index: args.rollback_index,
        flags: args.flags,
        rollback_index_location: args.rollback_index_location,
        properties: args.properties.clone(),
        kernel_cmdlines: args.kernel_cmdlines.clone(),
        extra_descriptors,
        include_descriptors_from_images: args.include_descriptors_from_images.clone(),
        chain_partitions: args.chain_partitions.clone(),
        release_string: args.release_string.clone(),
        append_to_release_string: args.append_to_release_string.clone(),
        padding_size: 0,
    };
    let vbmeta_blob = build_vbmeta_blob_with_options(&vbmeta_args, &options.build)?;

    if let Some(path) = &args.output_vbmeta_image {
        write_blob(path, &vbmeta_blob)?;
    }
    if args.do_not_append_vbmeta_image {
        return Ok(());
    }

    // Match AOSP fixed metadata reservation for hash footers.
    let max_metadata_size = MAX_VBMETA_SIZE + MAX_FOOTER_SIZE;
    let partition_size = if args.dynamic_partition_size {
        round_to_multiple(original_size + max_metadata_size, block_size)
    } else {
        args.partition_size.unwrap_or_default()
    };
    if !args.dynamic_partition_size && partition_size < max_metadata_size {
        return Err(DynoError::Validation(format!(
            "Partition size of {} is too small. Needs to be at least {}",
            partition_size, max_metadata_size
        )));
    }
    if !partition_size.is_multiple_of(block_size) {
        return Err(DynoError::Validation(format!(
            "Partition size of {} is not a multiple of the image block size {}.",
            partition_size, block_size
        )));
    }

    let max_image_size = partition_size - max_metadata_size;
    if original_size > max_image_size {
        return restore_and_err(
            &mut image,
            original_size,
            format!(
                "Image size of {} exceeds maximum image size of {} in order to fit \
             in a partition size of {}.",
                original_size, max_image_size, partition_size
            ),
        );
    }

    if let Err(err) =
        append_vbmeta_and_footer(&mut image, &vbmeta_blob, original_size, partition_size)
    {
        let _ = image.truncate(original_size);
        return Err(err);
    }
    Ok(())
}

/// Calculate the maximum image size that can fit a hash footer in `partition_size`.
///
/// Matches AOSP `add_hash_footer(..., calc_max_image_size=True)`: reserves a fixed
/// `MAX_VBMETA_SIZE + MAX_FOOTER_SIZE` metadata budget.
///
/// # Errors
///
/// Returns [`DynoError::Validation`] when `partition_size` is smaller than the
/// fixed metadata reservation.
pub fn calc_max_hash_footer_image_size(partition_size: u64) -> Result<u64> {
    let max_metadata_size = MAX_VBMETA_SIZE + MAX_FOOTER_SIZE;
    if partition_size < max_metadata_size {
        return Err(DynoError::Validation(format!(
            "Partition size of {} is too small. Needs to be at least {}",
            partition_size, max_metadata_size
        )));
    }
    Ok(partition_size - max_metadata_size)
}

/// Calculate the maximum image size that can fit a hashtree footer in `partition_size`.
///
/// Matches AOSP `add_hashtree_footer(..., calc_max_image_size=True)`:
/// reserves the maximum tree (and optional FEC) that would be generated for an
/// image filling the whole partition, plus `MAX_VBMETA_SIZE + MAX_FOOTER_SIZE`.
/// When `partition_size` is 0, returns 0 (AOSP treats this as "fit to content").
///
/// # Errors
///
/// Returns an error for unsupported hash algorithms or invalid FEC root counts.
pub fn calc_max_hashtree_footer_image_size(
    partition_size: u64,
    block_size: u64,
    hash_algorithm: &str,
    generate_fec: bool,
    fec_num_roots: u32,
    no_hashtree: bool,
) -> Result<u64> {
    if partition_size == 0 {
        return Ok(0);
    }
    if block_size == 0 {
        return Err(DynoError::Validation(
            "block_size must be greater than zero.".into(),
        ));
    }
    let (max_tree_size, max_fec_size) = max_hashtree_metadata_sizes(
        partition_size,
        block_size,
        hash_algorithm,
        generate_fec,
        fec_num_roots,
        no_hashtree,
    )?;
    let max_metadata_size = max_fec_size + max_tree_size + MAX_VBMETA_SIZE + MAX_FOOTER_SIZE;
    Ok(partition_size.saturating_sub(max_metadata_size))
}

pub fn add_hashtree_footer(image_filename: &Path, args: &HashtreeFooterArgs) -> Result<()> {
    add_hashtree_footer_with_options(image_filename, args, &FooterBuildOptions::default())
}

pub fn add_hashtree_footer_with_options(
    image_filename: &Path,
    args: &HashtreeFooterArgs,
    options: &FooterBuildOptions,
) -> Result<()> {
    let mut image =
        ImageHandler::open(image_filename, args.do_not_append_vbmeta_image).map_err(sparse_err)?;
    let image_block_size = u64::from(image.block_size());
    let block_size = args.block_size as u64;
    let original_size = truncate_to_existing_footer(&mut image)?;

    let result = (|| {
        // Ensure image is multiple of hashtree data block size.
        let aligned_image_size = round_to_multiple(image.image_size(), block_size);
        if aligned_image_size > image.image_size() {
            let pad = aligned_image_size - image.image_size();
            image
                .append_raw(&vec![0u8; pad as usize], false)
                .map_err(sparse_err)?;
        }

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
        let (hash_level_offsets, mut tree_size) = calc_hash_level_offsets(
            aligned_image_size,
            block_size,
            (digest_size + digest_padding) as u64,
        );
        let (root_digest, mut hash_tree) = generate_hash_tree_from_image(
            &mut image,
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

        // Compute the FEC layout up front so the Hashtree descriptor can carry
        // the correct `fec_offset` / `fec_size` / `fec_num_roots`.
        let hash_tree_padded_size = round_to_multiple(hash_tree.len() as u64, image_block_size);
        let (fec_num_roots, fec_size, fec_offset) = if args.generate_fec && !args.no_hashtree {
            validate_fec_num_roots(args.fec_num_roots)?;
            let fec_input_size = aligned_image_size + hash_tree_padded_size;
            let size = fec_size_for_input(fec_input_size, args.fec_num_roots);
            (
                args.fec_num_roots,
                size,
                tree_offset + hash_tree_padded_size,
            )
        } else {
            (0u32, 0u64, 0u64)
        };

        let hashtree_descriptor = DescriptorInfo::Hashtree {
            dm_verity_version: 1,
            image_size: aligned_image_size,
            tree_offset,
            tree_size,
            data_block_size: args.block_size,
            hash_block_size: args.block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm: args.hash_algorithm.clone(),
            partition_name: args.partition_name.clone(),
            salt,
            root_digest: if args.use_persistent_root_digest {
                Vec::new()
            } else {
                root_digest
            },
            flags: descriptor_flags,
        };

        let mut extra_descriptors = vec![hashtree_descriptor.clone()];
        if options.setup_as_rootfs_from_kernel {
            let cmdline = cmdline_descriptors_from_hashtree_descriptor(&hashtree_descriptor)?;
            extra_descriptors.extend(cmdline);
        }
        extra_descriptors.extend(options.extra_descriptors.clone());

        let vbmeta_args = VbmetaImageArgs {
            algorithm_name: args.algorithm_name.clone(),
            key_spec: args.key_spec.clone(),
            public_key_metadata: args.public_key_metadata.clone(),
            rollback_index: args.rollback_index,
            flags: args.flags,
            rollback_index_location: args.rollback_index_location,
            properties: args.properties.clone(),
            kernel_cmdlines: args.kernel_cmdlines.clone(),
            extra_descriptors,
            include_descriptors_from_images: args.include_descriptors_from_images.clone(),
            chain_partitions: args.chain_partitions.clone(),
            release_string: args.release_string.clone(),
            append_to_release_string: args.append_to_release_string.clone(),
            padding_size: 0,
        };
        let vbmeta_blob = build_vbmeta_blob_with_options(&vbmeta_args, &options.build)?;

        if let Some(path) = &args.output_vbmeta_image {
            write_blob(path, &vbmeta_blob)?;
        }
        if args.do_not_append_vbmeta_image {
            return Ok(());
        }

        let vbmeta_padded_size = round_to_multiple(vbmeta_blob.len() as u64, image_block_size);
        let requested_partition_size = args.partition_size.unwrap_or(0);
        let (max_image_size, partition_size) = if requested_partition_size > 0 {
            let (max_tree_size, max_fec_size) = max_hashtree_metadata_sizes(
                requested_partition_size,
                block_size,
                &args.hash_algorithm,
                args.generate_fec,
                args.fec_num_roots,
                args.no_hashtree,
            )?;
            let max_metadata_size =
                max_fec_size + max_tree_size + MAX_VBMETA_SIZE + MAX_FOOTER_SIZE;
            (
                requested_partition_size.saturating_sub(max_metadata_size),
                requested_partition_size,
            )
        } else {
            (
                0,
                aligned_image_size
                    + hash_tree_padded_size
                    + fec_size
                    + vbmeta_padded_size
                    + image_block_size,
            )
        };
        if requested_partition_size > 0 && !partition_size.is_multiple_of(image_block_size) {
            return Err(DynoError::Validation(format!(
                "Partition size of {} is not a multiple of the image block size {}.",
                partition_size, image_block_size
            )));
        }
        if requested_partition_size > 0 && original_size > max_image_size {
            return Err(DynoError::Validation(format!(
                "Image size of {} exceeds maximum image size of {} in order to fit \
             in a partition size of {}.",
                original_size, max_image_size, partition_size
            )));
        }

        // Align logical size to the image handler block size before append_raw.
        if !image.image_size().is_multiple_of(image_block_size) {
            if image.is_sparse() {
                return Err(DynoError::Tool(
                    "Sparse image size is not a multiple of block size.".into(),
                ));
            }
            let padding_needed = image_block_size - (image.image_size() % image_block_size);
            image
                .truncate(image.image_size() + padding_needed)
                .map_err(sparse_err)?;
        }

        if hash_tree_padded_size > 0 {
            let mut padded = hash_tree;
            padded.resize(hash_tree_padded_size as usize, 0);
            image.append_raw(&padded, true).map_err(sparse_err)?;
        }

        if fec_size > 0 {
            let fec_bytes = generate_fec_from_image(image_filename, fec_offset, fec_num_roots)?;
            if fec_bytes.len() as u64 != fec_size {
                return Err(DynoError::Tool(format!(
                    "FEC encoder produced {} bytes but descriptor expects {}",
                    fec_bytes.len(),
                    fec_size
                )));
            }
            if fec_size % FEC_BLOCKSIZE != 0 {
                return Err(DynoError::Tool(format!(
                    "Computed FEC size {} is not a multiple of FEC_BLOCKSIZE {}",
                    fec_size, FEC_BLOCKSIZE
                )));
            }
            let mut padded = fec_bytes;
            let padded_size = round_to_multiple(padded.len() as u64, image_block_size);
            padded.resize(padded_size as usize, 0);
            image.append_raw(&padded, true).map_err(sparse_err)?;
        }

        let vbmeta_offset = image.image_size();
        let mut vbmeta_padded = vbmeta_blob.clone();
        vbmeta_padded.resize(vbmeta_padded_size as usize, 0);
        image.append_raw(&vbmeta_padded, true).map_err(sparse_err)?;

        let vbmeta_end = image.image_size();
        if partition_size < vbmeta_end + image_block_size {
            return Err(DynoError::Validation(format!(
                "Partition too small: need at least {} bytes",
                vbmeta_end + image_block_size
            )));
        }
        image
            .append_dont_care(partition_size - vbmeta_end - image_block_size)
            .map_err(sparse_err)?;

        let mut footer_blob = vec![0u8; (image_block_size - AVB_FOOTER_SIZE) as usize];
        footer_blob.extend_from_slice(&encode_footer(&AvbFooter {
            magic: *b"AVBf",
            version_major: 1,
            version_minor: 0,
            original_image_size: original_size,
            vbmeta_offset,
            vbmeta_size: vbmeta_blob.len() as u64,
        }));
        image.append_raw(&footer_blob, true).map_err(sparse_err)?;
        Ok(())
    })();

    if let Err(err) = result {
        let _ = image.truncate(original_size);
        return Err(err);
    }
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

    let mut image = ImageHandler::open(image_filename, false).map_err(sparse_err)?;
    image.truncate(new_size).map_err(sparse_err)?;
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

    let mut image = ImageHandler::open(image_filename, false).map_err(sparse_err)?;
    let block_size = u64::from(image.block_size());
    let zero_end = tree_offset + tree_size + if fec_offset > 0 { fec_size } else { 0 };
    if zero_end > image.image_size() {
        return Err(DynoError::Validation(
            "Hashtree/FEC region exceeds image size.".into(),
        ));
    }

    // Preserve trailing metadata after the hashtree/FEC region, matching AOSP.
    let trailing_len = (image.image_size() - zero_end) as usize;
    let trailing = if trailing_len == 0 {
        Vec::new()
    } else {
        crate::image::read_exact_at(&mut image, zero_end, trailing_len)?
    };

    image.truncate(tree_offset).map_err(sparse_err)?;

    let first_block = {
        let mut block = vec![0u8; block_size as usize];
        let n = ZERO_HASHTREE_MAGIC.len().min(block.len());
        block[..n].copy_from_slice(&ZERO_HASHTREE_MAGIC[..n]);
        block
    };

    // AOSP: append magic first-block + FILL zeros for the rest of hashtree/FEC.
    if tree_size > 0 {
        if tree_size < block_size {
            return Err(DynoError::Validation(
                "Hashtree size smaller than image block size.".into(),
            ));
        }
        image.append_raw(&first_block, true).map_err(sparse_err)?;
        if tree_size > block_size {
            image
                .append_fill([0, 0, 0, 0], tree_size - block_size)
                .map_err(sparse_err)?;
        }
    }
    if fec_offset > 0 && fec_size > 0 {
        if fec_size < block_size {
            return Err(DynoError::Validation(
                "FEC size smaller than image block size.".into(),
            ));
        }
        image.append_raw(&first_block, true).map_err(sparse_err)?;
        if fec_size > block_size {
            image
                .append_fill([0, 0, 0, 0], fec_size - block_size)
                .map_err(sparse_err)?;
        }
    }

    if !trailing.is_empty() {
        // Trailing content is vbmeta + padding + footer block and is block-aligned
        // for both dense and sparse footer images produced by this crate.
        let mut trailing = trailing;
        if !(trailing.len() as u64).is_multiple_of(block_size) && image.is_sparse() {
            let pad = block_size - (trailing.len() as u64 % block_size);
            trailing.resize(trailing.len() + pad as usize, 0);
        }
        let multiple = (trailing.len() as u64).is_multiple_of(block_size);
        // Append in block-sized raw chunks to avoid sparse append_raw integer-division
        // issues when multiple_block_size is false.
        if multiple {
            let mut offset = 0usize;
            while offset < trailing.len() {
                let end = (offset + block_size as usize).min(trailing.len());
                image
                    .append_raw(&trailing[offset..end], true)
                    .map_err(sparse_err)?;
                offset = end;
            }
        } else {
            image.append_raw(&trailing, false).map_err(sparse_err)?;
        }
    }
    Ok(())
}

pub fn resize_image(image_filename: &Path, partition_size: u64) -> Result<()> {
    let mut image = ImageHandler::open(image_filename, false).map_err(sparse_err)?;
    let block_size = u64::from(image.block_size());
    if !partition_size.is_multiple_of(block_size) {
        return Err(DynoError::Validation(format!(
            "Partition size of {} is not a multiple of the image block size {}.",
            partition_size, block_size
        )));
    }

    let info = inspect_avb_image(image_filename)?;
    let footer = info
        .footer
        .ok_or_else(|| DynoError::Validation("Given image does not have a footer.".into()))?;
    let vbmeta_end_offset =
        round_to_multiple(footer.vbmeta_offset + footer.vbmeta_size, block_size);
    let minimum_partition_size = vbmeta_end_offset + block_size;
    if partition_size < minimum_partition_size {
        return Err(DynoError::Validation(format!(
            "Requested size {} too small; need at least {} bytes",
            partition_size, minimum_partition_size
        )));
    }

    image.truncate(vbmeta_end_offset).map_err(sparse_err)?;
    image
        .append_dont_care(partition_size - vbmeta_end_offset - block_size)
        .map_err(sparse_err)?;
    let mut footer_blob = vec![0u8; (block_size - AVB_FOOTER_SIZE) as usize];
    footer_blob.extend_from_slice(&encode_footer(&AvbFooter {
        magic: *b"AVBf",
        version_major: footer.version_major,
        version_minor: footer.version_minor,
        original_image_size: footer.original_image_size,
        vbmeta_offset: footer.vbmeta_offset,
        vbmeta_size: footer.vbmeta_size,
    }));
    image.append_raw(&footer_blob, true).map_err(sparse_err)?;
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

// Public AOSP-shaped helper; argument count mirrors upstream generate_hash_tree.
#[allow(clippy::too_many_arguments)]
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
    let mut image = ImageHandler::open(image_filename, true).map_err(sparse_err)?;
    generate_hash_tree_from_image(
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

// Public AOSP-shaped helper; argument count mirrors upstream generate_hash_tree.
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_hash_tree_from_image(
    image: &mut ImageHandler,
    image_size: u64,
    block_size: u32,
    hash_algorithm: &str,
    salt: &[u8],
    digest_padding: usize,
    hash_level_offsets: &[u64],
    tree_size: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    generate_hash_tree_from_reader(
        image,
        image_size,
        block_size,
        hash_algorithm,
        salt,
        digest_padding,
        hash_level_offsets,
        tree_size,
    )
}

// Internal helper keeps the same AOSP argument surface as generate_hash_tree.
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_hash_tree_from_reader(
    image: &mut ImageHandler,
    image_size: u64,
    block_size: u32,
    hash_algorithm: &str,
    salt: &[u8],
    digest_padding: usize,
    hash_level_offsets: &[u64],
    tree_size: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
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

    Ok((
        hash_bytes(hash_algorithm, salt, &last_level_output)?,
        hash_ret,
    ))
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
    if !trimmed.len().is_multiple_of(2) {
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
    let mut image = ImageHandler::open(image_filename, true).map_err(sparse_err)?;
    hash_image_prefix(&mut image, size, hash_algorithm, salt)
}

pub(crate) fn hash_image_prefix(
    image: &mut ImageHandler,
    size: u64,
    hash_algorithm: &str,
    salt: &[u8],
) -> Result<Vec<u8>> {
    match hash_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => {
            let mut hasher = Sha1::new();
            Sha1Digest::update(&mut hasher, salt);
            hash_handler_prefix(image, size, &mut |chunk| {
                Sha1Digest::update(&mut hasher, chunk)
            })?;
            Ok(hasher.finalize().to_vec())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hash_handler_prefix(image, size, &mut |chunk| hasher.update(chunk))?;
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(salt);
            hash_handler_prefix(image, size, &mut |chunk| hasher.update(chunk))?;
            Ok(hasher.finalize().to_vec())
        }
        "blake2b-256" => {
            let mut hasher = Blake2bVar::new(32)
                .map_err(|error| DynoError::Tool(format!("Failed to init blake2b: {}", error)))?;
            hasher.update(salt);
            hash_handler_prefix(image, size, &mut |chunk| hasher.update(chunk))?;
            let mut out = vec![0u8; 32];
            hasher.finalize_variable(&mut out).map_err(|error| {
                DynoError::Tool(format!("Failed to finalize blake2b: {}", error))
            })?;
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
            hasher.finalize_variable(&mut out).map_err(|error| {
                DynoError::Tool(format!("Failed to finalize blake2b: {}", error))
            })?;
            Ok(out)
        }
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported hash algorithm {}",
            other
        ))),
    }
}

fn truncate_to_existing_footer(image: &mut ImageHandler) -> Result<u64> {
    let image_size = image.image_size();
    if image_size < AVB_FOOTER_SIZE {
        return Ok(image_size);
    }
    image
        .seek(image_size - AVB_FOOTER_SIZE)
        .map_err(sparse_err)?;
    let footer_bytes = image.read(AVB_FOOTER_SIZE as usize).map_err(sparse_err)?;
    match AvbFooter::from_reader(footer_bytes.as_slice()) {
        Ok(footer) => {
            image
                .truncate(footer.original_image_size)
                .map_err(sparse_err)?;
            Ok(footer.original_image_size)
        }
        Err(_) => Ok(image_size),
    }
}

fn append_vbmeta_and_footer(
    image: &mut ImageHandler,
    vbmeta_blob: &[u8],
    original_size: u64,
    partition_size: u64,
) -> Result<()> {
    let block_size = u64::from(image.block_size());
    if !image.image_size().is_multiple_of(block_size) {
        if image.is_sparse() {
            return Err(DynoError::Tool(
                "Sparse image size is not a multiple of block size.".into(),
            ));
        }
        let padding_needed = block_size - (image.image_size() % block_size);
        image
            .truncate(image.image_size() + padding_needed)
            .map_err(sparse_err)?;
    }

    let vbmeta_offset = image.image_size();
    let vbmeta_padded_size = round_to_multiple(vbmeta_blob.len() as u64, block_size);
    let mut padded = vbmeta_blob.to_vec();
    padded.resize(vbmeta_padded_size as usize, 0);
    image.append_raw(&padded, true).map_err(sparse_err)?;

    let vbmeta_end = image.image_size();
    if partition_size < vbmeta_end + block_size {
        return Err(DynoError::Validation(format!(
            "Partition too small: need at least {} bytes",
            vbmeta_end + block_size
        )));
    }
    image
        .append_dont_care(partition_size - vbmeta_end - block_size)
        .map_err(sparse_err)?;

    let mut footer_blob = vec![0u8; (block_size - AVB_FOOTER_SIZE) as usize];
    footer_blob.extend_from_slice(&encode_footer(&AvbFooter {
        magic: *b"AVBf",
        version_major: 1,
        version_minor: 0,
        original_image_size: original_size,
        vbmeta_offset,
        vbmeta_size: vbmeta_blob.len() as u64,
    }));
    image.append_raw(&footer_blob, true).map_err(sparse_err)?;
    Ok(())
}

fn restore_and_err(image: &mut ImageHandler, original_size: u64, message: String) -> Result<()> {
    let _ = image.truncate(original_size);
    Err(DynoError::Validation(message))
}

fn hash_handler_prefix<F>(image: &mut ImageHandler, size: u64, update: &mut F) -> Result<()>
where
    F: FnMut(&[u8]),
{
    image.seek(0).map_err(sparse_err)?;
    let mut remaining = size;
    while remaining > 0 {
        let chunk_size = remaining.min(1024 * 1024) as usize;
        let data = image.read(chunk_size).map_err(sparse_err)?;
        if data.is_empty() {
            return Err(DynoError::Tool(
                "Unexpected EOF while hashing image prefix".into(),
            ));
        }
        update(&data);
        remaining -= data.len() as u64;
    }
    Ok(())
}

fn read_padded_block(
    image: &mut ImageHandler,
    offset: u64,
    block_size: usize,
    file_size: u64,
) -> Result<Vec<u8>> {
    let readable = file_size.saturating_sub(offset).min(block_size as u64) as usize;
    let mut block = vec![0u8; block_size];
    if readable > 0 {
        image.seek(offset).map_err(sparse_err)?;
        let data = image.read(readable).map_err(sparse_err)?;
        if data.len() != readable {
            return Err(DynoError::Tool(
                "Unexpected EOF while reading padded block".into(),
            ));
        }
        block[..readable].copy_from_slice(&data);
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
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, blob)?;
    Ok(())
}

fn validate_fec_num_roots(fec_num_roots: u32) -> Result<()> {
    if fec_num_roots == 0 || fec_num_roots >= 255 {
        return Err(DynoError::Validation(format!(
            "fec_num_roots must be in 1..255 (got {})",
            fec_num_roots
        )));
    }
    Ok(())
}

/// AOSP-style conservative tree/FEC budgets used for partition fit checks and
/// `--calc_max_image_size`. Tree and FEC sizes are computed as if the image
/// occupied the entire partition.
fn max_hashtree_metadata_sizes(
    partition_size: u64,
    block_size: u64,
    hash_algorithm: &str,
    generate_fec: bool,
    fec_num_roots: u32,
    no_hashtree: bool,
) -> Result<(u64, u64)> {
    if no_hashtree {
        return Ok((0, 0));
    }
    let digest_size = hash_digest_size(hash_algorithm)? as u64;
    let digest_padding = (round_to_pow2(digest_size as usize) as u64) - digest_size;
    let (_, max_tree_size) =
        calc_hash_level_offsets(partition_size, block_size, digest_size + digest_padding);
    let max_fec_size = if generate_fec {
        validate_fec_num_roots(fec_num_roots)?;
        // AOSP avbtool calc_max uses `fec --print-fec-size` which is actual FEC
        // data plus one 4096-byte tool footer (`calc_fec_data_size`).
        calc_fec_data_size(partition_size, fec_num_roots)
    } else {
        0
    };
    Ok((max_tree_size, max_fec_size))
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
                partition_size: Some(128 * 1024),
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
                fec_num_roots: AVB_DEFAULT_FEC_NUM_ROOTS,
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
        let mut handler = ImageHandler::open(&image, true).unwrap();
        handler.seek(tree_offset).unwrap();
        let marker = handler.read(8).unwrap();
        assert_eq!(marker.as_slice(), ZERO_HASHTREE_MAGIC);
    }

    #[test]
    fn calc_max_hash_footer_image_size_reserves_fixed_metadata() {
        let partition_size = 128 * 1024;
        let max = calc_max_hash_footer_image_size(partition_size).unwrap();
        assert_eq!(max, partition_size - MAX_VBMETA_SIZE - MAX_FOOTER_SIZE);
        assert!(calc_max_hash_footer_image_size(MAX_VBMETA_SIZE).is_err());
    }

    #[test]
    fn calc_max_hashtree_footer_image_size_matches_aosp_cases() {
        let partition_size = 1024 * 1024;
        // sha256 digest 32, padding 0; tree for 1 MiB @ 4 KiB is 12 KiB.
        // AOSP calc_fec_data_size (print-fec-size) for 1 MiB:
        //   roots2 = 16384 + 4096 = 20480
        //   roots4 = 32768 + 4096 = 36864
        // max_image = partition - tree - fec_print - vbmeta - footer
        // roots2: 1048576 - 12288 - 20480 - 65536 - 4096 = 946176
        // roots4: 1048576 - 12288 - 36864 - 65536 - 4096 = 929792
        assert_eq!(
            calc_max_hashtree_footer_image_size(partition_size, 4096, "sha256", true, 2, false)
                .unwrap(),
            946_176
        );
        assert_eq!(
            calc_max_hashtree_footer_image_size(partition_size, 4096, "sha256", true, 4, false)
                .unwrap(),
            929_792
        );
        assert_eq!(
            calc_max_hashtree_footer_image_size(partition_size, 4096, "sha256", false, 2, false)
                .unwrap(),
            966_656
        );
        assert_eq!(
            calc_max_hashtree_footer_image_size(partition_size, 4096, "sha256", true, 2, true)
                .unwrap(),
            978_944
        );
        assert_eq!(
            calc_max_hashtree_footer_image_size(0, 4096, "sha256", true, 2, false).unwrap(),
            0
        );
    }

    #[test]
    fn add_hashtree_footer_fec_roots_two_and_four() {
        for roots in [2u32, 4u32] {
            let temp = tempdir().unwrap();
            let image = temp.path().join(format!("system_r{roots}.img"));
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
                    generate_fec: true,
                    fec_num_roots: roots,
                },
            )
            .unwrap();

            let info = inspect_avb_image(&image).unwrap();
            let (fec_num_roots, fec_size, fec_offset, tree_offset, tree_size) = info
                .descriptors
                .iter()
                .find_map(|descriptor| match descriptor {
                    DescriptorInfo::Hashtree {
                        fec_num_roots,
                        fec_size,
                        fec_offset,
                        tree_offset,
                        tree_size,
                        ..
                    } => Some((
                        *fec_num_roots,
                        *fec_size,
                        *fec_offset,
                        *tree_offset,
                        *tree_size,
                    )),
                    _ => None,
                })
                .expect("hashtree descriptor");

            assert_eq!(fec_num_roots, roots);
            assert!(fec_size > 0);
            assert_eq!(
                fec_offset,
                tree_offset + round_to_multiple(tree_size, DEFAULT_BLOCK_SIZE)
            );
            let expected = fec_size_for_input(
                tree_offset + round_to_multiple(tree_size, DEFAULT_BLOCK_SIZE),
                roots,
            );
            assert_eq!(fec_size, expected);
        }
    }

    #[test]
    fn add_hashtree_footer_rejects_invalid_fec_num_roots() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("system.img");
        fs::write(&image, vec![0x5a; 8192]).unwrap();
        let err = add_hashtree_footer(
            &image,
            &HashtreeFooterArgs {
                partition_size: None,
                partition_name: "system".to_string(),
                hash_algorithm: "sha256".to_string(),
                block_size: 4096,
                salt: Some(vec![0x01]),
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
                generate_fec: true,
                fec_num_roots: 0,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("fec_num_roots"));
    }

    fn write_sparse_raw_fixture(path: &std::path::Path, payload: &[u8]) {
        use crate::sparse::{DEFAULT_BLOCK_SIZE, SparseImageBuilder};
        assert!((payload.len() as u64).is_multiple_of(u64::from(DEFAULT_BLOCK_SIZE)));
        let image = SparseImageBuilder::new(DEFAULT_BLOCK_SIZE)
            .raw(payload.to_vec())
            .build()
            .unwrap();
        fs::write(path, image.to_sparse_bytes().unwrap()).unwrap();
    }

    #[test]
    fn sparse_hash_footer_info_verify_erase_resize_roundtrip() {
        use crate::sparse::ImageHandler;
        use crate::verify::{VerifyImageOptions, verify_image};

        let temp = tempdir().unwrap();
        let image = temp.path().join("boot.img");
        write_sparse_raw_fixture(&image, &vec![0x41; 4096]);

        add_hash_footer(
            &image,
            &HashFooterArgs {
                partition_size: Some(128 * 1024),
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

        let handler = ImageHandler::open(&image, true).unwrap();
        assert!(handler.is_sparse());
        assert_eq!(handler.image_size(), 128 * 1024);

        let report = crate::info::generate_info_report(&image).unwrap();
        assert!(report.contains("(Sparse)"));
        assert!(
            report.contains("Image size:") && report.contains("131072 bytes"),
            "{report}"
        );

        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: None,
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();

        resize_image(&image, 256 * 1024).unwrap();
        let handler = ImageHandler::open(&image, true).unwrap();
        assert_eq!(handler.image_size(), 256 * 1024);

        erase_footer(&image, false).unwrap();
        let handler = ImageHandler::open(&image, true).unwrap();
        assert_eq!(handler.image_size(), 4096);
    }

    #[test]
    fn sparse_hashtree_fec_and_resign() {
        use crate::resign::resign_image;
        use crate::sparse::ImageHandler;
        use crate::verify::{VerifyImageOptions, verify_image};

        let temp = tempdir().unwrap();
        let image = temp.path().join("system.img");
        write_sparse_raw_fixture(&image, &vec![0x5a; 8192]);

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
                generate_fec: true,
                fec_num_roots: AVB_DEFAULT_FEC_NUM_ROOTS,
            },
        )
        .unwrap();

        let handler = ImageHandler::open(&image, true).unwrap();
        assert!(handler.is_sparse());
        let info = inspect_avb_image(&image).unwrap();
        let fec_size = info
            .descriptors
            .iter()
            .find_map(|d| match d {
                DescriptorInfo::Hashtree { fec_size, .. } => Some(*fec_size),
                _ => None,
            })
            .unwrap();
        assert!(fec_size > 0);

        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: None,
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();

        resign_image(&image, "testkey_rsa2048", Some("SHA256_RSA2048"), false).unwrap();
        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: None,
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn sparse_zero_hashtree_marks_region() {
        use crate::sparse::ImageHandler;

        let temp = tempdir().unwrap();
        let image = temp.path().join("system.img");
        // Use a larger fixed partition so tree/FEC/vbmeta/footer layout stays simple.
        write_sparse_raw_fixture(&image, &vec![0x5a; 8192]);
        add_hashtree_footer(
            &image,
            &HashtreeFooterArgs {
                partition_size: Some(256 * 1024),
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
                fec_num_roots: AVB_DEFAULT_FEC_NUM_ROOTS,
            },
        )
        .unwrap();

        let info = inspect_avb_image(&image).unwrap();
        let tree_offset = info
            .descriptors
            .iter()
            .find_map(|d| match d {
                DescriptorInfo::Hashtree { tree_offset, .. } => Some(*tree_offset),
                _ => None,
            })
            .unwrap();
        zero_hashtree(&image).unwrap();
        let mut handler = ImageHandler::open(&image, true).unwrap();
        assert!(handler.is_sparse());
        handler.seek(tree_offset).unwrap();
        let marker = handler.read(8).unwrap();
        assert_eq!(marker.as_slice(), ZERO_HASHTREE_MAGIC);
    }

    #[test]
    fn sparse_append_vbmeta_image() {
        use crate::builder::{VbmetaImageArgs, append_vbmeta_image, make_vbmeta_image};
        use crate::sparse::ImageHandler;

        let temp = tempdir().unwrap();
        let image = temp.path().join("data_sparse.img");
        let vbmeta = temp.path().join("vbmeta.img");
        write_sparse_raw_fixture(&image, &vec![0x10; 4096]);
        make_vbmeta_image(
            &vbmeta,
            &VbmetaImageArgs {
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
            },
        )
        .unwrap();
        append_vbmeta_image(&image, &vbmeta, 64 * 1024).unwrap();
        let handler = ImageHandler::open(&image, true).unwrap();
        assert!(handler.is_sparse());
        assert_eq!(handler.image_size(), 64 * 1024);
        let info = inspect_avb_image(&image).unwrap();
        assert!(info.footer.is_some());
    }

    #[test]
    fn setup_as_rootfs_from_kernel_emits_cmdline_descriptors() {
        let temp = tempdir().unwrap();
        let image = temp.path().join("system.img");
        fs::write(&image, vec![0x5a; 8192]).unwrap();
        add_hashtree_footer_with_options(
            &image,
            &HashtreeFooterArgs {
                partition_size: None,
                partition_name: "system".to_string(),
                hash_algorithm: "sha256".to_string(),
                block_size: 4096,
                salt: Some(vec![0x01, 0x02]),
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
                fec_num_roots: AVB_DEFAULT_FEC_NUM_ROOTS,
            },
            &FooterBuildOptions {
                setup_as_rootfs_from_kernel: true,
                ..FooterBuildOptions::default()
            },
        )
        .unwrap();
        let info = inspect_avb_image(&image).unwrap();
        let cmdlines: Vec<_> = info
            .descriptors
            .iter()
            .filter(|d| matches!(d, DescriptorInfo::KernelCmdline { .. }))
            .collect();
        assert_eq!(cmdlines.len(), 2);
    }
}
