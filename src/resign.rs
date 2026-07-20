use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::path::Path;
use tracing::info;

use crate::crypto::{
    AvbKey, AvbMldsaKey, AvbMldsaPublicKey, AvbPublicKey, SignOptions, compute_hash_for_algorithm,
    is_mldsa_algorithm, is_rsa_algorithm, load_key_from_spec, load_mldsa_key_from_spec,
    lookup_algorithm_by_name, round_to_multiple,
};
use crate::error::{AvbToolError as DynoError, Result};
use crate::image::{encode_footer as encode_footer_bytes, read_exact_at};
use crate::parser::{AvbFooter, AvbImageType, AvbVBMetaHeader, detect_avb_image_type, sparse_err};
use crate::sparse::ImageHandler;

const AVB_DESCRIPTOR_HEADER_SIZE: usize = 16;
const AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE: usize = 92;
const AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResignOutcome {
    Resigned,
    SkippedUnsigned,
}

/// Additive signing options for resign APIs.
#[derive(Debug, Clone, Default)]
pub struct ResignSignOptions {
    pub sign: SignOptions,
}

// Box key material so enum variants stay compact under Clippy.
enum SigningMaterial {
    Rsa(Box<AvbKey>),
    Mldsa(Box<AvbMldsaKey>),
}

impl SigningMaterial {
    fn encode_public_key(&self) -> Vec<u8> {
        match self {
            Self::Rsa(key) => key.encode_public_key(),
            Self::Mldsa(key) => key.encode_public_key(),
        }
    }

    fn sign(&self, data: &[u8], algorithm_name: &str, options: &SignOptions) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(key) => key.sign_with_options(data, algorithm_name, options),
            Self::Mldsa(key) => key.sign_with_options(data, algorithm_name, options),
        }
    }
}

pub fn resign_image(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
) -> Result<ResignOutcome> {
    resign_image_with_options(image_path, key_spec, algorithm_name, force, None, false)
}

pub fn resign_image_with_options(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
    rollback_index: Option<u64>,
    auto_resize: bool,
) -> Result<ResignOutcome> {
    resign_image_with_sign_options(
        image_path,
        key_spec,
        algorithm_name,
        force,
        rollback_index,
        auto_resize,
        &ResignSignOptions::default(),
    )
}

pub fn resign_image_with_sign_options(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
    rollback_index: Option<u64>,
    auto_resize: bool,
    options: &ResignSignOptions,
) -> Result<ResignOutcome> {
    let mut image = ImageHandler::open(image_path, false).map_err(sparse_err)?;
    let file_size = image.image_size();

    let img_type = detect_avb_image_type(image_path)?;
    let footer = match img_type {
        AvbImageType::Vbmeta => None,
        AvbImageType::Footer => {
            if file_size < 64 {
                return Err(DynoError::Tool("Footer image too small".into()));
            }
            let footer_bytes = read_exact_at(&mut image, file_size - 64, 64)?;
            Some(AvbFooter::from_reader(footer_bytes.as_slice())?)
        }
        AvbImageType::None => return Err(DynoError::Tool("Not an AVB image".into())),
    };
    let (vbmeta_offset, vbmeta_size) = match &footer {
        Some(footer) => (footer.vbmeta_offset, footer.vbmeta_size),
        None => (0, file_size),
    };

    let vbmeta_blob = read_exact_at(&mut image, vbmeta_offset, vbmeta_size as usize)?;

    let header = AvbVBMetaHeader::from_reader(&vbmeta_blob[..256])?;

    // Resolve target algorithm
    let resolved_algo = match algorithm_name {
        Some(name) => name.to_string(),
        None => resolve_default_algorithm_name(key_spec).unwrap_or_else(|_| "NONE".to_string()),
    };
    let algorithm = lookup_algorithm_by_name(&resolved_algo)?;

    // NONE algorithm: only update header fields (rollback_index, flags) in-place
    if algorithm.name == "NONE" {
        if header.algorithm_type == 0 {
            // Already NONE — just patch rollback_index in existing blob
            let mut new_header = header.clone();
            if let Some(ri) = rollback_index {
                new_header.rollback_index = ri;
            }
            let header_bytes = encode_header(&new_header);
            write_raw_at(&mut image, vbmeta_offset, &header_bytes, file_size, &footer)?;
            info!(
                "Updated rollback_index on unsigned image {}.",
                image_path.display()
            );
            return Ok(ResignOutcome::Resigned);
        }
        if !force {
            return Err(DynoError::Tool(
                "Cannot change a signed image to NONE without --force.".into(),
            ));
        }
        // --force: strip signature, rebuild as NONE
        let auth_offset = 256;
        let aux_offset = auth_offset + header.authentication_data_block_size as usize;
        let aux_blob = &vbmeta_blob[aux_offset..];
        let descriptors_blob = &aux_blob[header.descriptors_offset as usize
            ..header.descriptors_offset as usize + header.descriptors_size as usize];
        let pkmd_blob = &aux_blob[header.public_key_metadata_offset as usize
            ..header.public_key_metadata_offset as usize
                + header.public_key_metadata_size as usize];

        let mut new_aux = Vec::new();
        new_aux.extend_from_slice(descriptors_blob);
        let pkmd_off = new_aux.len();
        new_aux.extend_from_slice(pkmd_blob);
        let new_aux_size = round_to_multiple(new_aux.len() as u64, 64) as usize;
        new_aux.resize(new_aux_size, 0);

        let mut new_header = header.clone();
        new_header.algorithm_type = 0;
        new_header.authentication_data_block_size = 0;
        new_header.hash_offset = 0;
        new_header.hash_size = 0;
        new_header.signature_offset = 0;
        new_header.signature_size = 0;
        new_header.public_key_offset = 0;
        new_header.public_key_size = 0;
        new_header.public_key_metadata_offset = if pkmd_blob.is_empty() {
            0
        } else {
            pkmd_off as u64
        };
        new_header.public_key_metadata_size = pkmd_blob.len() as u64;
        new_header.descriptors_offset = 0;
        new_header.descriptors_size = descriptors_blob.len() as u64;
        new_header.auxiliary_data_block_size = new_aux_size as u64;
        if let Some(ri) = rollback_index {
            new_header.rollback_index = ri;
        }

        let header_bytes = encode_header(&new_header);
        let mut new_vbmeta = header_bytes;
        new_vbmeta.extend_from_slice(&new_aux);

        write_vbmeta_to_image(
            &mut image,
            &new_vbmeta,
            vbmeta_offset,
            file_size,
            footer,
            auto_resize,
        )?;
        info!(
            "Stripped signature and re-wrote {} as NONE.",
            image_path.display()
        );
        return Ok(ResignOutcome::Resigned);
    }

    // Signed algorithm path
    if header.algorithm_type == 0 && !force {
        info!(
            "Skipping {} because original AVB algorithm is NONE. Use --force to sign unsigned AVB images.",
            image_path.display()
        );
        return Ok(ResignOutcome::SkippedUnsigned);
    }

    // Upstream validates the existing signature before resign unless force is used
    // for unsigned images (handled above). Preserve local force behavior for unsigned.
    if header.algorithm_type != 0 && !verify_existing_vbmeta_signature(&header, &vbmeta_blob)? {
        return Err(DynoError::Tool(
            "VBMeta signature verification failed. Refusing to resign image.".into(),
        ));
    }

    let key = load_signing_material(key_spec, algorithm.name)?;
    let encoded_probe = key.encode_public_key();
    if encoded_probe.len() != algorithm.public_key_num_bytes {
        return Err(DynoError::Tool(format!(
            "Requested algorithm {} does not match key size {}",
            resolved_algo,
            encoded_probe.len()
        )));
    }

    let auth_offset = 256;
    let aux_offset = auth_offset + header.authentication_data_block_size as usize;
    let aux_blob = &vbmeta_blob[aux_offset..];

    let descriptors_blob = &aux_blob[header.descriptors_offset as usize
        ..header.descriptors_offset as usize + header.descriptors_size as usize];
    let pkmd_blob = &aux_blob[header.public_key_metadata_offset as usize
        ..header.public_key_metadata_offset as usize + header.public_key_metadata_size as usize];

    let encoded_key = key.encode_public_key();
    let rewritten_descriptors =
        rewrite_descriptors_with_new_chain_key(descriptors_blob, &encoded_key)?;
    let new_pk_size = encoded_key.len();

    let mut new_aux_unpadded = Vec::new();
    new_aux_unpadded.extend_from_slice(&rewritten_descriptors);
    let new_pk_offset = new_aux_unpadded.len();
    new_aux_unpadded.extend_from_slice(&encoded_key);
    let new_pkmd_offset = new_aux_unpadded.len();
    new_aux_unpadded.extend_from_slice(pkmd_blob);

    let new_aux_size = round_to_multiple(new_aux_unpadded.len() as u64, 64) as usize;
    let mut new_aux_blob = new_aux_unpadded;
    new_aux_blob.resize(new_aux_size, 0);

    let mut new_header = header.clone();
    new_header.algorithm_type = algorithm.algorithm_type;
    if let Some(ri) = rollback_index {
        new_header.rollback_index = ri;
    }
    if is_mldsa_algorithm(algorithm.name) {
        // ML-DSA signatures require libavb 1.4.
        new_header.required_libavb_version_minor = new_header.required_libavb_version_minor.max(4);
    }
    new_header.public_key_offset = new_pk_offset as u64;
    new_header.public_key_size = new_pk_size as u64;
    new_header.public_key_metadata_offset = if pkmd_blob.is_empty() {
        0
    } else {
        new_pkmd_offset as u64
    };
    new_header.public_key_metadata_size = pkmd_blob.len() as u64;
    new_header.descriptors_offset = 0;
    new_header.descriptors_size = rewritten_descriptors.len() as u64;
    new_header.auxiliary_data_block_size = new_aux_size as u64;

    let sig_size = algorithm.signature_num_bytes as u64;
    let hash_size = algorithm.hash_num_bytes as u64;
    let auth_block_size = round_to_multiple(hash_size + sig_size, 64);
    new_header.authentication_data_block_size = auth_block_size;
    new_header.hash_offset = 0;
    new_header.hash_size = hash_size;
    new_header.signature_offset = hash_size;
    new_header.signature_size = sig_size;

    let header_bytes = encode_header(&new_header);

    let mut data_to_sign = header_bytes.clone();
    data_to_sign.extend_from_slice(&new_aux_blob);

    let signature = key.sign(&data_to_sign, &resolved_algo, &options.sign)?;
    // ML-DSA has empty external hash (hash_num_bytes == 0).
    let hash = compute_hash_for_algorithm(algorithm, &data_to_sign)?;

    let mut new_auth_blob = Vec::new();
    new_auth_blob.extend_from_slice(&hash);
    new_auth_blob.extend_from_slice(&signature);
    new_auth_blob.resize(auth_block_size as usize, 0);

    let mut new_vbmeta = header_bytes;
    new_vbmeta.extend_from_slice(&new_auth_blob);
    new_vbmeta.extend_from_slice(&new_aux_blob);

    write_vbmeta_to_image(
        &mut image,
        &new_vbmeta,
        vbmeta_offset,
        file_size,
        footer,
        auto_resize,
    )?;
    info!(
        "Successfully re-signed {} using pure Rust ({}).",
        image_path.display(),
        resolved_algo
    );
    Ok(ResignOutcome::Resigned)
}

fn write_vbmeta_to_image(
    image: &mut ImageHandler,
    new_vbmeta: &[u8],
    vbmeta_offset: u64,
    file_size: u64,
    footer: Option<AvbFooter>,
    auto_resize: bool,
) -> Result<()> {
    let block = u64::from(image.block_size());
    if let Some(mut footer) = footer {
        // AOSP footer images reserve a full final block for the footer. Available
        // space for vbmeta is therefore everything before that last block.
        if file_size < block || vbmeta_offset > file_size - block {
            return Err(DynoError::Tool(
                "Footer image is too small for vbmeta rewrite.".into(),
            ));
        }
        let available_space = file_size - block - vbmeta_offset;
        if new_vbmeta.len() as u64 > available_space {
            return Err(DynoError::Tool(format!(
                "New VBMeta needs {} bytes but only {} bytes available before footer.",
                new_vbmeta.len(),
                available_space
            )));
        }

        image.truncate(vbmeta_offset).map_err(sparse_err)?;

        let mut region = new_vbmeta.to_vec();
        region.resize(available_space as usize, 0);
        // available_space is a multiple of the image block size for images produced
        // by this crate / AOSP append paths.
        if !(region.len() as u64).is_multiple_of(block) {
            // Dense images may still be non-sparse-compatible; write raw without
            // sparse block checks when not sparse.
            image
                .append_raw(&region, image.is_sparse())
                .map_err(sparse_err)?;
        } else {
            image.append_raw(&region, true).map_err(sparse_err)?;
        }

        footer.vbmeta_size = new_vbmeta.len() as u64;
        let footer_bytes = encode_footer_bytes(&footer);
        let mut footer_blob = vec![0u8; block.saturating_sub(64) as usize];
        footer_blob.extend_from_slice(&footer_bytes);
        image.append_raw(&footer_blob, true).map_err(sparse_err)?;

        if image.image_size() != file_size {
            if image.image_size() < file_size {
                image
                    .append_dont_care(file_size - image.image_size())
                    .map_err(sparse_err)?;
            } else {
                image.truncate(file_size).map_err(sparse_err)?;
            }
        }
    } else if auto_resize || new_vbmeta.len() as u64 > file_size {
        image.truncate(0).map_err(sparse_err)?;
        image.append_raw(new_vbmeta, false).map_err(sparse_err)?;
    } else {
        image.truncate(vbmeta_offset).map_err(sparse_err)?;
        let mut region = new_vbmeta.to_vec();
        region.resize((file_size - vbmeta_offset) as usize, 0);
        image.append_raw(&region, false).map_err(sparse_err)?;
    }
    Ok(())
}

fn write_raw_at(
    image: &mut ImageHandler,
    offset: u64,
    data: &[u8],
    file_size: u64,
    footer: &Option<AvbFooter>,
) -> Result<()> {
    // Small in-place header rewrite for unsigned NONE images: rebuild from offset.
    let trailing_start = offset + data.len() as u64;
    if trailing_start > file_size {
        return Err(DynoError::Tool("Header write exceeds image size".into()));
    }
    image.seek(trailing_start).map_err(sparse_err)?;
    let trailing = image
        .read((file_size - trailing_start) as usize)
        .map_err(sparse_err)?;
    image.truncate(offset).map_err(sparse_err)?;
    image.append_raw(data, false).map_err(sparse_err)?;
    if !trailing.is_empty() {
        image.append_raw(&trailing, false).map_err(sparse_err)?;
    }
    let _ = footer;
    Ok(())
}

fn encode_header(h: &AvbVBMetaHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&h.magic);
    buf.write_u32::<BigEndian>(h.required_libavb_version_major)
        .unwrap();
    buf.write_u32::<BigEndian>(h.required_libavb_version_minor)
        .unwrap();
    buf.write_u64::<BigEndian>(h.authentication_data_block_size)
        .unwrap();
    buf.write_u64::<BigEndian>(h.auxiliary_data_block_size)
        .unwrap();
    buf.write_u32::<BigEndian>(h.algorithm_type).unwrap();
    buf.write_u64::<BigEndian>(h.hash_offset).unwrap();
    buf.write_u64::<BigEndian>(h.hash_size).unwrap();
    buf.write_u64::<BigEndian>(h.signature_offset).unwrap();
    buf.write_u64::<BigEndian>(h.signature_size).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_offset).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_size).unwrap();
    buf.write_u64::<BigEndian>(h.public_key_metadata_offset)
        .unwrap();
    buf.write_u64::<BigEndian>(h.public_key_metadata_size)
        .unwrap();
    buf.write_u64::<BigEndian>(h.descriptors_offset).unwrap();
    buf.write_u64::<BigEndian>(h.descriptors_size).unwrap();
    buf.write_u64::<BigEndian>(h.rollback_index).unwrap();
    buf.write_u32::<BigEndian>(h.flags).unwrap();
    buf.write_u32::<BigEndian>(h.rollback_index_location)
        .unwrap();

    let mut rel = [0u8; 48];
    let rel_bytes = h.release_string.as_bytes();
    let len = std::cmp::min(rel_bytes.len(), 47);
    rel[..len].copy_from_slice(&rel_bytes[..len]);
    buf.extend_from_slice(&rel);

    buf.resize(256, 0);
    buf
}

fn rewrite_descriptors_with_new_chain_key(
    descriptors_blob: &[u8],
    new_key: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(descriptors_blob.len());
    let mut offset = 0usize;

    while offset < descriptors_blob.len() {
        let remaining = &descriptors_blob[offset..];
        if remaining.len() < AVB_DESCRIPTOR_HEADER_SIZE {
            return Err(DynoError::Tool(
                "Descriptor blob ends mid-header while resigning.".into(),
            ));
        }

        let mut cursor = std::io::Cursor::new(&remaining[..AVB_DESCRIPTOR_HEADER_SIZE]);
        let tag = cursor.read_u64::<BigEndian>()?;
        let num_bytes_following = cursor.read_u64::<BigEndian>()?;
        let total_len = AVB_DESCRIPTOR_HEADER_SIZE
            .checked_add(num_bytes_following as usize)
            .ok_or_else(|| DynoError::Tool("Descriptor size overflow while resigning.".into()))?;
        if total_len > remaining.len() {
            return Err(DynoError::Tool(
                "Descriptor blob truncated while resigning.".into(),
            ));
        }

        let descriptor = &remaining[..total_len];
        if tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION {
            output.extend_from_slice(&rewrite_chain_partition_descriptor(descriptor, new_key)?);
        } else {
            output.extend_from_slice(descriptor);
        }
        offset += total_len;
    }

    Ok(output)
}

fn rewrite_chain_partition_descriptor(descriptor: &[u8], new_key: &[u8]) -> Result<Vec<u8>> {
    if descriptor.len() < AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE {
        return Err(DynoError::Tool(
            "Chain partition descriptor shorter than header.".into(),
        ));
    }

    let mut cursor = std::io::Cursor::new(
        &descriptor[AVB_DESCRIPTOR_HEADER_SIZE..AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE],
    );
    let rollback_index_location = cursor.read_u32::<BigEndian>()?;
    let partition_name_len = cursor.read_u32::<BigEndian>()? as usize;
    let public_key_len = cursor.read_u32::<BigEndian>()? as usize;
    let flags = cursor.read_u32::<BigEndian>()?;

    let body = &descriptor[AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE..];
    let needed = partition_name_len
        .checked_add(public_key_len)
        .ok_or_else(|| DynoError::Tool("Chain descriptor body size overflow.".into()))?;
    if body.len() < needed {
        return Err(DynoError::Tool("Chain descriptor body truncated.".into()));
    }
    let partition_name = &body[..partition_name_len];

    let new_num_bytes_following = round_to_multiple(
        (AVB_CHAIN_PARTITION_DESCRIPTOR_SIZE - AVB_DESCRIPTOR_HEADER_SIZE
            + partition_name_len
            + new_key.len()) as u64,
        8,
    );

    let mut out = Vec::with_capacity(AVB_DESCRIPTOR_HEADER_SIZE + new_num_bytes_following as usize);
    out.write_u64::<BigEndian>(AVB_DESCRIPTOR_TAG_CHAIN_PARTITION)?;
    out.write_u64::<BigEndian>(new_num_bytes_following)?;
    out.write_u32::<BigEndian>(rollback_index_location)?;
    out.write_u32::<BigEndian>(partition_name_len as u32)?;
    out.write_u32::<BigEndian>(new_key.len() as u32)?;
    out.write_u32::<BigEndian>(flags)?;
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(partition_name);
    out.extend_from_slice(new_key);
    out.resize(
        AVB_DESCRIPTOR_HEADER_SIZE + new_num_bytes_following as usize,
        0,
    );
    Ok(out)
}

fn resolve_default_algorithm_name(key_spec: &str) -> Result<String> {
    if let Ok(key) = load_mldsa_key_from_spec(key_spec) {
        return Ok(key.algorithm_name().to_string());
    }
    let key = load_key_from_spec(key_spec)?;
    key.algorithm()
}

fn load_signing_material(key_spec: &str, algorithm_name: &str) -> Result<SigningMaterial> {
    if is_mldsa_algorithm(algorithm_name) {
        let key = load_mldsa_key_from_spec(key_spec)?;
        if key.algorithm_name() != algorithm_name {
            return Err(DynoError::Tool(format!(
                "ML-DSA key algorithm {} does not match selected algorithm {}.",
                key.algorithm_name(),
                algorithm_name
            )));
        }
        return Ok(SigningMaterial::Mldsa(Box::new(key)));
    }
    if is_rsa_algorithm(algorithm_name) {
        return Ok(SigningMaterial::Rsa(Box::new(load_key_from_spec(
            key_spec,
        )?)));
    }
    Err(DynoError::UnsupportedOperation(format!(
        "Unsupported AVB algorithm {algorithm_name}"
    )))
}

fn verify_existing_vbmeta_signature(header: &AvbVBMetaHeader, vbmeta_blob: &[u8]) -> Result<bool> {
    let algorithm = lookup_algorithm_by_type(header.algorithm_type)?;
    if algorithm.name == "NONE" {
        return Ok(true);
    }

    let auth_start = 256usize;
    let auth_end = auth_start + header.authentication_data_block_size as usize;
    let aux_start = auth_end;
    let aux_end = aux_start + header.auxiliary_data_block_size as usize;
    if aux_end > vbmeta_blob.len() {
        return Ok(false);
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
        return Ok(false);
    }

    let data_to_verify = [&vbmeta_blob[..256], aux_blob].concat();
    let computed_digest = compute_hash_for_algorithm(algorithm, &data_to_verify)?;
    let expected_digest = &auth_blob[header.hash_offset as usize..hash_end];
    if computed_digest.as_slice() != expected_digest {
        return Ok(false);
    }

    let embedded_public_key = &aux_blob[header.public_key_offset as usize..public_key_end];
    let signature = &auth_blob[header.signature_offset as usize..signature_end];
    if is_mldsa_algorithm(algorithm.name) {
        let public_key = AvbMldsaPublicKey::decode(algorithm.name, embedded_public_key)?;
        return public_key.verify(algorithm, signature, &data_to_verify);
    }
    let public_key = AvbPublicKey::decode(embedded_public_key)?;
    public_key.verify(algorithm, signature, &data_to_verify)
}

fn lookup_algorithm_by_type(algorithm_type: u32) -> Result<crate::crypto::AvbAlgorithm> {
    crate::crypto::lookup_algorithm_by_type(algorithm_type)
}

pub fn rebuild_vbmeta_image(
    output_path: &Path,
    original_vbmeta_path: &Path,
    chained_images: &[&Path],
    key_spec: &str,
    algorithm_name: Option<&str>,
) -> Result<()> {
    crate::builder::rebuild_vbmeta_image(
        output_path,
        original_vbmeta_path,
        chained_images,
        key_spec,
        algorithm_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AVB_MAGIC, AvbVBMetaHeader};
    use std::fs;
    use tempfile::tempdir;

    fn write_minimal_vbmeta(path: &Path, algorithm_type: u32) {
        let header = AvbVBMetaHeader {
            magic: *AVB_MAGIC,
            required_libavb_version_major: 1,
            required_libavb_version_minor: 0,
            authentication_data_block_size: 0,
            auxiliary_data_block_size: 0,
            algorithm_type,
            hash_offset: 0,
            hash_size: 0,
            signature_offset: 0,
            signature_size: 0,
            public_key_offset: 0,
            public_key_size: 0,
            public_key_metadata_offset: 0,
            public_key_metadata_size: 0,
            descriptors_offset: 0,
            descriptors_size: 0,
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            release_string: "avbtool 1.3.0".to_string(),
        };

        fs::write(path, encode_header(&header)).unwrap();
    }

    #[test]
    fn skip_unsigned_image_without_force() {
        let dir = tempdir().unwrap();
        let image_path = dir.path().join("unsigned.img");
        write_minimal_vbmeta(&image_path, 0);

        let before = fs::read(&image_path).unwrap();
        let outcome = resign_image(&image_path, "testkey_rsa2048", None, false).unwrap();
        let after = fs::read(&image_path).unwrap();
        let header = AvbVBMetaHeader::from_reader(&after[..256]).unwrap();

        assert_eq!(outcome, ResignOutcome::SkippedUnsigned);
        assert_eq!(before, after);
        assert_eq!(header.algorithm_type, 0);
    }

    #[test]
    fn force_sign_unsigned_image() {
        let dir = tempdir().unwrap();
        let image_path = dir.path().join("unsigned.img");
        write_minimal_vbmeta(&image_path, 0);

        let outcome = resign_image(&image_path, "testkey_rsa2048", None, true).unwrap();
        let after = fs::read(&image_path).unwrap();
        let header = AvbVBMetaHeader::from_reader(&after[..256]).unwrap();

        assert_eq!(outcome, ResignOutcome::Resigned);
        assert_eq!(header.algorithm_type, 1);
        assert!(after.len() > 256);
    }

    #[test]
    fn resign_mldsa_round_trip() {
        use crate::builder::{PropertySpec, VbmetaImageArgs, make_vbmeta_image};
        use crate::verify::{VerifyImageOptions, verify_image};

        let dir = tempdir().unwrap();
        let image_path = dir.path().join("mldsa.img");
        let args = VbmetaImageArgs {
            algorithm_name: "MLDSA65".to_string(),
            key_spec: Some("testkey_mldsa65".to_string()),
            public_key_metadata: None,
            rollback_index: 1,
            flags: 0,
            rollback_index_location: 0,
            properties: vec![PropertySpec {
                key: "k".to_string(),
                value: b"v".to_vec(),
            }],
            kernel_cmdlines: Vec::new(),
            extra_descriptors: Vec::new(),
            include_descriptors_from_images: Vec::new(),
            chain_partitions: Vec::new(),
            release_string: Some("resign-test".to_string()),
            append_to_release_string: None,
            padding_size: 0,
        };
        make_vbmeta_image(&image_path, &args).unwrap();

        let outcome = resign_image(&image_path, "testkey_mldsa65", Some("MLDSA65"), false).unwrap();
        assert_eq!(outcome, ResignOutcome::Resigned);
        let header = AvbVBMetaHeader::from_reader(&fs::read(&image_path).unwrap()[..256]).unwrap();
        assert_eq!(header.algorithm_type, 7);
        assert_eq!(header.hash_size, 0);
        assert_eq!(header.required_libavb_version_minor, 4);
        verify_image(
            &image_path,
            &VerifyImageOptions {
                key_blob: Some(crate::crypto::extract_public_key("testkey_mldsa65").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn resign_refuses_tampered_signature_without_force_semantics() {
        use crate::builder::{VbmetaImageArgs, make_vbmeta_image};

        let dir = tempdir().unwrap();
        let image_path = dir.path().join("rsa.img");
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
        make_vbmeta_image(&image_path, &args).unwrap();
        let mut bytes = fs::read(&image_path).unwrap();
        bytes[256 + 8] ^= 0xff;
        fs::write(&image_path, bytes).unwrap();
        let err = resign_image(
            &image_path,
            "testkey_rsa2048",
            Some("SHA256_RSA2048"),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("signature verification failed"), "{err}");
    }

    #[test]
    fn resign_helper_options_require_key_path() {
        use crate::builder::{VbmetaImageArgs, make_vbmeta_image};
        use crate::crypto::SignOptions;
        use std::io::Write as _;

        let dir = tempdir().unwrap();
        let image_path = dir.path().join("rsa.img");
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
        make_vbmeta_image(&image_path, &args).unwrap();

        let helper = dir.path().join("helper.cmd");
        {
            let mut f = fs::File::create(&helper).unwrap();
            writeln!(f, "@echo off").unwrap();
        }
        let options = ResignSignOptions {
            sign: SignOptions {
                signing_helper: Some(helper),
                signing_helper_with_files: None,
                key_path: None,
            },
        };
        let err = resign_image_with_sign_options(
            &image_path,
            "testkey_rsa2048",
            Some("SHA256_RSA2048"),
            false,
            None,
            true,
            &options,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("signing helper requires key_path"), "{err}");
    }
}
