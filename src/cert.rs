//! AVB certificate (libavb_cert) and historical ATX binary formats.
//!
//! This module implements the fixed-length certificate, permanent attributes,
//! public-key metadata, and unlock credential structures used by
//! `libavb_cert` and the matching `avbtool.py` commands
//! (`make_certificate`, `make_cert_*`, with `make_atx_*` aliases).
//!
//! Wire formats use little-endian `version` / `key_version` fields, a 1032-byte
//! RSA-4096 AVB public-key blob, SHA-256 subject/usage digests, and
//! SHA512_RSA4096 signatures (512 bytes).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, LittleEndian};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::crypto::{AvbKey, AvbPublicKey, SignOptions, load_key_from_spec};
use crate::error::{AvbToolError as DynoError, Result};

/// Current libavb_cert structure version written by avbtool.
pub const CERT_FORMAT_VERSION: u32 = 1;

/// Size in bytes of a product ID (`AVB_CERT_PRODUCT_ID_SIZE`).
pub const CERT_PRODUCT_ID_SIZE: usize = 16;

/// Size in bytes of an unlock challenge (`AVB_CERT_UNLOCK_CHALLENGE_SIZE`).
pub const CERT_UNLOCK_CHALLENGE_SIZE: usize = 16;

/// Serialized RSA-4096 public key size (`AVB_CERT_PUBLIC_KEY_SIZE`).
///
/// `sizeof(AvbRSAPublicKeyHeader) + 1024` = 8 + 512 + 512.
pub const CERT_PUBLIC_KEY_SIZE: usize = 1032;

/// SHA-256 digest size used for subject and usage fields.
pub const CERT_SHA256_DIGEST_SIZE: usize = 32;

/// RSA-4096 signature size (`AVB_RSA4096_NUM_BYTES`).
pub const CERT_RSA4096_SIGNATURE_SIZE: usize = 512;

/// Size of [`CertCertificateSignedData`] on the wire.
pub const CERT_SIGNED_DATA_SIZE: usize =
    4 + CERT_PUBLIC_KEY_SIZE + CERT_SHA256_DIGEST_SIZE + CERT_SHA256_DIGEST_SIZE + 8;

/// Full signed certificate size expected by metadata / unlock credentials.
pub const CERTIFICATE_SIZE: usize = CERT_SIGNED_DATA_SIZE + CERT_RSA4096_SIGNATURE_SIZE;

/// Permanent attributes size (`AvbCertPermanentAttributes`).
pub const CERT_PERMANENT_ATTRIBUTES_SIZE: usize = 4 + CERT_PUBLIC_KEY_SIZE + CERT_PRODUCT_ID_SIZE;

/// Public-key metadata size (`AvbCertPublicKeyMetadata`).
pub const CERT_METADATA_SIZE: usize = 4 + CERTIFICATE_SIZE + CERTIFICATE_SIZE;

/// Unlock credential size including challenge signature.
pub const CERT_UNLOCK_CREDENTIAL_SIZE: usize =
    4 + CERTIFICATE_SIZE + CERTIFICATE_SIZE + CERT_RSA4096_SIGNATURE_SIZE;

/// Unlock credential size without the optional challenge signature.
pub const CERT_UNLOCK_CREDENTIAL_WITHOUT_SIGNATURE_SIZE: usize =
    4 + CERTIFICATE_SIZE + CERTIFICATE_SIZE;

/// Algorithm used for all libavb_cert signatures.
pub const CERT_SIGNATURE_ALGORITHM: &str = "SHA512_RSA4096";

/// Historical usage string for product signing keys (PSK).
///
/// The `android.things` substring is historical; changing it would break
/// compatibility with existing devices and `libavb_cert`.
pub const CERT_USAGE_SIGNING: &str = "com.google.android.things.vboot";

/// Historical usage string for product intermediate keys (PIK).
pub const CERT_USAGE_INTERMEDIATE_AUTHORITY: &str = "com.google.android.things.vboot.ca";

/// Historical usage string for product unlock keys (PUK).
pub const CERT_USAGE_UNLOCK: &str = "com.google.android.things.vboot.unlock";

/// Alias for [`CERT_FORMAT_VERSION`].
pub const ATX_FORMAT_VERSION: u32 = CERT_FORMAT_VERSION;
/// Alias for [`CERT_PRODUCT_ID_SIZE`].
pub const ATX_PRODUCT_ID_SIZE: usize = CERT_PRODUCT_ID_SIZE;
/// Alias for [`CERT_UNLOCK_CHALLENGE_SIZE`].
pub const ATX_UNLOCK_CHALLENGE_SIZE: usize = CERT_UNLOCK_CHALLENGE_SIZE;
/// Alias for [`CERT_PUBLIC_KEY_SIZE`].
pub const ATX_PUBLIC_KEY_SIZE: usize = CERT_PUBLIC_KEY_SIZE;
/// Alias for [`CERTIFICATE_SIZE`].
pub const ATX_CERTIFICATE_SIZE: usize = CERTIFICATE_SIZE;
/// Alias for [`CERT_PERMANENT_ATTRIBUTES_SIZE`].
pub const ATX_PERMANENT_ATTRIBUTES_SIZE: usize = CERT_PERMANENT_ATTRIBUTES_SIZE;
/// Alias for [`CERT_METADATA_SIZE`].
pub const ATX_METADATA_SIZE: usize = CERT_METADATA_SIZE;
/// Alias for [`CERT_UNLOCK_CREDENTIAL_SIZE`].
pub const ATX_UNLOCK_CREDENTIAL_SIZE: usize = CERT_UNLOCK_CREDENTIAL_SIZE;
/// Alias for [`CERT_USAGE_SIGNING`].
pub const ATX_USAGE_SIGNING: &str = CERT_USAGE_SIGNING;
/// Alias for [`CERT_USAGE_INTERMEDIATE_AUTHORITY`].
pub const ATX_USAGE_INTERMEDIATE_AUTHORITY: &str = CERT_USAGE_INTERMEDIATE_AUTHORITY;
/// Alias for [`CERT_USAGE_UNLOCK`].
pub const ATX_USAGE_UNLOCK: &str = CERT_USAGE_UNLOCK;

/// Pre-computed SHA-256 of [`CERT_USAGE_SIGNING`].
pub const CERT_USAGE_HASH_SIGNING: [u8; CERT_SHA256_DIGEST_SIZE] = [
    0x75, 0x04, 0x7f, 0xe1, 0x5e, 0xd4, 0x99, 0x80, 0x2d, 0xfd, 0x77, 0x26, 0x00, 0x61, 0x18, 0xef,
    0x5b, 0x06, 0x58, 0x56, 0xf5, 0x9c, 0xa7, 0xf4, 0xdc, 0x63, 0xe7, 0x59, 0xe6, 0x48, 0xf8, 0x16,
];

/// Pre-computed SHA-256 of [`CERT_USAGE_INTERMEDIATE_AUTHORITY`].
pub const CERT_USAGE_HASH_INTERMEDIATE_AUTHORITY: [u8; CERT_SHA256_DIGEST_SIZE] = [
    0x04, 0xec, 0x7c, 0xc7, 0x42, 0x41, 0x76, 0x3b, 0xcc, 0x72, 0xe3, 0x5e, 0xd3, 0x92, 0xdf, 0xd8,
    0x2a, 0x6c, 0x51, 0xae, 0xa8, 0xec, 0x6d, 0x43, 0x27, 0xc7, 0x0d, 0xf4, 0x53, 0x4b, 0x21, 0x5c,
];

/// Pre-computed SHA-256 of [`CERT_USAGE_UNLOCK`].
pub const CERT_USAGE_HASH_UNLOCK: [u8; CERT_SHA256_DIGEST_SIZE] = [
    0x7b, 0x84, 0x6c, 0x4a, 0xfd, 0x85, 0x48, 0x8f, 0x42, 0x9b, 0x7a, 0xcf, 0x93, 0xcf, 0x6a, 0xff,
    0x5c, 0x50, 0x28, 0x1b, 0xbf, 0x9b, 0xd7, 0xb0, 0x18, 0xa5, 0x24, 0x2a, 0x86, 0x0d, 0xe3, 0xf8,
];

/// Signed fields of a libavb_cert certificate (`AvbCertCertificateSignedData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertCertificateSignedData {
    pub version: u32,
    pub public_key: Vec<u8>,
    pub subject: [u8; CERT_SHA256_DIGEST_SIZE],
    pub usage: [u8; CERT_SHA256_DIGEST_SIZE],
    pub key_version: u64,
}

/// A libavb_cert certificate (`AvbCertCertificate`).
///
/// When constructed without an authority key the signature is empty and
/// [`CertCertificate::encode`] emits only the signed data (1108 bytes),
/// matching `avbtool.py make_certificate` unsigned behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertCertificate {
    pub signed_data: CertCertificateSignedData,
    pub signature: Vec<u8>,
}

/// Permanent attributes (`AvbCertPermanentAttributes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPermanentAttributes {
    pub version: u32,
    pub product_root_public_key: Vec<u8>,
    pub product_id: [u8; CERT_PRODUCT_ID_SIZE],
}

/// Public-key metadata embedded in vbmeta (`AvbCertPublicKeyMetadata`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPublicKeyMetadata {
    pub version: u32,
    pub product_intermediate_key_certificate: CertCertificate,
    pub product_signing_key_certificate: CertCertificate,
}

/// Unlock challenge (`AvbCertUnlockChallenge`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertUnlockChallenge {
    pub version: u32,
    pub product_id_hash: [u8; CERT_SHA256_DIGEST_SIZE],
    pub challenge: [u8; CERT_UNLOCK_CHALLENGE_SIZE],
}

/// Unlock credential (`AvbCertUnlockCredential`).
///
/// `challenge_signature` may be empty when the credential was built without
/// signing a challenge (optional tail field in `avbtool.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertUnlockCredential {
    pub version: u32,
    pub product_intermediate_key_certificate: CertCertificate,
    pub product_unlock_key_certificate: CertCertificate,
    pub challenge_signature: Vec<u8>,
}

/// Alias for [`CertCertificateSignedData`].
pub type AtxCertificateSignedData = CertCertificateSignedData;
/// Alias for [`CertCertificate`].
pub type AtxCertificate = CertCertificate;
/// Alias for [`CertPermanentAttributes`].
pub type AtxPermanentAttributes = CertPermanentAttributes;
/// Alias for [`CertPublicKeyMetadata`].
pub type AtxPublicKeyMetadata = CertPublicKeyMetadata;
/// Alias for [`CertUnlockChallenge`].
pub type AtxUnlockChallenge = CertUnlockChallenge;
/// Alias for [`CertUnlockCredential`].
pub type AtxUnlockCredential = CertUnlockCredential;

impl CertCertificateSignedData {
    /// Encode signed data fields in wire order (little-endian version/key_version).
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_public_key_blob(&self.public_key, "certificate subject public key")?;
        let mut out = Vec::with_capacity(CERT_SIGNED_DATA_SIZE);
        let mut version = [0u8; 4];
        LittleEndian::write_u32(&mut version, self.version);
        out.extend_from_slice(&version);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(&self.usage);
        let mut key_version = [0u8; 8];
        LittleEndian::write_u64(&mut key_version, self.key_version);
        out.extend_from_slice(&key_version);
        debug_assert_eq!(out.len(), CERT_SIGNED_DATA_SIZE);
        Ok(out)
    }

    /// Parse signed data from a fixed 1108-byte blob.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != CERT_SIGNED_DATA_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid certificate signed-data length: expected {} bytes, got {} bytes",
                CERT_SIGNED_DATA_SIZE,
                data.len()
            )));
        }
        let version = LittleEndian::read_u32(&data[0..4]);
        let public_key = data[4..4 + CERT_PUBLIC_KEY_SIZE].to_vec();
        validate_public_key_blob(&public_key, "certificate subject public key")?;
        let mut subject = [0u8; CERT_SHA256_DIGEST_SIZE];
        subject.copy_from_slice(
            &data[4 + CERT_PUBLIC_KEY_SIZE..4 + CERT_PUBLIC_KEY_SIZE + CERT_SHA256_DIGEST_SIZE],
        );
        let usage_off = 4 + CERT_PUBLIC_KEY_SIZE + CERT_SHA256_DIGEST_SIZE;
        let mut usage = [0u8; CERT_SHA256_DIGEST_SIZE];
        usage.copy_from_slice(&data[usage_off..usage_off + CERT_SHA256_DIGEST_SIZE]);
        let key_version_off = usage_off + CERT_SHA256_DIGEST_SIZE;
        let key_version = LittleEndian::read_u64(&data[key_version_off..key_version_off + 8]);
        Ok(Self {
            version,
            public_key,
            subject,
            usage,
            key_version,
        })
    }
}

impl CertCertificate {
    /// Encode a certificate. Omits the signature when it is empty (unsigned).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = self.signed_data.encode()?;
        if self.signature.is_empty() {
            return Ok(out);
        }
        if self.signature.len() != CERT_RSA4096_SIGNATURE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid certificate signature length: expected {} bytes, got {} bytes",
                CERT_RSA4096_SIGNATURE_SIZE,
                self.signature.len()
            )));
        }
        out.extend_from_slice(&self.signature);
        debug_assert_eq!(out.len(), CERTIFICATE_SIZE);
        Ok(out)
    }

    /// Parse a full (1620-byte) or unsigned (1108-byte) certificate.
    pub fn decode(data: &[u8]) -> Result<Self> {
        match data.len() {
            CERT_SIGNED_DATA_SIZE => Ok(Self {
                signed_data: CertCertificateSignedData::decode(data)?,
                signature: Vec::new(),
            }),
            CERTIFICATE_SIZE => {
                let signed_data =
                    CertCertificateSignedData::decode(&data[..CERT_SIGNED_DATA_SIZE])?;
                let signature = data[CERT_SIGNED_DATA_SIZE..].to_vec();
                Ok(Self {
                    signed_data,
                    signature,
                })
            }
            other => Err(DynoError::Validation(format!(
                "invalid certificate length: expected {} (unsigned) or {} (signed) bytes, got {} bytes",
                CERT_SIGNED_DATA_SIZE, CERTIFICATE_SIZE, other
            ))),
        }
    }

    /// Parse a certificate that must include a signature (exactly 1620 bytes).
    pub fn decode_signed(data: &[u8]) -> Result<Self> {
        if data.len() != CERTIFICATE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid certificate length: expected {} bytes, got {} bytes",
                CERTIFICATE_SIZE,
                data.len()
            )));
        }
        Self::decode(data)
    }

    /// True when a signature is present.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

impl CertPermanentAttributes {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_public_key_blob(
            &self.product_root_public_key,
            "permanent attributes root public key",
        )?;
        let mut out = Vec::with_capacity(CERT_PERMANENT_ATTRIBUTES_SIZE);
        let mut version = [0u8; 4];
        LittleEndian::write_u32(&mut version, self.version);
        out.extend_from_slice(&version);
        out.extend_from_slice(&self.product_root_public_key);
        out.extend_from_slice(&self.product_id);
        debug_assert_eq!(out.len(), CERT_PERMANENT_ATTRIBUTES_SIZE);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != CERT_PERMANENT_ATTRIBUTES_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid permanent attributes length: expected {} bytes, got {} bytes",
                CERT_PERMANENT_ATTRIBUTES_SIZE,
                data.len()
            )));
        }
        let version = LittleEndian::read_u32(&data[0..4]);
        let product_root_public_key = data[4..4 + CERT_PUBLIC_KEY_SIZE].to_vec();
        validate_public_key_blob(
            &product_root_public_key,
            "permanent attributes root public key",
        )?;
        let mut product_id = [0u8; CERT_PRODUCT_ID_SIZE];
        product_id.copy_from_slice(&data[4 + CERT_PUBLIC_KEY_SIZE..]);
        Ok(Self {
            version,
            product_root_public_key,
            product_id,
        })
    }
}

impl CertPublicKeyMetadata {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let intermediate = self.product_intermediate_key_certificate.encode()?;
        let product = self.product_signing_key_certificate.encode()?;
        if intermediate.len() != CERTIFICATE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid intermediate key certificate length: expected {} bytes, got {} bytes (certificate must be fully signed)",
                CERTIFICATE_SIZE,
                intermediate.len()
            )));
        }
        if product.len() != CERTIFICATE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid product key certificate length: expected {} bytes, got {} bytes (certificate must be fully signed)",
                CERTIFICATE_SIZE,
                product.len()
            )));
        }
        let mut out = Vec::with_capacity(CERT_METADATA_SIZE);
        let mut version = [0u8; 4];
        LittleEndian::write_u32(&mut version, self.version);
        out.extend_from_slice(&version);
        out.extend_from_slice(&intermediate);
        out.extend_from_slice(&product);
        debug_assert_eq!(out.len(), CERT_METADATA_SIZE);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != CERT_METADATA_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid cert metadata length: expected {} bytes, got {} bytes",
                CERT_METADATA_SIZE,
                data.len()
            )));
        }
        let version = LittleEndian::read_u32(&data[0..4]);
        let intermediate = CertCertificate::decode_signed(&data[4..4 + CERTIFICATE_SIZE])?;
        let product =
            CertCertificate::decode_signed(&data[4 + CERTIFICATE_SIZE..4 + 2 * CERTIFICATE_SIZE])?;
        Ok(Self {
            version,
            product_intermediate_key_certificate: intermediate,
            product_signing_key_certificate: product,
        })
    }
}

impl CertUnlockChallenge {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + CERT_SHA256_DIGEST_SIZE + CERT_UNLOCK_CHALLENGE_SIZE);
        let mut version = [0u8; 4];
        LittleEndian::write_u32(&mut version, self.version);
        out.extend_from_slice(&version);
        out.extend_from_slice(&self.product_id_hash);
        out.extend_from_slice(&self.challenge);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let expected = 4 + CERT_SHA256_DIGEST_SIZE + CERT_UNLOCK_CHALLENGE_SIZE;
        if data.len() != expected {
            return Err(DynoError::Validation(format!(
                "invalid unlock challenge structure length: expected {} bytes, got {} bytes",
                expected,
                data.len()
            )));
        }
        let version = LittleEndian::read_u32(&data[0..4]);
        let mut product_id_hash = [0u8; CERT_SHA256_DIGEST_SIZE];
        product_id_hash.copy_from_slice(&data[4..4 + CERT_SHA256_DIGEST_SIZE]);
        let mut challenge = [0u8; CERT_UNLOCK_CHALLENGE_SIZE];
        challenge.copy_from_slice(&data[4 + CERT_SHA256_DIGEST_SIZE..]);
        Ok(Self {
            version,
            product_id_hash,
            challenge,
        })
    }
}

impl CertUnlockCredential {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let intermediate = self.product_intermediate_key_certificate.encode()?;
        let unlock = self.product_unlock_key_certificate.encode()?;
        if intermediate.len() != CERTIFICATE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid intermediate key certificate length: expected {} bytes, got {} bytes",
                CERTIFICATE_SIZE,
                intermediate.len()
            )));
        }
        if unlock.len() != CERTIFICATE_SIZE {
            return Err(DynoError::Validation(format!(
                "invalid unlock key certificate length: expected {} bytes, got {} bytes",
                CERTIFICATE_SIZE,
                unlock.len()
            )));
        }
        if !self.challenge_signature.is_empty()
            && self.challenge_signature.len() != CERT_RSA4096_SIGNATURE_SIZE
        {
            return Err(DynoError::Validation(format!(
                "invalid unlock challenge signature length: expected {} bytes, got {} bytes",
                CERT_RSA4096_SIGNATURE_SIZE,
                self.challenge_signature.len()
            )));
        }

        let mut out = Vec::with_capacity(
            4 + CERTIFICATE_SIZE + CERTIFICATE_SIZE + self.challenge_signature.len(),
        );
        let mut version = [0u8; 4];
        LittleEndian::write_u32(&mut version, self.version);
        out.extend_from_slice(&version);
        out.extend_from_slice(&intermediate);
        out.extend_from_slice(&unlock);
        out.extend_from_slice(&self.challenge_signature);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        match data.len() {
            CERT_UNLOCK_CREDENTIAL_WITHOUT_SIGNATURE_SIZE | CERT_UNLOCK_CREDENTIAL_SIZE => {}
            other => {
                return Err(DynoError::Validation(format!(
                    "invalid unlock credential length: expected {} (no challenge signature) or {} (with signature) bytes, got {} bytes",
                    CERT_UNLOCK_CREDENTIAL_WITHOUT_SIGNATURE_SIZE,
                    CERT_UNLOCK_CREDENTIAL_SIZE,
                    other
                )));
            }
        }
        let version = LittleEndian::read_u32(&data[0..4]);
        let intermediate = CertCertificate::decode_signed(&data[4..4 + CERTIFICATE_SIZE])?;
        let unlock =
            CertCertificate::decode_signed(&data[4 + CERTIFICATE_SIZE..4 + 2 * CERTIFICATE_SIZE])?;
        let challenge_signature = data[4 + 2 * CERTIFICATE_SIZE..].to_vec();
        Ok(Self {
            version,
            product_intermediate_key_certificate: intermediate,
            product_unlock_key_certificate: unlock,
            challenge_signature,
        })
    }
}

/// Create a libavb_cert certificate (`avbtool make_certificate` / `make_atx_certificate`).
///
/// * `subject` is hashed with SHA-256 into the certificate subject field.
/// * `usage` is hashed as ASCII with SHA-256 into the usage field.
/// * When `authority_key` is `None`, the certificate is left unsigned (signed
///   data only) so a signature can be appended out-of-band.
/// * When `subject_key_version` is `None`, the current UNIX time in seconds is used.
/// * Subject keys may be public-only RSA-4096 material.
/// * Authority signing requires private material unless a signing helper is
///   supplied via [`make_certificate_with_options`].
pub fn make_certificate(
    subject_key: &AvbKey,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key: Option<&AvbKey>,
) -> Result<Vec<u8>> {
    make_certificate_with_options(
        subject_key,
        subject,
        usage,
        subject_key_version,
        authority_key,
        &SignOptions::default(),
    )
}

/// Create a certificate with optional external signing helpers.
///
/// Helper semantics match upstream `avbtool.py make_certificate`: when an
/// authority key is present the certificate is signed with `SHA512_RSA4096`,
/// optionally through `signing_helper` / `signing_helper_with_files` from
/// [`SignOptions`].
pub fn make_certificate_with_options(
    subject_key: &AvbKey,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key: Option<&AvbKey>,
    sign_options: &SignOptions,
) -> Result<Vec<u8>> {
    let public_key = subject_key.encode_public_key();
    validate_public_key_blob(&public_key, "subject public key")?;

    let key_version = match subject_key_version {
        Some(v) => v,
        None => unix_time_seconds()?,
    };

    let signed_data = CertCertificateSignedData {
        version: CERT_FORMAT_VERSION,
        public_key,
        subject: sha256_array(subject),
        usage: sha256_array(usage.as_bytes()),
        key_version,
    };

    let signature = if let Some(authority) = authority_key {
        validate_signing_key(authority, "authority key", sign_options)?;
        authority.sign_with_options(
            &signed_data.encode()?,
            CERT_SIGNATURE_ALGORITHM,
            sign_options,
        )?
    } else {
        Vec::new()
    };

    CertCertificate {
        signed_data,
        signature,
    }
    .encode()
}

/// Path-based wrapper for [`make_certificate`].
pub fn make_certificate_from_paths(
    subject_key_path: impl AsRef<Path>,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key_path: Option<&Path>,
) -> Result<Vec<u8>> {
    make_certificate_from_paths_with_options(
        subject_key_path,
        subject,
        usage,
        subject_key_version,
        authority_key_path,
        None,
        None,
    )
}

/// Path-based certificate creation with optional external signing helpers.
///
/// When `authority_key_path` is set and a helper is provided, that path is also
/// used as [`SignOptions::key_path`] for helper protocols.
pub fn make_certificate_from_paths_with_options(
    subject_key_path: impl AsRef<Path>,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key_path: Option<&Path>,
    signing_helper: Option<PathBuf>,
    signing_helper_with_files: Option<PathBuf>,
) -> Result<Vec<u8>> {
    let subject_key = AvbKey::load_pem(subject_key_path.as_ref())?;
    let authority_key = match authority_key_path {
        Some(path) => Some(AvbKey::load_pem(path)?),
        None => None,
    };
    let mut options = SignOptions {
        signing_helper,
        signing_helper_with_files,
        key_path: None,
    };
    if authority_key_path.is_some()
        && (options.signing_helper.is_some() || options.signing_helper_with_files.is_some())
    {
        options.key_path = authority_key_path.map(Path::to_path_buf);
    }
    make_certificate_with_options(
        &subject_key,
        subject,
        usage,
        subject_key_version,
        authority_key.as_ref(),
        &options,
    )
}

/// Alias for [`make_certificate`].
pub fn make_atx_certificate(
    subject_key: &AvbKey,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key: Option<&AvbKey>,
) -> Result<Vec<u8>> {
    make_certificate(
        subject_key,
        subject,
        usage,
        subject_key_version,
        authority_key,
    )
}

/// Alias for [`make_certificate_with_options`].
pub fn make_atx_certificate_with_options(
    subject_key: &AvbKey,
    subject: &[u8],
    usage: &str,
    subject_key_version: Option<u64>,
    authority_key: Option<&AvbKey>,
    sign_options: &SignOptions,
) -> Result<Vec<u8>> {
    make_certificate_with_options(
        subject_key,
        subject,
        usage,
        subject_key_version,
        authority_key,
        sign_options,
    )
}

/// Create permanent attributes (`make_cert_permanent_attributes` / `make_atx_permanent_attributes`).
pub fn make_cert_permanent_attributes(
    root_authority_key: &AvbKey,
    product_id: &[u8],
) -> Result<Vec<u8>> {
    if product_id.len() != CERT_PRODUCT_ID_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid product ID length: expected {} bytes, got {} bytes",
            CERT_PRODUCT_ID_SIZE,
            product_id.len()
        )));
    }
    let product_root_public_key = root_authority_key.encode_public_key();
    validate_public_key_blob(&product_root_public_key, "root authority public key")?;
    let mut product_id_arr = [0u8; CERT_PRODUCT_ID_SIZE];
    product_id_arr.copy_from_slice(product_id);
    CertPermanentAttributes {
        version: CERT_FORMAT_VERSION,
        product_root_public_key,
        product_id: product_id_arr,
    }
    .encode()
}

/// Path-based wrapper for [`make_cert_permanent_attributes`].
pub fn make_cert_permanent_attributes_from_paths(
    root_authority_key_path: impl AsRef<Path>,
    product_id: &[u8],
) -> Result<Vec<u8>> {
    let key = AvbKey::load_pem(root_authority_key_path.as_ref())?;
    make_cert_permanent_attributes(&key, product_id)
}

/// Alias for [`make_cert_permanent_attributes`].
pub fn make_atx_permanent_attributes(
    root_authority_key: &AvbKey,
    product_id: &[u8],
) -> Result<Vec<u8>> {
    make_cert_permanent_attributes(root_authority_key, product_id)
}

/// Create public-key metadata (`make_cert_metadata` / `make_atx_metadata`).
pub fn make_cert_metadata(
    intermediate_key_certificate: &[u8],
    product_key_certificate: &[u8],
) -> Result<Vec<u8>> {
    if intermediate_key_certificate.len() != CERTIFICATE_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid intermediate key certificate length: expected {} bytes, got {} bytes",
            CERTIFICATE_SIZE,
            intermediate_key_certificate.len()
        )));
    }
    if product_key_certificate.len() != CERTIFICATE_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid product key certificate length: expected {} bytes, got {} bytes",
            CERTIFICATE_SIZE,
            product_key_certificate.len()
        )));
    }
    let intermediate = CertCertificate::decode_signed(intermediate_key_certificate)?;
    let product = CertCertificate::decode_signed(product_key_certificate)?;
    CertPublicKeyMetadata {
        version: CERT_FORMAT_VERSION,
        product_intermediate_key_certificate: intermediate,
        product_signing_key_certificate: product,
    }
    .encode()
}

/// Alias for [`make_cert_metadata`].
pub fn make_atx_metadata(
    intermediate_key_certificate: &[u8],
    product_key_certificate: &[u8],
) -> Result<Vec<u8>> {
    make_cert_metadata(intermediate_key_certificate, product_key_certificate)
}

/// Create an unlock credential (`make_cert_unlock_credential` / `make_atx_unlock_credential`).
///
/// When both `challenge` and `unlock_key` are provided the challenge is signed
/// with SHA512_RSA4096 and appended. Otherwise the challenge signature field
/// is omitted (credential is still valid to complete later by concatenation).
/// Unlock signing requires private material unless a signing helper is
/// supplied via [`make_cert_unlock_credential_with_options`].
pub fn make_cert_unlock_credential(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key: Option<&AvbKey>,
) -> Result<Vec<u8>> {
    make_cert_unlock_credential_with_options(
        intermediate_key_certificate,
        unlock_key_certificate,
        challenge,
        unlock_key,
        &SignOptions::default(),
    )
}

/// Create an unlock credential with optional external signing helpers.
///
/// Helper semantics match upstream `avbtool.py make_cert_unlock_credential`:
/// the challenge is signed with `SHA512_RSA4096` only when both the challenge
/// and unlock key are provided.
pub fn make_cert_unlock_credential_with_options(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key: Option<&AvbKey>,
    sign_options: &SignOptions,
) -> Result<Vec<u8>> {
    if intermediate_key_certificate.len() != CERTIFICATE_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid intermediate key certificate length: expected {} bytes, got {} bytes",
            CERTIFICATE_SIZE,
            intermediate_key_certificate.len()
        )));
    }
    if unlock_key_certificate.len() != CERTIFICATE_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid unlock key certificate length: expected {} bytes, got {} bytes",
            CERTIFICATE_SIZE,
            unlock_key_certificate.len()
        )));
    }

    let intermediate = CertCertificate::decode_signed(intermediate_key_certificate)?;
    let unlock_cert = CertCertificate::decode_signed(unlock_key_certificate)?;

    let challenge_signature = match (challenge, unlock_key) {
        (Some(challenge_bytes), Some(key)) => {
            if challenge_bytes.len() != CERT_UNLOCK_CHALLENGE_SIZE {
                return Err(DynoError::Validation(format!(
                    "invalid unlock challenge length: expected {} bytes, got {} bytes",
                    CERT_UNLOCK_CHALLENGE_SIZE,
                    challenge_bytes.len()
                )));
            }
            validate_signing_key(key, "unlock key", sign_options)?;
            key.sign_with_options(challenge_bytes, CERT_SIGNATURE_ALGORITHM, sign_options)?
        }
        (None, None) => Vec::new(),
        (Some(_), None) => {
            return Err(DynoError::Validation(
                "unlock key is required when a challenge is provided for signing".into(),
            ));
        }
        (None, Some(_)) => Vec::new(),
    };

    CertUnlockCredential {
        version: CERT_FORMAT_VERSION,
        product_intermediate_key_certificate: intermediate,
        product_unlock_key_certificate: unlock_cert,
        challenge_signature,
    }
    .encode()
}

/// Path-based wrapper for [`make_cert_unlock_credential`].
pub fn make_cert_unlock_credential_from_paths(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key_path: Option<&Path>,
) -> Result<Vec<u8>> {
    make_cert_unlock_credential_from_paths_with_options(
        intermediate_key_certificate,
        unlock_key_certificate,
        challenge,
        unlock_key_path,
        None,
        None,
    )
}

/// Path-based unlock credential creation with optional external signing helpers.
///
/// When `unlock_key_path` is set and a helper is provided, that path is used as
/// [`SignOptions::key_path`] for helper protocols.
pub fn make_cert_unlock_credential_from_paths_with_options(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key_path: Option<&Path>,
    signing_helper: Option<PathBuf>,
    signing_helper_with_files: Option<PathBuf>,
) -> Result<Vec<u8>> {
    let unlock_key = match unlock_key_path {
        Some(path) => Some(AvbKey::load_pem(path)?),
        None => None,
    };
    let mut options = SignOptions {
        signing_helper,
        signing_helper_with_files,
        key_path: None,
    };
    if unlock_key_path.is_some()
        && (options.signing_helper.is_some() || options.signing_helper_with_files.is_some())
    {
        options.key_path = unlock_key_path.map(Path::to_path_buf);
    }
    make_cert_unlock_credential_with_options(
        intermediate_key_certificate,
        unlock_key_certificate,
        challenge,
        unlock_key.as_ref(),
        &options,
    )
}

/// Alias for [`make_cert_unlock_credential`].
pub fn make_atx_unlock_credential(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key: Option<&AvbKey>,
) -> Result<Vec<u8>> {
    make_cert_unlock_credential(
        intermediate_key_certificate,
        unlock_key_certificate,
        challenge,
        unlock_key,
    )
}

/// Alias for [`make_cert_unlock_credential_with_options`].
pub fn make_atx_unlock_credential_with_options(
    intermediate_key_certificate: &[u8],
    unlock_key_certificate: &[u8],
    challenge: Option<&[u8]>,
    unlock_key: Option<&AvbKey>,
    sign_options: &SignOptions,
) -> Result<Vec<u8>> {
    make_cert_unlock_credential_with_options(
        intermediate_key_certificate,
        unlock_key_certificate,
        challenge,
        unlock_key,
        sign_options,
    )
}

/// Parse helpers matching the struct decoders.
pub fn parse_certificate(data: &[u8]) -> Result<CertCertificate> {
    CertCertificate::decode(data)
}

pub fn parse_permanent_attributes(data: &[u8]) -> Result<CertPermanentAttributes> {
    CertPermanentAttributes::decode(data)
}

pub fn parse_metadata(data: &[u8]) -> Result<CertPublicKeyMetadata> {
    CertPublicKeyMetadata::decode(data)
}

pub fn parse_unlock_credential(data: &[u8]) -> Result<CertUnlockCredential> {
    CertUnlockCredential::decode(data)
}

pub fn parse_unlock_challenge(data: &[u8]) -> Result<CertUnlockChallenge> {
    CertUnlockChallenge::decode(data)
}

/// ATX aliases for parsers.
pub fn parse_atx_certificate(data: &[u8]) -> Result<AtxCertificate> {
    parse_certificate(data)
}
pub fn parse_atx_permanent_attributes(data: &[u8]) -> Result<AtxPermanentAttributes> {
    parse_permanent_attributes(data)
}
pub fn parse_atx_metadata(data: &[u8]) -> Result<AtxPublicKeyMetadata> {
    parse_metadata(data)
}
pub fn parse_atx_unlock_credential(data: &[u8]) -> Result<AtxUnlockCredential> {
    parse_unlock_credential(data)
}

/// Format a single certificate the way `avbtool info_image --cert` prints one.
pub fn format_certificate_info(cert: &CertCertificate, indent: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}Version:               {}",
        indent, cert.signed_data.version
    );
    let _ = writeln!(
        out,
        "{}Public key (sha1):     {}",
        indent,
        sha1_hex(&cert.signed_data.public_key)
    );
    let _ = writeln!(
        out,
        "{}Subject:               {}",
        indent,
        bytes_to_hex(&cert.signed_data.subject)
    );
    let _ = writeln!(
        out,
        "{}Usage:                 {}",
        indent,
        bytes_to_hex(&cert.signed_data.usage)
    );
    let _ = writeln!(
        out,
        "{}Key version:           {}",
        indent, cert.signed_data.key_version
    );
    out
}

/// Format cert public-key metadata like `avbtool info_image --cert`.
pub fn format_cert_metadata_info(metadata: &CertPublicKeyMetadata) -> String {
    let mut out = String::new();
    out.push_str("avb_cert certificate:\n");
    let _ = writeln!(out, "    Metadata version:        {}", metadata.version);
    out.push_str("    Product Intermediate Key:\n");
    out.push_str(&format_certificate_info(
        &metadata.product_intermediate_key_certificate,
        "      ",
    ));
    out.push_str("    Product Signing Key:\n");
    out.push_str(&format_certificate_info(
        &metadata.product_signing_key_certificate,
        "      ",
    ));
    out
}

/// Format permanent attributes for human inspection.
pub fn format_permanent_attributes_info(attrs: &CertPermanentAttributes) -> String {
    let mut out = String::new();
    out.push_str("avb_cert permanent attributes:\n");
    let _ = writeln!(out, "    Version:               {}", attrs.version);
    let _ = writeln!(
        out,
        "    Root public key (sha1): {}",
        sha1_hex(&attrs.product_root_public_key)
    );
    let _ = writeln!(
        out,
        "    Product ID:            {}",
        bytes_to_hex(&attrs.product_id)
    );
    out
}

/// Resolve a built-in usage string from the mutually exclusive CLI flags.
pub fn resolve_builtin_usage(
    subject_is_intermediate_authority: bool,
    usage_for_unlock: bool,
) -> Result<&'static str> {
    match (subject_is_intermediate_authority, usage_for_unlock) {
        (true, false) => Ok(CERT_USAGE_INTERMEDIATE_AUTHORITY),
        (false, true) => Ok(CERT_USAGE_UNLOCK),
        (false, false) => Ok(CERT_USAGE_SIGNING),
        (true, true) => Err(DynoError::Validation(
            "usage options are mutually exclusive: cannot set both intermediate authority and unlock"
                .into(),
        )),
    }
}

/// SHA-256 of a usage string as embedded in certificates.
pub fn usage_hash(usage: &str) -> [u8; CERT_SHA256_DIGEST_SIZE] {
    sha256_array(usage.as_bytes())
}

/// SHA-256 of subject bytes as embedded in certificates.
pub fn subject_hash(subject: &[u8]) -> [u8; CERT_SHA256_DIGEST_SIZE] {
    sha256_array(subject)
}

/// Load a key from a filesystem path or embedded test key name.
pub fn load_cert_key(key_spec: &str) -> Result<AvbKey> {
    load_key_from_spec(key_spec)
}

fn validate_public_key_blob(blob: &[u8], field: &str) -> Result<()> {
    if blob.len() != CERT_PUBLIC_KEY_SIZE {
        return Err(DynoError::Validation(format!(
            "invalid {field} length: libavb_cert requires an RSA-4096 AVB public key blob of exactly {} bytes, got {} bytes",
            CERT_PUBLIC_KEY_SIZE,
            blob.len()
        )));
    }
    let key = AvbPublicKey::decode(blob)?;
    if key.num_bits != 4096 {
        return Err(DynoError::Validation(format!(
            "invalid {field}: expected RSA-4096 (4096 bits), got {} bits",
            key.num_bits
        )));
    }
    Ok(())
}

fn validate_signing_key(key: &AvbKey, field: &str, sign_options: &SignOptions) -> Result<()> {
    if key.bits() != 4096 {
        return Err(DynoError::Validation(format!(
            "invalid {field}: cert signatures require RSA-4096, got {} bits",
            key.bits()
        )));
    }
    let helper_present =
        sign_options.signing_helper.is_some() || sign_options.signing_helper_with_files.is_some();
    if !helper_present && !key.has_private_key() {
        return Err(DynoError::Validation(format!(
            "invalid {field}: private key material is required for signing unless a signing helper is supplied"
        )));
    }
    if helper_present && sign_options.key_path.is_none() {
        return Err(DynoError::Validation(format!(
            "invalid {field}: signing helper requires key_path in SignOptions"
        )));
    }
    Ok(())
}

fn sha256_array(data: &[u8]) -> [u8; CERT_SHA256_DIGEST_SIZE] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; CERT_SHA256_DIGEST_SIZE];
    out.copy_from_slice(&digest);
    out
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    bytes_to_hex(&hasher.finalize())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unix_time_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| DynoError::Tool(format!("system clock before UNIX epoch: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/cert")
            .join(name)
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    #[test]
    fn sizes_match_libavb_cert() {
        assert_eq!(CERT_SIGNED_DATA_SIZE, 1108);
        assert_eq!(CERTIFICATE_SIZE, 1620);
        assert_eq!(CERT_PERMANENT_ATTRIBUTES_SIZE, 1052);
        assert_eq!(CERT_METADATA_SIZE, 3244);
        assert_eq!(CERT_UNLOCK_CREDENTIAL_SIZE, 3756);
        assert_eq!(CERT_PUBLIC_KEY_SIZE, 1032);
        assert_eq!(CERT_RSA4096_SIGNATURE_SIZE, 512);
    }

    #[test]
    fn usage_hashes_match_libavb_cert_constants() {
        assert_eq!(usage_hash(CERT_USAGE_SIGNING), CERT_USAGE_HASH_SIGNING);
        assert_eq!(
            usage_hash(CERT_USAGE_INTERMEDIATE_AUTHORITY),
            CERT_USAGE_HASH_INTERMEDIATE_AUTHORITY
        );
        assert_eq!(usage_hash(CERT_USAGE_UNLOCK), CERT_USAGE_HASH_UNLOCK);
    }

    #[test]
    fn permanent_attributes_round_trip_and_fixture() {
        let expected = read_fixture("cert_permanent_attributes.bin");
        assert_eq!(expected.len(), CERT_PERMANENT_ATTRIBUTES_SIZE);

        let parsed = parse_permanent_attributes(&expected).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.product_id, [0u8; 16]);
        assert_eq!(parsed.encode().unwrap(), expected);

        let product_id = read_fixture("cert_product_id.bin");
        let prk = AvbKey::load_pem(&fixture("testkey_cert_prk.pem")).unwrap();
        let built = make_cert_permanent_attributes(&prk, &product_id).unwrap();
        assert_eq!(built, expected);
        assert_eq!(
            make_atx_permanent_attributes(&prk, &product_id).unwrap(),
            expected
        );
    }

    #[test]
    fn pik_certificate_matches_upstream_fixture() {
        let expected = read_fixture("cert_pik_certificate.bin");
        assert_eq!(expected.len(), CERTIFICATE_SIZE);

        let subject = b"fake PIK subject";
        let pik = AvbKey::load_pem(&fixture("testkey_cert_pik.pem")).unwrap();
        let prk = AvbKey::load_pem(&fixture("testkey_cert_prk.pem")).unwrap();
        let built = make_certificate(
            &pik,
            subject,
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            Some(&prk),
        )
        .unwrap();
        assert_eq!(built, expected);

        let parsed = parse_certificate(&built).unwrap();
        assert_eq!(parsed.signed_data.version, 1);
        assert_eq!(parsed.signed_data.key_version, 42);
        assert_eq!(
            parsed.signed_data.usage,
            CERT_USAGE_HASH_INTERMEDIATE_AUTHORITY
        );
        assert_eq!(parsed.signed_data.subject, subject_hash(subject));
        assert!(parsed.is_signed());
        assert_eq!(parsed.encode().unwrap(), expected);
    }

    #[test]
    fn psk_and_puk_certificates_match_fixtures() {
        let product_id = read_fixture("cert_product_id.bin");
        let pik = AvbKey::load_pem(&fixture("testkey_cert_pik.pem")).unwrap();

        let psk = AvbKey::load_pem(&fixture("testkey_cert_psk.pem")).unwrap();
        let psk_cert =
            make_certificate(&psk, &product_id, CERT_USAGE_SIGNING, Some(42), Some(&pik)).unwrap();
        assert_eq!(psk_cert, read_fixture("cert_psk_certificate.bin"));

        let puk = AvbKey::load_pem(&fixture("testkey_cert_puk.pem")).unwrap();
        let puk_cert =
            make_certificate(&puk, &product_id, CERT_USAGE_UNLOCK, Some(42), Some(&pik)).unwrap();
        assert_eq!(puk_cert, read_fixture("cert_puk_certificate.bin"));
    }

    #[test]
    fn metadata_round_trip_and_fixture() {
        let pik = read_fixture("cert_pik_certificate.bin");
        let psk = read_fixture("cert_psk_certificate.bin");
        let expected = read_fixture("cert_metadata.bin");
        let built = make_cert_metadata(&pik, &psk).unwrap();
        assert_eq!(built, expected);
        assert_eq!(make_atx_metadata(&pik, &psk).unwrap(), expected);

        let parsed = parse_metadata(&built).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.encode().unwrap(), expected);
        assert_eq!(
            parsed
                .product_intermediate_key_certificate
                .encode()
                .unwrap(),
            pik
        );
        assert_eq!(
            parsed.product_signing_key_certificate.encode().unwrap(),
            psk
        );
    }

    #[test]
    fn unlock_credential_matches_fixture() {
        let pik = read_fixture("cert_pik_certificate.bin");
        let puk_cert = read_fixture("cert_puk_certificate.bin");
        let challenge = read_fixture("cert_unlock_challenge.bin");
        let puk = AvbKey::load_pem(&fixture("testkey_cert_puk.pem")).unwrap();
        let built =
            make_cert_unlock_credential(&pik, &puk_cert, Some(&challenge), Some(&puk)).unwrap();
        assert_eq!(built, read_fixture("cert_unlock_credential.bin"));
        assert_eq!(built.len(), CERT_UNLOCK_CREDENTIAL_SIZE);

        let parsed = parse_unlock_credential(&built).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(
            parsed.challenge_signature.len(),
            CERT_RSA4096_SIGNATURE_SIZE
        );
        assert_eq!(parsed.encode().unwrap(), built);
    }

    #[test]
    fn unlock_credential_optional_challenge_signature() {
        let pik = read_fixture("cert_pik_certificate.bin");
        let puk_cert = read_fixture("cert_puk_certificate.bin");
        let built = make_cert_unlock_credential(&pik, &puk_cert, None, None).unwrap();
        assert_eq!(built.len(), CERT_UNLOCK_CREDENTIAL_WITHOUT_SIGNATURE_SIZE);
        let parsed = parse_unlock_credential(&built).unwrap();
        assert!(parsed.challenge_signature.is_empty());
    }

    #[test]
    fn unsigned_certificate_omits_signature() {
        let pik = AvbKey::load_pem(&fixture("testkey_cert_pik.pem")).unwrap();
        let built = make_certificate(
            &pik,
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            None,
        )
        .unwrap();
        assert_eq!(built.len(), CERT_SIGNED_DATA_SIZE);
        let parsed = parse_certificate(&built).unwrap();
        assert!(!parsed.is_signed());
        let fixture_bytes = read_fixture("cert_pik_certificate.bin");
        assert_eq!(built, fixture_bytes[..CERT_SIGNED_DATA_SIZE]);
    }

    #[test]
    fn rejects_wrong_sizes() {
        assert!(
            make_cert_permanent_attributes(
                &AvbKey::load_pem(&fixture("testkey_cert_prk.pem")).unwrap(),
                &[0u8; 15]
            )
            .is_err()
        );
        assert!(make_cert_metadata(&[0u8; 10], &read_fixture("cert_psk_certificate.bin")).is_err());
        assert!(parse_certificate(&[0u8; 100]).is_err());
        assert!(parse_metadata(&[0u8; 10]).is_err());
        assert!(parse_unlock_credential(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_non_rsa4096_subject_key() {
        let key = load_cert_key("testkey_rsa2048").unwrap();
        let err = make_certificate(&key, b"x", CERT_USAGE_SIGNING, Some(1), None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("1032") || msg.contains("RSA-4096") || msg.contains("4096"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn info_formatting_matches_avbtool_shape() {
        let metadata = parse_metadata(&read_fixture("cert_metadata.bin")).unwrap();
        let text = format_cert_metadata_info(&metadata);
        assert!(text.starts_with("avb_cert certificate:\n"));
        assert!(text.contains("Metadata version:        1\n"));
        assert!(text.contains("Product Intermediate Key:\n"));
        assert!(text.contains("Product Signing Key:\n"));
        assert!(text.contains("Version:               1\n"));
        assert!(text.contains("Key version:           42\n"));
        let pik = parse_certificate(&read_fixture("cert_pik_certificate.bin")).unwrap();
        assert!(text.contains(&sha1_hex(&pik.signed_data.public_key)));
    }

    #[test]
    fn little_endian_version_fields() {
        let cert = parse_certificate(&read_fixture("cert_pik_certificate.bin")).unwrap();
        let encoded = cert.encode().unwrap();
        assert_eq!(&encoded[0..4], &[1, 0, 0, 0]);
        let kv_off = CERT_SIGNED_DATA_SIZE - 8;
        assert_eq!(&encoded[kv_off..kv_off + 8], &[42, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn atx_aliases_point_at_same_constants() {
        assert_eq!(ATX_CERTIFICATE_SIZE, CERTIFICATE_SIZE);
        assert_eq!(ATX_USAGE_SIGNING, CERT_USAGE_SIGNING);
        assert_eq!(ATX_PUBLIC_KEY_SIZE, CERT_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn fixtures_resolve_under_repository_only() {
        let path = fixture("cert_pik_certificate.bin");
        assert!(
            path.exists(),
            "missing repository fixture: {}",
            path.display()
        );
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("tests") && path_str.contains("cert"),
            "fixture path escaped repository fixtures: {path_str}"
        );
        assert!(
            !path_str.contains("aosp-avb-main-kernel"),
            "absolute upstream fallback must not be used: {path_str}"
        );
    }

    #[test]
    fn subject_and_root_keys_may_be_public_only() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

        let product_id = read_fixture("cert_product_id.bin");
        let prk = AvbKey::load_pem(&fixture("testkey_cert_prk.pem")).unwrap();
        let private_pem = std::fs::read_to_string(fixture("testkey_cert_prk.pem")).unwrap();
        let private = rsa::RsaPrivateKey::from_pkcs8_pem(&private_pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(&private_pem))
            .unwrap();
        let public = private.to_public_key();
        let spki_pem = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_only = AvbKey::from_pem(&spki_pem).unwrap();
        assert!(!public_only.has_private_key());
        assert_eq!(public_only.encode_public_key(), prk.encode_public_key());

        let built = make_cert_permanent_attributes(&public_only, &product_id).unwrap();
        assert_eq!(built, read_fixture("cert_permanent_attributes.bin"));

        let unsigned = make_certificate(
            &public_only,
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            None,
        )
        .unwrap();
        assert_eq!(unsigned.len(), CERT_SIGNED_DATA_SIZE);
    }

    #[test]
    fn authority_and_unlock_signing_require_private_material_without_helper() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

        let private_pem = std::fs::read_to_string(fixture("testkey_cert_prk.pem")).unwrap();
        let private = rsa::RsaPrivateKey::from_pkcs8_pem(&private_pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(&private_pem))
            .unwrap();
        let public = private.to_public_key();
        let spki_pem = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let public_only = AvbKey::from_pem(&spki_pem).unwrap();
        assert!(!public_only.has_private_key());

        let subject = AvbKey::load_pem(&fixture("testkey_cert_pik.pem")).unwrap();
        let err = make_certificate(
            &subject,
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            Some(&public_only),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("private key material") || err.contains("public-only"),
            "unexpected error: {err}"
        );

        let pik = read_fixture("cert_pik_certificate.bin");
        let puk_cert = read_fixture("cert_puk_certificate.bin");
        let challenge = read_fixture("cert_unlock_challenge.bin");
        let unlock_err =
            make_cert_unlock_credential(&pik, &puk_cert, Some(&challenge), Some(&public_only))
                .unwrap_err()
                .to_string();
        assert!(
            unlock_err.contains("private key material") || unlock_err.contains("public-only"),
            "unexpected error: {unlock_err}"
        );
    }

    #[test]
    fn certificate_signing_helper_with_files_matches_builtin() {
        use std::fs;
        use std::io::Write;
        use std::sync::Mutex;

        static HELPER_LOCK: Mutex<()> = Mutex::new(());
        let _guard = HELPER_LOCK.lock().unwrap();

        let subject = AvbKey::load_pem(&fixture("testkey_cert_pik.pem")).unwrap();
        let authority = AvbKey::load_pem(&fixture("testkey_cert_prk.pem")).unwrap();
        let expected = make_certificate(
            &subject,
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            Some(&authority),
        )
        .unwrap();

        let signed_data = &expected[..CERT_SIGNED_DATA_SIZE];
        let signature = authority
            .sign(signed_data, CERT_SIGNATURE_ALGORITHM)
            .unwrap();
        let sig_path = std::env::temp_dir().join("avbtool-rs-cert-helper-sig.bin");
        fs::write(&sig_path, &signature).unwrap();

        let script_path = std::env::temp_dir().join("avbtool-rs-cert-helper.py");
        {
            let mut file = fs::File::create(&script_path).unwrap();
            writeln!(file, "#!/usr/bin/env python3").unwrap();
            writeln!(file, "import sys").unwrap();
            writeln!(file, "from pathlib import Path").unwrap();
            writeln!(file, "path = sys.argv[3]").unwrap();
            writeln!(file, "sig = Path(r\"{}\").read_bytes()", sig_path.display()).unwrap();
            writeln!(file, "Path(path).write_bytes(sig)").unwrap();
        }
        let launcher = std::env::temp_dir().join("avbtool-rs-cert-helper.cmd");
        {
            let mut file = fs::File::create(&launcher).unwrap();
            writeln!(file, "@echo off").unwrap();
            writeln!(file, "python \"{}\" %*", script_path.display()).unwrap();
        }

        let options = SignOptions {
            signing_helper: None,
            signing_helper_with_files: Some(launcher.clone()),
            key_path: Some(fixture("testkey_cert_prk.pem")),
        };
        let helper_built = make_certificate_with_options(
            &subject,
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            Some(&authority),
            &options,
        )
        .unwrap();
        assert_eq!(helper_built, expected);
        assert_eq!(helper_built, read_fixture("cert_pik_certificate.bin"));

        let from_paths = make_certificate_from_paths_with_options(
            fixture("testkey_cert_pik.pem"),
            b"fake PIK subject",
            CERT_USAGE_INTERMEDIATE_AUTHORITY,
            Some(42),
            Some(fixture("testkey_cert_prk.pem").as_path()),
            None,
            Some(launcher.clone()),
        )
        .unwrap();
        assert_eq!(from_paths, expected);

        let _ = fs::remove_file(&sig_path);
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_file(&launcher);
    }
}
