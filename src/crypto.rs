use crate::error::{AvbToolError as DynoError, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer as FipsSigner, Verifier as FipsVerifier};
use num_bigint_dig::{BigInt, Sign};
use num_integer::Integer;
use num_traits::Signed;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, traits::PrivateKeyParts, traits::PublicKeyParts};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
const MLDSA65_SIGNATURE_BYTES: usize = 3309;
const MLDSA87_SIGNATURE_BYTES: usize = 4627;
const MLDSA65_PRIVATE_KEY_BYTES: usize = 4032;
const MLDSA87_PRIVATE_KEY_BYTES: usize = 4896;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvbAlgorithm {
    pub name: &'static str,
    pub algorithm_type: u32,
    pub hash_name: &'static str,
    pub hash_num_bytes: usize,
    pub signature_num_bytes: usize,
    pub public_key_num_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct AvbPublicKey {
    pub num_bits: u32,
    pub modulus: BigUint,
}

/// Options for external signing helpers matching upstream avbtool protocols.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Path to a program that reads the padded message on stdin and writes the signature to stdout.
    pub signing_helper: Option<PathBuf>,
    /// Path to a program that signs via an in/out file path argument.
    pub signing_helper_with_files: Option<PathBuf>,
    /// Key path passed as the helper's key argument. Required when a helper is set.
    pub key_path: Option<PathBuf>,
}

/// RSA key material. Private material is required for signing; public-only keys are
/// supported for extract/encode paths used by cert subject and root authority flows.
pub struct AvbKey {
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
}

/// Loaded ML-DSA private key material for AVB algorithms MLDSA65/MLDSA87.
///
/// Private key bytes are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AvbMldsaKey {
    #[zeroize(skip)]
    algorithm_name: &'static str,
    #[zeroize(skip)]
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

/// Decoded ML-DSA public key in AvbMLDSAPublicKeyHeader + raw key form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvbMldsaPublicKey {
    pub algorithm_name: &'static str,
    pub raw_public_key: Vec<u8>,
}

impl AvbKey {
    pub fn load_pem(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn load_der(path: &Path) -> Result<Self> {
        let der = std::fs::read(path)?;
        Self::from_der(&der)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(private_key) =
            RsaPrivateKey::from_pkcs8_pem(pem).or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        {
            return Self::from_private(private_key);
        }
        if let Ok(public_key) =
            RsaPublicKey::from_public_key_pem(pem).or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
        {
            return Ok(Self {
                private_key: None,
                public_key,
            });
        }
        Err(DynoError::Tool("Failed to load RSA key".into()))
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        if let Ok(private_key) =
            RsaPrivateKey::from_pkcs8_der(der).or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
        {
            return Self::from_private(private_key);
        }
        if let Ok(public_key) =
            RsaPublicKey::from_public_key_der(der).or_else(|_| RsaPublicKey::from_pkcs1_der(der))
        {
            return Ok(Self {
                private_key: None,
                public_key,
            });
        }
        Err(DynoError::Tool("Failed to load RSA DER key".into()))
    }

    fn from_private(private_key: RsaPrivateKey) -> Result<Self> {
        let public_key = private_key.to_public_key();
        Ok(Self {
            private_key: Some(private_key),
            public_key,
        })
    }

    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    pub fn bits(&self) -> u32 {
        (self.public_key.size() * 8) as u32
    }

    pub fn algorithm(&self) -> Result<String> {
        default_algorithm_name_for_bits(self.bits()).map(str::to_string)
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        let n = self.public_key.n();
        let num_bits = self.bits();

        let b = BigUint::from(1u64 << 32);
        let n_mod_b = n % &b;
        let n0inv = if let Some(inv) = mod_inverse(&n_mod_b, &b) {
            let n0inv_val = &b - (inv % &b);
            let bytes = n0inv_val.to_bytes_le();
            let mut buf = [0u8; 4];
            let len = std::cmp::min(bytes.len(), 4);
            buf[..len].copy_from_slice(&bytes[..len]);
            u32::from_le_bytes(buf)
        } else {
            0
        };

        let r = BigUint::from(1u8) << n.bits();
        let rr = (&r * &r) % n;

        let mut ret = Vec::new();
        ret.extend_from_slice(&num_bits.to_be_bytes());
        ret.extend_from_slice(&n0inv.to_be_bytes());
        ret.extend(encode_biguint(n, num_bits / 8));
        ret.extend(encode_biguint(&rr, num_bits / 8));
        ret
    }

    pub fn public_key_sha1(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(self.encode_public_key());
        format!("{:x}", hasher.finalize())
    }

    pub fn sign(&self, data: &[u8], algorithm_name: &str) -> Result<Vec<u8>> {
        self.sign_with_options(data, algorithm_name, &SignOptions::default())
    }

    /// Sign using either local RSA or an external helper protocol.
    ///
    /// Helper semantics match upstream RSA signing_helper /
    /// signing_helper_with_files: the helper receives the PKCS#1 padded
    /// digest (not the raw message), must exit 0, and must return exactly
    /// signature_num_bytes bytes. There is no silent fallback between helper
    /// modes or to local signing.
    pub fn sign_with_options(
        &self,
        data: &[u8],
        algorithm_name: &str,
        options: &SignOptions,
    ) -> Result<Vec<u8>> {
        let algorithm = lookup_algorithm_by_name(algorithm_name)?;
        if algorithm.name == "NONE" {
            return Ok(Vec::new());
        }
        if !is_rsa_algorithm(algorithm.name) {
            return Err(DynoError::Tool(format!(
                "RSA key cannot sign with algorithm {}",
                algorithm_name
            )));
        }
        if self.bits() as usize != algorithm.signature_num_bytes * 8 {
            return Err(DynoError::Tool(format!(
                "RSA Key size of key ({} bits) does not match key size ({} bits) of given algorithm {}.",
                self.bits(),
                algorithm.signature_num_bytes * 8,
                algorithm_name
            )));
        }

        let mut to_sign = build_pkcs1_message(algorithm, data)?;
        let signature = if options.signing_helper_with_files.is_some()
            || options.signing_helper.is_some()
        {
            let key_path = options.key_path.as_ref().ok_or_else(|| {
                DynoError::Tool("signing helper requires key_path in SignOptions".into())
            })?;
            run_rsa_signing_helper(algorithm, &to_sign, options, key_path)?
        } else {
            let private_key = self.private_key.as_ref().ok_or_else(|| {
                DynoError::Tool("RSA public-only key cannot sign without private material".into())
            })?;
            let n = private_key.n();
            let d = private_key.d();
            let m = BigUint::from_bytes_be(&to_sign);
            let s = m.modpow(d, n);
            encode_biguint(&s, self.bits() / 8)
        };
        to_sign.fill(0);

        if signature.len() != algorithm.signature_num_bytes {
            return Err(DynoError::Tool(
                "Error signing: Invalid length of signature".into(),
            ));
        }
        Ok(signature)
    }

    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data, &self.algorithm()?)
    }
}

impl AvbPublicKey {
    pub fn decode(blob: &[u8]) -> Result<Self> {
        if blob.len() < 8 {
            return Err(DynoError::Tool("AVB public key blob too small".into()));
        }
        let mut cursor = Cursor::new(blob);
        let num_bits = cursor.read_u32::<BigEndian>()?;
        let _n0inv = cursor.read_u32::<BigEndian>()?;
        let word_len = (num_bits as usize) / 8;
        let expected_size = 8 + word_len * 2;
        if blob.len() != expected_size {
            return Err(DynoError::Tool(format!(
                "AVB public key blob size mismatch: expected {}, got {}",
                expected_size,
                blob.len()
            )));
        }
        let modulus = BigUint::from_bytes_be(&blob[8..8 + word_len]);
        Ok(Self { num_bits, modulus })
    }

    pub fn verify(&self, algorithm: AvbAlgorithm, signature: &[u8], data: &[u8]) -> Result<bool> {
        if algorithm.name == "NONE" {
            return Ok(true);
        }
        if !is_rsa_algorithm(algorithm.name) {
            return Err(DynoError::Tool(format!(
                "RSA public key cannot verify algorithm {}",
                algorithm.name
            )));
        }
        if signature.len() != algorithm.signature_num_bytes {
            return Ok(false);
        }
        if self.num_bits as usize != algorithm.signature_num_bytes * 8 {
            return Ok(false);
        }

        let exponent = BigUint::from(65537u32);
        let signature_value = BigUint::from_bytes_be(signature);
        let message = signature_value.modpow(&exponent, &self.modulus);
        let decoded = encode_biguint(&message, self.num_bits / 8);
        let expected = build_pkcs1_message(algorithm, data)?;
        Ok(decoded == expected)
    }
}

impl AvbMldsaKey {
    pub fn load_pem(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn load_der(path: &Path) -> Result<Self> {
        let der = std::fs::read(path)?;
        Self::from_pkcs8_der(&der)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut der = decode_pem_labeled(pem, PemKind::PrivateKey)?;
        let result = Self::from_pkcs8_der(&der);
        der.zeroize();
        result
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let algorithm_name = detect_mldsa_algorithm_from_private_pkcs8(der)?;
        let (mut seed, mut expanded) = parse_mldsa_pkcs8_private_key(der)?;
        let result = match algorithm_name {
            "MLDSA65" => {
                let private_key = resolve_mldsa65_private_key(&seed, expanded.as_deref())?;
                let public_key = mldsa65_public_from_private(&private_key)?;
                Ok(Self {
                    algorithm_name,
                    public_key,
                    private_key,
                })
            }
            "MLDSA87" => {
                let private_key = resolve_mldsa87_private_key(&seed, expanded.as_deref())?;
                let public_key = mldsa87_public_from_private(&private_key)?;
                Ok(Self {
                    algorithm_name,
                    public_key,
                    private_key,
                })
            }
            other => Err(DynoError::Tool(format!(
                "Unsupported ML-DSA algorithm in key: {}",
                other
            ))),
        };
        seed.zeroize();
        if let Some(ref mut expanded_bytes) = expanded {
            expanded_bytes.zeroize();
        }
        result
    }

    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm_name
    }

    pub fn raw_public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        encode_mldsa_public_key_blob(&self.public_key)
    }

    pub fn public_key_sha1(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(self.encode_public_key());
        format!("{:x}", hasher.finalize())
    }

    pub fn sign(&self, data: &[u8], algorithm_name: &str) -> Result<Vec<u8>> {
        self.sign_with_options(data, algorithm_name, &SignOptions::default())
    }

    /// Sign using pure ML-DSA (empty context) or an external helper.
    ///
    /// Helper order for ML-DSA matches upstream: signing_helper first, else
    /// signing_helper_with_files. Helpers receive the raw message bytes.
    pub fn sign_with_options(
        &self,
        data: &[u8],
        algorithm_name: &str,
        options: &SignOptions,
    ) -> Result<Vec<u8>> {
        let algorithm = lookup_algorithm_by_name(algorithm_name)?;
        if !is_mldsa_algorithm(algorithm.name) {
            return Err(DynoError::Tool(format!(
                "ML-DSA key cannot sign with algorithm {}",
                algorithm_name
            )));
        }
        if self.algorithm_name != algorithm.name {
            return Err(DynoError::Tool(format!(
                "ML-DSA Key size of key ({} bytes) does not match key size ({} bytes) of given algorithm {}.",
                self.public_key.len(),
                algorithm.public_key_num_bytes.saturating_sub(4),
                algorithm_name
            )));
        }
        if self.public_key.len() != algorithm.public_key_num_bytes - 4 {
            return Err(DynoError::Tool(format!(
                "ML-DSA Key size of key ({} bytes) does not match key size ({} bytes) of given algorithm {}.",
                self.public_key.len(),
                algorithm.public_key_num_bytes - 4,
                algorithm_name
            )));
        }

        let signature =
            if options.signing_helper.is_some() || options.signing_helper_with_files.is_some() {
                let key_path = options.key_path.as_ref().ok_or_else(|| {
                    DynoError::Tool("signing helper requires key_path in SignOptions".into())
                })?;
                run_mldsa_signing_helper(algorithm, data, options, key_path)?
            } else {
                match algorithm.name {
                    "MLDSA65" => {
                        let mut sk_bytes = [0u8; MLDSA65_PRIVATE_KEY_BYTES];
                        sk_bytes.copy_from_slice(&self.private_key);
                        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
                            sk_bytes.zeroize();
                            DynoError::Tool(format!("Failed to load ML-DSA-65 private key: {e}"))
                        })?;
                        sk_bytes.zeroize();
                        sk.try_sign(data, &[])
                            .map_err(|e| {
                                DynoError::Tool(format!("Error signing with ML-DSA key: {e}"))
                            })?
                            .to_vec()
                    }
                    "MLDSA87" => {
                        let mut sk_bytes = [0u8; MLDSA87_PRIVATE_KEY_BYTES];
                        sk_bytes.copy_from_slice(&self.private_key);
                        let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
                            sk_bytes.zeroize();
                            DynoError::Tool(format!("Failed to load ML-DSA-87 private key: {e}"))
                        })?;
                        sk_bytes.zeroize();
                        sk.try_sign(data, &[])
                            .map_err(|e| {
                                DynoError::Tool(format!("Error signing with ML-DSA key: {e}"))
                            })?
                            .to_vec()
                    }
                    other => {
                        return Err(DynoError::UnsupportedOperation(format!(
                            "Unsupported AVB algorithm {}",
                            other
                        )));
                    }
                }
            };

        if signature.len() != algorithm.signature_num_bytes {
            return Err(DynoError::Tool(
                "Error signing: Invalid length of signature".into(),
            ));
        }
        Ok(signature)
    }
}

impl AvbMldsaPublicKey {
    pub fn load_pem(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn load_der(path: &Path) -> Result<Self> {
        let der = std::fs::read(path)?;
        Self::from_spki_der(&der)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let der = decode_pem_labeled(pem, PemKind::PublicKey)?;
        Self::from_spki_der(&der)
    }

    /// Load an ML-DSA SubjectPublicKeyInfo (SPKI) public key from DER.
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        let (algorithm_name, raw_public_key) = parse_mldsa_spki_public_key(der)?;
        let algorithm = lookup_algorithm_by_name(algorithm_name)?;
        let expected_raw = algorithm.public_key_num_bytes - 4;
        // April 2026 raw key length fix: public keys must match FIPS-204 sizes exactly.
        if raw_public_key.len() != expected_raw {
            return Err(DynoError::Tool(format!(
                "Unexpected ML-DSA key length: expected {}, got {}",
                expected_raw,
                raw_public_key.len()
            )));
        }
        Ok(Self {
            algorithm_name: algorithm.name,
            raw_public_key,
        })
    }

    pub fn decode(algorithm_name: &str, blob: &[u8]) -> Result<Self> {
        let algorithm = lookup_algorithm_by_name(algorithm_name)?;
        if !is_mldsa_algorithm(algorithm.name) {
            return Err(DynoError::Tool(format!(
                "Unsupported ML-DSA algorithm: {}",
                algorithm_name
            )));
        }
        if blob.len() < 4 {
            return Err(DynoError::Tool(
                "AVB ML-DSA public key blob too small".into(),
            ));
        }
        let mut cursor = Cursor::new(blob);
        let key_num_bytes = cursor.read_u32::<BigEndian>()? as usize;
        let expected_raw = algorithm.public_key_num_bytes - 4;
        // April 2026 decode fix: require exact be32(raw length) and exact total size.
        if key_num_bytes != expected_raw {
            return Err(DynoError::Tool(format!(
                "Unexpected ML-DSA key length: expected {}, got {}",
                expected_raw, key_num_bytes
            )));
        }
        if blob.len() != 4 + key_num_bytes {
            return Err(DynoError::Tool(format!(
                "ML-DSA public key blob size mismatch: expected {}, got {}",
                4 + key_num_bytes,
                blob.len()
            )));
        }
        let raw_public_key = blob[4..].to_vec();
        Ok(Self {
            algorithm_name: algorithm.name,
            raw_public_key,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_mldsa_public_key_blob(&self.raw_public_key)
    }

    pub fn verify(&self, algorithm: AvbAlgorithm, signature: &[u8], data: &[u8]) -> Result<bool> {
        if algorithm.name != self.algorithm_name {
            return Err(DynoError::Tool(format!(
                "Key size of key ({} bytes) does not match key size ({} bytes) of given algorithm {}.",
                self.raw_public_key.len(),
                algorithm.public_key_num_bytes.saturating_sub(4),
                algorithm.name
            )));
        }
        if self.raw_public_key.len() != algorithm.public_key_num_bytes - 4 {
            return Err(DynoError::Tool(format!(
                "Key size of key ({} bytes) does not match key size ({} bytes) of given algorithm {}.",
                self.raw_public_key.len(),
                algorithm.public_key_num_bytes - 4,
                algorithm.name
            )));
        }
        if signature.len() != algorithm.signature_num_bytes {
            return Ok(false);
        }

        match algorithm.name {
            "MLDSA65" => {
                let mut pk_bytes = [0u8; MLDSA65_PUBLIC_KEY_BYTES];
                pk_bytes.copy_from_slice(&self.raw_public_key);
                let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
                    DynoError::Tool(format!("Failed to decode ML-DSA-65 public key: {e}"))
                })?;
                let mut sig = [0u8; MLDSA65_SIGNATURE_BYTES];
                sig.copy_from_slice(signature);
                Ok(pk.verify(data, &sig, &[]))
            }
            "MLDSA87" => {
                let mut pk_bytes = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
                pk_bytes.copy_from_slice(&self.raw_public_key);
                let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes).map_err(|e| {
                    DynoError::Tool(format!("Failed to decode ML-DSA-87 public key: {e}"))
                })?;
                let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
                sig.copy_from_slice(signature);
                Ok(pk.verify(data, &sig, &[]))
            }
            other => Err(DynoError::UnsupportedOperation(format!(
                "Unsupported AVB algorithm {}",
                other
            ))),
        }
    }
}

/// Pure-Rust builds always support ML-DSA; no OpenSSL runtime is required.
pub fn check_mldsa_support() -> bool {
    true
}

pub fn get_embedded_key(name: &str) -> Option<&'static str> {
    match name {
        "testkey_rsa2048" => Some(include_str!("keys/testkey_rsa2048.pem")),
        "testkey_rsa2048_2" => Some(include_str!("keys/testkey_rsa2048_2.pem")),
        "testkey_rsa4096" => Some(include_str!("keys/testkey_rsa4096.pem")),
        "testkey_rsa8192" => Some(include_str!("keys/testkey_rsa8192.pem")),
        "testkey_mldsa65" => Some(include_str!("keys/testkey_mldsa65.pem")),
        "testkey_mldsa87" => Some(include_str!("keys/testkey_mldsa87.pem")),
        _ => None,
    }
}

pub fn load_key_from_spec(key_spec: &str) -> Result<AvbKey> {
    if let Some(pem) = get_embedded_key(key_spec) {
        if key_spec.contains("mldsa") {
            return Err(DynoError::Tool(format!(
                "Key {} is ML-DSA; use load_mldsa_key_from_spec instead",
                key_spec
            )));
        }
        AvbKey::from_pem(pem)
    } else {
        let path = Path::new(key_spec);
        AvbKey::load_pem(path).or_else(|_| AvbKey::load_der(path))
    }
}

pub fn load_mldsa_key_from_spec(key_spec: &str) -> Result<AvbMldsaKey> {
    if let Some(pem) = get_embedded_key(key_spec) {
        AvbMldsaKey::from_pem(pem)
    } else {
        AvbMldsaKey::load_pem(Path::new(key_spec))
    }
}

/// Load either an RSA or ML-DSA key and return its AVB-encoded public key.
///
/// Accepts RSA private/public PEM/DER and ML-DSA private PKCS#8 or public SPKI
/// PEM/DER (AOSP/OpenSSL style), matching upstream extract_public_key semantics.
pub fn extract_public_key(key_spec: &str) -> Result<Vec<u8>> {
    if let Some(pem) = get_embedded_key(key_spec) {
        if let Ok(rsa) = AvbKey::from_pem(pem) {
            return Ok(rsa.encode_public_key());
        }
        if let Ok(mldsa_private) = AvbMldsaKey::from_pem(pem) {
            return Ok(mldsa_private.encode_public_key());
        }
        return Ok(AvbMldsaPublicKey::from_pem(pem)?.encode());
    }

    let path = Path::new(key_spec);
    if let Ok(rsa) = AvbKey::load_pem(path).or_else(|_| AvbKey::load_der(path)) {
        return Ok(rsa.encode_public_key());
    }
    if let Ok(mldsa_private) = AvbMldsaKey::load_pem(path).or_else(|_| AvbMldsaKey::load_der(path))
    {
        return Ok(mldsa_private.encode_public_key());
    }
    if let Ok(mldsa_public) =
        AvbMldsaPublicKey::load_pem(path).or_else(|_| AvbMldsaPublicKey::load_der(path))
    {
        return Ok(mldsa_public.encode());
    }
    Err(DynoError::Tool(format!(
        "Failed to load public key from {}",
        key_spec
    )))
}

pub fn extract_public_key_digest(key_spec: &str) -> Result<String> {
    let public_key = extract_public_key(key_spec)?;
    let digest = Sha256::digest(public_key);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn lookup_algorithm_by_name(name: &str) -> Result<AvbAlgorithm> {
    match name {
        "NONE" => Ok(AvbAlgorithm {
            name: "NONE",
            algorithm_type: 0,
            hash_name: "",
            hash_num_bytes: 0,
            signature_num_bytes: 0,
            public_key_num_bytes: 0,
        }),
        "SHA256_RSA2048" => Ok(AvbAlgorithm {
            name: "SHA256_RSA2048",
            algorithm_type: 1,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 256,
            public_key_num_bytes: 8 + 2 * 2048 / 8,
        }),
        "SHA256_RSA4096" => Ok(AvbAlgorithm {
            name: "SHA256_RSA4096",
            algorithm_type: 2,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 512,
            public_key_num_bytes: 8 + 2 * 4096 / 8,
        }),
        "SHA256_RSA8192" => Ok(AvbAlgorithm {
            name: "SHA256_RSA8192",
            algorithm_type: 3,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 1024,
            public_key_num_bytes: 8 + 2 * 8192 / 8,
        }),
        "SHA512_RSA2048" => Ok(AvbAlgorithm {
            name: "SHA512_RSA2048",
            algorithm_type: 4,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 256,
            public_key_num_bytes: 8 + 2 * 2048 / 8,
        }),
        "SHA512_RSA4096" => Ok(AvbAlgorithm {
            name: "SHA512_RSA4096",
            algorithm_type: 5,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 512,
            public_key_num_bytes: 8 + 2 * 4096 / 8,
        }),
        "SHA512_RSA8192" => Ok(AvbAlgorithm {
            name: "SHA512_RSA8192",
            algorithm_type: 6,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 1024,
            public_key_num_bytes: 8 + 2 * 8192 / 8,
        }),
        // April 2026 AVB key-size constants: header(be32 raw length) + FIPS-204 raw key.
        "MLDSA65" => Ok(AvbAlgorithm {
            name: "MLDSA65",
            algorithm_type: 7,
            hash_name: "",
            hash_num_bytes: 0,
            signature_num_bytes: MLDSA65_SIGNATURE_BYTES,
            public_key_num_bytes: 4 + MLDSA65_PUBLIC_KEY_BYTES,
        }),
        "MLDSA87" => Ok(AvbAlgorithm {
            name: "MLDSA87",
            algorithm_type: 8,
            hash_name: "",
            hash_num_bytes: 0,
            signature_num_bytes: MLDSA87_SIGNATURE_BYTES,
            public_key_num_bytes: 4 + MLDSA87_PUBLIC_KEY_BYTES,
        }),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB algorithm {}",
            other
        ))),
    }
}

pub fn lookup_algorithm_by_type(algorithm_type: u32) -> Result<AvbAlgorithm> {
    match algorithm_type {
        0 => lookup_algorithm_by_name("NONE"),
        1 => lookup_algorithm_by_name("SHA256_RSA2048"),
        2 => lookup_algorithm_by_name("SHA256_RSA4096"),
        3 => lookup_algorithm_by_name("SHA256_RSA8192"),
        4 => lookup_algorithm_by_name("SHA512_RSA2048"),
        5 => lookup_algorithm_by_name("SHA512_RSA4096"),
        6 => lookup_algorithm_by_name("SHA512_RSA8192"),
        7 => lookup_algorithm_by_name("MLDSA65"),
        8 => lookup_algorithm_by_name("MLDSA87"),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB algorithm type {}",
            other
        ))),
    }
}

pub fn default_algorithm_name_for_bits(bits: u32) -> Result<&'static str> {
    match bits {
        2048 => Ok("SHA256_RSA2048"),
        4096 => Ok("SHA256_RSA4096"),
        8192 => Ok("SHA256_RSA8192"),
        _ => Err(DynoError::Tool(format!(
            "No standard AVB algorithm for {} bits",
            bits
        ))),
    }
}

pub fn compute_hash_for_algorithm(algorithm: AvbAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm.hash_name {
        "" => Ok(Vec::new()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB hash algorithm {}",
            other
        ))),
    }
}

pub fn round_to_multiple(number: u64, size: u64) -> u64 {
    let remainder = number % size;
    if remainder == 0 {
        number
    } else {
        number + size - remainder
    }
}

pub fn round_to_pow2(number: usize) -> usize {
    if number <= 1 {
        1
    } else {
        1usize << (usize::BITS as usize - (number - 1).leading_zeros() as usize)
    }
}

pub fn is_rsa_algorithm(name: &str) -> bool {
    matches!(
        name,
        "SHA256_RSA2048"
            | "SHA256_RSA4096"
            | "SHA256_RSA8192"
            | "SHA512_RSA2048"
            | "SHA512_RSA4096"
            | "SHA512_RSA8192"
    )
}

pub fn is_mldsa_algorithm(name: &str) -> bool {
    matches!(name, "MLDSA65" | "MLDSA87")
}

fn run_rsa_signing_helper(
    algorithm: AvbAlgorithm,
    padded_message: &[u8],
    options: &SignOptions,
    key_path: &Path,
) -> Result<Vec<u8>> {
    // Upstream RSA prefers signing_helper_with_files when provided.
    if let Some(helper) = options.signing_helper_with_files.as_ref() {
        return run_signing_helper_with_files(
            helper,
            algorithm.name,
            key_path,
            padded_message,
            "Error signing with RSA key",
        );
    }
    if let Some(helper) = options.signing_helper.as_ref() {
        return run_signing_helper_stdin(
            helper,
            algorithm.name,
            key_path,
            padded_message,
            "Error signing with RSA key",
        );
    }
    Err(DynoError::Tool("No signing helper configured".into()))
}

fn run_mldsa_signing_helper(
    algorithm: AvbAlgorithm,
    message: &[u8],
    options: &SignOptions,
    key_path: &Path,
) -> Result<Vec<u8>> {
    // Upstream ML-DSA prefers signing_helper when provided.
    if let Some(helper) = options.signing_helper.as_ref() {
        return run_signing_helper_stdin(
            helper,
            algorithm.name,
            key_path,
            message,
            "Error signing with ML-DSA key",
        );
    }
    if let Some(helper) = options.signing_helper_with_files.as_ref() {
        return run_signing_helper_with_files(
            helper,
            algorithm.name,
            key_path,
            message,
            "Error signing with ML-DSA key",
        );
    }
    Err(DynoError::Tool("No signing helper configured".into()))
}

fn run_signing_helper_stdin(
    helper: &Path,
    algorithm_name: &str,
    key_path: &Path,
    input: &[u8],
    error_prefix: &str,
) -> Result<Vec<u8>> {
    let mut child = Command::new(helper)
        .arg(algorithm_name)
        .arg(key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DynoError::Tool(format!("{error_prefix}: failed to spawn helper: {e}")))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| DynoError::Tool(format!("{error_prefix}: missing helper stdin")))?;
        stdin.write_all(input).map_err(|e| {
            DynoError::Tool(format!("{error_prefix}: failed writing helper stdin: {e}"))
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| DynoError::Tool(format!("{error_prefix}: helper wait failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DynoError::Tool(format!(
            "{error_prefix}: {}",
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

fn run_signing_helper_with_files(
    helper: &Path,
    algorithm_name: &str,
    key_path: &Path,
    input: &[u8],
    error_prefix: &str,
) -> Result<Vec<u8>> {
    let temp_path = make_temp_path("avbtool-rs-sign")?;
    let _guard = TempPathGuard(temp_path.clone());
    {
        let mut file = std::fs::File::create(&temp_path).map_err(|e| {
            DynoError::Tool(format!("{error_prefix}: failed creating temp file: {e}"))
        })?;
        file.write_all(input).map_err(|e| {
            DynoError::Tool(format!("{error_prefix}: failed writing temp file: {e}"))
        })?;
        file.flush().map_err(|e| {
            DynoError::Tool(format!("{error_prefix}: failed flushing temp file: {e}"))
        })?;
    }

    let status = Command::new(helper)
        .arg(algorithm_name)
        .arg(key_path)
        .arg(&temp_path)
        .status()
        .map_err(|e| DynoError::Tool(format!("{error_prefix}: failed to spawn helper: {e}")))?;
    if !status.success() {
        return Err(DynoError::Tool(error_prefix.into()));
    }

    let mut file = std::fs::File::open(&temp_path)
        .map_err(|e| DynoError::Tool(format!("{error_prefix}: failed opening temp file: {e}")))?;
    let mut signature = Vec::new();
    file.read_to_end(&mut signature)
        .map_err(|e| DynoError::Tool(format!("{error_prefix}: failed reading temp file: {e}")))?;
    Ok(signature)
}

struct TempPathGuard(PathBuf);

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn make_temp_path(prefix: &str) -> Result<PathBuf> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| DynoError::Tool(format!("Failed generating temp path: {e}")))?;
    let name = format!(
        "{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        prefix, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    );
    Ok(std::env::temp_dir().join(name))
}

fn encode_mldsa_public_key_blob(raw_public_key: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(4 + raw_public_key.len());
    ret.write_u32::<BigEndian>(raw_public_key.len() as u32)
        .expect("vec write");
    ret.extend_from_slice(raw_public_key);
    ret
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PemKind {
    PrivateKey,
    PublicKey,
}

fn decode_pem_labeled(pem: &str, kind: PemKind) -> Result<Vec<u8>> {
    let (begin, end) = match kind {
        PemKind::PrivateKey => ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        PemKind::PublicKey => ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
    };

    let mut b64 = String::new();
    let mut in_body = false;
    let mut saw_begin = false;
    let mut saw_end = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == begin {
            if saw_begin {
                return Err(DynoError::Tool(
                    "PEM contains multiple BEGIN markers".into(),
                ));
            }
            saw_begin = true;
            in_body = true;
            continue;
        }
        if line == end {
            if !in_body {
                return Err(DynoError::Tool("PEM END without BEGIN".into()));
            }
            saw_end = true;
            break;
        }
        if line.starts_with("-----BEGIN ") || line.starts_with("-----END ") {
            // Reject mismatched labels rather than silently accepting them.
            if in_body {
                return Err(DynoError::Tool(
                    "Unexpected PEM boundary inside body".into(),
                ));
            }
            continue;
        }
        if in_body {
            b64.push_str(line);
        }
    }
    if !saw_begin || !saw_end {
        return Err(DynoError::Tool(match kind {
            PemKind::PrivateKey => "PEM private key body missing".into(),
            PemKind::PublicKey => "PEM public key body missing".into(),
        }));
    }
    if b64.is_empty() {
        return Err(DynoError::Tool("PEM body is empty".into()));
    }
    decode_base64(&b64)
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 256] = &{
        let mut t = [0xffu8; 256];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = 26 + i;
            i += 1;
        }
        i = 0;
        while i < 10 {
            t[(b'0' + i) as usize] = 52 + i;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let filtered: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(4) {
        return Err(DynoError::Tool("Invalid base64 length".into()));
    }

    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    let chunks = filtered.len() / 4;
    for (chunk_idx, chunk) in filtered.chunks_exact(4).enumerate() {
        let is_last = chunk_idx + 1 == chunks;
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if !is_last {
                    return Err(DynoError::Tool("Invalid base64 padding placement".into()));
                }
                if i < 2 {
                    return Err(DynoError::Tool("Invalid base64 padding".into()));
                }
                pad += 1;
                vals[i] = 0;
                continue;
            }
            if pad > 0 {
                return Err(DynoError::Tool("Invalid base64 data after padding".into()));
            }
            let v = TABLE[c as usize];
            if v == 0xff {
                return Err(DynoError::Tool("Invalid base64 character".into()));
            }
            vals[i] = v;
        }
        if pad > 2 {
            return Err(DynoError::Tool("Invalid base64 padding length".into()));
        }
        if pad > 0 {
            // Reject non-zero leftover bits in padded characters.
            if pad == 1 && (vals[2] & 0x03) != 0 {
                return Err(DynoError::Tool("Invalid base64 trailing bits".into()));
            }
            if pad == 2 && (vals[1] & 0x0f) != 0 {
                return Err(DynoError::Tool("Invalid base64 trailing bits".into()));
            }
        }

        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

fn mldsa_algorithm_from_oid_value(oid: &[u8]) -> Result<&'static str> {
    // Exact OID values only (no ambiguous prefix / substring matching).
    // id-ml-dsa-65 = 2.16.840.1.101.3.4.3.18
    // id-ml-dsa-87 = 2.16.840.1.101.3.4.3.19
    match oid {
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12] => Ok("MLDSA65"),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13] => Ok("MLDSA87"),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11] => Err(DynoError::Tool(
            "ML-DSA-44 keys are not supported by AVB".into(),
        )),
        _ => Err(DynoError::Tool("Unexpected key type, not ML-DSA".into())),
    }
}

fn parse_algorithm_identifier(alg: &[u8]) -> Result<&'static str> {
    let mut offset = 0;
    let (tag, oid_value) = read_tlv(alg, &mut offset)?;
    if tag != 0x06 {
        return Err(DynoError::Tool(
            "AlgorithmIdentifier missing OBJECT IDENTIFIER".into(),
        ));
    }
    // ML-DSA AlgorithmIdentifier must not include parameters.
    if offset != alg.len() {
        return Err(DynoError::Tool(
            "Unexpected AlgorithmIdentifier parameters for ML-DSA".into(),
        ));
    }
    mldsa_algorithm_from_oid_value(oid_value)
}

fn detect_mldsa_algorithm_from_private_pkcs8(der: &[u8]) -> Result<&'static str> {
    let body = expect_complete_tlv(der, 0x30)?;
    let mut offset = 0;
    let (_, version) = read_tlv(body, &mut offset)?;
    if version != [0x00] {
        return Err(DynoError::Tool("Unsupported PKCS#8 version".into()));
    }
    let (tag, alg) = read_tlv(body, &mut offset)?;
    if tag != 0x30 {
        return Err(DynoError::Tool(
            "PKCS#8 AlgorithmIdentifier is not a SEQUENCE".into(),
        ));
    }
    parse_algorithm_identifier(alg)
}

fn parse_mldsa_pkcs8_private_key(der: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    // PKCS#8 PrivateKeyInfo:
    // SEQUENCE { version, AlgorithmIdentifier, OCTET STRING privateKey, ... }
    let body = expect_complete_tlv(der, 0x30)?;
    let mut offset = 0;
    let (_, version) = read_tlv(body, &mut offset)?;
    if version != [0x00] {
        return Err(DynoError::Tool("Unsupported PKCS#8 version".into()));
    }
    let (tag, alg) = read_tlv(body, &mut offset)?;
    if tag != 0x30 {
        return Err(DynoError::Tool(
            "PKCS#8 AlgorithmIdentifier is not a SEQUENCE".into(),
        ));
    }
    // Validate OID strictly (rejects ambiguous / non-ML-DSA OIDs).
    let _algorithm_name = parse_algorithm_identifier(alg)?;
    let (tag, private_key_octets) = read_tlv(body, &mut offset)?;
    if tag != 0x04 {
        return Err(DynoError::Tool(
            "PKCS#8 privateKey is not an OCTET STRING".into(),
        ));
    }
    // Optional attributes ([0] IMPLICIT) may follow; reject any other trailing tag.
    if offset < body.len() {
        let (tag, _attrs) = read_tlv(body, &mut offset)?;
        if tag != 0xa0 {
            return Err(DynoError::Tool(
                "Unexpected trailing data in PKCS#8 PrivateKeyInfo".into(),
            ));
        }
        if offset != body.len() {
            return Err(DynoError::Tool(
                "Unexpected trailing data after PKCS#8 attributes".into(),
            ));
        }
    }

    // AOSP/OpenSSL fixtures wrap seed (+ optional expanded key) in a SEQUENCE.
    // RustCrypto seed-only form uses CHOICE seed [0] OCTET STRING.
    if private_key_octets.first() == Some(&0x30) {
        let inner = expect_complete_tlv(private_key_octets, 0x30)?;
        let mut i = 0;
        let mut seed = None;
        let mut expanded = None;
        while i < inner.len() {
            let (tag, value) = read_tlv(inner, &mut i)?;
            if tag != 0x04 {
                return Err(DynoError::Tool(
                    "Unsupported element in ML-DSA PKCS#8 private key SEQUENCE".into(),
                ));
            }
            if value.len() == 32 && seed.is_none() {
                seed = Some(value.to_vec());
            } else if expanded.is_none() {
                expanded = Some(value.to_vec());
            } else {
                return Err(DynoError::Tool(
                    "Unexpected extra OCTET STRING in ML-DSA PKCS#8 private key".into(),
                ));
            }
        }
        let seed = seed.ok_or_else(|| {
            DynoError::Tool("ML-DSA PKCS#8 private key missing 32-byte seed".into())
        })?;
        Ok((seed, expanded))
    } else if private_key_octets.first() == Some(&0x80) {
        // [0] IMPLICIT OCTET STRING seed
        let mut i = 0;
        let (tag, value) = read_tlv(private_key_octets, &mut i)?;
        if tag != 0x80 || value.len() != 32 || i != private_key_octets.len() {
            return Err(DynoError::Tool(
                "Unsupported ML-DSA PKCS#8 seed encoding".into(),
            ));
        }
        Ok((value.to_vec(), None))
    } else if private_key_octets.first() == Some(&0xa0) {
        // [0] EXPLICIT OCTET STRING seed
        let mut i = 0;
        let (tag, value) = read_tlv(private_key_octets, &mut i)?;
        if tag != 0xa0 || i != private_key_octets.len() {
            return Err(DynoError::Tool(
                "Unsupported ML-DSA PKCS#8 seed encoding".into(),
            ));
        }
        let mut j = 0;
        let (inner_tag, seed) = read_tlv(value, &mut j)?;
        if inner_tag != 0x04 || seed.len() != 32 || j != value.len() {
            return Err(DynoError::Tool(
                "Unsupported ML-DSA PKCS#8 seed encoding".into(),
            ));
        }
        Ok((seed.to_vec(), None))
    } else if private_key_octets.len() == 32 {
        Ok((private_key_octets.to_vec(), None))
    } else {
        Err(DynoError::Tool(
            "Unsupported ML-DSA PKCS#8 private key encoding".into(),
        ))
    }
}

fn parse_mldsa_spki_public_key(der: &[u8]) -> Result<(&'static str, Vec<u8>)> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    let body = expect_complete_tlv(der, 0x30)?;
    let mut offset = 0;
    let (tag, alg) = read_tlv(body, &mut offset)?;
    if tag != 0x30 {
        return Err(DynoError::Tool(
            "SPKI AlgorithmIdentifier is not a SEQUENCE".into(),
        ));
    }
    let algorithm_name = parse_algorithm_identifier(alg)?;
    let (tag, bit_string) = read_tlv(body, &mut offset)?;
    if tag != 0x03 {
        return Err(DynoError::Tool(
            "SPKI subjectPublicKey is not a BIT STRING".into(),
        ));
    }
    if offset != body.len() {
        return Err(DynoError::Tool(
            "Unexpected trailing data in SubjectPublicKeyInfo".into(),
        ));
    }
    if bit_string.is_empty() {
        return Err(DynoError::Tool("SPKI BIT STRING is empty".into()));
    }
    let unused_bits = bit_string[0];
    if unused_bits != 0 {
        return Err(DynoError::Tool(
            "SPKI BIT STRING must have zero unused bits for ML-DSA".into(),
        ));
    }
    let raw = bit_string[1..].to_vec();
    let expected = match algorithm_name {
        "MLDSA65" => MLDSA65_PUBLIC_KEY_BYTES,
        "MLDSA87" => MLDSA87_PUBLIC_KEY_BYTES,
        other => {
            return Err(DynoError::Tool(format!(
                "Unsupported ML-DSA algorithm in SPKI: {other}"
            )));
        }
    };
    if raw.len() != expected {
        return Err(DynoError::Tool(format!(
            "Unexpected ML-DSA key length: expected {expected}, got {}",
            raw.len()
        )));
    }
    Ok((algorithm_name, raw))
}

fn resolve_mldsa65_private_key(seed: &[u8], expanded: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut xi = [0u8; 32];
    if seed.len() != 32 {
        return Err(DynoError::Tool("ML-DSA-65 seed must be 32 bytes".into()));
    }
    xi.copy_from_slice(seed);
    let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&xi);
    xi.zeroize();
    let mut derived = sk.into_bytes().to_vec();
    if let Some(expanded) = expanded {
        if expanded.len() != MLDSA65_PRIVATE_KEY_BYTES {
            derived.zeroize();
            return Err(DynoError::Tool(format!(
                "ML-DSA-65 expanded private key must be {} bytes",
                MLDSA65_PRIVATE_KEY_BYTES
            )));
        }
        if expanded != derived.as_slice() {
            derived.zeroize();
            return Err(DynoError::Tool(
                "ML-DSA-65 expanded private key does not match seed".into(),
            ));
        }
    }
    Ok(derived)
}

fn resolve_mldsa87_private_key(seed: &[u8], expanded: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut xi = [0u8; 32];
    if seed.len() != 32 {
        return Err(DynoError::Tool("ML-DSA-87 seed must be 32 bytes".into()));
    }
    xi.copy_from_slice(seed);
    let (_pk, sk) = ml_dsa_87::KG::keygen_from_seed(&xi);
    xi.zeroize();
    let mut derived = sk.into_bytes().to_vec();
    if let Some(expanded) = expanded {
        if expanded.len() != MLDSA87_PRIVATE_KEY_BYTES {
            derived.zeroize();
            return Err(DynoError::Tool(format!(
                "ML-DSA-87 expanded private key must be {} bytes",
                MLDSA87_PRIVATE_KEY_BYTES
            )));
        }
        if expanded != derived.as_slice() {
            derived.zeroize();
            return Err(DynoError::Tool(
                "ML-DSA-87 expanded private key does not match seed".into(),
            ));
        }
    }
    Ok(derived)
}

fn mldsa65_public_from_private(private_key: &[u8]) -> Result<Vec<u8>> {
    let mut sk_bytes = [0u8; MLDSA65_PRIVATE_KEY_BYTES];
    sk_bytes.copy_from_slice(private_key);
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
        sk_bytes.zeroize();
        DynoError::Tool(format!("Failed to load ML-DSA-65 private key: {e}"))
    })?;
    sk_bytes.zeroize();
    Ok(sk.get_public_key().into_bytes().to_vec())
}

fn mldsa87_public_from_private(private_key: &[u8]) -> Result<Vec<u8>> {
    let mut sk_bytes = [0u8; MLDSA87_PRIVATE_KEY_BYTES];
    sk_bytes.copy_from_slice(private_key);
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes).map_err(|e| {
        sk_bytes.zeroize();
        DynoError::Tool(format!("Failed to load ML-DSA-87 private key: {e}"))
    })?;
    sk_bytes.zeroize();
    Ok(sk.get_public_key().into_bytes().to_vec())
}

fn expect_complete_tlv(data: &[u8], expected_tag: u8) -> Result<&[u8]> {
    let mut offset = 0;
    let (tag, value) = read_tlv(data, &mut offset)?;
    if tag != expected_tag {
        return Err(DynoError::Tool(format!(
            "ASN.1 tag mismatch: expected 0x{expected_tag:02x}, got 0x{tag:02x}"
        )));
    }
    if offset != data.len() {
        return Err(DynoError::Tool("ASN.1 unexpected trailing data".into()));
    }
    Ok(value)
}

fn read_tlv<'a>(data: &'a [u8], offset: &mut usize) -> Result<(u8, &'a [u8])> {
    if *offset >= data.len() {
        return Err(DynoError::Tool("ASN.1 truncated tag".into()));
    }
    let tag = data[*offset];
    *offset += 1;
    // Reject multi-byte tags.
    if tag & 0x1f == 0x1f {
        return Err(DynoError::Tool(
            "ASN.1 multi-byte tags are not supported".into(),
        ));
    }
    if *offset >= data.len() {
        return Err(DynoError::Tool("ASN.1 truncated length".into()));
    }
    let first = data[*offset];
    *offset += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        // Reject indefinite length (n == 0) and absurdly large length fields.
        if n == 0 || n > 4 || *offset + n > data.len() {
            return Err(DynoError::Tool("ASN.1 invalid length".into()));
        }
        // Reject non-minimal long-form lengths (leading zero).
        if data[*offset] == 0 {
            return Err(DynoError::Tool("ASN.1 non-minimal length encoding".into()));
        }
        let mut value = 0usize;
        for _ in 0..n {
            value = (value << 8) | data[*offset] as usize;
            *offset += 1;
        }
        // Reject long-form lengths that fit in short form.
        if value < 0x80 {
            return Err(DynoError::Tool("ASN.1 non-minimal length encoding".into()));
        }
        value
    };
    if *offset + len > data.len() {
        return Err(DynoError::Tool("ASN.1 truncated value".into()));
    }
    let value = &data[*offset..*offset + len];
    *offset += len;
    Ok((tag, value))
}
fn build_pkcs1_message(algorithm: AvbAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    if algorithm.name == "NONE" {
        return Ok(Vec::new());
    }

    let digest = compute_hash_for_algorithm(algorithm, data)?;
    let prefix = digest_info_prefix(algorithm.hash_name)?;
    let key_size = algorithm.signature_num_bytes;
    let pad_len = key_size
        .checked_sub(3 + prefix.len() + digest.len())
        .ok_or_else(|| DynoError::Tool("RSA key too small for digest padding".into()))?;

    let mut out = Vec::with_capacity(key_size);
    out.push(0x00);
    out.push(0x01);
    out.extend(std::iter::repeat_n(0xff, pad_len));
    out.push(0x00);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn digest_info_prefix(hash_name: &str) -> Result<&'static [u8]> {
    match hash_name {
        "sha256" => Ok(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        "sha512" => Ok(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported digest info prefix for {}",
            other
        ))),
    }
}

fn encode_biguint(val: &BigUint, len: u32) -> Vec<u8> {
    let bytes = val.to_bytes_be();
    if bytes.len() >= len as usize {
        bytes[bytes.len() - len as usize..].to_vec()
    } else {
        let mut ret = vec![0u8; len as usize - bytes.len()];
        ret.extend_from_slice(&bytes);
        ret
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_bytes = a.to_bytes_be();
    let m_bytes = m.to_bytes_be();
    let a_dig = BigInt::from_bytes_be(Sign::Plus, &a_bytes);
    let m_dig = BigInt::from_bytes_be(Sign::Plus, &m_bytes);

    let egcd = a_dig.extended_gcd(&m_dig);
    if egcd.gcd != BigInt::from(1) {
        return None;
    }

    let mut res = egcd.x % &m_dig;
    if res.is_negative() {
        res += &m_dig;
    }

    let (_, res_bytes) = res.to_bytes_be();
    Some(BigUint::from_bytes_be(&res_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::sync::Mutex;

    static HELPER_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn extract_public_key_digest_is_sha256_hex() {
        let digest = extract_public_key_digest("testkey_rsa2048").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = load_key_from_spec("testkey_rsa2048").unwrap();
        let algorithm = lookup_algorithm_by_name("SHA256_RSA2048").unwrap();
        let public_key = AvbPublicKey::decode(&key.encode_public_key()).unwrap();
        let signature = key.sign(b"hello", algorithm.name).unwrap();
        assert!(public_key.verify(algorithm, &signature, b"hello").unwrap());
    }

    #[test]
    fn rsa_public_only_loads_and_rejects_sign() {
        let private = load_key_from_spec("testkey_rsa2048").unwrap();
        let encoded = private.encode_public_key();
        // Build PKCS#1 public PEM via rsa crate round-trip path is unavailable here;
        // instead load from private and ensure has_private_key semantics, then
        // construct public-only via from_der of SPKI if available.
        assert!(private.has_private_key());
        let public_blob = extract_public_key("testkey_rsa2048").unwrap();
        assert_eq!(public_blob, encoded);

        // Encode modulus-only AVB blob is not PEM; generate SPKI PEM using openssl-less
        // path: RsaPublicKey export through pkcs1/spki traits is available via rsa crate.
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::EncodePublicKey;
        let public_key = private.public_key.clone();
        let spki_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let pkcs1_pem = public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();

        let from_spki = AvbKey::from_pem(&spki_pem).unwrap();
        assert!(!from_spki.has_private_key());
        assert_eq!(from_spki.encode_public_key(), encoded);
        let err = from_spki
            .sign(b"x", "SHA256_RSA2048")
            .unwrap_err()
            .to_string();
        assert!(err.contains("public-only"), "{err}");

        let from_pkcs1 = AvbKey::from_pem(&pkcs1_pem).unwrap();
        assert!(!from_pkcs1.has_private_key());
        assert_eq!(from_pkcs1.encode_public_key(), encoded);
    }

    #[test]
    fn check_mldsa_support_is_true() {
        assert!(check_mldsa_support());
    }

    #[test]
    fn mldsa_algorithm_sizes_match_upstream() {
        let a65 = lookup_algorithm_by_name("MLDSA65").unwrap();
        assert_eq!(a65.algorithm_type, 7);
        assert_eq!(a65.hash_num_bytes, 0);
        assert_eq!(a65.hash_name, "");
        assert_eq!(a65.signature_num_bytes, 3309);
        assert_eq!(a65.public_key_num_bytes, 4 + 1952);

        let a87 = lookup_algorithm_by_type(8).unwrap();
        assert_eq!(a87.name, "MLDSA87");
        assert_eq!(a87.signature_num_bytes, 4627);
        assert_eq!(a87.public_key_num_bytes, 4 + 2592);
    }

    #[test]
    fn extract_mldsa_public_keys() {
        let pk65 = extract_public_key("testkey_mldsa65").unwrap();
        assert_eq!(pk65.len(), 4 + 1952);
        let decoded = AvbMldsaPublicKey::decode("MLDSA65", &pk65).unwrap();
        assert_eq!(decoded.raw_public_key.len(), 1952);

        let pk87 = extract_public_key("testkey_mldsa87").unwrap();
        assert_eq!(pk87.len(), 4 + 2592);
        let decoded = AvbMldsaPublicKey::decode("MLDSA87", &pk87).unwrap();
        assert_eq!(decoded.raw_public_key.len(), 2592);
    }

    #[test]
    fn mldsa_sign_verify_round_trip_and_tamper() {
        for (spec, alg) in [
            ("testkey_mldsa65", "MLDSA65"),
            ("testkey_mldsa87", "MLDSA87"),
        ] {
            let key = load_mldsa_key_from_spec(spec).unwrap();
            let algorithm = lookup_algorithm_by_name(alg).unwrap();
            assert_eq!(
                compute_hash_for_algorithm(algorithm, b"x").unwrap(),
                Vec::<u8>::new()
            );
            let signature = key.sign(b"hello mldsa", alg).unwrap();
            assert_eq!(signature.len(), algorithm.signature_num_bytes);
            let public_key = AvbMldsaPublicKey::decode(alg, &key.encode_public_key()).unwrap();
            assert!(
                public_key
                    .verify(algorithm, &signature, b"hello mldsa")
                    .unwrap()
            );

            let mut tampered = signature.clone();
            tampered[0] ^= 0x01;
            assert!(
                !public_key
                    .verify(algorithm, &tampered, b"hello mldsa")
                    .unwrap()
            );
            assert!(
                !public_key
                    .verify(algorithm, &signature, b"hello mldsa!")
                    .unwrap()
            );
        }
    }

    #[test]
    fn mldsa_wrong_key_and_algorithm_mismatch() {
        let key65 = load_mldsa_key_from_spec("testkey_mldsa65").unwrap();
        let key87 = load_mldsa_key_from_spec("testkey_mldsa87").unwrap();
        let algorithm65 = lookup_algorithm_by_name("MLDSA65").unwrap();
        let signature = key65.sign(b"payload", "MLDSA65").unwrap();
        let public87 = AvbMldsaPublicKey::decode("MLDSA87", &key87.encode_public_key()).unwrap();
        assert!(
            public87
                .verify(algorithm65, &signature, b"payload")
                .is_err()
        );

        assert!(key65.sign(b"payload", "MLDSA87").is_err());
        assert!(key65.sign(b"payload", "SHA256_RSA2048").is_err());
        let rsa = load_key_from_spec("testkey_rsa2048").unwrap();
        assert!(rsa.sign(b"payload", "MLDSA65").is_err());
    }

    #[test]
    fn load_mldsa_from_fixture_paths() {
        let path65 =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/mldsa/testkey_mldsa65.pem");
        let path87 =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/mldsa/testkey_mldsa87.pem");
        let key65 = AvbMldsaKey::load_pem(&path65).unwrap();
        let key87 = AvbMldsaKey::load_pem(&path87).unwrap();
        assert_eq!(key65.algorithm_name(), "MLDSA65");
        assert_eq!(key87.algorithm_name(), "MLDSA87");
        assert_eq!(key65.encode_public_key().len(), 4 + 1952);
        assert_eq!(key87.encode_public_key().len(), 4 + 2592);
    }

    #[test]
    fn rsa_signing_helper_stdin_protocol() {
        let _guard = HELPER_LOCK.lock().unwrap();
        let key = load_key_from_spec("testkey_rsa2048").unwrap();
        let algorithm = lookup_algorithm_by_name("SHA256_RSA2048").unwrap();
        let helper = write_helper_script(
            "rsa_helper_stdin",
            r#"
import sys, os
from pathlib import Path
alg, key_path = sys.argv[1], sys.argv[2]
data = sys.stdin.buffer.read()
if os.environ.get('AVB_HELPER_WRONG_SIG') == '1':
    sys.stdout.buffer.write(b'X' * 256)
    sys.exit(0)
if os.environ.get('AVB_HELPER_FAIL') == '1':
    sys.stderr.write('helper failed\n')
    sys.exit(3)
sig = Path(os.environ['AVB_HELPER_SIG']).read_bytes()
sys.stdout.buffer.write(sig)
Path(os.environ['AVB_HELPER_DONE']).write_text('DONE', encoding='utf-8')
"#,
        );

        let expected = key.sign(b"helper-msg", "SHA256_RSA2048").unwrap();
        let sig_path = std::env::temp_dir().join("avbtool-rs-helper-sig.bin");
        let done_path = std::env::temp_dir().join("avbtool-rs-helper-done.txt");
        let _ = fs::remove_file(&done_path);
        fs::write(&sig_path, &expected).unwrap();
        unsafe {
            std::env::set_var("AVB_HELPER_SIG", &sig_path);
            std::env::set_var("AVB_HELPER_DONE", &done_path);
            std::env::remove_var("AVB_HELPER_WRONG_SIG");
            std::env::remove_var("AVB_HELPER_FAIL");
        }

        let options = SignOptions {
            signing_helper: Some(helper.clone()),
            signing_helper_with_files: None,
            key_path: Some(PathBuf::from("testkey_rsa2048")),
        };
        let signature = key
            .sign_with_options(b"helper-msg", "SHA256_RSA2048", &options)
            .unwrap();
        assert_eq!(signature, expected);
        assert_eq!(fs::read_to_string(&done_path).unwrap(), "DONE");

        unsafe {
            std::env::set_var("AVB_HELPER_WRONG_SIG", "1");
        }
        let wrong = key
            .sign_with_options(b"helper-msg", "SHA256_RSA2048", &options)
            .unwrap();
        let public_key = AvbPublicKey::decode(&key.encode_public_key()).unwrap();
        assert!(!public_key.verify(algorithm, &wrong, b"helper-msg").unwrap());

        unsafe {
            std::env::remove_var("AVB_HELPER_WRONG_SIG");
            std::env::set_var("AVB_HELPER_FAIL", "1");
        }
        let err = key
            .sign_with_options(b"helper-msg", "SHA256_RSA2048", &options)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Error signing with RSA key"), "{err}");
        unsafe {
            std::env::remove_var("AVB_HELPER_FAIL");
            std::env::remove_var("AVB_HELPER_SIG");
            std::env::remove_var("AVB_HELPER_DONE");
        }
    }

    #[test]
    fn rsa_signing_helper_with_files_protocol() {
        let _guard = HELPER_LOCK.lock().unwrap();
        let key = load_key_from_spec("testkey_rsa2048").unwrap();
        let helper = write_helper_script(
            "rsa_helper_files",
            r#"
import sys, os
from pathlib import Path
alg, key_path, path = sys.argv[1], sys.argv[2], sys.argv[3]
data = Path(path).read_bytes()
if not data:
    sys.stderr.write('empty\n')
    sys.exit(22)
if os.environ.get('AVB_HELPER_FAIL') == '1':
    sys.exit(5)
sig = Path(os.environ['AVB_HELPER_SIG']).read_bytes()
Path(path).write_bytes(sig)
Path(os.environ['AVB_HELPER_DONE']).write_text('DONE', encoding='utf-8')
"#,
        );

        let expected = key.sign(b"file-helper", "SHA256_RSA2048").unwrap();
        let sig_path = std::env::temp_dir().join("avbtool-rs-helper-files-sig.bin");
        let done_path = std::env::temp_dir().join("avbtool-rs-helper-files-done.txt");
        let _ = fs::remove_file(&done_path);
        fs::write(&sig_path, &expected).unwrap();
        unsafe {
            std::env::set_var("AVB_HELPER_SIG", &sig_path);
            std::env::set_var("AVB_HELPER_DONE", &done_path);
            std::env::remove_var("AVB_HELPER_FAIL");
        }

        let options = SignOptions {
            signing_helper: None,
            signing_helper_with_files: Some(helper),
            key_path: Some(PathBuf::from("testkey_rsa2048")),
        };
        let signature = key
            .sign_with_options(b"file-helper", "SHA256_RSA2048", &options)
            .unwrap();
        assert_eq!(signature, expected);
        assert_eq!(fs::read_to_string(&done_path).unwrap(), "DONE");

        unsafe {
            std::env::set_var("AVB_HELPER_FAIL", "1");
        }
        let err = key
            .sign_with_options(b"file-helper", "SHA256_RSA2048", &options)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Error signing with RSA key"), "{err}");
        unsafe {
            std::env::remove_var("AVB_HELPER_FAIL");
            std::env::remove_var("AVB_HELPER_SIG");
            std::env::remove_var("AVB_HELPER_DONE");
        }
    }

    #[test]
    fn rsa_signing_helper_with_files_takes_priority_and_no_fallback() {
        let _guard = HELPER_LOCK.lock().unwrap();
        let key = load_key_from_spec("testkey_rsa2048").unwrap();
        let files_helper = write_helper_script(
            "rsa_priority_files",
            r#"
import sys, os
from pathlib import Path
path = sys.argv[3]
sig = Path(os.environ['AVB_HELPER_SIG']).read_bytes()
Path(path).write_bytes(sig)
Path(os.environ['AVB_HELPER_DONE']).write_text('FILES', encoding='utf-8')
"#,
        );
        let stdin_helper = write_helper_script(
            "rsa_priority_stdin",
            r#"
import sys
sys.stderr.write('stdin helper should not run\n')
sys.exit(9)
"#,
        );
        let expected = key.sign(b"priority", "SHA256_RSA2048").unwrap();
        let sig_path = std::env::temp_dir().join("avbtool-rs-helper-priority-sig.bin");
        let done_path = std::env::temp_dir().join("avbtool-rs-helper-priority-done.txt");
        let _ = fs::remove_file(&done_path);
        fs::write(&sig_path, &expected).unwrap();
        unsafe {
            std::env::set_var("AVB_HELPER_SIG", &sig_path);
            std::env::set_var("AVB_HELPER_DONE", &done_path);
        }
        let options = SignOptions {
            signing_helper: Some(stdin_helper),
            signing_helper_with_files: Some(files_helper),
            key_path: Some(PathBuf::from("testkey_rsa2048")),
        };
        let signature = key
            .sign_with_options(b"priority", "SHA256_RSA2048", &options)
            .unwrap();
        assert_eq!(signature, expected);
        assert_eq!(fs::read_to_string(&done_path).unwrap(), "FILES");
        unsafe {
            std::env::remove_var("AVB_HELPER_SIG");
            std::env::remove_var("AVB_HELPER_DONE");
        }
    }

    #[test]
    fn mldsa_public_spki_round_trip_extract() {
        for (spec, alg, raw_len) in [
            ("testkey_mldsa65", "MLDSA65", 1952usize),
            ("testkey_mldsa87", "MLDSA87", 2592usize),
        ] {
            let private = load_mldsa_key_from_spec(spec).unwrap();
            let raw = private.raw_public_key().to_vec();
            assert_eq!(raw.len(), raw_len);

            let oid: &[u8] = match alg {
                "MLDSA65" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
                "MLDSA87" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
                _ => unreachable!(),
            };
            let spki = encode_test_mldsa_spki(oid, &raw);
            let loaded = AvbMldsaPublicKey::from_spki_der(&spki).unwrap();
            assert_eq!(loaded.algorithm_name, alg);
            assert_eq!(loaded.raw_public_key, raw);
            assert_eq!(loaded.encode(), private.encode_public_key());

            let pem = encode_test_pem("PUBLIC KEY", &spki);
            let from_pem = AvbMldsaPublicKey::from_pem(&pem).unwrap();
            assert_eq!(from_pem.encode(), private.encode_public_key());

            // extract_public_key path via temp public PEM
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("{spec}_pub.pem"));
            fs::write(&path, &pem).unwrap();
            let extracted = extract_public_key(path.to_str().unwrap()).unwrap();
            assert_eq!(extracted, private.encode_public_key());
        }
    }

    #[test]
    fn mldsa_rejects_malformed_asn1_and_ambiguous_oid() {
        // Trailing data after top-level SEQUENCE.
        let private = load_mldsa_key_from_spec("testkey_mldsa65").unwrap();
        let oid = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
        let mut spki = encode_test_mldsa_spki(oid, private.raw_public_key());
        spki.push(0x00);
        assert!(AvbMldsaPublicKey::from_spki_der(&spki).is_err());

        // Wrong raw length inside valid SPKI framing.
        let bad_raw = vec![0u8; 16];
        let bad = encode_test_mldsa_spki(oid, &bad_raw);
        let err = AvbMldsaPublicKey::from_spki_der(&bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unexpected ML-DSA key length"), "{err}");

        // ML-DSA-44 OID must not be accepted as ambiguous ML-DSA.
        let oid44 = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
        let spki44 = encode_test_mldsa_spki(oid44, private.raw_public_key());
        assert!(AvbMldsaPublicKey::from_spki_der(&spki44).is_err());

        // Non-minimal ASN.1 length encoding.
        let non_minimal = [0x30, 0x81, 0x01, 0x00];
        assert!(AvbMldsaPublicKey::from_spki_der(&non_minimal).is_err());

        // April 2026 AVB blob length fix: header length must match algorithm size.
        let mut blob = private.encode_public_key();
        blob[3] = 0x01; // corrupt be32 length
        assert!(AvbMldsaPublicKey::decode("MLDSA65", &blob).is_err());
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("@@@@").is_err());
        assert!(decode_base64("AAA=A").is_err() || decode_base64("AAA=AAAA").is_err());
        assert!(decode_base64("====").is_err());
    }

    fn encode_test_mldsa_spki(oid_value: &[u8], raw_public_key: &[u8]) -> Vec<u8> {
        let mut alg = Vec::new();
        // OBJECT IDENTIFIER
        alg.push(0x06);
        alg.push(oid_value.len() as u8);
        alg.extend_from_slice(oid_value);
        let alg_seq = encode_test_tlv(0x30, &alg);

        let mut bit_string = Vec::with_capacity(1 + raw_public_key.len());
        bit_string.push(0x00); // unused bits
        bit_string.extend_from_slice(raw_public_key);
        let bit_tlv = encode_test_tlv(0x03, &bit_string);

        let mut body = Vec::new();
        body.extend_from_slice(&alg_seq);
        body.extend_from_slice(&bit_tlv);
        encode_test_tlv(0x30, &body)
    }

    fn encode_test_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(tag);
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.push(0x81);
            out.push(len as u8);
        } else if len <= 0xffff {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        } else {
            panic!("test helper length too large");
        }
        out.extend_from_slice(value);
        out
    }

    fn encode_test_pem(label: &str, der: &[u8]) -> String {
        use std::fmt::Write as _;
        let b64 = {
            const TABLE: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            let mut i = 0;
            while i < der.len() {
                let b0 = der[i];
                let b1 = if i + 1 < der.len() { der[i + 1] } else { 0 };
                let b2 = if i + 2 < der.len() { der[i + 2] } else { 0 };
                let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
                let remain = der.len() - i;
                out.push(TABLE[((n >> 18) & 63) as usize] as char);
                out.push(TABLE[((n >> 12) & 63) as usize] as char);
                if remain > 1 {
                    out.push(TABLE[((n >> 6) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
                if remain > 2 {
                    out.push(TABLE[(n & 63) as usize] as char);
                } else {
                    out.push('=');
                }
                i += 3;
            }
            out
        };
        let mut pem = String::new();
        let _ = writeln!(pem, "-----BEGIN {label}-----");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        let _ = writeln!(pem, "-----END {label}-----");
        pem
    }
    fn write_helper_script(name: &str, body: &str) -> PathBuf {
        let script_path = std::env::temp_dir().join(format!("avbtool-rs-{name}.py"));
        {
            let mut file = fs::File::create(&script_path).unwrap();
            writeln!(file, "#!/usr/bin/env python3").unwrap();
            write!(file, "{body}").unwrap();
        }
        // Windows cannot execute .py files directly as Win32 apps; wrap with cmd.
        let launcher = std::env::temp_dir().join(format!("avbtool-rs-{name}.cmd"));
        let mut file = fs::File::create(&launcher).unwrap();
        writeln!(file, "@echo off").unwrap();
        writeln!(file, "python \"{}\" %*", script_path.display()).unwrap();
        launcher
    }
}
