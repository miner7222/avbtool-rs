//! DM-verity / rootfs kernel cmdline synthesis for AVB.
//!
//! Ports upstream `avbtool.py` helpers:
//! - `_get_cmdline_descriptors_for_hashtree_descriptor`
//! - `_get_cmdline_descriptors_for_dm_verity`
//!
//! These power `--setup_rootfs_from_kernel` and `--setup_as_rootfs_from_kernel`.

use std::fmt::Write as _;

use crate::error::{AvbToolError as DynoError, Result};
use crate::info::DescriptorInfo;

/// `AvbKernelCmdlineDescriptor.FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED`
pub const FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED: u32 = 1 << 0;
/// `AvbKernelCmdlineDescriptor.FLAGS_USE_ONLY_IF_HASHTREE_DISABLED`
pub const FLAGS_USE_ONLY_IF_HASHTREE_DISABLED: u32 = 1 << 1;

/// `AvbHashtreeDescriptor.FLAGS_DO_NOT_USE_AB`
pub const HASHTREE_FLAGS_DO_NOT_USE_AB: u32 = 1 << 0;
/// `AvbHashtreeDescriptor.FLAGS_CHECK_AT_MOST_ONCE`
pub const HASHTREE_FLAGS_CHECK_AT_MOST_ONCE: u32 = 1 << 1;

/// Upstream always emits this PARTUUID token for rootfs dm-verity setup.
pub const ANDROID_SYSTEM_PARTUUID_TOKEN: &str = "PARTUUID=$(ANDROID_SYSTEM_PARTUUID)";
/// Upstream verity mode placeholder substituted by libavb at boot.
pub const ANDROID_VERITY_MODE_TOKEN: &str = "$(ANDROID_VERITY_MODE)";

/// Hashtree fields required to synthesize dm-verity kernel cmdlines.
///
/// Mirrors the subset of `AvbHashtreeDescriptor` consumed by upstream
/// `_get_cmdline_descriptors_for_hashtree_descriptor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashtreeCmdlineInput<'a> {
    pub dm_verity_version: u32,
    pub image_size: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub fec_num_roots: u32,
    pub fec_offset: u64,
    pub hash_algorithm: &'a str,
    pub partition_name: &'a str,
    pub salt: &'a [u8],
    pub root_digest: &'a [u8],
    pub flags: u32,
}

impl<'a> HashtreeCmdlineInput<'a> {
    /// Build input from a parsed [`DescriptorInfo::Hashtree`].
    ///
    /// # Errors
    ///
    /// Returns an error when `descriptor` is not a hashtree descriptor.
    pub fn from_descriptor(descriptor: &'a DescriptorInfo) -> Result<Self> {
        match descriptor {
            DescriptorInfo::Hashtree {
                dm_verity_version,
                image_size,
                data_block_size,
                hash_block_size,
                fec_num_roots,
                fec_offset,
                hash_algorithm,
                partition_name,
                salt,
                root_digest,
                flags,
                ..
            } => Ok(Self {
                dm_verity_version: *dm_verity_version,
                image_size: *image_size,
                data_block_size: *data_block_size,
                hash_block_size: *hash_block_size,
                fec_num_roots: *fec_num_roots,
                fec_offset: *fec_offset,
                hash_algorithm,
                partition_name,
                salt,
                root_digest,
                flags: *flags,
            }),
            _ => Err(DynoError::Validation(
                "descriptor is not a hashtree descriptor".into(),
            )),
        }
    }

    /// True when the hashtree descriptor uses a persistent root digest
    /// (empty `root_digest`, as produced by `--use_persistent_digest`).
    #[must_use]
    pub fn uses_persistent_root_digest(&self) -> bool {
        self.root_digest.is_empty()
    }

    /// True when `FLAGS_DO_NOT_USE_AB` is set.
    #[must_use]
    pub fn do_not_use_ab(&self) -> bool {
        (self.flags & HASHTREE_FLAGS_DO_NOT_USE_AB) != 0
    }

    /// True when `FLAGS_CHECK_AT_MOST_ONCE` is set.
    #[must_use]
    pub fn check_at_most_once(&self) -> bool {
        (self.flags & HASHTREE_FLAGS_CHECK_AT_MOST_ONCE) != 0
    }
}

/// Build the libavb persistent root-digest substitution token for a partition.
///
/// For partition `foo` this is `$(AVB_FOO_ROOT_DIGEST)`, matching
/// `avb_add_root_digest_substitution` / README.
#[must_use]
pub fn persistent_root_digest_token(partition_name: &str) -> String {
    format!("$(AVB_{}_ROOT_DIGEST)", partition_name.to_ascii_uppercase())
}

/// Generate the two KernelCmdline descriptors for a hashtree descriptor.
///
/// Matches upstream `_get_cmdline_descriptors_for_hashtree_descriptor`:
/// 1. enabled hashtree (`FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED`)
/// 2. disabled hashtree (`FLAGS_USE_ONLY_IF_HASHTREE_DISABLED`)
///
/// This is the core of `--setup_as_rootfs_from_kernel`.
///
/// # Errors
///
/// Returns an error when `data_block_size` is zero (would divide by zero
/// while computing block counts / FEC block indices).
pub fn cmdline_descriptors_for_hashtree(
    ht: &HashtreeCmdlineInput<'_>,
) -> Result<[DescriptorInfo; 2]> {
    let enabled = DescriptorInfo::KernelCmdline {
        flags: FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED,
        kernel_cmdline: build_dm_verity_enabled_cmdline(ht)?,
    };
    let disabled = DescriptorInfo::KernelCmdline {
        flags: FLAGS_USE_ONLY_IF_HASHTREE_DISABLED,
        kernel_cmdline: build_dm_verity_disabled_cmdline(),
    };
    Ok([enabled, disabled])
}

/// Generate cmdline descriptors from a single hashtree [`DescriptorInfo`].
///
/// # Errors
///
/// Returns an error when `descriptor` is not a hashtree descriptor, or when
/// hashtree fields are invalid for cmdline synthesis.
pub fn cmdline_descriptors_from_hashtree_descriptor(
    descriptor: &DescriptorInfo,
) -> Result<[DescriptorInfo; 2]> {
    let input = HashtreeCmdlineInput::from_descriptor(descriptor)?;
    cmdline_descriptors_for_hashtree(&input)
}

/// Generate cmdline descriptors from the first hashtree in `descriptors`.
///
/// Matches upstream `_get_cmdline_descriptors_for_dm_verity` (used by
/// `--setup_rootfs_from_kernel`).
///
/// # Errors
///
/// Returns an error when no hashtree descriptor is present, or when hashtree
/// fields are invalid for cmdline synthesis.
pub fn cmdline_descriptors_for_dm_verity(
    descriptors: &[DescriptorInfo],
) -> Result<[DescriptorInfo; 2]> {
    let ht = descriptors
        .iter()
        .find(|descriptor| matches!(descriptor, DescriptorInfo::Hashtree { .. }))
        .ok_or_else(|| DynoError::Tool("No hashtree descriptor in given image".into()))?;
    cmdline_descriptors_from_hashtree_descriptor(ht)
}

/// Build the dm-verity kernel cmdline used when hashtree verification is enabled.
///
/// Exact upstream string layout from
/// `_get_cmdline_descriptors_for_hashtree_descriptor`.
///
/// Notes matching upstream:
/// - PARTUUID tokens are always `$(ANDROID_SYSTEM_PARTUUID)` (not partition-name based).
/// - Empty `root_digest` / `salt` (persistent digest) emit empty hex fields.
/// - `FLAGS_DO_NOT_USE_AB` does not change the synthesized string; it is retained
///   on the hashtree descriptor for runtime A/B partition naming.
/// - `FLAGS_CHECK_AT_MOST_ONCE` increases the optional-arg count and inserts
///   `check_at_most_once` immediately after that count.
///
/// # Errors
///
/// Returns an error when `data_block_size` is zero.
pub fn build_dm_verity_enabled_cmdline(ht: &HashtreeCmdlineInput<'_>) -> Result<String> {
    if ht.data_block_size == 0 {
        return Err(DynoError::Validation(
            "hashtree data_block_size must be non-zero for dm-verity cmdline".into(),
        ));
    }

    let sectors = ht.image_size / 512;
    let num_blocks = ht.image_size / u64::from(ht.data_block_size);
    let root_digest_hex = bytes_to_hex(ht.root_digest);
    let salt_hex = bytes_to_hex(ht.salt);
    let check_at_most_once = ht.check_at_most_once();

    // Capacity is a soft estimate; exact growth depends on FEC / flags.
    let mut c = String::with_capacity(256);
    // dm="1 vroot none ro 1,0 <sectors> verity <ver> PARTUUID=... PARTUUID=...
    //     <data_bs> <hash_bs> <blocks> <hash_offset> <alg> <root> <salt> ..."
    write!(
        &mut c,
        "dm=\"1 vroot none ro 1,0 {sectors} verity {version} {partuuid} {partuuid} {data_bs} {hash_bs} {num_blocks} {num_blocks} {alg} {root} {salt}",
        version = ht.dm_verity_version,
        partuuid = ANDROID_SYSTEM_PARTUUID_TOKEN,
        data_bs = ht.data_block_size,
        hash_bs = ht.hash_block_size,
        alg = ht.hash_algorithm,
        root = root_digest_hex,
        salt = salt_hex,
    )
    .expect("writing to String cannot fail");

    if ht.fec_num_roots > 0 {
        let fec_blocks = ht.fec_offset / u64::from(ht.data_block_size);
        if check_at_most_once {
            c.push_str(" 11 check_at_most_once");
        } else {
            c.push_str(" 10");
        }
        write!(
            &mut c,
            " {verity_mode} ignore_zero_blocks use_fec_from_device {partuuid} fec_roots {roots} fec_blocks {fec_blocks} fec_start {fec_blocks}",
            verity_mode = ANDROID_VERITY_MODE_TOKEN,
            partuuid = ANDROID_SYSTEM_PARTUUID_TOKEN,
            roots = ht.fec_num_roots,
        )
        .expect("writing to String cannot fail");
    } else if check_at_most_once {
        write!(
            &mut c,
            " 3 check_at_most_once {verity_mode} ignore_zero_blocks",
            verity_mode = ANDROID_VERITY_MODE_TOKEN,
        )
        .expect("writing to String cannot fail");
    } else {
        write!(
            &mut c,
            " 2 {verity_mode} ignore_zero_blocks",
            verity_mode = ANDROID_VERITY_MODE_TOKEN,
        )
        .expect("writing to String cannot fail");
    }

    c.push_str("\" root=/dev/dm-0");
    Ok(c)
}

/// Build the kernel cmdline used when hashtree verification is disabled.
///
/// Exact upstream string:
/// `root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)`
#[must_use]
pub fn build_dm_verity_disabled_cmdline() -> String {
    format!("root={ANDROID_SYSTEM_PARTUUID_TOKEN}")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            let _ = write!(&mut out, "{byte:02x}");
            out
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden values derived from upstream avbtool_unittest.cc
    // (AddHashtreeFooter / setup_rootfs_from_kernel / setup_as_rootfs_from_kernel).
    const IMAGE_SIZE: u64 = 1_052_672;
    const DATA_BLOCK_SIZE: u32 = 4096;
    const HASH_BLOCK_SIZE: u32 = 4096;
    const ROOT_DIGEST: [u8; 20] = [
        0xe8, 0x11, 0x61, 0x14, 0x67, 0xdc, 0xd6, 0xe8, 0xdc, 0x43, 0x24, 0xe4, 0x5f, 0x70, 0x6c,
        0x2b, 0xdd, 0x51, 0xdb, 0x67,
    ];
    const SALT: [u8; 4] = [0xd0, 0x0d, 0xf0, 0x0d];
    const FEC_OFFSET: u64 = 1_069_056;

    const GOLDEN_NO_FEC: &str = concat!(
        r#"dm="1 vroot none ro 1,0 2056 verity 1 "#,
        "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d ",
        r#"2 $(ANDROID_VERITY_MODE) ignore_zero_blocks" root=/dev/dm-0"#,
    );

    const GOLDEN_FEC: &str = concat!(
        r#"dm="1 vroot none ro 1,0 2056 verity 1 "#,
        "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d ",
        "10 $(ANDROID_VERITY_MODE) ignore_zero_blocks ",
        "use_fec_from_device PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        r#"fec_roots 2 fec_blocks 261 fec_start 261" root=/dev/dm-0"#,
    );

    const GOLDEN_FEC_CHECK_AT_MOST_ONCE: &str = concat!(
        r#"dm="1 vroot none ro 1,0 2056 verity 1 "#,
        "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d ",
        "11 check_at_most_once $(ANDROID_VERITY_MODE) ignore_zero_blocks ",
        "use_fec_from_device PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        r#"fec_roots 2 fec_blocks 261 fec_start 261" root=/dev/dm-0"#,
    );

    const GOLDEN_NO_FEC_CHECK_AT_MOST_ONCE: &str = concat!(
        r#"dm="1 vroot none ro 1,0 2056 verity 1 "#,
        "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d ",
        r#"3 check_at_most_once $(ANDROID_VERITY_MODE) ignore_zero_blocks" root=/dev/dm-0"#,
    );

    // Persistent digest: empty root_digest + empty salt produce empty hex fields
    // (two consecutive spaces around the missing values), matching Python `.hex()`.
    const GOLDEN_PERSISTENT_FEC: &str = concat!(
        r#"dm="1 vroot none ro 1,0 2056 verity 1 "#,
        "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        "4096 4096 257 257 sha1   ",
        "10 $(ANDROID_VERITY_MODE) ignore_zero_blocks ",
        "use_fec_from_device PARTUUID=$(ANDROID_SYSTEM_PARTUUID) ",
        r#"fec_roots 2 fec_blocks 261 fec_start 261" root=/dev/dm-0"#,
    );

    const GOLDEN_DISABLED: &str = "root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)";

    fn sample_ht<'a>(
        root_digest: &'a [u8],
        salt: &'a [u8],
        fec_num_roots: u32,
        fec_offset: u64,
        flags: u32,
    ) -> HashtreeCmdlineInput<'a> {
        HashtreeCmdlineInput {
            dm_verity_version: 1,
            image_size: IMAGE_SIZE,
            data_block_size: DATA_BLOCK_SIZE,
            hash_block_size: HASH_BLOCK_SIZE,
            fec_num_roots,
            fec_offset,
            hash_algorithm: "sha1",
            partition_name: "rootfs",
            salt,
            root_digest,
            flags,
        }
    }

    fn sample_descriptor(
        root_digest: Vec<u8>,
        salt: Vec<u8>,
        fec_num_roots: u32,
        fec_offset: u64,
        flags: u32,
        partition_name: &str,
    ) -> DescriptorInfo {
        DescriptorInfo::Hashtree {
            dm_verity_version: 1,
            image_size: IMAGE_SIZE,
            tree_offset: IMAGE_SIZE,
            tree_size: 16_384,
            data_block_size: DATA_BLOCK_SIZE,
            hash_block_size: HASH_BLOCK_SIZE,
            fec_num_roots,
            fec_offset,
            fec_size: if fec_num_roots > 0 { 16_384 } else { 0 },
            hash_algorithm: "sha1".to_string(),
            partition_name: partition_name.to_string(),
            salt,
            root_digest,
            flags,
        }
    }

    fn assert_pair(pair: &[DescriptorInfo; 2], enabled: &str) {
        match &pair[0] {
            DescriptorInfo::KernelCmdline {
                flags,
                kernel_cmdline,
            } => {
                assert_eq!(*flags, FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED);
                assert_eq!(kernel_cmdline, enabled);
            }
            other => panic!("expected KernelCmdline, got {other:?}"),
        }
        match &pair[1] {
            DescriptorInfo::KernelCmdline {
                flags,
                kernel_cmdline,
            } => {
                assert_eq!(*flags, FLAGS_USE_ONLY_IF_HASHTREE_DISABLED);
                assert_eq!(kernel_cmdline, GOLDEN_DISABLED);
            }
            other => panic!("expected KernelCmdline, got {other:?}"),
        }
    }

    #[test]
    fn golden_no_fec_enabled_cmdline() {
        let ht = sample_ht(&ROOT_DIGEST, &SALT, 0, 0, 0);
        assert_eq!(build_dm_verity_enabled_cmdline(&ht).unwrap(), GOLDEN_NO_FEC);
        assert_eq!(build_dm_verity_disabled_cmdline(), GOLDEN_DISABLED);
        assert_pair(
            &cmdline_descriptors_for_hashtree(&ht).unwrap(),
            GOLDEN_NO_FEC,
        );
    }

    #[test]
    fn golden_fec_enabled_cmdline() {
        let ht = sample_ht(&ROOT_DIGEST, &SALT, 2, FEC_OFFSET, 0);
        assert_eq!(build_dm_verity_enabled_cmdline(&ht).unwrap(), GOLDEN_FEC);
        assert_pair(&cmdline_descriptors_for_hashtree(&ht).unwrap(), GOLDEN_FEC);
    }

    #[test]
    fn golden_fec_check_at_most_once() {
        let ht = sample_ht(
            &ROOT_DIGEST,
            &SALT,
            2,
            FEC_OFFSET,
            HASHTREE_FLAGS_CHECK_AT_MOST_ONCE,
        );
        assert_eq!(
            build_dm_verity_enabled_cmdline(&ht).unwrap(),
            GOLDEN_FEC_CHECK_AT_MOST_ONCE
        );
        assert_pair(
            &cmdline_descriptors_for_hashtree(&ht).unwrap(),
            GOLDEN_FEC_CHECK_AT_MOST_ONCE,
        );
    }

    #[test]
    fn golden_no_fec_check_at_most_once() {
        let ht = sample_ht(&ROOT_DIGEST, &SALT, 0, 0, HASHTREE_FLAGS_CHECK_AT_MOST_ONCE);
        assert_eq!(
            build_dm_verity_enabled_cmdline(&ht).unwrap(),
            GOLDEN_NO_FEC_CHECK_AT_MOST_ONCE
        );
    }

    #[test]
    fn golden_persistent_root_digest_empty_hex_fields() {
        let ht = sample_ht(&[], &[], 2, FEC_OFFSET, 0);
        assert!(ht.uses_persistent_root_digest());
        assert_eq!(
            build_dm_verity_enabled_cmdline(&ht).unwrap(),
            GOLDEN_PERSISTENT_FEC
        );
        // Placeholder token used by libavb / user cmdlines for persistent digests.
        assert_eq!(
            persistent_root_digest_token(ht.partition_name),
            "$(AVB_ROOTFS_ROOT_DIGEST)"
        );
        assert_eq!(
            persistent_root_digest_token("factory"),
            "$(AVB_FACTORY_ROOT_DIGEST)"
        );
    }

    #[test]
    fn do_not_use_ab_flag_does_not_change_partuuid_token() {
        // Upstream hardcodes ANDROID_SYSTEM_PARTUUID regardless of partition_name
        // and FLAGS_DO_NOT_USE_AB. The flag only affects runtime A/B suffixing.
        let ht = sample_ht(
            &ROOT_DIGEST,
            &SALT,
            2,
            FEC_OFFSET,
            HASHTREE_FLAGS_DO_NOT_USE_AB,
        );
        assert!(ht.do_not_use_ab());
        assert_eq!(build_dm_verity_enabled_cmdline(&ht).unwrap(), GOLDEN_FEC);
        assert!(
            build_dm_verity_enabled_cmdline(&ht)
                .unwrap()
                .contains(ANDROID_SYSTEM_PARTUUID_TOKEN)
        );
    }

    #[test]
    fn do_not_use_ab_with_check_at_most_once() {
        let flags = HASHTREE_FLAGS_DO_NOT_USE_AB | HASHTREE_FLAGS_CHECK_AT_MOST_ONCE;
        let ht = sample_ht(&ROOT_DIGEST, &SALT, 2, FEC_OFFSET, flags);
        assert_eq!(
            build_dm_verity_enabled_cmdline(&ht).unwrap(),
            GOLDEN_FEC_CHECK_AT_MOST_ONCE
        );
    }

    #[test]
    fn from_hashtree_descriptor_and_dm_verity_lookup() {
        let hashtree = sample_descriptor(
            ROOT_DIGEST.to_vec(),
            SALT.to_vec(),
            2,
            FEC_OFFSET,
            0,
            "rootfs",
        );
        let property = DescriptorInfo::Property {
            key: "k".into(),
            value: b"v".to_vec(),
        };
        let hash = DescriptorInfo::Hash {
            image_size: 1,
            hash_algorithm: "sha256".into(),
            partition_name: "boot".into(),
            salt: vec![1],
            digest: vec![2],
            flags: 0,
        };

        let pair = cmdline_descriptors_from_hashtree_descriptor(&hashtree).unwrap();
        assert_pair(&pair, GOLDEN_FEC);

        let pair = cmdline_descriptors_for_dm_verity(&[property, hash, hashtree]).unwrap();
        assert_pair(&pair, GOLDEN_FEC);
    }

    #[test]
    fn dm_verity_errors_when_no_hashtree_descriptor() {
        let descriptors = vec![
            DescriptorInfo::Property {
                key: "k".into(),
                value: b"v".to_vec(),
            },
            DescriptorInfo::KernelCmdline {
                flags: 0,
                kernel_cmdline: "console=ttyS0".into(),
            },
        ];
        let err = cmdline_descriptors_for_dm_verity(&descriptors).unwrap_err();
        assert!(
            err.to_string()
                .contains("No hashtree descriptor in given image")
        );
    }

    #[test]
    fn rejects_non_hashtree_descriptor() {
        let desc = DescriptorInfo::Hash {
            image_size: 1,
            hash_algorithm: "sha256".into(),
            partition_name: "boot".into(),
            salt: vec![],
            digest: vec![],
            flags: 0,
        };
        let err = cmdline_descriptors_from_hashtree_descriptor(&desc).unwrap_err();
        assert!(err.to_string().contains("not a hashtree descriptor"));
    }

    #[test]
    fn rejects_zero_data_block_size() {
        let mut ht = sample_ht(&ROOT_DIGEST, &SALT, 0, 0, 0);
        ht.data_block_size = 0;
        let err = build_dm_verity_enabled_cmdline(&ht).unwrap_err();
        assert!(err.to_string().contains("data_block_size"));
    }

    #[test]
    fn flags_constants_match_upstream() {
        assert_eq!(FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED, 1);
        assert_eq!(FLAGS_USE_ONLY_IF_HASHTREE_DISABLED, 2);
        assert_eq!(HASHTREE_FLAGS_DO_NOT_USE_AB, 1);
        assert_eq!(HASHTREE_FLAGS_CHECK_AT_MOST_ONCE, 2);
    }
}
