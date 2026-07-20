use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use avbtool_rs::builder::{
    BuildSignOptions, ChainPartitionSpec, PropertySpec, VbmetaImageArgs, append_vbmeta_image,
    make_vbmeta_image_with_options, required_libavb_minor_for_args,
    update_partition_descriptor_with_options,
};
use avbtool_rs::cert::{
    CERT_USAGE_SIGNING, format_cert_metadata_info, make_cert_metadata,
    make_cert_permanent_attributes_from_paths, make_cert_unlock_credential_from_paths_with_options,
    make_certificate_from_paths_with_options, parse_metadata, resolve_builtin_usage,
};
use avbtool_rs::cmdline::cmdline_descriptors_for_dm_verity;
use avbtool_rs::crypto::{
    SignOptions, check_mldsa_support, extract_public_key, extract_public_key_digest,
    is_mldsa_algorithm,
};
use avbtool_rs::digest::{
    calculate_kernel_cmdline, calculate_vbmeta_digest, print_partition_digests,
};
use avbtool_rs::footer::{
    AVB_DEFAULT_FEC_NUM_ROOTS, FooterBuildOptions, HashFooterArgs, HashtreeFooterArgs,
    add_hash_footer_with_options, add_hashtree_footer_with_options,
    calc_max_hash_footer_image_size, calc_max_hashtree_footer_image_size, erase_footer,
    parse_hex_string, resize_image, zero_hashtree,
};
use avbtool_rs::image::{extract_public_key_metadata, load_vbmeta_blob};
use avbtool_rs::info::{InfoRenderOptions, generate_info_report_with_options, scan_input};
use avbtool_rs::resign::{ResignOutcome, ResignSignOptions, resign_image_with_sign_options};
use avbtool_rs::sparse::ImageHandler;
use avbtool_rs::verify::{ExpectedChainPartition, VerifyImageOptions, verify_image};
use clap::{Parser, Subcommand, ValueEnum};
use crc32fast::Hasher as Crc32Hasher;

const AVBTOOL_VERSION: &str = "avbtool 1.4.0";

#[derive(Parser, Debug)]
#[command(
    name = "avbtool-rs",
    about = "Pure Rust AVB tooling",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Version,
    CheckMldsaSupport,
    GenerateTestImage {
        #[arg(long)]
        image_size: u64,
        #[arg(long, default_value_t = 0)]
        start_byte: u8,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    InfoImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long = "cert", alias = "atx", visible_alias = "atx")]
        cert: bool,
        #[arg(long)]
        output_pubkey: Option<PathBuf>,
    },
    ExtractPublicKey {
        #[arg(long)]
        key: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    ExtractPublicKeyDigest {
        #[arg(long)]
        key: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    CalculateVbmetaDigest {
        #[arg(long)]
        image: PathBuf,
        #[arg(long, default_value = "sha256")]
        hash_algorithm: String,
        #[arg(long, value_enum, default_value_t = DigestFormat::Hex)]
        format: DigestFormat,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    CalculateKernelCmdline {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        hashtree_disabled: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    PrintPartitionDigests {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    MakeVbmetaImage {
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        common: CommonArgs,
        #[arg(long, default_value_t = 0)]
        padding_size: u64,
    },
    AppendVbmetaImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        vbmeta_image: PathBuf,
        #[arg(long)]
        partition_size: u64,
    },
    AddHashFooter {
        #[arg(long)]
        image: Option<PathBuf>,
        #[arg(long)]
        partition_size: Option<u64>,
        #[arg(long)]
        dynamic_partition_size: bool,
        #[arg(long)]
        partition_name: Option<String>,
        #[arg(long, default_value = "sha256")]
        hash_algorithm: String,
        #[arg(long)]
        salt: Option<String>,
        #[arg(long)]
        calc_max_image_size: bool,
        #[arg(long)]
        output_vbmeta_image: Option<PathBuf>,
        #[arg(long)]
        do_not_append_vbmeta_image: bool,
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        footer: CommonFooterArgs,
    },
    AddHashtreeFooter {
        #[arg(long)]
        image: Option<PathBuf>,
        #[arg(long)]
        partition_size: Option<u64>,
        #[arg(long, default_value = "")]
        partition_name: String,
        /// Empty default matches AOSP so defaulted sha1 can be distinguished from explicit sha1.
        #[arg(long, default_value = "")]
        hash_algorithm: String,
        #[arg(long, default_value_t = 4096)]
        block_size: u32,
        #[arg(long)]
        salt: Option<String>,
        #[arg(long)]
        do_not_generate_fec: bool,
        #[arg(long, default_value_t = AVB_DEFAULT_FEC_NUM_ROOTS)]
        fec_num_roots: u32,
        #[arg(long)]
        calc_max_image_size: bool,
        #[arg(long)]
        output_vbmeta_image: Option<PathBuf>,
        #[arg(long)]
        do_not_append_vbmeta_image: bool,
        #[arg(long)]
        setup_as_rootfs_from_kernel: bool,
        #[arg(long)]
        no_hashtree: bool,
        #[arg(long)]
        check_at_most_once: bool,
        /// Deprecated AOSP flag retained for compatibility; FEC is generated by default.
        #[arg(long, hide = true)]
        generate_fec: bool,
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        footer: CommonFooterArgs,
    },
    EraseFooter {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        keep_hashtree: bool,
    },
    ZeroHashtree {
        #[arg(long)]
        image: PathBuf,
    },
    ExtractVbmetaImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        padding_size: u64,
    },
    ResizeImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        partition_size: u64,
    },
    VerifyImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "expected-chain-partition")]
        expected_chain_partitions: Vec<String>,
        #[arg(long)]
        follow_chain_partitions: bool,
        #[arg(long)]
        accept_zeroed_hashtree: bool,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    ResignImage {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        key: String,
        #[arg(long)]
        algorithm: String,
        #[arg(long)]
        signing_helper: Option<String>,
        #[arg(long)]
        signing_helper_with_files: Option<String>,
        #[arg(long)]
        auto_resize: bool,
        #[arg(long)]
        rollback_index: Option<u64>,
        /// Local extension: allow resigning when algorithm/key size would otherwise be rejected.
        #[arg(long)]
        force: bool,
    },
    UpdatePartitionDescriptor {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        partition_image: PathBuf,
        #[arg(long, short)]
        output: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
    SetAbMetadata {
        #[arg(long)]
        misc_image: PathBuf,
        #[arg(long, default_value = "15:7:0:14:7:0")]
        slot_data: String,
    },
    #[command(name = "make-certificate", alias = "make-atx-certificate")]
    MakeCertificate {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        subject: PathBuf,
        #[arg(long)]
        subject_key: PathBuf,
        #[arg(long)]
        subject_key_version: Option<u64>,
        #[arg(long)]
        subject_is_intermediate_authority: bool,
        #[arg(long)]
        usage: Option<String>,
        #[arg(long)]
        usage_for_unlock: bool,
        #[arg(long)]
        authority_key: Option<PathBuf>,
        #[arg(long)]
        signing_helper: Option<String>,
        #[arg(long)]
        signing_helper_with_files: Option<String>,
    },
    #[command(
        name = "make-cert-permanent-attributes",
        alias = "make-atx-permanent-attributes"
    )]
    MakeCertPermanentAttributes {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        root_authority_key: PathBuf,
        #[arg(long)]
        product_id: PathBuf,
    },
    #[command(name = "make-cert-metadata", alias = "make-atx-metadata")]
    MakeCertMetadata {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        intermediate_key_certificate: PathBuf,
        #[arg(long)]
        product_key_certificate: PathBuf,
    },
    #[command(
        name = "make-cert-unlock-credential",
        alias = "make-atx-unlock-credential"
    )]
    MakeCertUnlockCredential {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        intermediate_key_certificate: PathBuf,
        #[arg(long)]
        unlock_key_certificate: PathBuf,
        #[arg(long)]
        challenge: Option<PathBuf>,
        #[arg(long)]
        unlock_key: Option<PathBuf>,
        #[arg(long)]
        signing_helper: Option<String>,
        #[arg(long)]
        signing_helper_with_files: Option<String>,
    },
    #[command(external_subcommand)]
    Unsupported(Vec<String>),
}

#[derive(Parser, Debug, Clone)]
struct CommonArgs {
    #[arg(long, default_value = "NONE")]
    algorithm: String,
    #[arg(long)]
    key: Option<String>,
    #[arg(long)]
    signing_helper: Option<String>,
    #[arg(long)]
    signing_helper_with_files: Option<String>,
    #[arg(long)]
    public_key_metadata: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    rollback_index: u64,
    #[arg(long, default_value_t = 0)]
    flags: u32,
    #[arg(long, default_value_t = 0)]
    rollback_index_location: u32,
    #[arg(long, hide = true)]
    internal_release_string: Option<String>,
    #[arg(long)]
    release_string: Option<String>,
    #[arg(long)]
    append_to_release_string: Option<String>,
    #[arg(long = "prop")]
    props: Vec<String>,
    #[arg(long = "prop-from-file")]
    props_from_file: Vec<String>,
    #[arg(long = "kernel-cmdline")]
    kernel_cmdlines: Vec<String>,
    #[arg(
        long = "setup-rootfs-from-kernel",
        alias = "generate-dm-verity-cmdline-from-hashtree",
        visible_alias = "generate_dm_verity_cmdline_from_hashtree"
    )]
    setup_rootfs_from_kernel: Option<PathBuf>,
    #[arg(long = "include-descriptors-from-image")]
    include_descriptors_from_images: Vec<PathBuf>,
    #[arg(long)]
    print_required_libavb_version: bool,
    #[arg(long = "chain-partition")]
    chain_partitions: Vec<String>,
    #[arg(long = "chain-partition-do-not-use-ab")]
    chain_partitions_do_not_use_ab: Vec<String>,
    #[arg(long)]
    set_hashtree_disabled_flag: bool,
    #[arg(long)]
    set_verification_disabled_flag: bool,
}

#[derive(Parser, Debug, Clone)]
struct CommonFooterArgs {
    /// AOSP flag name. Local alias: --use_persistent_root_digest.
    #[arg(
        long = "use-persistent-digest",
        alias = "use-persistent-root-digest",
        visible_alias = "use_persistent_root_digest"
    )]
    use_persistent_digest: bool,
    #[arg(long)]
    do_not_use_ab: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ReportFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum DigestFormat {
    Hex,
    Raw,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse_from(normalize_cli_args(std::env::args_os()));
    std::thread::Builder::new()
        .name("avbtool-rs-main".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || run(cli))?
        .join()
        .map_err(|_| anyhow::anyhow!("avbtool-rs worker thread panicked"))?
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Version => write_text_output(None, format!("{AVBTOOL_VERSION}\n").as_bytes()),
        Commands::CheckMldsaSupport => {
            if check_mldsa_support() {
                write_text_output(None, b"ML-DSA is supported.\n")
            } else {
                anyhow::bail!("ML-DSA is NOT supported.")
            }
        }
        Commands::GenerateTestImage {
            image_size,
            start_byte,
            output,
        } => {
            let mut bytes = vec![0u8; image_size as usize];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = start_byte.wrapping_add(index as u8);
            }
            write_binary_output(output, &bytes)
        }
        Commands::InfoImage {
            image,
            format,
            output,
            cert,
            output_pubkey,
        } => {
            if let Some(output_pubkey) = output_pubkey {
                let public_key = extract_embedded_public_key(&image)?;
                write_binary_output(Some(output_pubkey), &public_key)?;
            }
            match format {
                ReportFormat::Text => {
                    let sparse = image_is_sparse(&image);
                    let cert_text = if cert {
                        Some(load_cert_info_text(&image)?)
                    } else {
                        None
                    };
                    let report = generate_info_report_with_options(
                        &image,
                        &InfoRenderOptions {
                            sparse,
                            include_cert: cert,
                            cert_text,
                        },
                    )?;
                    write_text_output(output, report.as_bytes())
                }
                ReportFormat::Json => {
                    let report = serde_json::to_string_pretty(&scan_input(&image)?)?;
                    write_text_output(output, report.as_bytes())
                }
            }
        }
        Commands::ExtractPublicKey { key, output } => {
            let blob = extract_public_key(&key)?;
            write_binary_output(output, &blob)
        }
        Commands::ExtractPublicKeyDigest { key, output } => {
            let digest = extract_public_key_digest(&key)?;
            write_text_output(output, format!("{digest}\n").as_bytes())
        }
        Commands::CalculateVbmetaDigest {
            image,
            hash_algorithm,
            format,
            output,
        } => {
            let digest = calculate_vbmeta_digest(&image, &hash_algorithm)?;
            match format {
                DigestFormat::Hex => {
                    let hex = digest
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    write_text_output(output, format!("{hex}\n").as_bytes())
                }
                DigestFormat::Raw => write_binary_output(output, &digest),
            }
        }
        Commands::CalculateKernelCmdline {
            image,
            hashtree_disabled,
            output,
        } => {
            let cmdline = calculate_kernel_cmdline(&image, hashtree_disabled)?;
            write_text_output(output, cmdline.as_bytes())
        }
        Commands::PrintPartitionDigests {
            image,
            json,
            output,
        } => {
            let entries = print_partition_digests(&image)?;
            if json {
                let payload = serde_json::to_string_pretty(&entries)?;
                write_text_output(output, payload.as_bytes())
            } else {
                let text = entries
                    .into_iter()
                    .map(|(name, digest)| format!("{name}: {digest}\n"))
                    .collect::<String>();
                write_text_output(output, text.as_bytes())
            }
        }
        Commands::MakeVbmetaImage {
            output,
            common,
            padding_size,
        } => {
            let (args, sign_options) = build_vbmeta_args(&common, padding_size, Vec::new())?;
            if common.print_required_libavb_version {
                return write_text_output(
                    None,
                    format!("1.{}\n", required_libavb_minor_for_args(&args)).as_bytes(),
                );
            }
            if let Some(output) = output {
                make_vbmeta_image_with_options(
                    &output,
                    &args,
                    &BuildSignOptions { sign: sign_options },
                )?;
                Ok(())
            } else {
                let mut blob = avbtool_rs::builder::build_vbmeta_blob_with_options(
                    &args,
                    &BuildSignOptions { sign: sign_options },
                )?;
                if args.padding_size > 0 {
                    let padded =
                        avbtool_rs::crypto::round_to_multiple(blob.len() as u64, args.padding_size)
                            as usize;
                    blob.resize(padded, 0);
                }
                write_binary_output(None, &blob)
            }
        }
        Commands::AppendVbmetaImage {
            image,
            vbmeta_image,
            partition_size,
        } => append_vbmeta_image(&image, &vbmeta_image, partition_size).map_err(Into::into),
        Commands::AddHashFooter {
            image,
            partition_size,
            dynamic_partition_size,
            partition_name,
            hash_algorithm,
            salt,
            calc_max_image_size,
            output_vbmeta_image,
            do_not_append_vbmeta_image,
            common,
            footer,
        } => {
            if dynamic_partition_size && calc_max_image_size {
                anyhow::bail!("--calc_max_image_size not supported with --dynamic_partition_size");
            }
            if common.print_required_libavb_version {
                let minor = required_minor_for_hash_footer(
                    common.rollback_index_location,
                    !common.chain_partitions_do_not_use_ab.is_empty(),
                    footer.use_persistent_digest || footer.do_not_use_ab,
                    &common.algorithm,
                );
                return write_text_output(None, format!("1.{minor}\n").as_bytes());
            }
            if calc_max_image_size {
                let partition_size =
                    partition_size.ok_or_else(|| anyhow::anyhow!("partition_size required"))?;
                let max = calc_max_hash_footer_image_size(partition_size)?;
                return write_text_output(None, format!("{max}\n").as_bytes());
            }

            let image =
                image.ok_or_else(|| anyhow::anyhow!("--image is required for add_hash_footer"))?;
            let partition_name = partition_name.ok_or_else(|| {
                anyhow::anyhow!("--partition_name is required for add_hash_footer")
            })?;
            let (vbmeta_common, sign_options) = build_vbmeta_args(&common, 0, Vec::new())?;
            let salt = salt.map(|value| parse_hex_string(&value)).transpose()?;
            add_hash_footer_with_options(
                &image,
                &HashFooterArgs {
                    partition_size,
                    dynamic_partition_size,
                    partition_name,
                    hash_algorithm,
                    salt,
                    chain_partitions: vbmeta_common.chain_partitions,
                    algorithm_name: vbmeta_common.algorithm_name,
                    key_spec: vbmeta_common.key_spec,
                    public_key_metadata: vbmeta_common.public_key_metadata,
                    rollback_index: vbmeta_common.rollback_index,
                    flags: vbmeta_common.flags,
                    rollback_index_location: vbmeta_common.rollback_index_location,
                    properties: vbmeta_common.properties,
                    kernel_cmdlines: vbmeta_common.kernel_cmdlines,
                    include_descriptors_from_images: vbmeta_common.include_descriptors_from_images,
                    release_string: vbmeta_common.release_string,
                    append_to_release_string: vbmeta_common.append_to_release_string,
                    output_vbmeta_image,
                    do_not_append_vbmeta_image,
                    use_persistent_digest: footer.use_persistent_digest,
                    do_not_use_ab: footer.do_not_use_ab,
                },
                &FooterBuildOptions {
                    build: BuildSignOptions { sign: sign_options },
                    extra_descriptors: vbmeta_common.extra_descriptors,
                    setup_as_rootfs_from_kernel: false,
                },
            )
            .map_err(Into::into)
        }
        Commands::AddHashtreeFooter {
            image,
            partition_size,
            partition_name,
            mut hash_algorithm,
            block_size,
            salt,
            do_not_generate_fec,
            fec_num_roots,
            calc_max_image_size,
            output_vbmeta_image,
            do_not_append_vbmeta_image,
            setup_as_rootfs_from_kernel,
            no_hashtree,
            check_at_most_once,
            generate_fec,
            common,
            footer,
        } => {
            if generate_fec {
                eprintln!(
                    "The --generate_fec option is deprecated since FEC is now generated by default. Use the option --do_not_generate_fec to not generate FEC."
                );
            }
            if hash_algorithm.is_empty() {
                hash_algorithm = "sha1".to_string();
                if !calc_max_image_size {
                    eprintln!(
                        "Warning: 'avbtool add_hashtree_footer' executed without an explicit\n--hash_algorithm option. Defaulting to sha1 for backwards compatibility.\nPlease use '--hash_algorithm sha256'."
                    );
                }
            }
            let generate_fec = !do_not_generate_fec;

            if common.print_required_libavb_version {
                let minor = required_minor_for_hashtree_footer(
                    common.rollback_index_location,
                    !common.chain_partitions_do_not_use_ab.is_empty(),
                    footer.use_persistent_digest || footer.do_not_use_ab || check_at_most_once,
                    &common.algorithm,
                );
                return write_text_output(None, format!("1.{minor}\n").as_bytes());
            }
            if calc_max_image_size {
                let partition_size = partition_size.unwrap_or(0);
                let max = calc_max_hashtree_footer_image_size(
                    partition_size,
                    block_size as u64,
                    &hash_algorithm,
                    generate_fec,
                    fec_num_roots,
                    no_hashtree,
                )?;
                return write_text_output(None, format!("{max}\n").as_bytes());
            }

            let image = image
                .ok_or_else(|| anyhow::anyhow!("--image is required for add_hashtree_footer"))?;
            let (vbmeta_common, sign_options) = build_vbmeta_args(&common, 0, Vec::new())?;
            let salt = salt.map(|value| parse_hex_string(&value)).transpose()?;
            add_hashtree_footer_with_options(
                &image,
                &HashtreeFooterArgs {
                    partition_size,
                    partition_name,
                    hash_algorithm,
                    block_size,
                    salt,
                    chain_partitions: vbmeta_common.chain_partitions,
                    algorithm_name: vbmeta_common.algorithm_name,
                    key_spec: vbmeta_common.key_spec,
                    public_key_metadata: vbmeta_common.public_key_metadata,
                    rollback_index: vbmeta_common.rollback_index,
                    flags: vbmeta_common.flags,
                    rollback_index_location: vbmeta_common.rollback_index_location,
                    properties: vbmeta_common.properties,
                    kernel_cmdlines: vbmeta_common.kernel_cmdlines,
                    include_descriptors_from_images: vbmeta_common.include_descriptors_from_images,
                    release_string: vbmeta_common.release_string,
                    append_to_release_string: vbmeta_common.append_to_release_string,
                    output_vbmeta_image,
                    do_not_append_vbmeta_image,
                    use_persistent_root_digest: footer.use_persistent_digest,
                    do_not_use_ab: footer.do_not_use_ab,
                    no_hashtree,
                    check_at_most_once,
                    generate_fec,
                    fec_num_roots,
                },
                &FooterBuildOptions {
                    build: BuildSignOptions { sign: sign_options },
                    extra_descriptors: vbmeta_common.extra_descriptors,
                    setup_as_rootfs_from_kernel,
                },
            )
            .map_err(Into::into)
        }
        Commands::EraseFooter {
            image,
            keep_hashtree,
        } => erase_footer(&image, keep_hashtree).map_err(Into::into),
        Commands::ZeroHashtree { image } => zero_hashtree(&image).map_err(Into::into),
        Commands::ExtractVbmetaImage {
            image,
            output,
            padding_size,
        } => {
            let mut blob = load_vbmeta_blob(&image)?;
            if padding_size > 0 {
                let padded =
                    avbtool_rs::crypto::round_to_multiple(blob.len() as u64, padding_size) as usize;
                blob.resize(padded, 0);
            }
            write_binary_output(output, &blob)
        }
        Commands::ResizeImage {
            image,
            partition_size,
        } => resize_image(&image, partition_size).map_err(Into::into),
        Commands::VerifyImage {
            image,
            key,
            expected_chain_partitions,
            follow_chain_partitions,
            accept_zeroed_hashtree,
            format,
            output,
        } => {
            let key_blob = key.as_deref().map(extract_public_key).transpose()?;
            let expected_chain_partitions = expected_chain_partitions
                .into_iter()
                .map(parse_expected_chain_partition_spec)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let report = verify_image(
                &image,
                &VerifyImageOptions {
                    key_blob,
                    expected_chain_partitions,
                    follow_chain_partitions,
                    accept_zeroed_hashtree,
                },
            )?;
            let rendered = match format {
                ReportFormat::Text => report.messages.join("\n") + "\n",
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
            };
            write_text_output(output, rendered.as_bytes())
        }
        Commands::ResignImage {
            image,
            key,
            algorithm,
            signing_helper,
            signing_helper_with_files,
            auto_resize,
            rollback_index,
            force,
        } => {
            let sign =
                build_sign_options(Some(key.clone()), signing_helper, signing_helper_with_files)?;
            match resign_image_with_sign_options(
                &image,
                &key,
                Some(algorithm.as_str()),
                force,
                rollback_index,
                auto_resize,
                &ResignSignOptions { sign },
            )? {
                ResignOutcome::Resigned | ResignOutcome::SkippedUnsigned => Ok(()),
            }
        }
        Commands::UpdatePartitionDescriptor {
            image,
            partition_image,
            output,
            common,
        } => {
            let (args, sign_options) = build_vbmeta_args(&common, 0, Vec::new())?;
            if common.print_required_libavb_version {
                let result = update_partition_descriptor_with_options(
                    &image,
                    &partition_image,
                    &args,
                    &BuildSignOptions { sign: sign_options },
                )?;
                return write_text_output(
                    None,
                    format!("1.{}\n", result.required_libavb_version_minor).as_bytes(),
                );
            }
            let result = update_partition_descriptor_with_options(
                &image,
                &partition_image,
                &args,
                &BuildSignOptions { sign: sign_options },
            )?;
            write_binary_output(Some(output), &result.blob)
        }
        Commands::SetAbMetadata {
            misc_image,
            slot_data,
        } => set_ab_metadata(&misc_image, &slot_data),
        Commands::MakeCertificate {
            output,
            subject,
            subject_key,
            subject_key_version,
            subject_is_intermediate_authority,
            usage,
            usage_for_unlock,
            authority_key,
            signing_helper,
            signing_helper_with_files,
        } => {
            let usage = if let Some(usage) = usage {
                usage
            } else {
                resolve_builtin_usage(subject_is_intermediate_authority, usage_for_unlock)
                    .unwrap_or(CERT_USAGE_SIGNING)
                    .to_string()
            };
            let subject_bytes = fs::read(&subject)
                .with_context(|| format!("Failed to read {}", subject.display()))?;
            let blob = make_certificate_from_paths_with_options(
                &subject_key,
                &subject_bytes,
                &usage,
                subject_key_version,
                authority_key.as_deref(),
                signing_helper.map(PathBuf::from),
                signing_helper_with_files.map(PathBuf::from),
            )?;
            write_binary_output(output, &blob)
        }
        Commands::MakeCertPermanentAttributes {
            output,
            root_authority_key,
            product_id,
        } => {
            let product_id = fs::read(&product_id)
                .with_context(|| format!("Failed to read {}", product_id.display()))?;
            let blob = make_cert_permanent_attributes_from_paths(&root_authority_key, &product_id)?;
            write_binary_output(output, &blob)
        }
        Commands::MakeCertMetadata {
            output,
            intermediate_key_certificate,
            product_key_certificate,
        } => {
            let intermediate = fs::read(&intermediate_key_certificate).with_context(|| {
                format!("Failed to read {}", intermediate_key_certificate.display())
            })?;
            let product = fs::read(&product_key_certificate)
                .with_context(|| format!("Failed to read {}", product_key_certificate.display()))?;
            let blob = make_cert_metadata(&intermediate, &product)?;
            write_binary_output(output, &blob)
        }
        Commands::MakeCertUnlockCredential {
            output,
            intermediate_key_certificate,
            unlock_key_certificate,
            challenge,
            unlock_key,
            signing_helper,
            signing_helper_with_files,
        } => {
            let intermediate = fs::read(&intermediate_key_certificate).with_context(|| {
                format!("Failed to read {}", intermediate_key_certificate.display())
            })?;
            let unlock_cert = fs::read(&unlock_key_certificate)
                .with_context(|| format!("Failed to read {}", unlock_key_certificate.display()))?;
            let challenge_bytes = challenge
                .as_ref()
                .map(|path| {
                    fs::read(path).with_context(|| format!("Failed to read {}", path.display()))
                })
                .transpose()?;
            let blob = make_cert_unlock_credential_from_paths_with_options(
                &intermediate,
                &unlock_cert,
                challenge_bytes.as_deref(),
                unlock_key.as_deref(),
                signing_helper.map(PathBuf::from),
                signing_helper_with_files.map(PathBuf::from),
            )?;
            write_binary_output(output, &blob)
        }
        Commands::Unsupported(args) => {
            let command = args
                .first()
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            anyhow::bail!(
                "Subcommand '{}' is not implemented in avbtool-rs yet.",
                command
            )
        }
    }
}

fn build_vbmeta_args(
    common: &CommonArgs,
    padding_size: u64,
    mut extra_descriptors: Vec<avbtool_rs::info::DescriptorInfo>,
) -> anyhow::Result<(VbmetaImageArgs, SignOptions)> {
    let public_key_metadata = common
        .public_key_metadata
        .as_ref()
        .map(fs::read)
        .transpose()?;
    let mut properties = common
        .props
        .iter()
        .cloned()
        .map(parse_property_spec)
        .collect::<anyhow::Result<Vec<_>>>()?;
    properties.extend(
        common
            .props_from_file
            .iter()
            .cloned()
            .map(parse_property_file_spec)
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    let mut chain_specs = common
        .chain_partitions
        .iter()
        .map(|spec| parse_chain_partition_spec(spec, 0))
        .collect::<anyhow::Result<Vec<_>>>()?;
    chain_specs.extend(
        common
            .chain_partitions_do_not_use_ab
            .iter()
            .map(|spec| parse_chain_partition_spec(spec, 1))
            .collect::<anyhow::Result<Vec<_>>>()?,
    );

    if let Some(setup_image) = &common.setup_rootfs_from_kernel {
        let info = avbtool_rs::image::inspect_avb_image(setup_image)?;
        let pair = cmdline_descriptors_for_dm_verity(&info.descriptors)?;
        extra_descriptors.extend(pair);
    }

    let mut flags = common.flags;
    if common.set_hashtree_disabled_flag {
        flags |= 1;
    }
    if common.set_verification_disabled_flag {
        flags |= 2;
    }

    let release_string = common
        .internal_release_string
        .clone()
        .or_else(|| common.release_string.clone());

    let args = VbmetaImageArgs {
        algorithm_name: common.algorithm.clone(),
        key_spec: common.key.clone(),
        public_key_metadata,
        rollback_index: common.rollback_index,
        flags,
        rollback_index_location: common.rollback_index_location,
        properties,
        kernel_cmdlines: common.kernel_cmdlines.clone(),
        extra_descriptors,
        include_descriptors_from_images: common.include_descriptors_from_images.clone(),
        chain_partitions: chain_specs,
        release_string,
        append_to_release_string: common.append_to_release_string.clone(),
        padding_size,
    };
    let sign = build_sign_options(
        common.key.clone(),
        common.signing_helper.clone(),
        common.signing_helper_with_files.clone(),
    )?;
    Ok((args, sign))
}

fn build_sign_options(
    key: Option<String>,
    signing_helper: Option<String>,
    signing_helper_with_files: Option<String>,
) -> anyhow::Result<SignOptions> {
    let helper = signing_helper.map(PathBuf::from);
    let helper_files = signing_helper_with_files.map(PathBuf::from);
    let key_path = if helper.is_some() || helper_files.is_some() {
        let key = key.ok_or_else(|| {
            anyhow::anyhow!("signing helper requires --key with a filesystem path")
        })?;
        if key.starts_with("testkey_") {
            anyhow::bail!("signing helper requires --key with a filesystem path, not embedded key");
        }
        Some(PathBuf::from(key))
    } else {
        None
    };
    Ok(SignOptions {
        signing_helper: helper,
        signing_helper_with_files: helper_files,
        key_path,
    })
}

fn parse_property_spec(spec: String) -> anyhow::Result<PropertySpec> {
    let (key, value) = split_once_required(&spec, ':', "property")?;
    Ok(PropertySpec {
        key: key.to_string(),
        value: value.as_bytes().to_vec(),
    })
}

fn parse_property_file_spec(spec: String) -> anyhow::Result<PropertySpec> {
    let (key, path) = split_once_required(&spec, ':', "property file")?;
    Ok(PropertySpec {
        key: key.to_string(),
        value: fs::read(path).with_context(|| format!("Failed to read {path}"))?,
    })
}

fn parse_chain_partition_spec(spec: &str, flags: u32) -> anyhow::Result<ChainPartitionSpec> {
    let mut parts = spec.splitn(3, ':');
    let partition_name = parts.next().unwrap_or_default();
    let rollback_index_location = parts.next().unwrap_or_default();
    let key_path = parts.next().unwrap_or_default();
    if partition_name.is_empty() || rollback_index_location.is_empty() || key_path.is_empty() {
        anyhow::bail!(
            "Malformed chain partition spec '{spec}'. Expected PARTITION:ROLLBACK_SLOT:KEY_PATH"
        );
    }
    Ok(ChainPartitionSpec {
        partition_name: partition_name.to_string(),
        rollback_index_location: rollback_index_location.parse()?,
        public_key: fs::read(key_path).with_context(|| format!("Failed to read {key_path}"))?,
        flags,
    })
}

fn parse_expected_chain_partition_spec(spec: String) -> anyhow::Result<ExpectedChainPartition> {
    let (partition_name, rest) = split_once_required(&spec, ':', "expected chain partition")?;
    let (rollback_index_location, key_path) =
        split_once_required(rest, ':', "expected chain partition")?;
    Ok(ExpectedChainPartition {
        partition_name: partition_name.to_string(),
        rollback_index_location: rollback_index_location.parse()?,
        public_key: fs::read(key_path).with_context(|| format!("Failed to read {key_path}"))?,
    })
}

fn split_once_required<'a>(
    value: &'a str,
    separator: char,
    label: &str,
) -> anyhow::Result<(&'a str, &'a str)> {
    value
        .split_once(separator)
        .ok_or_else(|| anyhow::anyhow!("Malformed {label} spec '{value}'"))
}

fn write_text_output(output: Option<PathBuf>, bytes: &[u8]) -> anyhow::Result<()> {
    write_binary_output(output, bytes)
}

fn write_binary_output(output: Option<PathBuf>, bytes: &[u8]) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            ensure_parent_dir(&path)?;
            fs::write(path, bytes)?;
            Ok(())
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(bytes)?;
            stdout.flush()?;
            Ok(())
        }
    }
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn normalize_cli_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut iter = args.into_iter();
    let mut normalized = Vec::new();
    if let Some(program) = iter.next() {
        normalized.push(program);
    }
    if let Some(first) = iter.next() {
        normalized.push(normalize_first_arg(first));
    }
    normalized.extend(iter.map(normalize_flag_arg));
    normalized
}

fn normalize_first_arg(arg: OsString) -> OsString {
    match arg.to_str() {
        Some(text) if !text.starts_with('-') => OsString::from(text.replace('_', "-")),
        _ => arg,
    }
}

fn normalize_flag_arg(arg: OsString) -> OsString {
    match arg.to_str() {
        Some(text) if text.starts_with("--") => {
            if let Some((flag, value)) = text.split_once('=') {
                OsString::from(format!("{}={}", flag.replace('_', "-"), value))
            } else {
                OsString::from(text.replace('_', "-"))
            }
        }
        _ => arg,
    }
}

fn extract_embedded_public_key(image: &Path) -> anyhow::Result<Vec<u8>> {
    let info = avbtool_rs::image::inspect_avb_image(image)?;
    let blob = load_vbmeta_blob(image)?;
    let aux_start = 256 + info.header.authentication_data_block_size as usize;
    let public_key_offset = aux_start + info.header.public_key_offset as usize;
    let public_key_end = public_key_offset + info.header.public_key_size as usize;
    if public_key_end > blob.len() {
        anyhow::bail!("Embedded public key range exceeds vbmeta blob size.");
    }
    Ok(blob[public_key_offset..public_key_end].to_vec())
}

fn load_cert_info_text(image: &Path) -> anyhow::Result<String> {
    let info = avbtool_rs::image::inspect_avb_image(image)?;
    let blob = load_vbmeta_blob(image)?;
    let metadata = extract_public_key_metadata(&info.header, &blob)?;
    if metadata.is_empty() {
        return Ok(String::new());
    }
    let parsed = parse_metadata(&metadata)?;
    Ok(format_cert_metadata_info(&parsed))
}

fn image_is_sparse(image: &Path) -> bool {
    ImageHandler::open(image, true)
        .map(|handler| handler.is_sparse())
        .unwrap_or(false)
}

fn required_minor_for_hash_footer(
    rollback_index_location: u32,
    has_chain_partition_do_not_use_ab: bool,
    persistent_or_do_not_use_ab: bool,
    algorithm: &str,
) -> u32 {
    let mut minor = 0;
    if persistent_or_do_not_use_ab {
        minor = 1;
    }
    if rollback_index_location > 0 {
        minor = 2;
    }
    if has_chain_partition_do_not_use_ab {
        minor = 3;
    }
    if is_mldsa_algorithm(algorithm) {
        minor = 4;
    }
    minor
}

fn required_minor_for_hashtree_footer(
    rollback_index_location: u32,
    has_chain_partition_do_not_use_ab: bool,
    flag_minor_one: bool,
    algorithm: &str,
) -> u32 {
    let mut minor = 0;
    if flag_minor_one {
        minor = 1;
    }
    if rollback_index_location > 0 {
        minor = 2;
    }
    if has_chain_partition_do_not_use_ab {
        minor = 3;
    }
    if is_mldsa_algorithm(algorithm) {
        minor = 4;
    }
    minor
}

fn set_ab_metadata(misc_image: &Path, slot_data: &str) -> anyhow::Result<()> {
    let tokens = slot_data.split(':').collect::<Vec<_>>();
    if tokens.len() != 6 {
        anyhow::bail!("Malformed slot data '{slot_data}'.");
    }
    let values = tokens
        .iter()
        .map(|token| token.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()?;
    let mut payload = Vec::with_capacity(28);
    payload.extend_from_slice(b"\0AB0");
    payload.push(1);
    payload.push(0);
    payload.extend_from_slice(&[0u8; 2]);
    payload.push(values[0]);
    payload.push(values[1]);
    payload.push(u8::from(values[2] != 0));
    payload.push(0);
    payload.push(values[3]);
    payload.push(values[4]);
    payload.push(u8::from(values[5] != 0));
    payload.push(0);
    payload.extend_from_slice(&[0u8; 12]);
    let mut crc = Crc32Hasher::new();
    crc.update(&payload);
    payload.extend_from_slice(&crc.finalize().to_be_bytes());

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(misc_image)?;
    let required_size = 2048 + payload.len() as u64;
    if file.metadata()?.len() < required_size {
        file.set_len(required_size)?;
    }
    file.seek(std::io::SeekFrom::Start(2048))?;
    file.write_all(&payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse_cli<I, T>(args: I) -> Cli
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let normalized = normalize_cli_args(args.into_iter().map(Into::into));
        Cli::try_parse_from(normalized).expect("parse cli")
    }

    fn parse_cli_err<I, T>(args: I) -> clap::Error
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let normalized = normalize_cli_args(args.into_iter().map(Into::into));
        Cli::try_parse_from(normalized).expect_err("expected parse error")
    }

    #[test]
    fn version_command_parses() {
        let cli = parse_cli(["avbtool-rs", "version"]);
        assert!(matches!(cli.command, Commands::Version));
    }

    #[test]
    fn check_mldsa_support_parses() {
        let cli = parse_cli(["avbtool-rs", "check_mldsa_support"]);
        assert!(matches!(cli.command, Commands::CheckMldsaSupport));
    }

    #[test]
    fn normalize_accepts_underscore_commands_and_flags() {
        let args = normalize_cli_args([
            OsString::from("avbtool-rs"),
            OsString::from("info_image"),
            OsString::from("--print_required_libavb_version"),
            OsString::from("--use_persistent_digest"),
        ]);
        assert_eq!(args[1], "info-image");
        assert_eq!(args[2], "--print-required-libavb-version");
        assert_eq!(args[3], "--use-persistent-digest");
    }

    #[test]
    fn info_image_accepts_cert_and_atx_aliases() {
        for flag in ["--cert", "--atx"] {
            let cli = parse_cli(["avbtool-rs", "info_image", "--image", "x.img", flag]);
            match cli.command {
                Commands::InfoImage { cert, .. } => assert!(cert),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn resign_image_requires_algorithm() {
        let err = parse_cli_err([
            "avbtool-rs",
            "resign_image",
            "--image",
            "x.img",
            "--key",
            "k.pem",
        ]);
        let rendered = err.to_string();
        assert!(
            rendered.contains("algorithm") || rendered.contains("--algorithm"),
            "{rendered}"
        );
    }

    #[test]
    fn make_certificate_aliases_parse() {
        for command in ["make_certificate", "make_atx_certificate"] {
            let cli = parse_cli([
                "avbtool-rs",
                command,
                "--subject",
                "subject.bin",
                "--subject_key",
                "subject.pem",
                "--authority_key",
                "auth.pem",
            ]);
            assert!(matches!(cli.command, Commands::MakeCertificate { .. }));
        }
    }

    #[test]
    fn permanent_attributes_aliases_parse() {
        for command in [
            "make_cert_permanent_attributes",
            "make_atx_permanent_attributes",
        ] {
            let cli = parse_cli([
                "avbtool-rs",
                command,
                "--root_authority_key",
                "root.pem",
                "--product_id",
                "product.bin",
            ]);
            assert!(matches!(
                cli.command,
                Commands::MakeCertPermanentAttributes { .. }
            ));
        }
    }

    #[test]
    fn metadata_and_unlock_aliases_parse() {
        let metadata = parse_cli([
            "avbtool-rs",
            "make_atx_metadata",
            "--intermediate_key_certificate",
            "i.cert",
            "--product_key_certificate",
            "p.cert",
        ]);
        assert!(matches!(
            metadata.command,
            Commands::MakeCertMetadata { .. }
        ));

        let unlock = parse_cli([
            "avbtool-rs",
            "make_atx_unlock_credential",
            "--intermediate_key_certificate",
            "i.cert",
            "--unlock_key_certificate",
            "u.cert",
        ]);
        assert!(matches!(
            unlock.command,
            Commands::MakeCertUnlockCredential { .. }
        ));
    }

    #[test]
    fn add_hashtree_footer_accepts_fec_num_roots_and_setup_flags() {
        let cli = parse_cli([
            "avbtool-rs",
            "add_hashtree_footer",
            "--image",
            "system.img",
            "--partition_size",
            "4096",
            "--partition_name",
            "system",
            "--fec_num_roots",
            "4",
            "--setup_as_rootfs_from_kernel",
            "--use_persistent_digest",
            "--setup_rootfs_from_kernel",
            "ht.img",
            "--set_hashtree_disabled_flag",
            "--set_verification_disabled_flag",
            "--internal_release_string",
            "avbtool 1.4.0",
        ]);
        match cli.command {
            Commands::AddHashtreeFooter {
                fec_num_roots,
                setup_as_rootfs_from_kernel,
                footer,
                common,
                ..
            } => {
                assert_eq!(fec_num_roots, 4);
                assert!(setup_as_rootfs_from_kernel);
                assert!(footer.use_persistent_digest);
                assert!(common.setup_rootfs_from_kernel.is_some());
                assert!(common.set_hashtree_disabled_flag);
                assert!(common.set_verification_disabled_flag);
                assert_eq!(
                    common.internal_release_string.as_deref(),
                    Some("avbtool 1.4.0")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn footer_calculation_and_version_only_forms_do_not_require_mutation_args() {
        let hash_calc = parse_cli([
            "avbtool-rs",
            "add_hash_footer",
            "--partition_size",
            "69632",
            "--calc_max_image_size",
        ]);
        match &hash_calc.command {
            Commands::AddHashFooter {
                image,
                partition_size,
                partition_name,
                calc_max_image_size,
                ..
            } => {
                assert!(image.is_none());
                assert!(partition_name.is_none());
                assert!(*calc_max_image_size);
                assert_eq!(
                    calc_max_hash_footer_image_size(partition_size.unwrap()).unwrap(),
                    0
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        run(hash_calc).unwrap();

        let hash_version = parse_cli([
            "avbtool-rs",
            "add_hash_footer",
            "--partition_size",
            "69632",
            "--print_required_libavb_version",
        ]);
        match &hash_version.command {
            Commands::AddHashFooter {
                image,
                partition_name,
                common,
                ..
            } => {
                assert!(image.is_none());
                assert!(partition_name.is_none());
                assert!(common.print_required_libavb_version);
            }
            other => panic!("unexpected {other:?}"),
        }
        run(hash_version).unwrap();

        let hashtree_calc = parse_cli([
            "avbtool-rs",
            "add_hashtree_footer",
            "--partition_size",
            "69632",
            "--calc_max_image_size",
        ]);
        match &hashtree_calc.command {
            Commands::AddHashtreeFooter {
                image,
                partition_size,
                partition_name,
                hash_algorithm,
                block_size,
                do_not_generate_fec,
                fec_num_roots,
                calc_max_image_size,
                no_hashtree,
                ..
            } => {
                assert!(image.is_none());
                assert!(partition_name.is_empty());
                assert!(hash_algorithm.is_empty());
                assert!(*calc_max_image_size);
                assert_eq!(
                    calc_max_hashtree_footer_image_size(
                        partition_size.unwrap(),
                        u64::from(*block_size),
                        "sha1",
                        !*do_not_generate_fec,
                        *fec_num_roots,
                        *no_hashtree,
                    )
                    .unwrap(),
                    0
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        run(hashtree_calc).unwrap();

        let hashtree_version = parse_cli([
            "avbtool-rs",
            "add_hashtree_footer",
            "--print_required_libavb_version",
        ]);
        match &hashtree_version.command {
            Commands::AddHashtreeFooter {
                image,
                partition_name,
                common,
                ..
            } => {
                assert!(image.is_none());
                assert!(partition_name.is_empty());
                assert!(common.print_required_libavb_version);
            }
            other => panic!("unexpected {other:?}"),
        }
        run(hashtree_version).unwrap();
    }

    #[test]
    fn footer_mutations_validate_runtime_only_args() {
        let hash_image_err = run(parse_cli([
            "avbtool-rs",
            "add_hash_footer",
            "--partition_size",
            "131072",
            "--partition_name",
            "boot",
        ]))
        .unwrap_err();
        assert_eq!(
            hash_image_err.to_string(),
            "--image is required for add_hash_footer"
        );

        let hash_name_err = run(parse_cli([
            "avbtool-rs",
            "add_hash_footer",
            "--image",
            "unused.img",
            "--partition_size",
            "131072",
        ]))
        .unwrap_err();
        assert_eq!(
            hash_name_err.to_string(),
            "--partition_name is required for add_hash_footer"
        );

        let hashtree_image_err = run(parse_cli([
            "avbtool-rs",
            "add_hashtree_footer",
            "--partition_name",
            "system",
            "--hash_algorithm",
            "sha256",
        ]))
        .unwrap_err();
        assert_eq!(
            hashtree_image_err.to_string(),
            "--image is required for add_hashtree_footer"
        );
    }

    #[test]
    fn footer_calc_partition_size_semantics_match_aosp() {
        let hash_err = run(parse_cli([
            "avbtool-rs",
            "add_hash_footer",
            "--calc_max_image_size",
        ]))
        .unwrap_err();
        assert!(hash_err.to_string().contains("partition_size required"));

        let hashtree_calc =
            parse_cli(["avbtool-rs", "add_hashtree_footer", "--calc_max_image_size"]);
        assert!(matches!(
            &hashtree_calc.command,
            Commands::AddHashtreeFooter {
                image: None,
                partition_size: None,
                calc_max_image_size: true,
                ..
            }
        ));
        assert_eq!(
            calc_max_hashtree_footer_image_size(
                0,
                4096,
                "sha1",
                true,
                AVB_DEFAULT_FEC_NUM_ROOTS,
                false,
            )
            .unwrap(),
            0
        );
        run(hashtree_calc).unwrap();
    }

    #[test]
    fn update_partition_descriptor_accepts_common_args() {
        let cli = parse_cli([
            "avbtool-rs",
            "update_partition_descriptor",
            "--image",
            "vbmeta.img",
            "--partition_image",
            "boot.img",
            "--output",
            "out.img",
            "--algorithm",
            "SHA256_RSA2048",
            "--key",
            "key.pem",
            "--prop",
            "a:b",
            "--setup_rootfs_from_kernel",
            "root.img",
            "--print_required_libavb_version",
        ]);
        match cli.command {
            Commands::UpdatePartitionDescriptor { common, .. } => {
                assert_eq!(common.algorithm, "SHA256_RSA2048");
                assert_eq!(common.key.as_deref(), Some("key.pem"));
                assert!(common.print_required_libavb_version);
                assert_eq!(common.props, vec!["a:b".to_string()]);
                assert!(common.setup_rootfs_from_kernel.is_some());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_command_tree_builds() {
        Cli::command().debug_assert();
    }
}
