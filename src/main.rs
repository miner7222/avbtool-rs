use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use avbtool_rs::builder::{
    ChainPartitionSpec, PropertySpec, VbmetaImageArgs, append_vbmeta_image, make_vbmeta_image,
};
use avbtool_rs::crypto::{extract_public_key, extract_public_key_digest};
use avbtool_rs::digest::{
    calculate_kernel_cmdline, calculate_vbmeta_digest, print_partition_digests,
};
use avbtool_rs::footer::{
    HashFooterArgs, HashtreeFooterArgs, add_hash_footer, add_hashtree_footer, erase_footer,
    parse_hex_string, resize_image, zero_hashtree,
};
use avbtool_rs::info::{generate_info_report, scan_input};
use avbtool_rs::image::load_vbmeta_blob;
use avbtool_rs::resign::ResignOutcome;
use avbtool_rs::verify::{ExpectedChainPartition, VerifyImageOptions, verify_image};
use clap::{Parser, Subcommand, ValueEnum};
use crc32fast::Hasher as Crc32Hasher;

#[derive(Parser, Debug)]
#[command(name = "avbtool-rs", version, about = "Pure Rust AVB tooling")]
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
        #[arg(long, alias = "atx")]
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
        #[arg(long)]
        internal_release_string: Option<String>,
        #[arg(long)]
        setup_rootfs_from_kernel: Option<PathBuf>,
        #[arg(long = "prop")]
        props: Vec<String>,
        #[arg(long = "prop-from-file")]
        props_from_file: Vec<String>,
        #[arg(long = "kernel-cmdline")]
        kernel_cmdlines: Vec<String>,
        #[arg(long = "include-descriptors-from-image")]
        include_descriptors_from_images: Vec<PathBuf>,
        #[arg(long = "chain-partition")]
        chain_partitions: Vec<String>,
        #[arg(long = "chain-partition-do-not-use-ab")]
        chain_partitions_do_not_use_ab: Vec<String>,
        #[arg(long)]
        release_string: Option<String>,
        #[arg(long)]
        append_to_release_string: Option<String>,
        #[arg(long, default_value_t = 0)]
        padding_size: u64,
        #[arg(long)]
        print_required_libavb_version: bool,
        #[arg(long)]
        set_hashtree_disabled_flag: bool,
        #[arg(long)]
        set_verification_disabled_flag: bool,
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
        image: PathBuf,
        #[arg(long)]
        partition_size: Option<u64>,
        #[arg(long)]
        dynamic_partition_size: bool,
        #[arg(long)]
        partition_name: String,
        #[arg(long, default_value = "sha256")]
        hash_algorithm: String,
        #[arg(long)]
        salt: Option<String>,
        #[arg(long)]
        calc_max_image_size: bool,
        #[arg(long = "chain-partition")]
        chain_partitions: Vec<String>,
        #[arg(long = "chain-partition-do-not-use-ab")]
        chain_partitions_do_not_use_ab: Vec<String>,
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
        #[arg(long = "prop")]
        props: Vec<String>,
        #[arg(long = "prop-from-file")]
        props_from_file: Vec<String>,
        #[arg(long = "kernel-cmdline")]
        kernel_cmdlines: Vec<String>,
        #[arg(long = "include-descriptors-from-image")]
        include_descriptors_from_images: Vec<PathBuf>,
        #[arg(long)]
        release_string: Option<String>,
        #[arg(long)]
        append_to_release_string: Option<String>,
        #[arg(long)]
        output_vbmeta_image: Option<PathBuf>,
        #[arg(long)]
        do_not_append_vbmeta_image: bool,
        #[arg(long)]
        use_persistent_digest: bool,
        #[arg(long)]
        do_not_use_ab: bool,
        #[arg(long)]
        print_required_libavb_version: bool,
    },
    AddHashtreeFooter {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        partition_size: Option<u64>,
        #[arg(long)]
        partition_name: String,
        #[arg(long, default_value = "sha1")]
        hash_algorithm: String,
        #[arg(long, default_value_t = 4096)]
        block_size: u32,
        #[arg(long)]
        salt: Option<String>,
        #[arg(long)]
        do_not_generate_fec: bool,
        #[arg(long, default_value_t = 2)]
        fec_num_roots: u32,
        #[arg(long)]
        calc_max_image_size: bool,
        #[arg(long = "chain-partition")]
        chain_partitions: Vec<String>,
        #[arg(long = "chain-partition-do-not-use-ab")]
        chain_partitions_do_not_use_ab: Vec<String>,
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
        #[arg(long = "prop")]
        props: Vec<String>,
        #[arg(long = "prop-from-file")]
        props_from_file: Vec<String>,
        #[arg(long = "kernel-cmdline")]
        kernel_cmdlines: Vec<String>,
        #[arg(long = "include-descriptors-from-image")]
        include_descriptors_from_images: Vec<PathBuf>,
        #[arg(long)]
        release_string: Option<String>,
        #[arg(long)]
        append_to_release_string: Option<String>,
        #[arg(long)]
        output_vbmeta_image: Option<PathBuf>,
        #[arg(long)]
        do_not_append_vbmeta_image: bool,
        #[arg(long)]
        setup_as_rootfs_from_kernel: bool,
        #[arg(long)]
        use_persistent_root_digest: bool,
        #[arg(long)]
        do_not_use_ab: bool,
        #[arg(long)]
        no_hashtree: bool,
        #[arg(long)]
        check_at_most_once: bool,
        #[arg(long)]
        generate_fec: bool,
        #[arg(long)]
        print_required_libavb_version: bool,
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
        #[arg(long, default_value = "")]
        key: String,
        #[arg(long)]
        algorithm: Option<String>,
        #[arg(long)]
        signing_helper: Option<String>,
        #[arg(long)]
        signing_helper_with_files: Option<String>,
        #[arg(long)]
        auto_resize: bool,
        #[arg(long)]
        rollback_index: Option<u64>,
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
        #[arg(long)]
        key: String,
        #[arg(long)]
        algorithm: Option<String>,
        #[arg(long)]
        signing_helper: Option<String>,
        #[arg(long)]
        signing_helper_with_files: Option<String>,
        #[arg(long)]
        rollback_index: Option<u64>,
        #[arg(long)]
        flags: Option<u32>,
    },
    SetAbMetadata {
        #[arg(long)]
        misc_image: PathBuf,
        #[arg(long, default_value = "15:7:0:14:7:0")]
        slot_data: String,
    },
    #[command(external_subcommand)]
    Unsupported(Vec<String>),
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
        Commands::Version => write_text_output(None, format!("avbtool-rs {}\n", env!("CARGO_PKG_VERSION")).as_bytes()),
        Commands::CheckMldsaSupport => anyhow::bail!("ML-DSA is NOT supported."),
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
            if cert {
                anyhow::bail!("--cert/--atx info view is not implemented in pure Rust yet.");
            }
            let report = match format {
                ReportFormat::Text => generate_info_report(&image)?,
                ReportFormat::Json => serde_json::to_string_pretty(&scan_input(&image)?)?,
            };
            if let Some(output_pubkey) = output_pubkey {
                let public_key = extract_embedded_public_key(&image)?;
                write_binary_output(Some(output_pubkey), &public_key)?;
            }
            write_text_output(output, report.as_bytes())
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
            algorithm,
            key,
            signing_helper,
            signing_helper_with_files,
            public_key_metadata,
            rollback_index,
            flags,
            rollback_index_location,
            internal_release_string,
            setup_rootfs_from_kernel,
            props,
            props_from_file,
            kernel_cmdlines,
            include_descriptors_from_images,
            chain_partitions,
            chain_partitions_do_not_use_ab,
            release_string,
            append_to_release_string,
            padding_size,
            print_required_libavb_version,
            set_hashtree_disabled_flag,
            set_verification_disabled_flag,
        } => {
            reject_unsupported_helper_args(signing_helper, signing_helper_with_files)?;
            reject_unsupported_option(
                "setup_rootfs_from_kernel",
                setup_rootfs_from_kernel.is_some(),
            )?;
            let public_key_metadata = public_key_metadata
                .map(|path| fs::read(path))
                .transpose()?;
            let mut properties = props
                .into_iter()
                .map(parse_property_spec)
                .collect::<anyhow::Result<Vec<_>>>()?;
            properties.extend(
                props_from_file
                    .into_iter()
                    .map(parse_property_file_spec)
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let mut chain_specs = chain_partitions
                .into_iter()
                .map(|spec| parse_chain_partition_spec(&spec, 0))
                .collect::<anyhow::Result<Vec<_>>>()?;
            chain_specs.extend(
                chain_partitions_do_not_use_ab
                    .into_iter()
                    .map(|spec| parse_chain_partition_spec(&spec, 1))
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let mut flags = flags;
            if set_hashtree_disabled_flag {
                flags |= 1;
            }
            if set_verification_disabled_flag {
                flags |= 2;
            }
            let args = VbmetaImageArgs {
                algorithm_name: algorithm,
                key_spec: key,
                public_key_metadata,
                rollback_index,
                flags,
                rollback_index_location,
                properties,
                kernel_cmdlines,
                extra_descriptors: Vec::new(),
                include_descriptors_from_images,
                chain_partitions: chain_specs,
                release_string: internal_release_string.or(release_string),
                append_to_release_string,
                padding_size,
            };
            if print_required_libavb_version {
                return write_text_output(
                    None,
                    format!(
                        "1.{}\n",
                        avbtool_rs::builder::required_libavb_minor_for_args(&args)
                    )
                    .as_bytes(),
                );
            }
            if let Some(output) = output {
                make_vbmeta_image(&output, &args)?;
                Ok(())
            } else {
                let mut blob = avbtool_rs::builder::build_vbmeta_blob(&args)?;
                if args.padding_size > 0 {
                    let padded = avbtool_rs::crypto::round_to_multiple(
                        blob.len() as u64,
                        args.padding_size,
                    ) as usize;
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
            chain_partitions,
            chain_partitions_do_not_use_ab,
            algorithm,
            key,
            signing_helper,
            signing_helper_with_files,
            public_key_metadata,
            rollback_index,
            flags,
            rollback_index_location,
            props,
            props_from_file,
            kernel_cmdlines,
            include_descriptors_from_images,
            release_string,
            append_to_release_string,
            output_vbmeta_image,
            do_not_append_vbmeta_image,
            use_persistent_digest,
            do_not_use_ab,
            print_required_libavb_version,
        } => {
            reject_unsupported_helper_args(signing_helper, signing_helper_with_files)?;
            if print_required_libavb_version {
                let minor = required_minor_for_hash_footer(
                    rollback_index_location as u64,
                    !chain_partitions_do_not_use_ab.is_empty(),
                    use_persistent_digest || do_not_use_ab,
                );
                return write_text_output(None, format!("1.{minor}\n").as_bytes());
            }
            if calc_max_image_size {
                let max = calc_max_hash_footer_image_size(
                    partition_size,
                    &partition_name,
                    &hash_algorithm,
                    algorithm.as_str(),
                    key.as_deref(),
                    public_key_metadata.as_deref(),
                    props.as_slice(),
                    props_from_file.as_slice(),
                    kernel_cmdlines.as_slice(),
                    include_descriptors_from_images.as_slice(),
                    chain_partitions.as_slice(),
                    chain_partitions_do_not_use_ab.as_slice(),
                    rollback_index,
                    flags,
                    rollback_index_location as u64,
                    release_string.clone(),
                    append_to_release_string.clone(),
                    use_persistent_digest,
                    do_not_use_ab,
                )?;
                return write_text_output(None, format!("{max}\n").as_bytes());
            }
            let public_key_metadata = public_key_metadata
                .map(|path| fs::read(path))
                .transpose()?;
            let mut properties = props
                .into_iter()
                .map(parse_property_spec)
                .collect::<anyhow::Result<Vec<_>>>()?;
            properties.extend(
                props_from_file
                    .into_iter()
                    .map(parse_property_file_spec)
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let mut chain_specs = chain_partitions
                .into_iter()
                .map(|spec| parse_chain_partition_spec(&spec, 0))
                .collect::<anyhow::Result<Vec<_>>>()?;
            chain_specs.extend(
                chain_partitions_do_not_use_ab
                    .into_iter()
                    .map(|spec| parse_chain_partition_spec(&spec, 1))
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let salt = salt.map(|value| parse_hex_string(&value)).transpose()?;
            add_hash_footer(
                &image,
                &HashFooterArgs {
                    partition_size,
                    dynamic_partition_size,
                    partition_name,
                    hash_algorithm,
                    salt,
                    chain_partitions: chain_specs,
                    algorithm_name: algorithm,
                    key_spec: key,
                    public_key_metadata,
                    rollback_index,
                    flags,
                    rollback_index_location,
                    properties,
                    kernel_cmdlines,
                    include_descriptors_from_images,
                    release_string,
                    append_to_release_string,
                    output_vbmeta_image,
                    do_not_append_vbmeta_image,
                    use_persistent_digest,
                    do_not_use_ab,
                },
            )
            .map_err(Into::into)
        }
        Commands::AddHashtreeFooter {
            image,
            partition_size,
            partition_name,
            hash_algorithm,
            block_size,
            salt,
            do_not_generate_fec,
            fec_num_roots,
            calc_max_image_size,
            chain_partitions,
            chain_partitions_do_not_use_ab,
            algorithm,
            key,
            signing_helper,
            signing_helper_with_files,
            public_key_metadata,
            rollback_index,
            flags,
            rollback_index_location,
            props,
            props_from_file,
            kernel_cmdlines,
            include_descriptors_from_images,
            release_string,
            append_to_release_string,
            output_vbmeta_image,
            do_not_append_vbmeta_image,
            setup_as_rootfs_from_kernel,
            use_persistent_root_digest,
            do_not_use_ab,
            no_hashtree,
            check_at_most_once,
            generate_fec,
            print_required_libavb_version,
        } => {
            reject_unsupported_helper_args(signing_helper, signing_helper_with_files)?;
            reject_unsupported_option("setup_as_rootfs_from_kernel", setup_as_rootfs_from_kernel)?;
            let generate_fec = generate_fec || !do_not_generate_fec;
            reject_unsupported_option("fec_num_roots", fec_num_roots != 2)?;
            if print_required_libavb_version {
                let minor = required_minor_for_hashtree_footer(
                    rollback_index_location as u64,
                    !chain_partitions_do_not_use_ab.is_empty(),
                    use_persistent_root_digest || do_not_use_ab || check_at_most_once,
                );
                return write_text_output(None, format!("1.{minor}\n").as_bytes());
            }
            reject_unsupported_option("calc_max_image_size", calc_max_image_size)?;
            let public_key_metadata = public_key_metadata
                .map(|path| fs::read(path))
                .transpose()?;
            let mut properties = props
                .into_iter()
                .map(parse_property_spec)
                .collect::<anyhow::Result<Vec<_>>>()?;
            properties.extend(
                props_from_file
                    .into_iter()
                    .map(parse_property_file_spec)
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let mut chain_specs = chain_partitions
                .into_iter()
                .map(|spec| parse_chain_partition_spec(&spec, 0))
                .collect::<anyhow::Result<Vec<_>>>()?;
            chain_specs.extend(
                chain_partitions_do_not_use_ab
                    .into_iter()
                    .map(|spec| parse_chain_partition_spec(&spec, 1))
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
            let salt = salt.map(|value| parse_hex_string(&value)).transpose()?;
            add_hashtree_footer(
                &image,
                &HashtreeFooterArgs {
                    partition_size,
                    partition_name,
                    hash_algorithm,
                    block_size,
                    salt,
                    chain_partitions: chain_specs,
                    algorithm_name: algorithm,
                    key_spec: key,
                    public_key_metadata,
                    rollback_index,
                    flags,
                    rollback_index_location,
                    properties,
                    kernel_cmdlines,
                    include_descriptors_from_images,
                    release_string,
                    append_to_release_string,
                    output_vbmeta_image,
                    do_not_append_vbmeta_image,
                    use_persistent_root_digest,
                    do_not_use_ab,
                    no_hashtree,
                    check_at_most_once,
                    generate_fec,
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
                let padded = avbtool_rs::crypto::round_to_multiple(blob.len() as u64, padding_size) as usize;
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
            reject_unsupported_helper_args(signing_helper, signing_helper_with_files)?;
            match avbtool_rs::resign::resign_image_with_options(
                &image,
                &key,
                algorithm.as_deref(),
                force,
                rollback_index,
                auto_resize,
            )? {
                ResignOutcome::Resigned | ResignOutcome::SkippedUnsigned => Ok(()),
            }
        }
        Commands::UpdatePartitionDescriptor {
            image,
            partition_image,
            output,
            key,
            algorithm,
            signing_helper,
            signing_helper_with_files,
            rollback_index,
            flags,
        } => {
            reject_unsupported_helper_args(signing_helper, signing_helper_with_files)?;
            avbtool_rs::builder::rebuild_vbmeta_image_with_overrides(
                &output,
                &image,
                &[partition_image.as_path()],
                &key,
                algorithm.as_deref(),
                rollback_index,
                flags,
            )?;
            Ok(())
        }
        Commands::SetAbMetadata {
            misc_image,
            slot_data,
        } => set_ab_metadata(&misc_image, &slot_data),
        Commands::Unsupported(args) => {
            let command = args.first().cloned().unwrap_or_else(|| "<unknown>".to_string());
            anyhow::bail!(
                "Subcommand '{}' is not implemented in avbtool-rs yet.",
                command
            )
        }
    }
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
        value: fs::read(path).with_context(|| format!("Failed to read {}", path))?,
    })
}

fn parse_chain_partition_spec(spec: &str, flags: u32) -> anyhow::Result<ChainPartitionSpec> {
    let mut parts = spec.splitn(3, ':');
    let partition_name = parts.next().unwrap_or_default();
    let rollback_index_location = parts.next().unwrap_or_default();
    let key_path = parts.next().unwrap_or_default();
    if partition_name.is_empty() || rollback_index_location.is_empty() || key_path.is_empty() {
        anyhow::bail!(
            "Malformed chain partition spec '{}'. Expected PARTITION:ROLLBACK_SLOT:KEY_PATH",
            spec
        );
    }
    Ok(ChainPartitionSpec {
        partition_name: partition_name.to_string(),
        rollback_index_location: rollback_index_location.parse()?,
        public_key: fs::read(key_path).with_context(|| format!("Failed to read {}", key_path))?,
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
        public_key: fs::read(key_path).with_context(|| format!("Failed to read {}", key_path))?,
    })
}

fn split_once_required<'a>(
    value: &'a str,
    separator: char,
    label: &str,
) -> anyhow::Result<(&'a str, &'a str)> {
    value
        .split_once(separator)
        .ok_or_else(|| anyhow::anyhow!("Malformed {} spec '{}'", label, value))
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
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

fn reject_unsupported_helper_args(
    signing_helper: Option<String>,
    signing_helper_with_files: Option<String>,
) -> anyhow::Result<()> {
    reject_unsupported_option("signing_helper", signing_helper.is_some())?;
    reject_unsupported_option("signing_helper_with_files", signing_helper_with_files.is_some())
}

fn reject_unsupported_option(name: &str, used: bool) -> anyhow::Result<()> {
    if used {
        anyhow::bail!("Option '{}' is not implemented in pure Rust yet.", name);
    }
    Ok(())
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

fn required_minor_for_hash_footer(
    rollback_index_location: u64,
    has_chain_partition_do_not_use_ab: bool,
    persistent_or_do_not_use_ab: bool,
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
    minor
}

fn required_minor_for_hashtree_footer(
    rollback_index_location: u64,
    has_chain_partition_do_not_use_ab: bool,
    flag_minor_one: bool,
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
    minor
}

#[allow(clippy::too_many_arguments)]
fn calc_max_hash_footer_image_size(
    partition_size: Option<u64>,
    partition_name: &str,
    hash_algorithm: &str,
    algorithm: &str,
    key: Option<&str>,
    public_key_metadata: Option<&Path>,
    props: &[String],
    props_from_file: &[String],
    kernel_cmdlines: &[String],
    include_descriptors_from_images: &[PathBuf],
    chain_partitions: &[String],
    chain_partitions_do_not_use_ab: &[String],
    rollback_index: u64,
    flags: u32,
    rollback_index_location: u64,
    release_string: Option<String>,
    append_to_release_string: Option<String>,
    use_persistent_digest: bool,
    do_not_use_ab: bool,
) -> anyhow::Result<u64> {
    let partition_size = partition_size.ok_or_else(|| anyhow::anyhow!("partition_size required"))?;
    let public_key_metadata = public_key_metadata.map(fs::read).transpose()?;
    let mut properties = props
        .iter()
        .cloned()
        .map(parse_property_spec)
        .collect::<anyhow::Result<Vec<_>>>()?;
    properties.extend(
        props_from_file
            .iter()
            .cloned()
            .map(parse_property_file_spec)
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    let mut chain_specs = chain_partitions
        .iter()
        .map(|spec| parse_chain_partition_spec(spec, 0))
        .collect::<anyhow::Result<Vec<_>>>()?;
    chain_specs.extend(
        chain_partitions_do_not_use_ab
            .iter()
            .map(|spec| parse_chain_partition_spec(spec, 1))
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    let digest_size = avbtool_rs::footer::hash_digest_size(hash_algorithm)?;
    let mut descriptor_flags = 0u32;
    if do_not_use_ab {
        descriptor_flags |= 1;
    }
    let vbmeta = avbtool_rs::builder::build_vbmeta_blob(&VbmetaImageArgs {
        algorithm_name: algorithm.to_string(),
        key_spec: key.map(str::to_string),
        public_key_metadata,
        rollback_index,
        flags,
        rollback_index_location: rollback_index_location as u32,
        properties,
        kernel_cmdlines: kernel_cmdlines.to_vec(),
        extra_descriptors: vec![avbtool_rs::info::DescriptorInfo::Hash {
            image_size: 0,
            hash_algorithm: hash_algorithm.to_string(),
            partition_name: partition_name.to_string(),
            salt: vec![0u8; digest_size],
            digest: if use_persistent_digest {
                Vec::new()
            } else {
                vec![0u8; digest_size]
            },
            flags: descriptor_flags,
        }],
        include_descriptors_from_images: include_descriptors_from_images.to_vec(),
        chain_partitions: chain_specs,
        release_string,
        append_to_release_string,
        padding_size: 0,
    })?;
    let metadata = avbtool_rs::crypto::round_to_multiple(vbmeta.len() as u64, 4096) + 4096;
    Ok(partition_size.saturating_sub(metadata))
}

fn set_ab_metadata(misc_image: &Path, slot_data: &str) -> anyhow::Result<()> {
    let tokens = slot_data.split(':').collect::<Vec<_>>();
    if tokens.len() != 6 {
        anyhow::bail!("Malformed slot data '{}'.", slot_data);
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
