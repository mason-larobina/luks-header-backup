use anyhow::{Context, Result};
use clap::Parser;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::collections::HashMap;
use tempdir::TempDir;

#[derive(Parser)]
struct Args {
    /// Remote SCP destinations (e.g., root@host:/backup/dir/)
    #[arg(required = true)]
    remotes: Vec<String>,
}

fn get_luks_device_uuid_map() -> Result<HashMap<String, String>> {
    let output = Command::new("blkid")
        .args(["-o", "export"])
        .output()
        .context("Failed to run blkid to find LUKS devices")?;

    let output_str = String::from_utf8(output.stdout).context("Failed to parse blkid output")?;

    let mut result: HashMap<String, String> = HashMap::new();

    for segment in output_str.split("\n\n") {
        let mut map: HashMap<String, String> = HashMap::new();
        for line in segment.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        if map.get("TYPE").map_or(false, |ty| ty == "crypto_LUKS") {
            if let (Some(dev), Some(uuid)) = (map.get("DEVNAME"), map.get("UUID")) {
                result.insert(dev.clone(), uuid.clone());
            }
        }
    }

    Ok(result)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let hostname = hostname::get()
        .context("Failed to get hostname")?
        .to_string_lossy()
        .into_owned();

    let temp_dir = TempDir::new("luks-header-backup").context("Failed to create temp dir")?;

    let mut files_to_copy: Vec<PathBuf> = Vec::new();

    let device_uuid_map = get_luks_device_uuid_map()?;

    for (device, uuid) in device_uuid_map {
        let temp_file_path = temp_dir.path().join(format!("{}.tmp", uuid));

        let status = Command::new("cryptsetup")
            .args(["luksHeaderBackup", &device, "--header-backup-file", &temp_file_path.to_string_lossy()])
            .status()
            .context("Failed to backup LUKS header")?;

        if !status.success() {
            anyhow::bail!("cryptsetup failed with exit code {}", status.code().unwrap_or(-1));
        }

        let mut header_data = Vec::new();
        let mut file = fs::File::open(&temp_file_path).context("Failed to open temp file")?;
        file.read_to_end(&mut header_data).context("Failed to read temp file")?;

        let mut hasher = Sha1::new();
        hasher.update(&header_data);
        let hash = hasher.finalize();

        let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();

        let final_path = temp_dir.path().join(format!("luks-header-{}-{}-{}.img", hostname, uuid, hash_hex));

        fs::rename(&temp_file_path, &final_path).context("Failed to rename temp file")?;

        files_to_copy.push(final_path);
    }

    for remote in &args.remotes {
        if files_to_copy.is_empty() {
            continue;
        }

        let mut scp_args: Vec<String> = files_to_copy.iter().map(|p| p.to_string_lossy().to_string()).collect();
        scp_args.push(remote.clone());

        let status = Command::new("scp")
            .args(scp_args)
            .status()
            .context("Failed to run scp")?;

        if !status.success() {
            anyhow::bail!("scp failed with exit code {}", status.code().unwrap_or(-1));
        }
    }

    Ok(())
}
