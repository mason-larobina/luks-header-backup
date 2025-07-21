use anyhow::{Context, Result};
use clap::Parser;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use tempdir::TempDir;

#[derive(Parser)]
struct Args {
    /// Remote SCP destinations (e.g., root@host:/backup/dir/)
    #[arg(required = true)]
    remotes: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let hostname = hostname::get()
        .context("Failed to get hostname")?
        .to_string_lossy()
        .into_owned();

    let temp_dir = TempDir::new("luks-header-backup").context("Failed to create temp dir")?;

    let mut files_to_copy: Vec<PathBuf> = Vec::new();

    let output = Command::new("blkid")
        .args(["-t", "TYPE=crypto_LUKS", "-o", "device"])
        .output()
        .context("Failed to run blkid to find LUKS devices")?;

    let devices: Vec<String> = String::from_utf8(output.stdout)?
        .lines()
        .map(|s| s.to_string())
        .collect();

    for device in devices {
        let uuid_output = Command::new("blkid")
            .args(["-s", "UUID", "-o", "value", &device])
            .output()
            .context("Failed to get UUID")?;

        let uuid = String::from_utf8(uuid_output.stdout)?
            .trim()
            .to_string();

        let temp_file_path = temp_dir.path().join(format!("{}.tmp.img", uuid));

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

        let final_path = temp_dir.path().join(format!("{}-{}-{}.img", hostname, uuid, hash_hex));

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
