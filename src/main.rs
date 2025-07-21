use anyhow::{Context, Result};
use clap::Parser;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::process::Command;

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

        let temp_file = format!("{}.tmp.img", uuid);

        let status = Command::new("cryptsetup")
            .args(["luksHeaderBackup", &device, "--header-backup-file", &temp_file])
            .status()
            .context("Failed to backup LUKS header")?;

        if !status.success() {
            anyhow::bail!("cryptsetup failed with exit code {}", status.code().unwrap_or(-1));
        }

        let mut header_data = Vec::new();
        let mut file = fs::File::open(&temp_file).context("Failed to open temp file")?;
        file.read_to_end(&mut header_data).context("Failed to read temp file")?;

        let mut hasher = Sha1::new();
        hasher.update(&header_data);
        let hash = hasher.finalize();

        let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();

        let filename = format!("{}-{}-{}.img", hostname, uuid, hash_hex);

        fs::rename(&temp_file, &filename).context("Failed to rename temp file")?;

        for remote in &args.remotes {
            let status = Command::new("scp")
                .args([&filename, remote])
                .status()
                .context("Failed to run scp")?;

            if !status.success() {
                anyhow::bail!("scp failed with exit code {}", status.code().unwrap_or(-1));
            }
        }
    }

    Ok(())
}
