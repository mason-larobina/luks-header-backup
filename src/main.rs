use anyhow::{Context, Result};
use clap::Parser;
use env_logger;
use hostname;
use log::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use tempfile;

#[derive(Parser)]
struct Args {
    /// Remote SCP destinations (e.g., root@host:/backup/dir/)
    #[arg(required = true)]
    remotes: Vec<String>,
}

fn parse_blkid_output(output_str: &str) -> Result<HashMap<String, String>> {
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
                debug!("Found LUKS device {} with UUID {}", dev, uuid);
            }
        }
    }

    Ok(result)
}

fn get_luks_device_uuid_map() -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("blkid");
    cmd.args(["-o", "export"]);

    debug!("Running: {:?}", cmd);
    let output = cmd
        .output()
        .context("Failed to run blkid to find LUKS devices")?;

    let output_str = String::from_utf8(output.stdout).context("Failed to parse blkid output")?;

    parse_blkid_output(&output_str)
}

fn main() -> Result<()> {
    let args = Args::parse();

    if std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("Failed to check user ID")?;
    let uid_str = String::from_utf8(output.stdout).context("Invalid UTF-8 in id output")?;
    if uid_str.trim() != "0" {
        anyhow::bail!("This program must be run as root");
    }

    info!(
        "Starting LUKS header backup with remotes: {:?}",
        args.remotes
    );

    let hostname = hostname::get()
        .context("Failed to get hostname")?
        .to_string_lossy()
        .into_owned();

    info!("Hostname: {}", hostname);

    let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;

    info!("Created temporary directory: {:?}", temp_dir.path());

    let mut files_to_copy: Vec<PathBuf> = Vec::new();

    let device_uuid_map = get_luks_device_uuid_map()?;

    info!("Found {} LUKS devices", device_uuid_map.len());

    for (device, uuid) in device_uuid_map {
        info!(
            "Backing up LUKS header for device {} with UUID {}",
            device, uuid
        );

        let temp_file_path = temp_dir.path().join(format!("{}.tmp", uuid));

        let mut cmd = Command::new("cryptsetup");
        cmd.arg("luksHeaderBackup");
        cmd.arg(&device);
        cmd.arg("--header-backup-file");
        cmd.arg(&temp_file_path);

        debug!("Running: {:?}", cmd);
        let status = cmd.status().context("Failed to backup LUKS header")?;

        if !status.success() {
            anyhow::bail!(
                "cryptsetup failed with exit code {}",
                status.code().unwrap_or(-1)
            );
        }

        info!("Backup successful for {}", device);

        let mut header_data = Vec::new();
        let mut file = fs::File::open(&temp_file_path).context("Failed to open temp file")?;
        file.read_to_end(&mut header_data)
            .context("Failed to read temp file")?;

        let mut hasher = Sha256::new();
        hasher.update(&header_data);
        let hash = hasher.finalize();

        let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();

        info!("Computed SHA256 hash: {}", hash_hex);

        let final_path = temp_dir.path().join(format!(
            "luks_header_backup.{}.{}.{}.img",
            hostname,
            uuid,
            &hash_hex[0..8]
        ));

        fs::rename(&temp_file_path, &final_path).context("Failed to rename temp file")?;

        info!("Saved header to {:?}", final_path);

        files_to_copy.push(final_path);
    }

    if files_to_copy.is_empty() {
        info!("No files to copy, exit");
        return Ok(());
    }

    for remote in &args.remotes {
        info!("Processing remote: {}", remote);

        assert!(files_to_copy.len() > 0);
        let mut scp_args: Vec<String> = files_to_copy
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        scp_args.push(remote.clone());

        let mut cmd = Command::new("scp");
        cmd.args(&scp_args);

        debug!("Running: {:?}", cmd);
        let status = cmd.status().context("Failed to run scp")?;

        if !status.success() {
            anyhow::bail!("scp failed with exit code {}", status.code().unwrap_or(-1));
        }

        info!("Copy successful to {}", remote);
    }

    info!("Backup process completed successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_blkid_output() -> Result<()> {
        let sample_output = r#"
DEVNAME=/dev/sda1
UUID=12345678-1234-1234-1234-123456789abc
TYPE=crypto_LUKS

DEVNAME=/dev/sda2
UUID=abcdef12-3456-7890-abcd-ef1234567890
TYPE=ext4

DEVNAME=/dev/sdb1
UUID=87654321-4321-4321-4321-876543210fed
TYPE=crypto_LUKS
"#;

        let result = parse_blkid_output(sample_output)?;

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get("/dev/sda1").unwrap(),
            "12345678-1234-1234-1234-123456789abc"
        );
        assert_eq!(
            result.get("/dev/sdb1").unwrap(),
            "87654321-4321-4321-4321-876543210fed"
        );
        assert!(result.get("/dev/sda2").is_none());

        // Test empty output
        let empty_result = parse_blkid_output("")?;
        assert!(empty_result.is_empty());

        // Test malformed segment
        let malformed = "DEVNAME=/dev/sdc1\nTYPE=crypto_LUKS\n\nINVALID";
        let malformed_result = parse_blkid_output(malformed)?;
        assert_eq!(malformed_result.len(), 0); // Skips invalid, no UUID

        Ok(())
    }
}
