use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output};

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
        if map.get("TYPE").map(|t| t == "crypto_LUKS").unwrap_or(false) {
            if let (Some(dev), Some(uuid)) = (map.get("DEVNAME"), map.get("UUID")) {
                result.insert(dev.clone(), uuid.clone());
                debug!("Found LUKS device {dev} with UUID {uuid}");
            } else {
                warn!("Found LUKS device but missing expected fields DEVNAME and UUID: {map:?}");
            }
        }
    }

    Ok(result)
}

fn run_command(cmd: &mut Command) -> Result<Output> {
    debug!("Running: {cmd:?}");

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to execute command {:?}: {}", cmd, e);
            return Err(anyhow!("Failed to execute command {:?}: {}", cmd, e));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "Command {:?} failed with exit code {}: stderr: {}",
            cmd,
            output.status.code().unwrap_or(-1),
            stderr
        );
        return Err(anyhow!(
            "Command {:?} failed with exit code {}",
            cmd,
            output.status.code().unwrap_or(-1)
        ));
    }

    Ok(output)
}

fn get_luks_device_uuid_map() -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("blkid");
    cmd.args(["-o", "export"]);

    let output = run_command(&mut cmd).with_context(|| "run blkid to find LUKS devices")?;

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

    if !nix::unistd::getuid().is_root() {
        anyhow::bail!("This program must be run as root");
    }

    info!(
        "Starting LUKS header backup with remotes: {:?}",
        args.remotes
    );

    let hostname = nix::unistd::gethostname()
        .context("Failed to get hostname")?
        .to_string_lossy()
        .to_string();
    info!("Hostname: {hostname}");

    let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;

    info!("Created temporary directory: {:?}", temp_dir.path());

    let mut files_to_copy: Vec<PathBuf> = Vec::new();

    let device_uuid_map = get_luks_device_uuid_map()?;

    info!("Found {} LUKS devices", device_uuid_map.len());

    for (device, uuid) in device_uuid_map {
        info!("Backing up LUKS header for device {device} with UUID {uuid}");

        let temp_file_path = temp_dir.path().join(format!("{uuid}.tmp"));

        let mut cmd = Command::new("cryptsetup");
        cmd.arg("luksHeaderBackup");
        cmd.arg(&device);
        cmd.arg("--header-backup-file");
        cmd.arg(&temp_file_path);

        run_command(&mut cmd).with_context(|| "backup LUKS header")?;

        info!("Backup successful for {device}");

        let temp_txt_path = temp_dir.path().join(format!("{uuid}.tmp.txt"));

        let mut dump_cmd = Command::new("cryptsetup");
        dump_cmd.arg("luksDump");
        dump_cmd.arg(&temp_file_path);

        let dump_output = run_command(&mut dump_cmd).with_context(|| "run luksDump")?;

        fs::write(&temp_txt_path, &dump_output.stdout)
            .context("Failed to write luksDump output to file")?;

        info!("luksDump successful for {device}");

        let mut header_data = Vec::new();
        let mut file = fs::File::open(&temp_file_path).context("Failed to open temp file")?;
        file.read_to_end(&mut header_data)
            .context("Failed to read temp file")?;

        let mut hasher = Sha256::new();
        hasher.update(&header_data);
        let hash = hasher.finalize();

        let hash_hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();

        info!("Computed SHA256 hash: {hash_hex}");

        let final_img_path = temp_dir.path().join(format!(
            "luks_header_backup.{hostname}.{uuid}.{}.img",
            &hash_hex[0..8]
        ));

        let final_txt_path = temp_dir.path().join(format!(
            "luks_header_backup.{hostname}.{uuid}.{}.txt",
            &hash_hex[0..8]
        ));

        fs::rename(&temp_file_path, &final_img_path).context("Failed to rename temp img file")?;

        fs::rename(&temp_txt_path, &final_txt_path).context("Failed to rename temp txt file")?;

        info!("Saved header to {final_img_path:?}");
        info!("Saved dump to {final_txt_path:?}");

        files_to_copy.push(final_img_path);
        files_to_copy.push(final_txt_path);
    }

    if files_to_copy.is_empty() {
        info!("No files to copy, exit");
        return Ok(());
    }

    let mut all_success = true;

    for remote in &args.remotes {
        info!("Processing remote: {remote}");

        assert!(!files_to_copy.is_empty());
        let mut scp_args: Vec<String> = files_to_copy
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        scp_args.push(remote.clone());

        let mut cmd = Command::new("scp");
        cmd.args(&scp_args);

        if let Err(_) = run_command(&mut cmd).with_context(|| format!("run scp to {remote}")) {
            all_success = false;
            // Error already logged in wrapper
        } else {
            info!("Copy successful to {remote}");
        }
    }

    if all_success {
        info!("Backup process completed successfully");
        Ok(())
    } else {
        anyhow::bail!("Some remote copies failed");
    }
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
