use anyhow::{Context, Result, anyhow};
use clap::Parser;
use log::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Parser, Debug)]
#[command(about = "A tool to backup LUKS headers.")]
struct Args {
    /// Remote SCP destinations (e.g., root@host:/backup/dir/).
    #[arg(long = "remote-path")]
    remote_paths: Vec<String>,

    /// Local paths to backup headers to.
    #[arg(long = "backup-path")]
    backup_paths: Vec<PathBuf>,
}

fn run_command(cmd: &mut Command) -> Result<Output> {
    debug!("Running: {cmd:?}");

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return Err(anyhow!("Failed to execute command {:?}: {}", cmd, e));
        }
    };

    if !output.status.success() {
        return Err(anyhow!(
            "Command {cmd:?} failed with exit code {}: stderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    Ok(output)
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

fn get_luks_device_uuid_map() -> Result<HashMap<String, String>> {
    let mut cmd = Command::new("blkid");
    cmd.args(["-o", "export"]);

    let output = run_command(&mut cmd).context("Find LUKS devices")?;
    let output_str = String::from_utf8(output.stdout).context("Failed to parse blkid output")?;

    parse_blkid_output(&output_str)
}

struct BackupArtifacts {
    uuid: String,
    img_path: PathBuf,
    txt_path: PathBuf,
    short_hash: String,
}

fn create_backup_artifacts(
    device: &str,
    uuid: &str,
    hostname: &str,
    temp_path: &Path,
) -> Result<BackupArtifacts> {
    info!("Creating backup artifacts for device {device} with UUID {uuid}");

    let temp_file_path = temp_path.join(format!("{uuid}.img.tmp"));
    let temp_txt_path = temp_path.join(format!("{uuid}.txt.tmp"));

    let mut cmd = Command::new("cryptsetup");
    cmd.arg("luksHeaderBackup");
    cmd.arg(device);
    cmd.arg("--header-backup-file");
    cmd.arg(&temp_file_path);
    run_command(&mut cmd).context("Backup LUKS header")?;

    let mut dump_cmd = Command::new("cryptsetup");
    dump_cmd.arg("luksDump");
    dump_cmd.arg(&temp_file_path);
    let dump_output = run_command(&mut dump_cmd).context("Dump LUKS header")?;
    fs::write(&temp_txt_path, &dump_output.stdout)
        .context("Failed to write luksDump output to file")?;

    let mut header_data = Vec::new();
    let mut file = fs::File::open(&temp_file_path).context("Failed to open temp file")?;
    file.read_to_end(&mut header_data)
        .context("Failed to read temp file")?;

    let mut hasher = Sha256::new();
    hasher.update(&header_data);
    let hash = hasher.finalize();
    let hash_hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    let short_hash = hash_hex[0..8].to_string();
    debug!("Computed SHA256 hash: {hash_hex}");

    let final_img_path = temp_path.join(format!(
        "luks_header_backup.{hostname}.{uuid}.{short_hash}.img"
    ));
    let final_txt_path = temp_path.join(format!(
        "luks_header_backup.{hostname}.{uuid}.{short_hash}.txt"
    ));

    fs::rename(&temp_file_path, &final_img_path).context("Failed to rename temp img file")?;
    fs::rename(&temp_txt_path, &final_txt_path).context("Failed to rename temp txt file")?;

    fs::set_permissions(&final_img_path, Permissions::from_mode(0o600))
        .context("Set img permissions")?;
    fs::set_permissions(&final_txt_path, Permissions::from_mode(0o600))
        .context("Set txt permissions")?;

    info!("Saved header to {final_img_path:?}");
    info!("Saved header dump to {final_txt_path:?}");

    Ok(BackupArtifacts {
        uuid: uuid.to_string(),
        img_path: final_img_path,
        txt_path: final_txt_path,
        short_hash,
    })
}

fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    let args = Args::parse();
    debug!("{args:?}");

    if args.remote_paths.is_empty() && args.backup_paths.is_empty() {
        anyhow::bail!("At least one of --remote-path or --backup-path must be provided.");
    }

    if !nix::unistd::getuid().is_root() {
        anyhow::bail!("This program must be run as root");
    }

    let hostname = nix::unistd::gethostname()
        .context("Failed to get hostname")?
        .to_str()
        .context("Invalid hostname encoding.")?
        .to_string();
    info!("Hostname: {hostname}");

    let temp_dir = tempfile::tempdir().context("Failed to create temp dir")?;
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700))
        .context("Failed to set temp dir permissions")?;
    info!("Created temporary directory: {:?}", temp_dir.path());

    let device_uuid_map = get_luks_device_uuid_map()?;
    if device_uuid_map.is_empty() {
        anyhow::bail!("Expected to find at least one LUKS device to backup header.");
    } else {
        info!("Found {} LUKS devices", device_uuid_map.len());
    }

    let mut artifacts: Vec<BackupArtifacts> = Vec::new();
    for (device, uuid) in device_uuid_map {
        artifacts.push(create_backup_artifacts(&device, &uuid, &hostname, temp_dir.path())?);
    }

    if !args.backup_paths.is_empty() {
        for backup_path in &args.backup_paths {
            info!("Backing up to local path: {backup_path:?}");
            fs::create_dir_all(backup_path).context("Failed to create backup directory")?;

            for artifact in &artifacts {
                let dest_img_path = backup_path.join(artifact.img_path.file_name().unwrap());
                let dest_txt_path = backup_path.join(artifact.txt_path.file_name().unwrap());

                let tmp_img_path = backup_path.join(format!(".{}.tmp", artifact.img_path.file_name().unwrap().to_str().unwrap()));
                fs::copy(&artifact.img_path, &tmp_img_path)?;
                fs::rename(&tmp_img_path, &dest_img_path)?;

                let tmp_txt_path = backup_path.join(format!(".{}.tmp", artifact.txt_path.file_name().unwrap().to_str().unwrap()));
                fs::copy(&artifact.txt_path, &tmp_txt_path)?;
                fs::rename(&tmp_txt_path, &dest_txt_path)?;

                info!("Saved backup for {} to {dest_img_path:?}", artifact.uuid);
            }
        }
    }

    if !args.remote_paths.is_empty() {
        let files_to_copy: Vec<PathBuf> = artifacts.iter().flat_map(|a| vec![a.img_path.clone(), a.txt_path.clone()]).collect();

        if files_to_copy.is_empty() {
            info!("No backups to create for remote locations.");
        } else {
            let mut all_success = true;
            for remote in &args.remote_paths {
                info!("Pushing to remote: {remote}");

                let mut cmd = Command::new("scp");
                cmd.args(["-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes"]);
                for path in &files_to_copy {
                    cmd.arg(path);
                }
                cmd.arg(remote);

                if let Err(e) = run_command(&mut cmd) {
                    error!("{e}");
                    all_success = false;
                } else {
                    info!("Copy successful to {remote}");
                }
            }

            if !all_success {
                anyhow::bail!("Some remote copies failed");
            }
        }
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
