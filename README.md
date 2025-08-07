# LUKS Header Backup Tool

## Description

This is a command-line tool written in Rust that automates the backup of LUKS (Linux Unified Key Setup) headers from encrypted devices on your system. It detects LUKS devices using `blkid`, backs up their headers with `cryptsetup luksHeaderBackup`, generates a textual dump with `cryptsetup luksDump`, computes a SHA256 hash of the header for verification, and names the files incorporating the hostname, device UUID, and a short hash. The backups are then copied to one or more remote destinations via SCP.

The tool requires root privileges to access devices and run commands. It logs progress and errors, with configurable log levels via the `RUST_LOG` environment variable.

## Installation

1. Ensure you have Rust and Cargo installed. If not, follow the instructions at [rustup.rs](https://rustup.rs/).

1. Clone the repository:

   ```
   git clone https://github.com/mason-larobina/luks-header-backup
   cd luks-header-backup
   ```

1. Build the project:

   ```
   cargo build --release

   # Or 
   cargo install --path=.
   ```

   The binary will be available at `target/release/luks-header-backup`

1. Install the binary:

   ```
   $ sudo cp "${PWD}/target/release/luks-header-backup" /usr/local/bin/

   # Or
   $ sudo cp $(which luks-header-backup) /usr/local/bin/
   ```

## Usage

Run the tool as root, providing one or more remote SCP destinations (e.g., `root@host:/backup/dir/`):

```
sudo luks-header-backup --remote-path=<remote1> --remote-path=<remote2> [..]
```

### Options

- The tool uses `clap` for argument parsing. Use `--help` for details.
- Set the log level with `RUST_LOG` (e.g., `RUST_LOG=debug sudo luks-header-backup ...` for verbose output).

### Example

```
sudo luks-header-backup \
    root@backup-server-a:/backups/ \
    root@another-server-b:/storage/
```

This will backup LUKS headers, save them temporarily with unique names like `luks_header_backup.hostname.uuid.shorthash.img` and `.txt`, and SCP them to the specified remotes.

## Recommendations

- **Run periodically**: Schedule this tool to run regularly (e.g., via cron) to ensure backups are current, especially after changes to LUKS setups.
- **Secure storage**: Use secure, offsite or encrypted remote destinations to store backups. Avoid storing them on the same system as the originals.
- **Verify backups**: After backup, verify the files by checking the embedded hash and testing restoration with `cryptsetup luksHeaderRestore` in a safe environment.
- **Dependencies**: The tool relies on system commands like `blkid`, `cryptsetup`, and `scp`. Ensure they are installed and functional.
- **Error handling**: Monitor logs for failures, especially SCP transfers. The tool will bail if any remote copy fails.

## Scheduling with systemd

To automate periodic backups, you can use systemd timer and service units. Below is an example configuration to run the backup weekly.

Create `/etc/systemd/system/luks-header-backup.service` with the following content:

```
[Unit]
Description=LUKS Header Backup

[Service]
Type=simple
ExecStart=/usr/local/bin/luks-header-backup root@backup-server:/backups/ # Add more remotes as arguments
```

Create `/etc/systemd/system/luks-header-backup.timer` with the following content:

```
[Unit]
Description=Run LUKS Header Backup weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Then, reload systemd, enable, and start the timer:

```
sudo systemctl daemon-reload
sudo systemctl enable luks-header-backup.timer --now
```

Customize the `ExecStart` line with your actual remote destinations and adjust the `OnCalendar` for your preferred schedule (e.g., `daily`, `monthly`).

For issues or contributions, see the repository.
