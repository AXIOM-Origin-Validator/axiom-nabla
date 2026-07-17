// AXIOM Nabla — DB Compaction and Backup
// Reference: AXIOM_GUIDE_Nabla.md Phase 6 Task 48
//
// WAL compaction: after snapshot, truncate WAL entries older than snapshot tick.
// Snapshot scheduling: periodic snapshots at SNAPSHOT_INTERVAL_TICKS.
// Backup: copy snapshot + current WAL to backup directory.
//
// WAL grows unbounded without compaction. Compaction is safe because:
//   - Snapshot contains full SMT state at a point in time
//   - WAL entries before that point are redundant
//   - Recovery: load snapshot, replay WAL from snapshot tick forward

use std::fs;
use std::path::{Path, PathBuf};

use crate::constants::SNAPSHOT_INTERVAL_TICKS;

/// Compaction result.
#[derive(Debug)]
pub struct CompactionResult {
    /// WAL entries removed.
    pub entries_removed: u64,
    /// WAL size before compaction (bytes).
    pub size_before: u64,
    /// WAL size after compaction (bytes).
    pub size_after: u64,
}

/// Backup result.
#[derive(Debug)]
pub struct BackupResult {
    /// Path to backup directory.
    pub backup_dir: PathBuf,
    /// Total backup size (bytes).
    pub total_size: u64,
    /// Files backed up.
    pub files: Vec<String>,
}

/// Compaction manager — schedules WAL compaction and backups.
pub struct CompactionManager {
    /// Data directory.
    data_dir: PathBuf,
    /// Tick of last compaction.
    last_compaction_tick: u64,
    /// Compaction interval (in ticks).
    compaction_interval: u64,
    /// Maximum WAL size before forced compaction (bytes).
    max_wal_size: u64,
    /// Whether backup is enabled.
    backup_enabled: bool,
    /// Backup directory (separate from data_dir).
    backup_dir: PathBuf,
    /// Maximum number of backups to keep.
    max_backups: usize,
}

impl CompactionManager {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            last_compaction_tick: 0,
            compaction_interval: SNAPSHOT_INTERVAL_TICKS, // compact after each snapshot
            max_wal_size: 100 * 1024 * 1024, // 100 MB
            backup_enabled: false,
            backup_dir: data_dir.join("backups"),
            max_backups: 5,
        }
    }

    /// Enable backups to a specific directory.
    pub fn enable_backup(&mut self, backup_dir: &Path, max_backups: usize) {
        self.backup_enabled = true;
        self.backup_dir = backup_dir.to_path_buf();
        self.max_backups = max_backups;
    }

    /// Check if compaction should run.
    pub fn should_compact(&self, current_tick: u64, wal_size: u64) -> bool {
        // Time-based: after compaction_interval ticks
        let time_due = current_tick - self.last_compaction_tick >= self.compaction_interval;
        // Size-based: WAL exceeds max size
        let size_due = wal_size >= self.max_wal_size;
        time_due || size_due
    }

    /// Record that compaction was performed.
    pub fn mark_compacted(&mut self, tick: u64) {
        self.last_compaction_tick = tick;
    }

    /// Perform a backup of the current data directory.
    ///
    /// Copies snapshot files and current WAL to the backup directory.
    /// Rotates old backups if max_backups exceeded.
    pub fn backup(&self, current_tick: u64) -> Result<BackupResult, std::io::Error> {
        if !self.backup_enabled {
            return Err(std::io::Error::other(
                "backup not enabled",
            ));
        }

        // Create backup subdirectory with tick number
        let tick_dir = self.backup_dir.join(format!("backup_{}", current_tick));
        fs::create_dir_all(&tick_dir)?;

        let mut total_size = 0u64;
        let mut files = Vec::new();

        // Copy all .snap files
        if let Ok(entries) = fs::read_dir(&self.data_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                if name.ends_with(".snap") || name.ends_with(".wal") {
                    let dest = tick_dir.join(&name);
                    fs::copy(&path, &dest)?;
                    let size = fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
                    total_size += size;
                    files.push(name);
                }
            }
        }

        // Rotate old backups
        self.rotate_backups()?;

        Ok(BackupResult {
            backup_dir: tick_dir,
            total_size,
            files,
        })
    }

    /// Remove old backups exceeding max_backups.
    fn rotate_backups(&self) -> Result<(), std::io::Error> {
        if !self.backup_dir.exists() {
            return Ok(());
        }

        let mut backups: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.backup_dir)?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                if name.starts_with("backup_") {
                    backups.push(path);
                }
            }
        }

        // Sort by name (tick number) ascending
        backups.sort();

        // Remove oldest if exceeding max
        while backups.len() > self.max_backups {
            if let Some(oldest) = backups.first() {
                fs::remove_dir_all(oldest)?;
                backups.remove(0);
            }
        }

        Ok(())
    }

    /// Get compaction interval.
    pub fn compaction_interval(&self) -> u64 {
        self.compaction_interval
    }

    /// Set compaction interval.
    pub fn set_compaction_interval(&mut self, ticks: u64) {
        self.compaction_interval = ticks;
    }

    /// Set max WAL size.
    pub fn set_max_wal_size(&mut self, bytes: u64) {
        self.max_wal_size = bytes;
    }

    /// Is backup enabled?
    pub fn backup_enabled(&self) -> bool {
        self.backup_enabled
    }
}

// ── WAL Compaction Logic ──

/// Compute how many WAL entries can be safely removed.
/// Any entry with tick <= snapshot_tick is redundant (covered by snapshot).
///
/// This is informational — the actual truncation happens in the WAL module.
/// Returns the snapshot tick (entries at or before this tick can be removed).
pub fn compaction_boundary(snapshot_tick: u64) -> u64 {
    snapshot_tick
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compaction_should_run_by_time() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = CompactionManager::new(dir.path());

        // After compaction_interval ticks, should compact
        assert!(mgr.should_compact(SNAPSHOT_INTERVAL_TICKS, 0));
        // Before interval, should not
        assert!(!mgr.should_compact(10, 0));
    }

    #[test]
    fn compaction_should_run_by_size() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = CompactionManager::new(dir.path());

        // WAL exceeds max size
        assert!(mgr.should_compact(1, 200 * 1024 * 1024));
    }

    #[test]
    fn compaction_mark_resets_timer() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = CompactionManager::new(dir.path());

        mgr.mark_compacted(100);
        // Should not compact right away after marking
        assert!(!mgr.should_compact(101, 0));
        // Should compact after interval
        assert!(mgr.should_compact(100 + SNAPSHOT_INTERVAL_TICKS, 0));
    }

    #[test]
    fn backup_disabled_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = CompactionManager::new(dir.path());
        assert!(!mgr.backup_enabled());

        let result = mgr.backup(1);
        assert!(result.is_err());
    }

    #[test]
    fn backup_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let mut mgr = CompactionManager::new(dir.path());
        mgr.enable_backup(backup_dir.path(), 3);

        // Create a fake WAL file to back up
        fs::write(dir.path().join("nabla.wal"), b"test wal data").unwrap();

        let result = mgr.backup(42).unwrap();
        assert!(result.backup_dir.exists());
        assert!(result.files.contains(&"nabla.wal".to_string()));
        assert!(result.total_size > 0);
    }

    #[test]
    fn backup_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let mut mgr = CompactionManager::new(dir.path());
        mgr.enable_backup(backup_dir.path(), 2); // keep only 2

        fs::write(dir.path().join("nabla.wal"), b"data").unwrap();

        mgr.backup(1).unwrap();
        mgr.backup(2).unwrap();
        mgr.backup(3).unwrap(); // should trigger rotation

        let mut count = 0;
        for entry in fs::read_dir(backup_dir.path()).unwrap().flatten() {
            if entry.path().is_dir() {
                count += 1;
            }
        }
        assert_eq!(count, 2); // oldest removed
    }

    #[test]
    fn compaction_boundary_matches_snapshot() {
        assert_eq!(compaction_boundary(1000), 1000);
    }
}
