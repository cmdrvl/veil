//! The user's own settings in a fixture home. Only they may loosen the policy
//! or move the audit log: a project `.veil.toml` can only tighten (bd-02q).

use std::fs;
use std::path::{Path, PathBuf};

pub fn config_path(home: &Path) -> PathBuf {
    home.join(".cmdrvl/config/veil/config.toml")
}

#[track_caller]
pub fn write_config(home: &Path, contents: &str) {
    let path = config_path(home);
    fs::create_dir_all(path.parent().expect("the config has a directory"))
        .expect("user config directory");
    fs::write(path, contents).expect("user config should be written");
}
