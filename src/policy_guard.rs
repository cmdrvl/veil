//! bd-02q: the files that decide what veil refuses, which no tool call veil
//! sees may write: a `.veil.toml` in any directory (a nested one replaces the
//! outer one) and the user's settings. Reading them is judged as any read is.
//!
//! This is a rule about what a call's text shows. A program that writes one of
//! these files without naming it is not stopped here; the sandbox's rules are
//! what hold against that.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::{self, PROJECT_CONFIG_NAME};
use crate::derived::{could_expand_to, resolve_links, same_name};
use crate::extract::{ConfigWrite, WriteReach};

/// How many different paths one tool call is followed through the filesystem
/// to. The hook has to finish in time to stop anything.
const MAX_PATHS: usize = 4096;

/// veil's configuration as paths a tool call might name.
pub(crate) struct PolicyFiles {
    /// The user's settings and where a project config would be read from, as
    /// spelled and with symlinks followed.
    files: Vec<PathBuf>,
    /// The directories that hold the user's settings, and those above them that
    /// are veil's or the user's configuration: moving one takes them along.
    containers: Vec<PathBuf>,
    /// Whether each path looked at is a config, and whether it holds one.
    looked: BTreeMap<PathBuf, (bool, bool)>,
}

impl PolicyFiles {
    pub fn from_env(cwd: &Path) -> Self {
        let directory = |name: &str| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        let home = directory("HOME");
        Self::new(
            cwd,
            home.as_deref(),
            directory("XDG_CONFIG_HOME").as_deref(),
        )
    }

    fn new(cwd: &Path, home: Option<&Path>, xdg_config_home: Option<&Path>) -> Self {
        let sources = config::policy_sources(cwd, home, xdg_config_home);
        let mut files = sources.files;
        let followed: Vec<PathBuf> = files.iter().map(|file| resolve_links(file)).collect();
        files.extend(followed);
        files.dedup();

        let mut containers = Vec::new();
        for directory in &sources.directories {
            // `~/.cmdrvl/config/veil` has two directories of veil's above it;
            // `~/.config/veil` has one, and above that is the home itself
            let above = if directory
                .ancestors()
                .any(|at| at.file_name().is_some_and(|name| name == ".cmdrvl"))
            {
                3
            } else {
                2
            };
            for container in directory.ancestors().take(above) {
                for spelling in [container.to_path_buf(), resolve_links(container)] {
                    if !containers.contains(&spelling) {
                        containers.push(spelling);
                    }
                }
            }
        }

        Self {
            files,
            containers,
            looked: BTreeMap::new(),
        }
    }

    /// `path` is a project config or the user's settings, by any name veil can
    /// tell: through symlinks (a dangling one too), in another letter case, as
    /// a hard link to a config in force here, or as a glob that spells it.
    pub fn is_file(&self, path: &Path) -> bool {
        let resolved = resolve_links(path);
        [path, resolved.as_path()].into_iter().any(|candidate| {
            is_project_config_name(candidate)
                || self.files.iter().any(|file| same_name(candidate, file))
        }) || self.glob_reaches(path, &self.files)
            || self.is_another_name(path)
    }

    pub fn is_container(&self, path: &Path) -> bool {
        let resolved = resolve_links(path);
        self.containers
            .iter()
            .any(|container| same_name(path, container) || same_name(&resolved, container))
            || self.glob_reaches(path, &self.containers)
    }

    /// Whether a call that does `write` changes veil's configuration. `Err`
    /// when the call names more paths than veil follows and this one may
    /// change a file.
    pub fn is_changed_by(&mut self, write: &ConfigWrite) -> Result<bool, TooMany> {
        // the name alone says it, and costs nothing
        if is_project_config_name(&write.path) {
            return Ok(true);
        }
        if write.reach == WriteReach::Mention
            && is_glob(&write.path)
            && !spells_part_of_a_config_name(&write.path)
        {
            return Ok(false);
        }
        let (file, container) = match self.looked.get(&write.path) {
            Some(&found) => found,
            None if self.looked.len() >= MAX_PATHS => {
                return match write.reach {
                    WriteReach::Mention => Ok(false),
                    WriteReach::File | WriteReach::Tree => Err(TooMany),
                };
            }
            None => {
                let found = (self.is_file(&write.path), self.is_container(&write.path));
                self.looked.insert(write.path.clone(), found);
                found
            }
        };
        Ok(file || (write.reach == WriteReach::Tree && container))
    }

    /// Whether a shell could expand the glob `path` to a project config in any
    /// directory, or to one of `wanted`.
    fn glob_reaches(&self, path: &Path, wanted: &[PathBuf]) -> bool {
        if !is_glob(path) {
            return false;
        }
        if path.file_name().is_some_and(|name| {
            could_expand_to(name.as_encoded_bytes(), PROJECT_CONFIG_NAME.as_bytes())
        }) {
            return true;
        }
        wanted.iter().any(|target| {
            path.components().count() == target.components().count()
                && path
                    .components()
                    .zip(target.components())
                    .all(|(pattern, name)| {
                        could_expand_to(
                            pattern.as_os_str().as_encoded_bytes(),
                            name.as_os_str().as_encoded_bytes(),
                        )
                    })
        })
    }

    /// A hard link to a config that is in force here.
    fn is_another_name(&self, path: &Path) -> bool {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        // a file with one name has no hard link
        metadata.is_file()
            && metadata.nlink() > 1
            && self.files.iter().any(|file| {
                fs::metadata(file).is_ok_and(|other| {
                    (other.dev(), other.ino()) == (metadata.dev(), metadata.ino())
                })
            })
    }
}

/// More paths than veil follows in one call.
#[derive(Debug)]
pub(crate) struct TooMany;

/// A redirect target veil cannot resolve that ends in a project config's name.
pub(crate) fn names_a_project_config(written: &str) -> bool {
    let bare = written.trim_matches(['"', '\'']);
    is_project_config_name(Path::new(bare))
}

fn is_project_config_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name.as_encoded_bytes()
            .eq_ignore_ascii_case(PROJECT_CONFIG_NAME.as_bytes())
    })
}

fn is_glob(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn spells_part_of_a_config_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy().to_ascii_lowercase();
        name.contains("veil") || name.contains("toml")
    })
}
