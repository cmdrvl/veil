//! How a veil process tells that `veil sandbox` confines it.
//!
//! The launcher sets [`ENFORCEMENT_ENV`] for the command it confines. Anyone
//! can set a variable, so veil does not believe it alone: the launcher also
//! leaves an empty marker file beside its broker's socket, and the profile it
//! applies does not let that file be opened.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::seatbelt::BROKER_SOCKET_PREFIX;
use crate::broker::BROKER_SOCKET_ENV;

/// Set to [`SANDBOX`] by the launcher for the command it confines.
pub const ENFORCEMENT_ENV: &str = "VEIL_ENFORCEMENT";

/// The variable's value, and what an audit record and a doctor report say.
pub const SANDBOX: &str = "sandbox";

/// Where the marker is of the session whose broker listens on `socket`.
pub fn beside(socket: &Path) -> PathBuf {
    socket.with_extension("marker")
}

/// Whether `veil sandbox` confines this process: it runs on macOS,
/// [`ENFORCEMENT_ENV`] says so, and the marker of the session that
/// `VEIL_BROKER_SOCKET` names is there and cannot be opened.
///
/// What this does not show is that the profile in force is the one veil
/// compiled. A process under another profile that closes such a file, which it
/// can put itself under, is taken to be confined by veil.
pub fn confines_this_process() -> bool {
    cfg!(target_os = "macos")
        && std::env::var_os(ENFORCEMENT_ENV).is_some_and(|claim| claim == SANDBOX)
        && std::env::var_os(BROKER_SOCKET_ENV)
            .is_some_and(|socket| is_closed_to_this_process(Path::new(&socket)))
}

/// A file's permissions refuse with EACCES, so EPERM comes from a policy on the
/// process. macOS also gives it for files its privacy controls guard, so the
/// marker has to be what the launcher makes, a plain, empty file with one name:
/// neither a symlink nor a second name for another file is that.
fn is_closed_to_this_process(socket: &Path) -> bool {
    let named_by_a_launcher = socket.is_absolute()
        && socket
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(BROKER_SOCKET_PREFIX) && name.ends_with(".sock"));
    let marker = beside(socket);
    named_by_a_launcher
        && fs::symlink_metadata(&marker)
            .is_ok_and(|found| found.is_file() && found.len() == 0 && found.nlink() == 1)
        && fs::File::open(&marker).is_err_and(|error| error.raw_os_error() == Some(libc::EPERM))
}
