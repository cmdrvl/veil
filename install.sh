#!/usr/bin/env bash
set -euo pipefail

VEIL_REPO="${VEIL_REPO:-cmdrvl/veil}"
VEIL_RELEASE_TAG="${VEIL_RELEASE_TAG:-}"
VEIL_DOWNLOAD_BASE_URL="${VEIL_DOWNLOAD_BASE_URL:-https://github.com/${VEIL_REPO}/releases/download}"
VEIL_RELEASES_API_URL="${VEIL_RELEASES_API_URL:-https://api.github.com/repos/${VEIL_REPO}/releases/latest}"
VEIL_INSTALL_DIR="${VEIL_INSTALL_DIR:-}"

DRY_RUN=0
FORCE=0
MODE="install"

usage() {
  cat <<'EOF'
Usage: install.sh [--dry-run] [--force] [--status | --uninstall]

Install modes:
  (default)    Download the correct veil release artifact, install it to
               ~/.local/bin/veil, then delegate hook setup to `veil install`.
  --status     Report whether veil is installed and, if present, run `veil doctor`.
  --uninstall  Delegate hook teardown to `veil uninstall`, then remove the binary.

Flags:
  --dry-run    Print the actions without changing disk or invoking the binary.
  --force      Reinstall the binary even if ~/.local/bin/veil already exists.
  --help       Show this help text.

Optional environment overrides:
  VEIL_RELEASE_TAG       Install a specific release tag (for example v0.1.0).
  VEIL_REPO              Override the GitHub repository (default: cmdrvl/veil).
  VEIL_DOWNLOAD_BASE_URL Override the release download base URL.
  VEIL_RELEASES_API_URL  Override the GitHub latest-release API URL.
  VEIL_INSTALL_DIR       Override the install directory (default: ~/.local/bin).
EOF
}

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

normalize_release_tag() {
  case "$1" in
    v*) printf '%s\n' "$1" ;;
    *) printf 'v%s\n' "$1" ;;
  esac
}

download_text() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO- "$1"
    return
  fi

  die "either curl or wget is required"
}

download_file() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
    return
  fi

  die "either curl or wget is required"
}

resolve_release_tag() {
  if [ -n "$VEIL_RELEASE_TAG" ]; then
    normalize_release_tag "$VEIL_RELEASE_TAG"
    return
  fi

  tag="$(
    download_text "$VEIL_RELEASES_API_URL" |
      awk -F'"' '/"tag_name"[[:space:]]*:/ { print $4; exit }'
  )"
  [ -n "$tag" ] || die "could not determine the latest release tag from ${VEIL_RELEASES_API_URL}"
  normalize_release_tag "$tag"
}

detect_archive_suffix() {
  local os
  local arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os="darwin" ;;
    Linux) os="linux" ;;
    *) die "unsupported operating system: ${os}" ;;
  esac

  case "$arch" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64) arch="x86_64" ;;
    *) die "unsupported architecture: ${arch}" ;;
  esac

  printf '%s-%s\n' "$os" "$arch"
}

install_path() {
  local install_dir

  if [ -n "$VEIL_INSTALL_DIR" ]; then
    install_dir="${VEIL_INSTALL_DIR%/}"
  elif [ -n "${HOME:-}" ]; then
    install_dir="${HOME%/}/.local/bin"
  else
    die "VEIL_INSTALL_DIR is empty and HOME is not set"
  fi

  printf '%s/veil\n' "${install_dir}"
}

print_status() {
  local target

  target="$(install_path)"
  log "Install directory: ${target%/veil}"
  log "Binary path: ${target}"

  if [ ! -x "$target" ]; then
    log "Binary: not installed"
    return 0
  fi

  log "Binary: installed"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would run: ${target} --version"
    log "[dry-run] would run: ${target} doctor"
    return 0
  fi

  "${target}" --version
  "${target}" doctor
}

install_binary() {
  local target
  local target_dir
  local tag
  local suffix
  local artifact
  local url
  local temp_dir
  local archive_path
  local archive_stem
  local extracted_binary
  local staging_path

  target="$(install_path)"
  target_dir="${target%/veil}"
  if [ -x "$target" ] && [ "$FORCE" -eq 0 ]; then
    log "Binary already exists at ${target}; reusing it (pass --force to replace it)."
    return 0
  fi

  need_command tar
  need_command mktemp

  tag="$(resolve_release_tag)"
  suffix="$(detect_archive_suffix)"
  archive_stem="veil-${tag}-${suffix}"
  artifact="${archive_stem}.tar.gz"
  url="${VEIL_DOWNLOAD_BASE_URL%/}/${tag}/${artifact}"

  log "Selected release: ${tag}"
  log "Selected archive: ${artifact}"
  log "Download URL: ${url}"
  log "Install path: ${target}"

  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would create ${target_dir}"
    log "[dry-run] would download ${url}"
    log "[dry-run] would extract ${artifact}"
    log "[dry-run] would install ${target}"
    return 0
  fi

  temp_dir="$(mktemp -d)"
  trap 'rm -rf "${temp_dir}"' EXIT
  archive_path="${temp_dir}/${artifact}"

  mkdir -p "$target_dir"
  download_file "$url" "$archive_path"
  tar -xzf "$archive_path" -C "$temp_dir"

  extracted_binary="${temp_dir}/${archive_stem}/veil"
  [ -x "$extracted_binary" ] || die "downloaded archive did not contain ${archive_stem}/veil"

  staging_path="${target}.tmp"
  cp "$extracted_binary" "$staging_path"
  chmod 0755 "$staging_path"
  mv "$staging_path" "$target"
}

delegate_install() {
  local target

  target="$(install_path)"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would run: ${target} install"
    return 0
  fi

  [ -x "$target" ] || die "expected installed binary at ${target}"

  "$target" install
}

delegate_uninstall() {
  local target

  target="$(install_path)"
  if [ ! -x "$target" ]; then
    log "Binary not present at ${target}; nothing to uninstall."
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] would run: ${target} uninstall"
    log "[dry-run] would remove: ${target}"
    return 0
  fi

  "$target" uninstall
  rm -f "$target"
  log "Removed ${target}"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        ;;
      --force)
        FORCE=1
        ;;
      --status)
        [ "$MODE" = "install" ] || die "only one of --status or --uninstall may be provided"
        MODE="status"
        ;;
      --uninstall)
        [ "$MODE" = "install" ] || die "only one of --status or --uninstall may be provided"
        MODE="uninstall"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
    shift
  done
}

main() {
  parse_args "$@"

  case "$MODE" in
    install)
      install_binary
      delegate_install
      ;;
    uninstall)
      delegate_uninstall
      ;;
    status)
      print_status
      ;;
    *)
      die "unsupported mode: ${MODE}"
      ;;
  esac
}

main "$@"
