# Bug bounty bots

A read-only pipeline that helps bug bounty hunters decide what to study next.

- **Daily digest** (`daily-digest.py`) — new and changed public bug bounty programs (HackerOne, Bugcrowd, Intigriti, YesWeHack), plus recent unauthenticated CVEs that have a public proof-of-concept and appear to line up with program scopes.
- **Research ranking** (`rank-findings.py`) — the same CVE findings, scored 1–10 by how easy the public write-up looks to study and how commonly the affected product shows up in public bounty scopes.

It only aggregates already-public metadata (NVD, GitHub PoC indexes, and published program scopes). It never runs a PoC, never compiles exploit code, never scans, and never contacts a target host.

## Quick start

From a fresh machine, with `git` and Python 3.10+ on your PATH:

```bash
git clone https://github.com/hackbot1x-del/bug-bounty-bots.git ~/bounty-pipeline && bash ~/bounty-pipeline/install.sh
```

`install.sh` is idempotent. It checks for Python 3.10+ (stdlib only; no pip packages) and clones or updates [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data). The first clone of that dataset can take several minutes because the digest diffs program history over 24–72 hours.

To install into a different directory:

```bash
git clone https://github.com/hackbot1x-del/bug-bounty-bots.git /path/to/dir && bash /path/to/dir/install.sh
```

Or set `BOUNTY_PIPELINE_DIR` and pass that path to both commands.

## Usage

```bash
python3 ~/bounty-pipeline/daily-digest.py
python3 ~/bounty-pipeline/rank-findings.py
```

If the install is not at the default path, pass `--base-dir` or set `BOUNTY_PIPELINE_DIR`.

Useful options:

- `--platform hackerone,bugcrowd,intigriti,yeswehack` on the digest (default: all)
- `--days 14` for the CVE window (default: 14)
- `--priv-level unauth` (default) keeps only unauthenticated CVEs
- `--no-pull` reuses local clones and caches
- The ranker works standalone: if no digest cache exists, it builds the feed and program matches itself

The first digest or ranking run also clones [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) into the data directory. That clone is used as a public index only; proofs of concept are not executed.

## Optional environment variables

- `GITHUB_TOKEN` or `GH_TOKEN` — higher GitHub API budget when tagging how trustworthy a public PoC repo looks
- `NVD_API_KEY` or `NIST_API_KEY` — faster NVD CVE fetches (otherwise unauthenticated rate limits apply)
- `BOUNTY_PIPELINE_DIR` — override the default data directory (`~/bounty-pipeline`)

## Safety

- **Read-only public metadata only.** Sources are the NVD CVE API, public GitHub indexes and READMEs, and published bug bounty program scope data.
- **Never runs PoCs.** The tools do not download, build, or execute exploit code.
- **Never contacts targets.** No requests or payloads are sent to bounty program hosts or any other target system.
- **You test only where you are authorized.** A scope match means the program's public text indicates it runs that product — not that a given instance is vulnerable, in scope, or on the affected version. Community PoCs are unverified. Read the program policy, and only test systems you are authorized to test.

## License

MIT. See [LICENSE](LICENSE).
