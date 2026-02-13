# CLAUDE.md

This file provides context to Claude Code (claude.ai/code) when working with this repository.

## Project Overview

Pre-optimized, deduplicated blocklists for Pi-hole. Lists are built weekly from 59 upstream sources using the [Pi-hole-Blocklist-Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer) Rust binary, then committed and served via GitHub + Git LFS.

## How It Works

A GitHub Actions workflow (`.github/workflows/update-blocklists.yml`) runs every Sunday at midnight UTC:

1. Downloads the latest `pihole-optimizer` binary from GitHub Releases
2. Runs it against `blocklists.conf` (source URLs) and `whitelist.txt` (false-positive exclusions)
3. Produces deduplicated, categorized blocklists in `pihole_blocklists_prod/`
4. Copies changed files into `lists/`, updates README statistics, and commits

## Project Structure

```
Pi-hole-Optimized-Blocklists/
├── .github/
│   ├── workflows/
│   │   ├── update-blocklists.yml   # Weekly blocklist update automation
│   │   ├── claude-code-review.yml  # Claude Code PR reviews
│   │   └── claude.yml              # Interactive Claude Code assistant
│   ├── ISSUE_TEMPLATE/             # Bug report, feature request, false positive
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml
├── lists/                          # Output blocklists (Git LFS)
│   ├── all_domains.txt             # Combined (except NSFW)
│   ├── advertising.txt
│   ├── tracking.txt
│   ├── malicious.txt
│   ├── suspicious.txt
│   ├── comprehensive.txt
│   └── nsfw.txt
├── blocklists.conf                 # Source URLs: url|name|category
├── whitelist.txt                   # Domains to exclude from blocking
├── README.md
├── CONTRIBUTING.md
├── CLAUDE.md
└── LICENCE
```

## Key Files

| File | Purpose |
|------|---------|
| `blocklists.conf` | Source list configuration (`url\|name\|category` format) |
| `whitelist.txt` | Domains excluded from blocking (exact, wildcard, regex) |
| `.github/workflows/update-blocklists.yml` | Main automation workflow |
| `lists/*.txt` | Output blocklists tracked with Git LFS |
| `.gitattributes` | Git LFS configuration for `lists/*.txt` |

## Important Notes

- The `lists/` directory uses Git LFS — large text files are stored as LFS pointers
- The optimizer binary is downloaded from GitHub Releases, not built locally
- `nsfw.txt` is deliberately excluded from `all_domains.txt`
- The workflow uses a `GH_PAT` secret for pushing commits and LFS operations
- `CLAUDE_CODE_OAUTH_TOKEN` secret is required for Claude Code workflows
