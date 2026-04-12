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
│   │   └── claude.yml              # Automated issue processing + @claude assistant
│   ├── ISSUE_TEMPLATE/             # Bug report, block domain, false positive, feature request
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml
├── custom/                         # Community-reported domains (fed to optimizer via URL)
│   ├── malicious.txt               # Fake shops, scams, phishing
│   ├── advertising.txt             # Ad-serving domains
│   ├── tracking.txt                # Tracking and telemetry
│   ├── suspicious.txt              # Cryptojacking, etc.
│   └── nsfw.txt                    # Adult content
├── lists/                          # Output blocklists (Git LFS — DO NOT edit directly)
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
| `custom/*.txt` | Community-reported domains to block (one domain per line) |
| `.github/workflows/update-blocklists.yml` | Main automation workflow |
| `lists/*.txt` | Output blocklists tracked with Git LFS |
| `.gitattributes` | Git LFS configuration for `lists/*.txt` |

## Important Notes

- The `lists/` directory uses Git LFS — large text files are stored as LFS pointers. **NEVER edit these files directly.**
- The optimizer binary is downloaded from GitHub Releases, not built locally
- `nsfw.txt` is deliberately excluded from `all_domains.txt`
- The workflow uses a `GH_PAT` secret for pushing commits and LFS operations
- `CLAUDE_CODE_OAUTH_TOKEN` secret is required for Claude Code workflows

## Issue Processing (CI Agent Instructions)

When running as a GitHub Actions agent processing issues, follow these procedures exactly.

### Blocklist requests (label: `blocklist`)

1. Extract the domain from the issue body — look for the **Domain** form field
2. Clean the domain: lowercase, strip any `http://`/`https://` prefix, strip trailing dots or slashes
3. Determine the category from the **Category** form field:
   - "Malicious (fake shops, scams, phishing)" → `custom/malicious.txt`
   - "Advertising (ad-serving domains)" → `custom/advertising.txt`
   - "Tracking (telemetry, analytics)" → `custom/tracking.txt`
   - "Suspicious (cryptojacking, etc.)" → `custom/suspicious.txt`
   - "NSFW (adult content)" → `custom/nsfw.txt`
   - If ambiguous or missing, default to `custom/malicious.txt`
4. Validate the domain: must contain at least one dot, no spaces, no path components
5. Check the domain is not already in any `custom/*.txt` file or `whitelist.txt`
6. Append the domain on a new line at the end of the appropriate `custom/<category>.txt`
7. Create a PR:
   - Title: `feat(blocklist): add <domain> to <category> list`
   - Body: explain what was added, why, and include `Closes #<issue_number>`

### Whitelist requests (label: `whitelist`)

1. Extract the domain from the issue body — look for the **Blocked Domain** form field
2. Extract the service name from the **Service/Application Affected** field
3. Clean and validate the domain (same rules as above)
4. Check the domain is not already in `whitelist.txt`
5. Find the best matching section in `whitelist.txt`:
   - Google services → `GOOGLE SERVICES` section
   - Microsoft/Windows/Xbox → `MICROSOFT / WINDOWS / XBOX` section
   - Apple services → `APPLE` section
   - Meta/Facebook/Instagram/WhatsApp → `META / FACEBOOK` section
   - VPN services → `VPN Services` section
   - DNS services → look for existing similar entries
   - If no section matches → `MISCELLANEOUS SERVICES` section
6. Add the domain with a comment indicating what service it's for (follow the existing pattern in that section)
7. Create a PR:
   - Title: `fix(whitelist): add <domain> for <service>`
   - Body: explain what was added, what service it fixes, and include `Closes #<issue_number>`

### Bug reports (label: `bug`)

1. Analyze the issue to understand the problem
2. If it's something you can fix (config, workflow, documentation):
   - Create a branch, make the fix, open a PR
   - Title: `fix(<scope>): <description>`
3. If you can't fix it, comment with your analysis and suggestions

### General rules

- Always create a new branch from main
- One logical change per PR
- Keep changes minimal — only modify the relevant file(s)
- If the issue is unclear or missing required information, comment asking for clarification
- If a domain is already present, comment explaining it's already handled
- Commit messages must use conventional commit format: `type(scope): description`
