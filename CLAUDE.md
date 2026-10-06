# CLAUDE.md

This file provides context to Claude Code (claude.ai/code) when working with this repository.

## Project Overview

Pre-optimized, deduplicated blocklists for Pi-hole. Lists are built weekly from the upstream sources in `blocklists.conf` using the [Pi-hole-Blocklist-Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer) Rust binary, then committed and served via GitHub + Git LFS.

## How It Works

A GitHub Actions workflow (`.github/workflows/update-blocklists.yml`) runs every Sunday at midnight UTC:

1. Downloads the latest `pihole-optimizer` binary from GitHub Releases
2. Runs it against `blocklists.conf` (source URLs) and `whitelist.txt` (false-positive exclusions)
3. Produces deduplicated, categorized blocklists in `pihole_blocklists_prod/`
4. Copies changed files into `lists/`, updates README statistics, and commits

Production publishing runs only on `main`; manual dispatches must select `main`. Branch/PR validation uses the offline triage CI instead.

## Project Structure

```
Pi-hole-Optimized-Blocklists/
├── .github/
│   ├── workflows/
│   │   ├── update-blocklists.yml   # Weekly blocklist update automation
│   │   └── issue-triage.yml        # Evidence report, AI view and labels on new issues
│   ├── triage/                     # Python package the triage workflow runs (uv)
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
- The triage workflow uses `VIRUSTOTAL_API_KEY`, `MINIMAX_API_KEY`, `DISCORD_TRIAGE_WEBHOOK` and `DISCORD_PING_USER_ID` secrets

## Issue Triage Bot

`.github/workflows/issue-triage.yml` runs `.github/triage` (`uv run python -m triage issue <n>`) when an issue opens:

- Posts one report comment (marker `<!-- issue-triage-report -->`, updated in place on re-runs) with deterministic evidence: custom/whitelist matches, which upstream feeds list the domain, dated VirusTotal and registration records, Tranco rank, HTTP probes, a separate browser capture, and lookalike brands for block requests. Reports and hidden state are read or updated only from comments whose author is `github-actions[bot]` with user type `Bot`; human copies of markers are ignored.
- Collects directly referenced GitHub image attachments, public HTML/plain-text corroborating URLs, and same-repository issue references from the body and first 20 loaded comments. Collection is bounded to 12 materials, six image/link inspections, three issue reads and 12 requests, with a cooperative 60-second budget. Downloaded images are decoded/resized with Pillow; unavailable or merely mentioned materials remain uninspected. Reading a source, related issue or screenshot does not verify its claims or justify blocking by association.
- HTTP redirects are public-address checked and downloads have streamed byte limits. The native browser capture denies non-GET requests, child frames, workers, popups, downloads and WebSockets; it retains obtainable partial content and status. Browser transfer limits are best-effort, not a hard transfer/memory sandbox. Public DNS checks do not pin subsequent resolutions or eliminate DNS rebinding. Challenges, 403 responses and failed/empty probes do not establish that a site is offline; insufficient probes are not reported as matching visitor experiences. Identity-encoded HTTP bodies are checked against byte/deadline budgets on each unbuffered transport chunk. Website-controlled title substring matches remain attributed heuristics, not authenticated provider warnings or standalone block corroboration.
- Asks MiniMax M3 for an advisory view using snapshot-local observation IDs, provenance and up to four bounded images. Public factual reasons and site context must reference current observations, not freeform model assertions. Visual interpretations are explicitly advisory and at most medium confidence; quiet scanners are neutral, not proof of safety. Scanner-supported high confidence requires an explicit usable target-content observation from rendered content on the target host. Error/challenge pages, partial/failed captures, unrelated redirect destinations and arbitrary submitted images do not establish that inspection. Unsupported recommendations fall back to `needs_info`, low confidence and no entry. Shared-host restrictions still apply. Reporter questions use a fixed minimal/redacted-evidence request that forbids purchases or entering sensitive information. The AI never changes a list.
- The AI may set labels: fix the type label, set one `impact:` label, and add `needs info`. It never sets `declined` or `duplicate` and never closes issues.
- Re-runs automatically when the issue body is edited or anyone other than the owner comments, but only when the new activity adds something useful. A new URL on the reported domain or a changed domain always counts. Otherwise MiniMax does a quick yes/no check against the last verdict and its open questions. Thanks, "+1" and repeats do nothing. A re-run reads the whole comment thread and its own previous verdict, updates the report with a history line (deleting it and posting a fresh one at the bottom if anyone other than the owner has commented since, so it always sits below the latest reply), and removes `needs info` once it can decide. State lives in a hidden `<!-- triage-state:… -->` marker in the report.
- Sends a Discord ping for every new issue and for every re-run. Replies on bug and feature issues ping without a re-run. Reporter signals (account age, the same domain filed in other repos) go only to Discord, never to the public comment.
- Tunable rules (reputable VirusTotal engines, false-positive-prone feeds, threat-intel feeds, thresholds) live in `.github/triage/triage/policy.py`.
- Re-run on any issue: `gh workflow run issue-triage.yml -f issue=<n>`. Local dry run: `cd .github/triage && uv run python -m triage issue <n> --dry-run` (needs `GITHUB_TOKEN`, optionally `VIRUSTOTAL_API_KEY` and `MINIMAX_API_KEY`).

Maintainer commands (Stage 2): only an issue comment with `author_association: OWNER` can invoke the `command` job. It is the only issue-triage job with `contents: write`. Commits go through the contents API as `github-actions[bot]`, so no git identity is set. Command inputs are normalized and deduplicated (at most 100 domains); every merge attempt validates against a pinned fresh-main configuration under the lock. Already-covered domains are skipped only when their existing entries cover the requested scope; unsafe targets or whitelist conflicts refuse the whole batch. Closed issues require explicit domains for `/block` and `/allow`.
- Commands posted at once run one after another. Each takes a lock, a branch named `triage-lock` created through the API, before it branches from `main`, and releases it after the merge. A waiting command polls every 5 seconds for up to 8 minutes, and takes over a lock older than 12 minutes. If a PR still will not merge, for example because the weekly build committed meanwhile, the command closes it, deletes the branch and redoes the change from the current `main`, up to 4 times.
- `/block [category] [exact] [now] [domain ...]` appends `||domain^` (or a bare entry with `exact`) to `custom/<category>.txt`. The category defaults to the issue's, then `malicious`, and the domain defaults to the reported one. The command opens a PR, merges it, records the configuration change as pending publication, posts follow-up messages and closes the issue as completed.
- `/allow [exact | subdomains] [now] [domain ...]` inserts into `whitelist.txt` at the end of REPORTED FALSE POSITIVES and bumps the `Last Updated` header. The default writes `example.com`, which allows the domain and every subdomain. `exact` writes `/^example\.com$/` for that host only, and `subdomains` writes `*.example.com` for the subdomains but not the bare domain. Using both is refused.
- `/allow` normally posts a maintainer-facing change comment and a reporter reply, then closes the issue. Reporter text supplied by the owner takes precedence. Otherwise fixed templates use validated command facts, exact scope, pending-build timing and recorded upstream feed names; MiniMax may choose only an owner/visitor/unknown audience. Model-written reply text and legacy unbound site descriptions are never published as reply facts. The same neutral template works without an AI key; invalid command facts fail closed.
- `/decline <reason>` labels the issue `declined` and closes it as not planned. `/retriage` re-runs the triage. Resolved commands remove `needs info`.
- Text on the lines after the command is the closing message (for `/allow`, the reply to the reporter). Its first paragraph also becomes the file note. Without owner text, notes use only observation-bound saved site context plus deterministic evidence; legacy freeform descriptions are not reused as verified facts.
- `now` attempts to dispatch `update-blocklists.yml` after merge. A successful dispatch means queued, not published; a failed dispatch is explicitly reported without claiming a rebuild was queued.
- Commands record an authenticated pending-publication marker before follow-up work. Cleanup, dispatch, comment, label, closure, reaction and notification failures report the merged PR and precise failed stage, rather than saying nothing changed. The CLI also logs a structured merge outcome. If all comment attempts fail, the maintainer must recover persistent tracking from that log and PR.
- Refusals include shared-by-path hosts (`policy.SHARED_PATH_HOSTS`), platform suffixes, unsafe domains, whitelist conflicts, implicit domains on closed issues and unknown commands. Entirely redundant batches need no merge; partially redundant batches report skips. Successful command handling gets a rocket reaction and a Discord message without a ping.

Scheduled checks (Stage 3):
- The weekly build (`update-blocklists.yml`) runs `triage buildcheck` after the optimizer, with `continue-on-error` so a bug in the check never blocks the build. It checks three things:
  - Feed health: each feed's parsed file in `pihole_blocklists/<category>/<name>.txt` is compared with `.github/triage/feed-stats.json`. A feed counts as a problem when it is missing, empty or less than half last week's size.
  - List size: an `all_domains` shrink of more than 10% holds the commit, so users keep last week's lists, but only when a feed also failed. A big shrink with healthy feeds is treated as upstream pruning. It pings but still commits, because HaGeZi TIF alone can drop 400k entries in a week.
  - New blocks: domains newly in `all_domains` or `nsfw` that exactly match a Tranco top-100k site, or its `www.` form. Hits from a single feed, up to 15, are reviewed by MiniMax in one batch using VirusTotal, the page title and a text excerpt. Each is grouped as likely false positive, unclear or likely correct, and only the first two ping. Hits from several feeds are summarised as likely correct.
  It pings on problems and sends a quiet summary otherwise. Held builds skip checkout-list/README mutation and publishing. The deterministic check writes temporary feed-health JSON independently of optional AI review; failed/missing checks cannot authorize publication confirmation.
- Publication verification runs only after a successful unheld check, recorded manifest and successful push or verified no-change comparison. The optimizer uses a temporary `--config` file pinning only this repository's five custom feed URLs to the pre-optimizer checkout SHA. The manifest binds original configuration hashes, effective config hash, pinned URLs, actual downloaded custom raw-feed hashes, all eight output hashes, feed problems and hold state. Post-publish recording separately verifies the published `main` commit, tracked main ref, configuration ancestry and each committed Git LFS pointer's SHA256/size. Before any confirmation the verifier reads authenticated current-main provenance; if main moved, it leaves changes pending for a later build. A missing/inconsistent input, failed feed or output mismatch prevents confirmation.
- `triage.publication` then checks authenticated pending changes, actual PR merge/base/SHA provenance, inclusion in optimizer inputs, retained configuration and full requested output scope. It edits the original change comment once to confirm publication; it never adds a second notification. Broad non-NSFW blocks require actual covering wildcards in both category and combined outputs; flattened root-only output remains pending. NSFW broad scope requires `nsfw_abp.txt`, with the host-only alternative stated separately. Allow scopes must be absent from all eight outputs, not merely absent at the root host. A dry run reports `would_publish` and writes nothing. Discovery is bounded to 100 pending changes, 1,000 recently updated issues and 1,000 comments per issue, so unusually old changes/long threads may need maintainer recovery.
- The weekly workflow's verification token has `contents: read`, `issues: write`, `pull-requests: read`; GH_PAT-based publishing is unchanged. Verification/notification failures are nonblocking and explicitly say confirmations may be pending, not that the published build failed.
- `triage-watch.yml` runs `held` daily: when reputable VirusTotal engines rise on an open block request, it re-triages and pings. On the 1st of each month it runs `remediated`, which lists custom entries whose comment says "review if remediated" and that are clean on VirusTotal now, and `scorecard`, which counts separate whitelisted false-positive reports per feed and alerts at 3 or more. Run either by hand with `gh workflow run triage-watch.yml -f task=<held|remediated|scorecard>`.

Data/browser caches use a versioned OS/architecture/lockfile key. Issue jobs restore only and never save caches. The main-only `triage-cache.yml` warms Chromium, Tranco and the public suffix list daily/manual/on relevant pushes, saving at most one compatible cache per UTC day. `triage-tests.yml` runs the frozen offline pytest suite on PRs and main pushes (Python 3.12); test guards reject real HTTP, DNS, sockets and browser starts while allowing explicit fakes/MockTransport. Local offline checks: `cd .github/triage && uv sync --frozen && uv run --frozen python -m pytest -q`.

Labels: type (`blocklist`, `whitelist`, `bug`, `enhancement`), status (`needs info`, `duplicate`, `declined`), impact (`impact: high`, `impact: medium`, `impact: low`) and `maintenance` for Dependabot and CI PRs.

## Issue Processing

When handling a block or whitelist issue, follow these procedures.

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
   - To block a domain **and all its subdomains** (e.g. a tracking SDK that uses many hashed subdomains), append `||<domain>^` instead of the bare domain. A plain `<domain>` blocks only the exact host. Reporter requests written as `*.<domain>` map to `||<domain>^`.
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
