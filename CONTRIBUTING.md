# Contributing

Contributions are welcome. This document covers the basics.

## Reporting Domains

The most common contributions are domain reports. Use the issue templates provided and the maintainer will review your report and open a PR.

### Block a domain

Use the **Block Domain** template. Provide:
- The domain to block
- The category (malicious, advertising, tracking, or suspicious)
- Evidence or reasoning

The maintainer will verify the domain and add it to the appropriate `custom/<category>.txt` file via a PR.

### Report a false positive

Use the **False Positive Report** template. Provide:
- The domain being incorrectly blocked
- The service or application affected
- Which blocklist you're using

The maintainer will verify the report and add the domain to `whitelist.txt` in the correct section via a PR.

### Report a bug

Use the **Bug Report** template with as much detail as possible. Steps to reproduce are essential. The maintainer will investigate and either fix the problem or follow up with questions.

## What happens after you open an issue

A bot posts an evidence report on block and false-positive issues: repository/upstream coverage, dated scanner/registration results, HTTP probes and a separate browser capture where available. It can inspect directly referenced GitHub image attachments, public HTML/plain-text sources and same-repository issues within bounded limits. Mentioned, inspected and unavailable materials are distinguished; fetched source claims and related issues are not proof of wrongdoing. A 403, challenge or failed probe does not mean a site is offline.

The AI view is advisory. Public factual reasons refer to identified observations; bounded screenshots can support explicitly advisory visual interpretations, not prove authenticity. Unsupported recommendations ask for more information rather than suggesting a block. The bot may set type, impact and `needs info` labels, but never changes a list, declines or closes an issue by itself. Only the repository owner's commands can merge domain changes.

Please share only minimal, redacted evidence you have already observed. Remove personal/confidential information from screenshots and descriptions. Do not make a purchase, enter sensitive information or share private credentials/payment details to gather evidence. Directly referenced material may appear in public reports and be sent to the advisory review service, so do not submit confidential content.

## How It Works

- `custom/<category>.txt` files hold community-reported domains to block (one domain per line)
- Custom lists support wildcard blocking: a line `||example.com^` (or the shorthand `*.example.com`) blocks `example.com` **and all its subdomains**, while a plain `example.com` blocks only that exact host. Wildcards apply to `custom/*.txt` only.
- `whitelist.txt` holds domains that should not be blocked (organised by service/section)
- `blocklists.conf` holds URLs to upstream blocklist sources (`url|name|category` format)
- The optimizer binary runs weekly, downloads all sources (including the custom lists via raw GitHub URL), and produces the deduplicated output in `lists/`
- `lists/*.txt` are generated files tracked with Git LFS — **do not edit these directly**

Merging a PR changes the configuration, not the published lists immediately. Publication waits for a successful optimizer rebuild that consumes the merged configuration (normally Sunday midnight UTC, or a maintainer-triggered run selecting `main`). A queued rebuild is not a publication confirmation, and a held build keeps the previous lists. The production publishing job is main-only; branch/PR checks use the offline CI.

Owner-command changes are tracked as pending publication. After a healthy unheld build publishes or verifies unchanged outputs, the bot checks commit/input provenance and actual output coverage, then updates the original change comment once. Missing/failed feeds, mismatched outputs or incomplete requested scope leave the change pending. Broad rules flattened to a root host cannot be confirmed as covering all subdomains. NSFW descendant coverage is verified in the ABP-format list separately from the host-format list. Your Pi-hole must still refresh its lists after publication.

The owner can use `/block [category] [exact] [now] [domain ...]` and `/allow [exact | subdomains] [now] [domain ...]`. Block scope defaults to the host and descendants; `exact` blocks only the host. Allow scope defaults to the domain and descendants; `exact` allows only the host, while `subdomains` excludes the bare domain. Explicit domains can be supplied on closed issues. Commands normalize/deduplicate batches, skip entries already covered in the requested scope and refuse unsafe targets or whitelist conflicts without partially applying a conflicting batch. A `now` request only attempts to queue an immediate rebuild. Reporter replies use the owner's supplied wording or a scope-correct fixed template with pending-publication timing, never arbitrary model-written text.

## Manual Contributions

If you want to contribute directly rather than through an issue:

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-change`
3. Make your changes:
   - To block a domain: add it to the appropriate `custom/<category>.txt` file
   - To whitelist a domain: add it to `whitelist.txt` in the matching section
   - To add a new upstream source: add the URL to `blocklists.conf` in `url|name|category` format
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(blocklist): add example.com to malicious list
   fix(whitelist): add vpn.example.com for ExampleVPN
   ```
5. Push to your fork and open a Pull Request

### Branch naming

| Prefix | Use |
| --- | --- |
| `feature/<description>` | New features or domain additions |
| `fix/<description>` | Bug fixes or whitelist additions |
| `hotfix/<description>` | Urgent production fixes |
| `chore/<description>` | Maintenance tasks |

### Pull request guidelines

- Keep PRs focused on a single change
- Write a clear title following conventional commit format
- Fill in the PR template
- Reference the related issue where applicable (`Closes #123`)
- The maintainer will review your PR for domain validity, correct formatting, and duplicates

## Offline triage tests

Changes to triage automation are checked on PRs and main pushes with Python 3.12 and frozen dependencies. To run the same suite locally:

```sh
cd .github/triage
uv sync --frozen
uv run --frozen python -m pytest -q
```

Tests use bundled public-suffix data and explicit fakes. Real HTTP, DNS, socket and browser calls fail rather than silently becoming empty evidence. Normal issue jobs restore data/browser caches only; a separate main-only workflow warms and saves compatible daily caches.

## Licence

By contributing, you agree that your contributions will be licensed under the same licence as the project.
