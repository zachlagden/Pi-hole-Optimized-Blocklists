# Contributing

Contributions are welcome. This document covers the basics.

## Reporting Domains

The most common contributions are domain reports. Use the issue templates provided and Claude will automatically create a PR for you to review.

### Block a domain

Use the **Block Domain** template. Provide:
- The domain to block
- The category (malicious, advertising, tracking, or suspicious)
- Evidence or reasoning

Claude will automatically add the domain to the appropriate `custom/<category>.txt` file and open a PR.

### Report a false positive

Use the **False Positive Report** template. Provide:
- The domain being incorrectly blocked
- The service or application affected
- Which blocklist you're using

Claude will automatically add the domain to `whitelist.txt` in the correct section and open a PR.

### Report a bug

Use the **Bug Report** template with as much detail as possible. Steps to reproduce are essential. Claude will analyse the issue and attempt a fix or comment with suggestions.

## How It Works

- `custom/<category>.txt` files hold community-reported domains to block (one domain per line)
- `whitelist.txt` holds domains that should not be blocked (organised by service/section)
- `blocklists.conf` holds URLs to upstream blocklist sources (`url|name|category` format)
- The optimizer binary runs weekly, downloads all sources (including the custom lists via raw GitHub URL), and produces the deduplicated output in `lists/`
- `lists/*.txt` are generated files tracked with Git LFS — **do not edit these directly**

When your PR is merged, the domain change takes effect on the next weekly optimizer run (Sunday midnight UTC), or when a maintainer manually triggers the workflow.

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
- Claude will automatically review your PR for domain validity, correct formatting, and duplicates

## Using @claude

You can mention `@claude` in any issue or PR comment to ask for help. Claude can:
- Process domain requests that weren't auto-handled
- Answer questions about the project
- Analyse and attempt fixes for bug reports
- Review and suggest improvements

## Licence

By contributing, you agree that your contributions will be licensed under the same licence as the project.
