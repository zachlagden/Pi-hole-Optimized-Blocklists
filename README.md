# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-2.5M%2B-blue?style=flat-square)
![Updated Weekly](https://img.shields.io/badge/updated-weekly-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/)**

</div>

> **Looking for more features?** Check out [Zach's Lists](https://lists.zachlagden.uk) — a full-featured blocklist platform with custom source selection, smart whitelisting, and multiple output formats.

---

## Available Lists

| List | Description | Domains |
|------|-------------|--------:|
| **[all_domains.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt)** | Everything combined (except NSFW) | 2,533,174 |
| **[advertising.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/advertising.txt)** | Ad networks & services | 100,298 |
| **[tracking.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/tracking.txt)** | Analytics & telemetry | 35,300 |
| **[malicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/malicious.txt)** | Malware, phishing, scams | 1,950,002 |
| **[suspicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/suspicious.txt)** | Potentially unwanted | 63,801 |
| **[comprehensive.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/comprehensive.txt)** | Curated multi-category | 731,281 |
| **[nsfw.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw.txt)** | Adult content (separate) | 324,681 |

> **Note:** `nsfw.txt` is **not** included in `all_domains.txt` because it blocks legitimate adult sites. Add it separately if you want NSFW blocking.

**Last updated**: May 10, 2026

## Quick Start

1. Go to Pi-hole admin → **Settings** → **Adlists**
2. Add the raw URL for your chosen list(s)
3. Run `pihole -g` to update

## Report a Domain

Found a domain that should be blocked or a false positive? Open an issue using one of the templates:

- **[Block Domain](../../issues/new?template=block-domain.yml)** — request a malicious, ad, tracking, or suspicious domain to be blocked
- **[False Positive](../../issues/new?template=false-positive.yml)** — report a legitimate domain that's being incorrectly blocked
- **[Bug Report](../../issues/new?template=bug_report.yml)** — report a problem with the lists or automation

Claude will automatically process your request and create a PR. The maintainer reviews and merges it, and the change takes effect on the next weekly update.

## FAQ

<details>
<summary><b>What's the difference between this and Zach's Lists?</b></summary>

This repository provides static, pre-built blocklists updated weekly. [Zach's Lists](https://lists.zachlagden.uk) offers additional features:
- Custom source selection — pick which blocklists to include
- Smart whitelisting — regex, wildcards, subdomain patterns
- Multiple formats — hosts, plain, and Adblock syntax
- Real-time build progress

Both use the same underlying sources and are maintained by the same person.
</details>

<details>
<summary><b>How often are these lists updated?</b></summary>

Every Sunday at midnight UTC via GitHub Actions. Community-reported domains are included once their PR is merged before the next run.
</details>

<details>
<summary><b>Which list should I use?</b></summary>

- **comprehensive.txt** — Good balance for most users
- **all_domains.txt** — Maximum blocking (may cause false positives)
- Individual category lists — If you want granular control
</details>

<details>
<summary><b>How do community-reported domains work?</b></summary>

Domains reported via issues are added to `custom/<category>.txt` files in the repo. These are referenced as sources in `blocklists.conf` via raw GitHub URLs, so the optimizer picks them up on the next weekly run just like any other upstream source.
</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to report domains, submit PRs, and use the automated workflows.

## Sponsors

Thanks to everyone who supports this project.

**One-Time**

[![@rnsimmons](https://img.shields.io/badge/@rnsimmons-EA4AAA?style=flat&logo=github-sponsors&logoColor=white)](https://github.com/rnsimmons)

## Star History

<a href="https://star-history.com/#zachlagden/Pi-hole-Optimized-Blocklists&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=zachlagden/Pi-hole-Optimized-Blocklists&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=zachlagden/Pi-hole-Optimized-Blocklists&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=zachlagden/Pi-hole-Optimized-Blocklists&type=Date" />
 </picture>
</a>

## License

MIT License — see [LICENCE](LICENCE) for details.
