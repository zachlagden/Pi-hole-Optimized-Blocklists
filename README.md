# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-1.6M%2B-blue?style=flat-square)
![Updated Weekly](https://img.shields.io/badge/updated-weekly-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/)**

</div>

> **Looking for more features?** Check out [Zach's Lists](https://lists.zachlagden.uk) — a full-featured blocklist platform with custom source selection, smart whitelisting, and multiple output formats.

---

## Available Lists

| List | Description | Domains |
|------|-------------|--------:|
| **[all_domains.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt)** | Everything combined (except NSFW) | 1,606,124 |
| **[advertising.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/advertising.txt)** | Ad networks & services | 107,689 |
| **[tracking.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/tracking.txt)** | Analytics & telemetry | 35,943 |
| **[malicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/malicious.txt)** | Malware, phishing, scams | 1,170,186 |
| **[suspicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/suspicious.txt)** | Potentially unwanted | 58,774 |
| **[comprehensive.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/comprehensive.txt)** | Curated multi-category | 487,323 |
| **[nsfw.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw.txt)** | Adult content (separate) | 395,208 |

> **Note:** `nsfw.txt` is **not** included in `all_domains.txt` because it blocks legitimate adult sites. Add it separately if you want NSFW blocking.

**Last updated**: February 01, 2026

## Quick Start

1. Go to Pi-hole admin → **Settings** → **Adlists**
2. Add the raw URL for your chosen list(s)
3. Run `pihole -g` to update

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

Every Sunday at midnight UTC via GitHub Actions.
</details>

<details>
<summary><b>Which list should I use?</b></summary>

- **comprehensive.txt** — Good balance for most users
- **all_domains.txt** — Maximum blocking (may cause false positives)
- Individual category lists — If you want granular control
</details>

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
