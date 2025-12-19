# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-6.9M%2B-blue?style=flat-square)
![Updated Weekly](https://img.shields.io/badge/updated-weekly-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/)**

</div>

---

> **Looking for more features?** Check out [Zach's Lists](https://lists.zachlagden.uk) — a full-featured blocklist platform with custom source selection, smart whitelisting, and multiple output formats.

---

## Available Lists

| List | Description | Domains |
|------|-------------|--------:|
| **[all_domains.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt)** | Everything combined | 6,783,097 |
| **[advertising.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/advertising.txt)** | Ad networks & services | 206,725 |
| **[tracking.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/tracking.txt)** | Analytics & telemetry | 88,701 |
| **[malicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/malicious.txt)** | Malware, phishing, scams | 1,514,637 |
| **[suspicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/suspicious.txt)** | Potentially unwanted | 179,918 |
| **[comprehensive.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/comprehensive.txt)** | Curated multi-category | 296,921 |
| **[nsfw.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw.txt)** | Adult content | 4,901,662 |

**Last updated**: December 19, 2025

---

## Quick Start

1. Go to Pi-hole admin → **Settings** → **Adlists**
2. Add the raw URL for your chosen list(s)
3. Run `pihole -g` to update

---

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

---

## License

MIT License — see [LICENCE](LICENCE) for details.
