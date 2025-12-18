# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-6.8M%2B-blue?style=flat-square)
![No Longer Updated](https://img.shields.io/badge/status-archived-red?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/)**

</div>

---

> ## ⚠️ This Repository Is No Longer Updated
>
> **This project has evolved into [Zach's Lists](https://lists.zachlagden.uk)** — a full-featured blocklist platform.
>
> ### Migrate Now
>
> Replace your current URLs with these (same lists, actively updated):
>
> | Old URL | New URL |
> |---------|---------|
> | `.../lists/all_domains.txt` | `https://lists.zachlagden.uk/lists/all_domains.txt` |
> | `.../lists/advertising.txt` | `https://lists.zachlagden.uk/lists/advertising.txt` |
> | `.../lists/tracking.txt` | `https://lists.zachlagden.uk/lists/tracking.txt` |
> | `.../lists/malicious.txt` | `https://lists.zachlagden.uk/lists/malicious.txt` |
> | `.../lists/suspicious.txt` | `https://lists.zachlagden.uk/lists/suspicious.txt` |
> | `.../lists/comprehensive.txt` | `https://lists.zachlagden.uk/lists/comprehensive.txt` |
>
> ### Why Migrate?
>
> - **Weekly updates** — these lists stay current
> - **Faster delivery** — optimized hosting
> - **Build your own** — create custom blocklists with your choice of sources
> - **Smart whitelisting** — regex, wildcards, subdomain patterns
> - **Multiple formats** — hosts, plain, and Adblock syntax
>
> **[Visit Zach's Lists →](https://lists.zachlagden.uk)**

---

## Legacy Lists (No Longer Updated)

These lists remain available but are frozen as of December 2025:

| List | Description | Domains |
|------|-------------|--------:|
| **[all_domains.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt)** | Everything combined | 6,783,097 |
| **[advertising.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/advertising.txt)** | Ad networks & services | 206,725 |
| **[tracking.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/tracking.txt)** | Analytics & telemetry | 88,701 |
| **[malicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/malicious.txt)** | Malware, phishing, scams | 1,514,637 |
| **[suspicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/suspicious.txt)** | Potentially unwanted | 179,918 |
| **[comprehensive.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/comprehensive.txt)** | Curated multi-category | 296,921 |
| **[nsfw.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw.txt)** | Adult content | 4,901,662 |

**Last updated**: December 14, 2025

---

## FAQ

<details>
<summary><b>Will the old URLs keep working?</b></summary>

Yes. The lists hosted here will remain available, but they won't receive updates. For actively maintained lists, use the new URLs at lists.zachlagden.uk.
</details>

<details>
<summary><b>How do I migrate?</b></summary>

In Pi-hole, go to **Settings → Adlists**, remove the old GitHub URL, and add the new lists.zachlagden.uk URL. Then run `pihole -g` to update.
</details>

<details>
<summary><b>Can I build my own custom blocklist?</b></summary>

Yes! That's the main feature of [Zach's Lists](https://lists.zachlagden.uk). Sign in with GitHub, pick your sources, add whitelist patterns, and get a personalized blocklist URL.
</details>

---

## License

MIT License — see [LICENCE](LICENCE) for details.

---

<div align="center">

**[Migrate to Zach's Lists →](https://lists.zachlagden.uk)**

</div>
