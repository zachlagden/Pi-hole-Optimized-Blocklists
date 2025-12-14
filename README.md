# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-6.8M%2B-blue?style=flat-square)
![Updated Weekly](https://img.shields.io/badge/updated-weekly-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/) — updated weekly**

[Quick Start](#quick-start) •
[Available Lists](#available-lists) •
[Statistics](#statistics) •
[FAQ](#faq)

</div>

---

## What Is This?

Ready-to-use blocklists compiled from 49+ trusted sources, processed by the [Pi-hole Blocklist Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer):

- **6.7M+ unique domains** across all categories
- **Deduplicated** — no redundant entries
- **Validated** — only properly formatted domains
- **Whitelisted** — common false positives removed
- **Updated weekly** via GitHub Actions

## Quick Start

Add one URL to Pi-hole (Settings → Adlists):

```
https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt
```

Then run: `pihole -g`

**That's it.** You now have 6.7M+ domains blocked.

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

### Which List Should I Use?

| Use Case | Recommended List(s) |
|----------|---------------------|
| Most users | `comprehensive.txt` |
| Maximum protection | `all_domains.txt` |
| Ads + tracking only | `advertising.txt` + `tracking.txt` |
| Security focused | `malicious.txt` + `suspicious.txt` |
| Parental controls | Add `nsfw.txt` |

## Statistics

| Metric | Value |
|--------|-------|
| Total unique domains | 6,783,097 |
| Source blocklists | 49 |
| Categories | 6 |
| Duplicates removed | ~420,000 |
| Whitelisted domains | 300+ |
| Update frequency | Weekly (Sundays) |

**Last updated**: December 14, 2025

## How It Works

```
49 Source Lists → Download → Validate → Deduplicate → Whitelist → Categorize → Output
```

Every Sunday, GitHub Actions:
1. Downloads all source blocklists
2. Validates domain formatting
3. Removes duplicates across all lists
4. Applies whitelist (false positive removal)
5. Generates category-specific and combined lists
6. Commits changes to this repository

## Whitelist

Common services are pre-whitelisted to prevent breakage. If something isn't working, you may need to whitelist it in Pi-hole:

<details>
<summary>Common whitelist entries (click to expand)</summary>

```
# Microsoft
outlook.office365.com
products.office.com
login.microsoftonline.com

# Google
accounts.google.com
clients2.google.com
clients4.google.com

# Apple
appleid.apple.com
gsp-ssl.ls.apple.com

# CDNs & APIs
s.shopify.com
cdn.shopify.com
gravatar.com
api.github.com
raw.githubusercontent.com

# Streaming
spclient.wg.spotify.com
```

</details>

## FAQ

<details>
<summary><b>How often are lists updated?</b></summary>

Weekly, every Sunday at midnight UTC.
</details>

<details>
<summary><b>Something legitimate is blocked — what do I do?</b></summary>

1. Add it to your Pi-hole whitelist
2. [Open an issue](https://github.com/zachlagden/Pi-hole-Optimized-Blocklists/issues) so we can review it
</details>

<details>
<summary><b>Will this slow down my Pi-hole?</b></summary>

No. Pi-hole handles millions of domains efficiently. The `all_domains.txt` list works fine on a Raspberry Pi 4. For older hardware (Pi 3 or earlier), consider using specific category lists instead.
</details>

<details>
<summary><b>Can I use this with AdGuard Home?</b></summary>

Yes. The lists use standard hosts format (`0.0.0.0 domain.com`) compatible with most DNS blockers.
</details>

<details>
<summary><b>How is this different from default Pi-hole lists?</b></summary>

These lists are significantly more comprehensive (6.7M vs ~300K domains), deduplicated, and categorized. They combine 49+ trusted sources into optimized outputs.
</details>

<details>
<summary><b>Can I run the optimizer myself?</b></summary>

Yes! See [Pi-hole-Blocklist-Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer).
</details>

## Links

- [Pi-hole Blocklist Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer) — The tool that generates these lists
- [Pi-hole](https://pi-hole.net/) — Network-wide ad blocking

## License

MIT License — see [LICENCE](LICENCE) for details.

---

<div align="center">

**If this helps you, consider giving it a star!**

</div>
