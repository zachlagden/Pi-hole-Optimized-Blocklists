# Pi-hole Optimized Blocklists

<div align="center">

![Last Updated](https://img.shields.io/github/last-commit/zachlagden/Pi-hole-Optimized-Blocklists?label=last%20updated&style=flat-square)
![Total Domains](https://img.shields.io/badge/domains-6.7M%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-Unlicense-green?style=flat-square)

**Ready-to-use, optimized blocklists for Pi-hole, regularly updated and categorized by threat type**

[Installation](#-installation) •
[The Lists](#-the-lists) •
[Statistics](#-statistics) •
[Usage](#-usage) •
[Weekly Updates](#-weekly-updates) •
[FAQ](#-faq)

</div>

## ℹ️ About

This repository contains regularly updated, optimized blocklists for use with [Pi-hole](https://pi-hole.net/), the popular DNS-level ad blocker. These lists have been processed with the [Pi-hole Blocklist Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer) to:

- Remove duplicates across all source lists
- Validate all domains for proper formatting
- Organize domains by category
- Pre-optimize for Pi-hole compatibility
- Remove false positives and problematic domains

These lists are updated on a regular basis to ensure they contain the latest threats while minimizing false positives.

## 🚀 Installation

### Option 1: Quick Setup (Recommended)

Simply add these URLs to your Pi-hole's blocklist settings (Settings → Blocklists):

| Category | URL |
|----------|-----|
| **All Domains** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/all_domains.txt` |
| **Advertising** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/advertising.txt` |
| **Tracking** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/tracking.txt` |
| **Malicious** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/malicious.txt` |
| **Suspicious** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/suspicious.txt` |
| **Comprehensive** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/comprehensive.txt` |
| **NSFW** | `https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/nsfw.txt` |

After adding your desired lists, click "Save and update" to apply them to your Pi-hole.

### Option 2: Manual Download

If you prefer to download the lists manually:

```bash
# Download the lists to your Pi-hole
cd /etc/pihole/
sudo wget -O advertising.txt https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/advertising.txt
# Download other lists as desired
sudo pihole restartdns reload
```

## 📋 The Lists

| List | Description | Domains | Raw Link |
|------|-------------|---------|----------|
| **all_domains.txt** | Complete collection of all unique domains |  | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/all_domains.txt) |
| **advertising.txt** | Ad networks and services | 160594 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/advertising.txt) |
| **tracking.txt** | Analytics and tracking services | 88480 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/tracking.txt) |
| **malicious.txt** | Malware, phishing, and scams | 1415171 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/malicious.txt) |
| **suspicious.txt** | Potentially unwanted content | 180976 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/suspicious.txt) |
| **comprehensive.txt** | Well-maintained multi-category lists | 305283 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/comprehensive.txt) |
| **nsfw.txt** | Adult content | 4777799 | [Download](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/refs/heads/main/lists/nsfw.txt) |

### Recommendations

- **Balanced Protection**: Use the `comprehensive.txt` list (excellent for most users)
- **Standard Protection**: Use the `advertising.txt` and `tracking.txt` lists
- **Enhanced Protection**: Add the `malicious.txt` list
- **Complete Protection**: Use `all_domains.txt` (may require more powerful hardware)
- **Parental Controls**: Add the `nsfw.txt` list

## 📊 Statistics

These lists are compiled from over 45 trusted sources, and the current version includes:

- **6.7+ million** unique domains
- **47** source blocklists
- **6** categories
- **~495776** duplicate domains removed
- **Last updated**: March 21, 2025

## 🛠️ Usage

### Whitelist Recommendations

Some domains may need to be whitelisted to prevent interference with normal services. Common whitelist recommendations:

```
# Microsoft services
outlook.office365.com
products.office.com
c.s-microsoft.com
i.s-microsoft.com

# Google services
accounts.google.com
clients2.google.com
clients4.google.com

# Apple services
appleid.apple.com
token.safebrowsing.apple

# Other services
gravatar.com
s.shopify.com
api.github.com
```

Add these to your Pi-hole whitelist if you experience issues.

### Performance Impact

- Pi-hole can easily handle millions of domains on modern hardware (RPi 4+)
- For older devices (RPi 3 or earlier), consider using only specific category lists instead of all_domains.txt
- The impact on DNS query performance is minimal after initial loading

## 🔄 Weekly Updates

These blocklists are automatically updated every Sunday using GitHub Actions. The process:

1. Downloads the latest blocklists from their original sources
2. Processes and optimizes them using [Pi-hole-Blocklist-Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer)
3. Removes duplicates and validates domains
4. Updates the repository with changes

### Latest Update

- **Date**: March 15, 2025
- **Processing time**: 80.24 seconds
- **Total domains**: 6,776,057
- **Duplicates removed**: 492,043

## ❓ FAQ

### How often are these lists updated?

These lists are updated weekly, typically on Sunday. Check the last commit date for the most recent update.

### Why are some legitimate domains blocked?

Occasionally, legitimate domains may be included in blocklists. If you find a false positive, please:

1. Add it to your whitelist in Pi-hole
2. [Open an issue](https://github.com/zachlagden/Pi-hole-Optimized-Blocklists/issues/new) with details so it can be reviewed

### How do these compare to default Pi-hole lists?

These lists are considerably more comprehensive than the default Pi-hole lists, offering broader protection across multiple categories.

### Can I use these with AdGuard Home or similar tools?

Yes, these lists use the standard hosts format (`0.0.0.0 domain.com`) which is compatible with most DNS-based blocking tools.

### Do I need all these lists?

No, you can choose which categories to use based on your needs. For most users, the comprehensive list provides excellent protection without requiring multiple lists.

## 🙏 Acknowledgements

These lists are compiled from numerous open-source blocklist projects. Full credit goes to the maintainers of these source lists who do the hard work of identifying and categorizing domains.

Created using the [Pi-hole Blocklist Optimizer](https://github.com/zachlagden/Pi-hole-Blocklist-Optimizer).

## 📜 License

This repository is released under the [Unlicense](UNLICENCE), placing these lists in the public domain.