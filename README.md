# Pi-hole Optimized Blocklists

<div align="center">

![Total Domains](https://img.shields.io/badge/domains-2.9M%2B-blue?style=flat-square)
![Updated Weekly](https://img.shields.io/badge/updated-weekly-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

**Pre-optimized, deduplicated blocklists for [Pi-hole](https://pi-hole.net/)**

</div>

> [!NOTE]
> **New — `nsfw_abp.txt`, a subdomain-blocking NSFW list.** An ABP-format version of `nsfw.txt` that blocks adult domains **and all their subdomains** (e.g. `cdn.example.com` as well as `example.com`) for more complete filtering. Requires Pi-hole Core ≥ 5.16 / FTL ≥ 5.22. See [Available Lists](#available-lists).

> **Looking for more features?** Check out [Zach's Lists](https://lists.zachlagden.uk) — a full-featured blocklist platform with custom source selection, smart whitelisting, and multiple output formats.

---

## Available Lists

| List | Description | Domains |
|------|-------------|--------:|
| **[all_domains.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/all_domains.txt)** | Everything combined (except NSFW) | 2,995,355 |
| **[advertising.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/advertising.txt)** | Ad networks & services | 256,303 |
| **[tracking.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/tracking.txt)** | Analytics & telemetry | 17,909 |
| **[malicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/malicious.txt)** | Malware, phishing, scams | 2,510,928 |
| **[suspicious.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/suspicious.txt)** | Potentially unwanted | 49,633 |
| **[comprehensive.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/comprehensive.txt)** | Curated multi-category | 515,907 |
| **[nsfw.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw.txt)** | Adult content (separate) | 526,338 |
| **[nsfw_abp.txt](https://media.githubusercontent.com/media/zachlagden/Pi-hole-Optimized-Blocklists/main/lists/nsfw_abp.txt)** | Adult content — ABP format, blocks subdomains too | 526,338 |

> **Note:** `nsfw.txt` is **not** included in `all_domains.txt` because it blocks legitimate adult sites. Add it separately if you want NSFW blocking. `nsfw_abp.txt` covers the same domains in ABP form (`||domain^`), so subdomains are blocked too. It leaves out subdomains that one of its rules already blocks, so it has fewer lines than `nsfw.txt`. Use it instead of `nsfw.txt`, not alongside it, for more thorough filtering (needs Pi-hole Core ≥ 5.16).

**Last updated**: October 04, 2026

## Quick Start

1. In the Pi-hole admin interface, open **Lists** (Pi-hole v6) or **Group Management → Adlists** (Pi-hole v5)
2. Add the URL of each list you want from the table above
3. Run `pihole -g`, or use **Tools → Update Gravity**, to load them

> The lists may include ABP-style entries (`||domain^`) that block a domain and all its subdomains. These require Pi-hole Core ≥ 5.16 / FTL ≥ 5.22 (released 2023; standard on current installs). Note that `pihole -q` won't enumerate the individual subdomains covered by an ABP entry.

## Report a Domain

Found a domain that should be blocked or a false positive? Open an issue using one of the templates:

- **[Block Domain](../../issues/new?template=block-domain.yml)** — request a malicious, ad, tracking, suspicious or adult domain to be blocked
- **[False Positive](../../issues/new?template=false-positive.yml)** — report a legitimate domain that's being incorrectly blocked
- **[Bug Report](../../issues/new?template=bug_report.yml)** — report a problem with the lists or automation

A bot posts an evidence report on each block and false-positive issue, and the maintainer makes every decision. An accepted change takes effect at the next weekly update.

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

Every Sunday, by a GitHub Actions build scheduled for 00:00 UTC. GitHub often starts scheduled builds a few hours late. Community-reported domains are included once their PR is merged before the next run.
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

## Sources

The lists are built from these sources, configured in [`blocklists.conf`](blocklists.conf). Each list keeps its own licence.

| Source | Lists used | Category | Licence |
|--------|------------|----------|---------|
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | Pro | comprehensive | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| | Threat Intelligence Feeds, Fake, DynDNS | malicious | |
| | Pop-Up Ads | advertising | |
| | Native trackers: Amazon, Apple, Huawei, LG webOS, OPPO/Realme, Roku, Samsung, TikTok, Vivo, Windows/Office, Xiaomi | tracking | |
| [OISD](https://oisd.nl) | Big | comprehensive | [GPL-3.0](https://github.com/sjhgvr/oisd/blob/main/LICENSE) |
| | NSFW | nsfw | |
| [1Hosts](https://github.com/badmojr/1Hosts) | Lite | comprehensive | [MPL-2.0](https://github.com/badmojr/1Hosts/blob/master/LICENSE) |
| [AdAway](https://adaway.org) | Hosts | advertising | [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/) |
| [Peter Lowe's list](https://pgl.yoyo.org/adservers/) | Ad servers | advertising | [Own licence, no commercial use](https://pgl.yoyo.org/license/) |
| [anudeepND](https://github.com/anudeepND/blacklist) | Ad servers | advertising | [MIT](https://github.com/anudeepND/blacklist/blob/master/LICENSE) |
| [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | DNS filter | advertising | [GPL-3.0](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE) |
| [Frogeye](https://hostfiles.frogeye.fr) | First-party trackers | tracking | [MIT](https://git.frogeye.fr/geoffrey/eulaurarien/src/branch/master/LICENSE) |
| [Perflyst](https://github.com/Perflyst/PiHoleBlocklist) | Smart TV, Android tracking | tracking | [MIT](https://github.com/Perflyst/PiHoleBlocklist/blob/master/LICENSE) |
| [URLhaus](https://urlhaus.abuse.ch) | Host file | malicious | [abuse.ch terms of use](https://abuse.ch/terms-of-use/) |
| [Phishing Army](https://phishing.army) | Extended | malicious | [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) |
| [Stalkerware indicators](https://github.com/AssoEchap/stalkerware-indicators) | Hosts | malicious | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) |
| [DandelionSprout](https://github.com/DandelionSprout/adfilt) | Anti-Malware List | malicious | [Dandelicence](https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md) |
| [malware-filter](https://gitlab.com/malware-filter/phishing-filter) | Phishing filter | malicious | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| [Spam404](https://github.com/Spam404/lists) | Main blacklist | malicious | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| [ShadowWhisperer](https://github.com/ShadowWhisperer/BlockLists) | Scam, Malware | malicious | [Unlicense](https://github.com/ShadowWhisperer/BlockLists/blob/master/LICENSE) |
| [UT1 blacklists](https://dsi.ut-capitole.fr/blacklists/) (via [Firebog](https://firebog.net)) | Cryptojacking | suspicious | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| [KADhosts](https://github.com/PolishFiltersTeam/KADhosts) | KADhosts | suspicious | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) | Porn only | nsfw | [MIT](https://github.com/StevenBlack/hosts/blob/master/license.txt) |
| Community reports ([`custom/`](custom)) | One list per category | all except comprehensive | [MIT](LICENCE) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to report domains, submit PRs, and use the automated workflows.

## Sponsors

Thanks to everyone who supports this project.

**One-Time**

[![@rnsimmons](https://img.shields.io/badge/@rnsimmons-EA4AAA?style=flat&logo=github-sponsors&logoColor=white)](https://github.com/rnsimmons)

## Star History

<a href="https://github.com/zachlagden/Pi-hole-Optimized-Blocklists/stargazers">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://repo-star-history.zachlagden.uk/svg?repos=zachlagden/pi-hole-optimized-blocklists&type=Date&theme=dark&legend=top-left&format=png&cb=2" />
   <source media="(prefers-color-scheme: light)" srcset="https://repo-star-history.zachlagden.uk/svg?repos=zachlagden/pi-hole-optimized-blocklists&type=Date&legend=top-left&format=png&cb=2" />
   <img alt="Star History Chart for zachlagden/Pi-hole-Optimized-Blocklists" src="https://repo-star-history.zachlagden.uk/svg?repos=zachlagden/pi-hole-optimized-blocklists&type=Date&legend=top-left&format=png&cb=2" />
 </picture>
</a>

<sub>Live chart, self-hosted (star-history.com's open-source backend) after GitHub <a href="https://www.star-history.com/blog/github-stargazer-api-restriction">restricted the stargazers API</a> in mid-2026.</sub>

## License

MIT License — see [LICENCE](LICENCE) for details.
