REPUTABLE_VT_ENGINES = {
    "Avira",
    "BitDefender",
    "Dr.Web",
    "ESET",
    "Emsisoft",
    "Forcepoint ThreatSeeker",
    "Fortinet",
    "G-Data",
    "Google Safebrowsing",
    "Kaspersky",
    "Netcraft",
    "Sophos",
    "Webroot",
}

MIN_REPUTABLE_VT_HITS = 2

FP_PRONE_SOURCES = {
    "phishing_army": "phishing.army extended list, false positives #52 and #54",
    "badmojr_1hosts_lite": "1Hosts Lite, false positive #83",
    "hagezi_dyndns": "blocks dynamic-DNS providers as a class, false positive #84",
    "oisd_nsfw": "miscategorises non-adult sites, false positives #62 and #71",
    "hagezi_tif_full": "threat intel that can keep stale listings from past WordPress compromises, #56 and #63",
}

THREAT_INTEL_SOURCES = {
    "hagezi_tif_full",
    "hagezi_fake",
    "urlhaus",
    "curbengh_phishing",
    "dandelion_antimalware",
    "shadowwhisperer_malware",
    "shadowwhisperer_scam",
}

PROVIDER_PHISHING_TITLES = {
    "suspected phishing": "Cloudflare's suspected-phishing block page",
    "deceptive site ahead": "Google Safe Browsing's deceptive-site warning",
    "phishing site warning": "a host's phishing warning page",
}

SHARED_PATH_HOSTS = {
    "storage.googleapis.com": "Google Cloud Storage",
    "firebasestorage.googleapis.com": "Firebase Storage",
    "s3.amazonaws.com": "Amazon S3",
    "docs.google.com": "Google Docs and Forms",
    "drive.google.com": "Google Drive",
    "sites.google.com": "Google Sites",
    "forms.gle": "Google Forms short links",
    "t.co": "X link shortener",
    "bit.ly": "Bitly link shortener",
    "github.com": "GitHub",
    "raw.githubusercontent.com": "GitHub raw files",
    "cdn.discordapp.com": "Discord attachments",
    "www.dropbox.com": "Dropbox",
    "dropbox.com": "Dropbox",
    "1drv.ms": "OneDrive short links",
    "onedrive.live.com": "OneDrive",
}

POPULAR_RANK = 100_000
YOUNG_DOMAIN_DAYS = 90
TYPOSQUAT_POOL = 10_000

RULES_FOR_REVIEWERS = """\
Blocking needs positive evidence of malicious behaviour: a captured phishing or malware URL,
credential or payment harvesting, a listing in reputable threat intel (URLhaus, HaGeZi TIF or fake,
curbengh phishing), several reputable VirusTotal engines, or documented fraud or regulatory action.
These are NOT enough on their own: two domains being related, a low ScamAdviser score, one scanner
such as Gridinsoft, WHOIS privacy, a cheap registrar, or low traffic.
Judge every domain on its own evidence. A reporter acting in bad faith can still be right about one
domain, and relatedness never justifies blocking a clean domain.
For false-positive reports, a single listing from an aggressive source is a strong false-positive
signal, especially phishing_army, badmojr_1hosts_lite, hagezi_dyndns or oisd_nsfw. Independent
corroboration (several sources, VirusTotal detections, a young domain, a cloned storefront) overrides
the reporter's claim that a site is legitimate, and then the right move is to ask for proof.
Whitelist as precisely as possible: the exact host rather than the whole domain when shared
infrastructure has abusive tenants.
"""
