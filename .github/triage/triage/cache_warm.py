from pathlib import Path

from triage import domains, reputation

CACHE_DIR = Path.home() / ".cache" / "issue-triage"


def warm() -> None:
    tranco_dir = CACHE_DIR / "tranco"
    for cached in tranco_dir.glob("tranco-*.csv"):
        cached.unlink()
    ranks = reputation.tranco_ranks(tranco_dir)
    if not ranks:
        raise ValueError("Tranco returned no ranks; refusing to warm an empty cache")
    domains._extractor().update(fetch_now=True)
    print(f"Warmed {len(ranks):,} Tranco ranks and the public suffix list")


if __name__ == "__main__":
    warm()
