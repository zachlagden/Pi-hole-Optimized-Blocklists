import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

REPO = "zachlagden/Pi-hole-Optimized-Blocklists"
ACCENT = "#E3B341"

THEMES = {
    "light": {"bg": "#ffffff", "fg": "#24292f", "muted": "#57606a", "grid": "#e6e8eb", "fill": 0.10},
    "dark": {"bg": "#0d1117", "fg": "#c9d1d9", "muted": "#8b949e", "grid": "#21262d", "fill": 0.16},
}


def fetch_starred_at() -> list[datetime]:
    out = subprocess.run(
        ["gh", "api", "-H", "Accept: application/vnd.github.star+json",
         f"/repos/{REPO}/stargazers?per_page=100", "--paginate", "--jq", ".[].starred_at"],
        capture_output=True, text=True, check=True,
    ).stdout.strip().splitlines()
    stamps = [datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) for s in out]
    return sorted(stamps)


def build_series(stamps: list[datetime]):
    xs = [stamps[0]]
    ys = [0]
    for i, t in enumerate(stamps, start=1):
        xs.append(t)
        ys.append(i)
    xs.append(datetime.now(timezone.utc))
    ys.append(len(stamps))
    return xs, ys


def render(xs, ys, theme: str, out_path: Path):
    c = THEMES[theme]
    fig, ax = plt.subplots(figsize=(8, 4), dpi=200)
    fig.patch.set_facecolor(c["bg"])
    ax.set_facecolor(c["bg"])

    ax.plot(xs, ys, color=ACCENT, linewidth=2.6, solid_capstyle="round", zorder=3)
    ax.fill_between(xs, ys, color=ACCENT, alpha=c["fill"], zorder=2)

    ax.set_ylim(bottom=0)
    ax.margins(x=0.01)
    ax.set_ylabel("GitHub Stars", color=c["muted"], fontsize=11)
    ax.set_title(f"Star History  —  {REPO}", color=c["fg"], fontsize=12, fontweight="bold", pad=14, loc="left")

    ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=4, maxticks=7))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    ax.yaxis.set_major_locator(MaxNLocator(nbins=5, integer=True))

    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(c["grid"])
    ax.tick_params(colors=c["muted"], labelsize=10, length=0)
    ax.grid(axis="y", color=c["grid"], linewidth=1, alpha=0.9, zorder=1)
    ax.set_axisbelow(True)

    fig.text(0.985, 0.02, "self-hosted · generated from GitHub stargazer data", ha="right", va="bottom",
             color=c["muted"], fontsize=7, alpha=0.8)

    fig.tight_layout(pad=1.2)
    fig.savefig(out_path, facecolor=c["bg"], bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def main():
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamps = fetch_starred_at()
    xs, ys = build_series(stamps)
    for theme in THEMES:
        render(xs, ys, theme, out_dir / f"star-history-{theme}.png")
    print(f"{len(stamps)} stars -> {out_dir}/star-history-light.png, star-history-dark.png")


if __name__ == "__main__":
    main()
