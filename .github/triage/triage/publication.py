import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from triage.commands import CATEGORIES, allow_entries_for, entries_for, normalized_domains
from triage.github_api import GitHub, is_bot_comment
from triage.listparse import Entry, entry_blocks, extract_entry
from triage.sources import REPO_SOURCE_PREFIX

MARKER_RE = re.compile(r"<!-- triage-change:([A-Za-z0-9+/=]+) -->")
MANIFEST = "triage-publication.json"
OUTPUTS = ("all_domains.txt", "advertising.txt", "tracking.txt", "malicious.txt", "suspicious.txt", "comprehensive.txt", "nsfw.txt", "nsfw_abp.txt")
CONFIG = ("blocklists.conf", "whitelist.txt", *(f"custom/{category}.txt" for category in sorted(CATEGORIES)))
MAX_CHANGES = 100
MAX_DOMAINS = 100


@dataclass
class PendingChange:
    issue: int
    pr: int
    pr_url: str
    merge_sha: str
    action: str
    path: str
    domains: list[str]
    entries: list[str]
    scope: str
    status: str = "pending"
    version: int = 1

    def marker(self) -> str:
        encoded = base64.b64encode(json.dumps(asdict(self), sort_keys=True).encode()).decode()
        return f"<!-- triage-change:{encoded} -->"


def parse_change(comment: dict) -> PendingChange | None:
    if not is_bot_comment(comment):
        return None
    match = MARKER_RE.search(comment.get("body") or "")
    if not match:
        return None
    try:
        data = json.loads(base64.b64decode(match[1], validate=True))
        change = PendingChange(**data)
        if change.version != 1 or change.status not in {"pending", "published"}:
            return None
        if type(change.issue) is not int or type(change.pr) is not int or change.issue <= 0 or change.pr <= 0:
            return None
        if change.action not in {"block", "allow"} or change.scope not in {"domain", "exact", "subdomains"}:
            return None
        if not isinstance(change.merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", change.merge_sha):
            return None
        if not isinstance(change.domains, list) or not change.domains or len(change.domains) > MAX_DOMAINS:
            return None
        if normalized_domains(change.domains) != change.domains:
            return None
        expected = entries_for(change.domains, change.scope == "exact") if change.action == "block" else allow_entries_for(change.domains, change.scope)
        if change.entries != expected:
            return None
        if change.action == "allow" and change.path != "whitelist.txt":
            return None
        if change.action == "block" and (change.path not in CONFIG or not change.path.startswith("custom/") or change.scope == "subdomains"):
            return None
        return change
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL).strip()


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def pinned_config(original: str, config_sha: str) -> tuple[str, dict[str, str]]:
    if not re.fullmatch(r"[0-9a-f]{40}", config_sha):
        raise ValueError("invalid build configuration SHA")
    urls = {f"custom/{category}.txt": f"{REPO_SOURCE_PREFIX}{config_sha}/custom/{category}.txt" for category in sorted(CATEGORIES)}
    effective = original
    for path, pinned in urls.items():
        category = Path(path).stem
        current = f"{REPO_SOURCE_PREFIX}main/{path}|custom_{category}|{category}|abp"
        lines = [line for line in original.splitlines() if line.strip() == current]
        if len(lines) != 1 or original.count(f"{REPO_SOURCE_PREFIX}main/{path}") != 1:
            raise ValueError("missing or ambiguous repository custom source")
        effective = effective.replace(current, pinned + f"|custom_{category}|{category}|abp")
    return effective, urls


def prepare_config(root: Path, config_sha: str, target: Path) -> None:
    if target.resolve() in {(root / path).resolve() for path in CONFIG}:
        raise ValueError("effective config must not overwrite tracked configuration")
    original = (root / "blocklists.conf").read_text()
    if git(root, "show", f"{config_sha}:blocklists.conf") != original.strip():
        raise ValueError("configuration does not match captured checkout")
    effective, _ = pinned_config(original, config_sha)
    target.write_text(effective)


def record_manifest(lists: Path, root: Path, config_sha: str, feed_check: dict, effective_config: Path, base: Path) -> dict:
    (lists / MANIFEST).unlink(missing_ok=True)
    if not re.fullmatch(r"[0-9a-f]{40}", config_sha):
        raise ValueError("invalid build configuration SHA")
    if set(feed_check) != {"successful", "held", "feed_problems"} or type(feed_check["successful"]) is not bool or type(feed_check["held"]) is not bool or not isinstance(feed_check["feed_problems"], list):
        raise ValueError("invalid feed-check evidence")
    configs = {path: digest(root / path) for path in CONFIG}
    for path in CONFIG:
        committed = subprocess.check_output(["git", "-C", str(root), "show", f"{config_sha}:{path}"], stderr=subprocess.DEVNULL)
        if hashlib.sha256(committed).hexdigest() != configs[path]:
            raise ValueError("configuration changed after optimizer checkout")
    expected_config, custom_urls = pinned_config((root / "blocklists.conf").read_text(), config_sha)
    effective_hash = hashlib.sha256(expected_config.encode()).hexdigest()
    if digest(effective_config) != effective_hash:
        raise ValueError("effective optimizer configuration does not match pinned inputs")
    downloaded_custom = {path: digest(base / Path(path).stem / f"custom_{Path(path).stem}.txt.raw") for path in custom_urls}
    if any(downloaded_custom[path] != configs[path] for path in custom_urls):
        raise ValueError("downloaded custom source does not match captured configuration")
    manifest = {
        "version": 1, "config_sha": config_sha, "config_sha256": configs,
        "effective_config_sha256": effective_hash, "custom_source_urls": custom_urls,
        "downloaded_custom_sha256": downloaded_custom,
        "output_sha256": {path: digest(lists / path) for path in OUTPUTS}, **feed_check,
    }
    (lists / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def validate_build_manifest(lists: Path, root: Path) -> dict:
    manifest = json.loads((lists / MANIFEST).read_text())
    if manifest.get("version") != 1 or manifest.get("successful") is not True or manifest.get("held") is not False or manifest.get("feed_problems") != []:
        raise ValueError("build check was failed, held, missing or had feed problems")
    config_sha = manifest.get("config_sha", "")
    if not isinstance(config_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", config_sha) or not is_ancestor(root, config_sha, git(root, "rev-parse", "HEAD")):
        raise ValueError("build configuration is not in the published checkout")
    for key, paths, directory in (("config_sha256", CONFIG, root), ("output_sha256", OUTPUTS, lists)):
        if set(manifest.get(key, {})) != set(paths):
            raise ValueError("incomplete build manifest")
        for path in paths:
            if manifest[key][path] != digest(directory / path):
                raise ValueError(f"build hash mismatch: {path}")
            if key == "output_sha256" and manifest[key][path] != digest(root / "lists" / path):
                raise ValueError(f"output not present in published checkout: {path}")
            if key == "config_sha256":
                committed = subprocess.check_output(["git", "-C", str(root), "show", f"{config_sha}:{path}"], stderr=subprocess.DEVNULL)
                if hashlib.sha256(committed).hexdigest() != manifest[key][path]:
                    raise ValueError("configuration provenance mismatch")
    expected_config, custom_urls = pinned_config((root / "blocklists.conf").read_text(), config_sha)
    if (manifest.get("effective_config_sha256") != hashlib.sha256(expected_config.encode()).hexdigest()
            or manifest.get("custom_source_urls") != custom_urls
            or manifest.get("downloaded_custom_sha256") != {path: manifest["config_sha256"][path] for path in custom_urls}):
        raise ValueError("missing or inconsistent pinned optimizer input evidence")
    return manifest


def validate_committed_outputs(lists: Path, root: Path, manifest: dict, published_sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", published_sha) or published_sha != git(root, "rev-parse", "HEAD"):
        raise ValueError("published commit does not match checkout")
    if published_sha != git(root, "rev-parse", "refs/remotes/origin/main"):
        raise ValueError("published commit is not the tracked production main ref")
    if not is_ancestor(root, manifest["config_sha"], published_sha):
        raise ValueError("build configuration is not in published commit")
    for path in CONFIG:
        committed = subprocess.check_output(["git", "-C", str(root), "show", f"{published_sha}:{path}"], stderr=subprocess.DEVNULL)
        if hashlib.sha256(committed).hexdigest() != manifest["config_sha256"][path]:
            raise ValueError("published configuration differs from optimizer inputs")
    for name in OUTPUTS:
        pointer = git(root, "show", f"{published_sha}:lists/{name}")
        match = re.fullmatch(r"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)", pointer)
        if not match or match[1] != manifest["output_sha256"][name] or int(match[2]) != (lists / name).stat().st_size:
            raise ValueError(f"committed LFS output does not match build: {name}")


def record_publication(lists: Path, root: Path, published_sha: str) -> None:
    manifest = validate_build_manifest(lists, root)
    validate_committed_outputs(lists, root, manifest, published_sha)
    manifest["published_sha"] = published_sha
    manifest["published_ref"] = "refs/heads/main"
    (lists / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")


def validate_manifest(lists: Path, root: Path) -> dict:
    manifest = validate_build_manifest(lists, root)
    published_sha = manifest.get("published_sha")
    if not isinstance(published_sha, str) or manifest.get("published_ref") != "refs/heads/main":
        raise ValueError("missing successful production-main publication evidence")
    validate_committed_outputs(lists, root, manifest, published_sha)
    return manifest


def output_entries(lists: Path, domains: set[str] | None = None) -> dict[str, list[Entry]]:
    result: dict[str, list[Entry]] = {}
    ancestors: dict[str, set[str]] = {}
    for domain in domains or set():
        labels = domain.split(".")
        for index in range(len(labels) - 1):
            ancestors.setdefault(".".join(labels[index:]), set()).add(domain)
    for name in OUTPUTS:
        entries: list[Entry] = []
        retained: dict[tuple[str, str], Entry] = {}
        with (lists / name).open() as handle:
            for raw in handle:
                entry = extract_entry(raw, allow_wildcards=True)
                if not entry:
                    if raw.strip() and not raw.lstrip().startswith(("#", "!")):
                        raise ValueError(f"unrecognized output entry: {name}")
                    continue
                if domains is None:
                    entries.append(entry)
                    continue
                for domain in ancestors.get(entry.domain, set()):
                    if entry.domain == domain:
                        retained[(domain, "wildcard" if entry.subdomains else "host")] = entry
                    elif entry.subdomains:
                        retained[(domain, "ancestor")] = entry
                labels = entry.domain.split(".")
                for index in range(1, len(labels) - 1):
                    parent = ".".join(labels[index:])
                    if parent in domains:
                        retained[(parent, "descendant")] = entry
        result[name] = list(retained.values()) if domains is not None else entries
    return result


def scope_includes(domain: str, scope: str, entry: Entry) -> bool:
    if scope == "exact":
        return entry_blocks(entry, domain)
    if scope == "subdomains":
        return entry.domain.endswith("." + domain) or entry.subdomains and (entry.domain == domain or domain.endswith("." + entry.domain))
    return entry.domain == domain or entry.domain.endswith("." + domain) or entry.subdomains and domain.endswith("." + entry.domain)


def verify_change(change: PendingChange, root: Path, manifest: dict, outputs: dict[str, list[Entry]], pr: dict) -> str:
    if not pr.get("merged") or pr.get("merge_commit_sha") != change.merge_sha or pr.get("base", {}).get("ref") != "main":
        return "PR merge provenance does not match"
    if not is_ancestor(root, change.merge_sha, manifest["config_sha"]):
        return "change was not in the optimizer checkout"
    actual = {line.split("#", 1)[0].strip() for line in (root / change.path).read_text().splitlines()}
    if not set(change.entries) <= actual:
        return "merged configuration is no longer present"
    committed = git(root, "show", f"{change.merge_sha}:{change.path}")
    if not set(change.entries) <= {line.split("#", 1)[0].strip() for line in committed.splitlines()}:
        return "entries do not match the merged configuration"
    if change.action == "allow":
        for name, entries in outputs.items():
            if any(scope_includes(domain, change.scope, entry) for domain in change.domains for entry in entries):
                return f"allowed scope is still blocked in {name}"
    else:
        category = Path(change.path).stem
        required = [(f"{category}.txt", change.scope), ("all_domains.txt", change.scope)] if category != "nsfw" else [("nsfw.txt", "exact"), ("nsfw_abp.txt", change.scope)]
        for name, scope in required:
            for domain in change.domains:
                if not any(entry_blocks(entry, domain) and (scope == "exact" or entry.subdomains) for entry in outputs[name]):
                    return f"requested block scope is not present in {name}"
    return ""


@dataclass
class PublicationResult:
    published: list[int] = field(default_factory=list)
    would_publish: list[int] = field(default_factory=list)
    pending: list[dict[str, Any]] = field(default_factory=list)


def pending_changes(github: GitHub) -> list[tuple[dict, PendingChange]]:
    pending: list[tuple[dict, PendingChange]] = []
    for issue in github.pending_issues():
        comments = github.comments(issue["number"])
        published = {change.pr for comment in comments if (change := parse_change(comment)) and change.issue == issue["number"] and change.status == "published"}
        seen: set[int] = set()
        for comment in comments:
            change = parse_change(comment)
            if not change or change.issue != issue["number"] or change.status != "pending" or change.pr in published or change.pr in seen:
                continue
            seen.add(change.pr)
            pending.append((comment, change))
            if len(pending) >= MAX_CHANGES:
                return pending
    return pending


def publish(github: GitHub, lists: Path, root: Path, dry_run: bool = False) -> PublicationResult:
    manifest = validate_manifest(lists, root)
    if github.main_sha() != manifest["published_sha"]:
        raise ValueError("production main moved since the verified publication commit")
    pending = pending_changes(github)
    result = PublicationResult()
    if not pending:
        return result
    outputs = output_entries(lists, {domain for _, change in pending for domain in change.domains})
    for comment, change in pending:
        reason = verify_change(change, root, manifest, outputs, github.pull_request(change.pr))
        if reason:
            result.pending.append({"issue": change.issue, "pr": change.pr, "reason": reason})
            continue
        change.status = "published"
        detail = " NSFW descendants are covered by nsfw_abp.txt; nsfw.txt is the host-format alternative." if change.path == "custom/nsfw.txt" and change.scope == "domain" else ""
        confirmation = f"Published lists now include the verified `/{change.action}` change merged in #{change.pr}.{detail}"
        body = MARKER_RE.sub(change.marker(), comment["body"]) + "\n\n" + confirmation
        if dry_run:
            result.would_publish.append(change.pr)
        else:
            github.edit_comment(comment["id"], body)
            result.published.append(change.pr)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.publication")
    parser.add_argument("--lists", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--record-manifest", action="store_true")
    mode.add_argument("--prepare-config", action="store_true")
    mode.add_argument("--record-publication", action="store_true")
    parser.add_argument("--config-sha")
    parser.add_argument("--published-sha")
    parser.add_argument("--effective-config", type=Path)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--feed-check", type=Path)
    options = parser.parse_args(argv)
    try:
        if options.prepare_config:
            if not options.config_sha or not options.effective_config or options.dry_run:
                parser.error("--prepare-config requires --config-sha and --effective-config, without --dry-run")
            prepare_config(options.repo_root, options.config_sha, options.effective_config)
            print(json.dumps({"status": "prepared"}))
        elif options.record_manifest:
            if not options.config_sha or not options.feed_check or not options.effective_config or not options.base or options.dry_run:
                parser.error("--record-manifest requires --config-sha, --feed-check, --effective-config and --base, without --dry-run")
            (options.lists / MANIFEST).unlink(missing_ok=True)
            record_manifest(options.lists, options.repo_root, options.config_sha, json.loads(options.feed_check.read_text()), options.effective_config, options.base)
            print(json.dumps({"status": "recorded"}))
        elif options.record_publication:
            if not options.published_sha or options.dry_run:
                parser.error("--record-publication requires --published-sha, without --dry-run")
            record_publication(options.lists, options.repo_root, options.published_sha)
            print(json.dumps({"status": "publication_recorded"}))
        else:
            result = publish(GitHub.from_env(), options.lists, options.repo_root, options.dry_run)
            print(json.dumps(asdict(result), sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"status": "pending", "stage": "publication verification", "error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
