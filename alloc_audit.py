#!/usr/bin/env python3
"""agentic-dotnet-alloc-audit — static managed-allocation auditor for .NET / IL2CPP / Mono assemblies.

Disassembles assemblies with ilspycmd and scans the IL for managed-allocation patterns,
attributing each hit to its containing method and (optionally) flagging hits inside
caller-supplied "hot path" methods.

Detectors:
  delegate      newobj of a delegate (`.ctor(object, native int)`), classified cached vs uncached
  box           `box` opcode (value type boxed to object)
  newarr        array allocation
  collection    newobj of a generic collection (List/Dictionary/HashSet/Queue/Stack/...)
  linq          call into System.Linq.Enumerable
  stringalloc   String::Concat/Format/Join or StringBuilder::.ctor

!!! THIS IS A CANDIDATE FINDER, NOT A GC ORACLE !!!
  * It finds allocation SITES, not hotness. A site in a one-time method (Awake, .cctor,
    event subscription) is usually harmless. Use --hot-path to pre-filter to methods that
    actually run per frame, and still verify with a profiler.
  * It is BLIND to allocations internal to the BCL / engine. e.g. the parameterless
    Array.Sort(T[]) overload can allocate inside Mono with NO `newobj` in your IL; only a
    profiler catches those.
Treat its output as a shortlist to confirm in the Unity profiler (deep profile + allocation
callstacks), never as proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent

# --- IL patterns ------------------------------------------------------------------------

END_OF_METHOD = re.compile(r"\}\s*//\s*end of method (.+?)\s*$")
LDFTN = re.compile(r"ldftn\s+(.+?)\s*$")

# Each detector: name -> compiled regex matched against a single IL line.
DETECTORS: dict[str, re.Pattern] = {
    "delegate": re.compile(r"\bnewobj instance void .*::\.ctor\(object, native int\)"),
    "box": re.compile(r"\bIL_[0-9a-fA-F]+:\s*box\b"),
    "newarr": re.compile(r"\bIL_[0-9a-fA-F]+:\s*newarr\b"),
    "collection": re.compile(
        r"\bnewobj instance void .*"
        r"(List`1|Dictionary`2|HashSet`1|Queue`1|Stack`1|SortedList`2|"
        r"SortedDictionary`2|LinkedList`1|ConcurrentDictionary`2)<.*>::\.ctor"
    ),
    "linq": re.compile(r"\b(call|callvirt)\b.*System\.Linq\.Enumerable::"),
    "stringalloc": re.compile(
        r"\b(call|callvirt)\b.*"
        r"(System\.String::(Concat|Format|Join)|System\.Text\.StringBuilder::\.ctor)"
    ),
}

# A delegate newobj is a compiler-cached lambda / method-group conversion when the next few
# lines stash it into a `<>9__` cache field. Anything else (incl. field initialisers) is
# reported as uncached; the hot-path filter is what separates per-frame from one-time.
CACHE_STORE = re.compile(r"\bstsfld\b.*<>9")
CACHE_LOOKAHEAD = 5


@dataclass
class Hit:
    assembly: str
    detector: str
    line_no: int
    method: str
    snippet: str
    hot: bool = False
    cached: bool | None = None  # delegate only
    source: str = ""            # delegate only: ldftn target (the method being wrapped)


# --- ilspycmd bootstrap -----------------------------------------------------------------

def resolve_ilspycmd(explicit: str | None) -> str:
    """Find ilspycmd: explicit path, then local .tools/, then PATH, else install into .tools/."""
    if explicit:
        return explicit

    names = ["ilspycmd.exe", "ilspycmd"] if os.name == "nt" else ["ilspycmd"]
    local_dir = TOOL_DIR / ".tools"
    for n in names:
        cand = local_dir / n
        if cand.exists():
            return str(cand)

    on_path = shutil.which("ilspycmd")
    if on_path:
        return on_path

    print(f"[bootstrap] installing ilspycmd into {local_dir} ...", file=sys.stderr)
    subprocess.run(
        ["dotnet", "tool", "install", "ilspycmd", "--tool-path", str(local_dir)],
        check=True,
    )
    for n in names:
        cand = local_dir / n
        if cand.exists():
            return str(cand)
    raise RuntimeError("ilspycmd install succeeded but the executable was not found")


def dump_il(ilspycmd: str, assembly: str) -> list[str]:
    res = subprocess.run([ilspycmd, assembly, "-il"], capture_output=True, text=True,
                         errors="replace")
    if res.returncode != 0:
        raise RuntimeError(f"ilspycmd failed on {assembly}:\n{res.stderr.strip()}")
    return res.stdout.splitlines()


# --- scanning ---------------------------------------------------------------------------

def scan_assembly(assembly: str, lines: list[str], detectors: list[str],
                  hot_patterns: list[re.Pattern]) -> list[Hit]:
    """Single pass: attribute each detector match to the method whose end-marker follows it."""
    def is_hot(method: str) -> bool:
        return any(p.search(method) for p in hot_patterns)

    active = [(name, DETECTORS[name]) for name in detectors]
    pending: list[Hit] = []
    results: list[Hit] = []
    asm = Path(assembly).name

    for i, line in enumerate(lines):
        for name, rx in active:
            if not rx.search(line):
                continue
            hit = Hit(assembly=asm, detector=name, line_no=i + 1, method="<unknown>",
                      snippet=line.strip())
            if name == "delegate":
                window = "\n".join(lines[i + 1: i + 1 + CACHE_LOOKAHEAD])
                hit.cached = bool(CACHE_STORE.search(window))
                for k in range(i - 1, max(-1, i - 3), -1):
                    m = LDFTN.search(lines[k])
                    if m:
                        hit.source = m.group(1)
                        break
            pending.append(hit)

        m = END_OF_METHOD.search(line)
        if m and pending:
            method = m.group(1)
            hot = is_hot(method)
            for h in pending:
                h.method = method
                h.hot = hot
            results.extend(pending)
            pending = []

    return results


# --- reporting --------------------------------------------------------------------------

def is_actionable(h: Hit) -> bool:
    """A hit worth surfacing: a hot site, or an uncached delegate (hot or not)."""
    if h.hot:
        return h.detector != "delegate" or h.cached is False
    return False


def text_report(hits: list[Hit], hot_only: bool) -> str:
    out: list[str] = []
    by_detector: dict[str, list[Hit]] = {}
    for h in hits:
        by_detector.setdefault(h.detector, []).append(h)

    out.append("=" * 78)
    out.append("agentic-dotnet-alloc-audit - candidate sites (verify hotness in the profiler!)")
    out.append("=" * 78)

    for det in DETECTORS:
        dh = by_detector.get(det, [])
        if not dh:
            continue
        hot = [h for h in dh if h.hot]
        out.append("")
        if det == "delegate":
            unc = [h for h in dh if h.cached is False]
            unc_hot = [h for h in unc if h.hot]
            out.append(f"## {det}: {len(dh)} sites | {len(unc)} uncached | "
                       f"{len(unc_hot)} UNCACHED in hot paths")
            listing = unc_hot if hot_only else unc
            for h in sorted(listing, key=lambda x: (not x.hot, x.method)):
                flag = "HOT " if h.hot else "    "
                out.append(f"  {flag}{h.assembly}  {h.method}")
                if h.source:
                    out.append(f"        -> {h.source}")
        else:
            out.append(f"## {det}: {len(dh)} sites | {len(hot)} in hot paths")
            listing = hot if hot_only else dh
            shown: dict[str, int] = {}
            for h in listing:
                shown[h.method] = shown.get(h.method, 0) + 1
            for method, n in sorted(shown.items(), key=lambda kv: (-kv[1], kv[0])):
                flag = "HOT " if is_hot_method(method, hits) else "    "
                out.append(f"  {flag}{method}  x{n}")

    out.append("")
    out.append("-" * 78)
    out.append("Reminder: this finds SITES, not hotness, and is blind to BCL-internal allocs")
    out.append("(e.g. Array.Sort(T[]) boxing). Confirm every finding in the Unity profiler.")
    return "\n".join(out)


def is_hot_method(method: str, hits: list[Hit]) -> bool:
    for h in hits:
        if h.method == method:
            return h.hot
    return False


def json_report(hits: list[Hit]) -> str:
    return json.dumps(
        [
            {
                "assembly": h.assembly, "detector": h.detector, "method": h.method,
                "line": h.line_no, "hot": h.hot, "cached": h.cached,
                "source": h.source, "snippet": h.snippet,
            }
            for h in hits
        ],
        indent=2,
    )


# --- CLI --------------------------------------------------------------------------------

def gather_assemblies(args) -> list[str]:
    found: list[str] = list(args.assembly or [])
    if args.assembly_dir:
        d = Path(args.assembly_dir)
        for pat in (args.pattern or ["*.dll"]):
            found.extend(str(p) for p in sorted(d.glob(pat)))
    return found


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser(description="Static managed-allocation auditor for .NET assemblies.")
    ap.add_argument("--assembly", action="append", help="Assembly .dll path (repeatable).")
    ap.add_argument("--assembly-dir", help="Directory to scan with --pattern.")
    ap.add_argument("--pattern", action="append", help="Glob within --assembly-dir (repeatable; default *.dll).")
    ap.add_argument("--detectors", default="delegate",
                    help="Comma list or 'all'. Choices: " + ",".join(DETECTORS))
    ap.add_argument("--hot-path", action="append", default=[],
                    help="Regex; methods matching are flagged hot (repeatable).")
    ap.add_argument("--hot-only", action="store_true", help="Report only hits in hot-path methods.")
    ap.add_argument("--config", help="JSON config supplying assemblies/detectors/hot_path (CLI overrides).")
    ap.add_argument("--ilspycmd", help="Path to ilspycmd (else auto-detect/bootstrap).")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config else {}

    assemblies = gather_assemblies(args) or cfg.get("assemblies", [])
    if not assemblies:
        ap.error("no assemblies (use --assembly/--assembly-dir or a --config with 'assemblies').")

    det_arg = args.detectors if args.detectors != "delegate" or "detectors" not in cfg \
        else ",".join(cfg["detectors"])
    detectors = list(DETECTORS) if det_arg == "all" else [d.strip() for d in det_arg.split(",")]
    for d in detectors:
        if d not in DETECTORS:
            ap.error(f"unknown detector '{d}'. Choices: {','.join(DETECTORS)},all")

    hot_raw = args.hot_path or cfg.get("hot_path", [])
    hot_patterns = [re.compile(p) for p in hot_raw]

    ilspycmd = resolve_ilspycmd(args.ilspycmd or cfg.get("ilspycmd"))

    all_hits: list[Hit] = []
    for asm in assemblies:
        if not Path(asm).exists():
            print(f"[warn] missing assembly, skipped: {asm}", file=sys.stderr)
            continue
        print(f"[scan] {asm}", file=sys.stderr)
        all_hits.extend(scan_assembly(asm, dump_il(ilspycmd, asm), detectors, hot_patterns))

    if args.format == "json":
        print(json_report([h for h in all_hits if not args.hot_only or h.hot]))
    else:
        print(text_report(all_hits, args.hot_only))
    return 0


if __name__ == "__main__":
    sys.exit(main())
