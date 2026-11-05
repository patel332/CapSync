#!/usr/bin/env python3
"""
Rename sensitive documents using filenames only.

This script never opens or reads a document. It only enumerates directory
entries, parses their names, and (when explicitly requested) renames them.
Preview mode is the default.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable, Sequence


SUPPORTED_EXTENSIONS = frozenset(
    {".pdf", ".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic"}
)

MONTHS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}
MONTH_PATTERN = "|".join(sorted(MONTHS, key=len, reverse=True))

# Specific document types must appear before broad ones such as Certificate.
DOCUMENT_TYPE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("Permanent-Resident-Card", r"\b(?:permanent[\s._-]*resident[\s._-]*card|green[\s._-]*card)\b"),
    ("Employment-Authorization", r"\b(?:employment[\s._-]*authorization(?:[\s._-]*(?:document|card))?|ead[\s._-]*card)\b"),
    ("Naturalization-Certificate", r"\b(?:certificate[\s._-]*of[\s._-]*naturalization|naturalization[\s._-]*certificate)\b"),
    ("Citizenship-Certificate", r"\b(?:certificate[\s._-]*of[\s._-]*citizenship|citizenship[\s._-]*certificate)\b"),
    ("Birth-Certificate", r"\b(?:birth[\s._-]*certificate|certificate[\s._-]*of[\s._-]*birth)\b"),
    ("Marriage-Certificate", r"\b(?:marriage[\s._-]*(?:certificate|license)|certificate[\s._-]*of[\s._-]*marriage)\b"),
    ("Death-Certificate", r"\b(?:death[\s._-]*certificate|certificate[\s._-]*of[\s._-]*death)\b"),
    ("Drivers-License", r"\b(?:driver'?s?|driving)[\s._-]*(?:license|licence)\b"),
    ("Professional-License", r"\bprofessional[\s._-]*(?:license|licence)\b"),
    ("Medical-License", r"\bmedical[\s._-]*(?:license|licence)\b"),
    ("Nursing-License", r"\b(?:nursing|nurse)[\s._-]*(?:license|licence)\b"),
    ("Teaching-Certificate", r"\b(?:teaching|teacher)[\s._-]*(?:certificate|certification|license|licence)\b"),
    ("Passport-Card", r"\bpassport[\s._-]*card\b"),
    ("Social-Security-Card", r"\b(?:social[\s._-]*security[\s._-]*card|ssn[\s._-]*card)\b"),
    ("National-ID", r"\bnational[\s._-]*(?:id|identity)[\s._-]*(?:card)?\b"),
    ("State-ID", r"\bstate[\s._-]*(?:id|identity)[\s._-]*(?:card)?\b"),
    ("Work-Permit", r"\bwork[\s._-]*permit\b"),
    ("CPR-Certification", r"\bcpr[\s._-]*(?:certificate|certification|card)\b"),
    ("First-Aid-Certification", r"\bfirst[\s._-]*aid[\s._-]*(?:certificate|certification|card)\b"),
    ("Passport", r"\bpassport\b"),
    ("Visa", r"\bvisa\b"),
    ("Diploma", r"\bdiploma\b"),
    ("Transcript", r"\b(?:academic[\s._-]*)?transcript\b"),
    ("Certification", r"\bcertification\b"),
    ("Certificate", r"\bcertificate\b"),
)

ISSUER_ALIASES = {
    "american heart association": "American-Heart-Association",
    "american red cross": "American-Red-Cross",
    "department of state": "US-Department-of-State",
    "social security administration": "Social-Security-Administration",
    "u s citizenship and immigration services": "USCIS",
    "u s department of state": "US-Department-of-State",
    "uscis": "USCIS",
    "us department of state": "US-Department-of-State",
    "usdos": "US-Department-of-State",
}

NOISE_WORDS = re.compile(
    r"\b(?:copy|doc|document|expires?|expiration|front|image|issue|issued|"
    r"issuer|original|photo|renewal|renewed|scan|scanned|valid)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DateHit:
    start: int
    end: int
    value: date


@dataclass(frozen=True)
class RenamePlan:
    source: Path
    target: Path


def valid_date(year: int, month: int, day: int) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:
        return None


def extract_date(
    stem: str, date_order: str
) -> tuple[str | None, tuple[tuple[int, int], ...], str | None]:
    hits: list[DateHit] = []
    ambiguous_numeric_dates: list[str] = []

    def add_hit(match: re.Match[str], year: int, month: int, day: int) -> None:
        parsed = valid_date(year, month, day)
        if parsed is not None:
            hits.append(DateHit(match.start(), match.end(), parsed))

    for match in re.finditer(
        r"(?<!\d)(?P<y>(?:19|20)\d{2})[-_. ](?P<m>\d{1,2})[-_. ](?P<d>\d{1,2})(?!\d)",
        stem,
    ):
        add_hit(match, int(match["y"]), int(match["m"]), int(match["d"]))

    for match in re.finditer(
        r"(?<!\d)(?P<y>(?:19|20)\d{2})(?P<m>\d{2})(?P<d>\d{2})(?!\d)",
        stem,
    ):
        add_hit(match, int(match["y"]), int(match["m"]), int(match["d"]))

    for match in re.finditer(
        rf"(?<![A-Za-z])(?P<month>{MONTH_PATTERN})[\s._-]+"
        r"(?P<day>\d{1,2})(?:st|nd|rd|th)?(?:,)?[\s._-]+"
        r"(?P<year>(?:19|20)\d{2})(?!\d)",
        stem,
        re.IGNORECASE,
    ):
        add_hit(
            match,
            int(match["year"]),
            MONTHS[match["month"].lower()],
            int(match["day"]),
        )

    for match in re.finditer(
        rf"(?<!\d)(?P<day>\d{{1,2}})(?:st|nd|rd|th)?[\s._-]+"
        rf"(?P<month>{MONTH_PATTERN})(?:,)?[\s._-]+"
        r"(?P<year>(?:19|20)\d{2})(?!\d)",
        stem,
        re.IGNORECASE,
    ):
        add_hit(
            match,
            int(match["year"]),
            MONTHS[match["month"].lower()],
            int(match["day"]),
        )

    for match in re.finditer(
        r"(?<!\d)(?P<a>\d{1,2})[-_. ](?P<b>\d{1,2})[-_. ]"
        r"(?P<y>(?:19|20)\d{2})(?!\d)",
        stem,
    ):
        first, second, year = int(match["a"]), int(match["b"]), int(match["y"])
        if first > 12 >= second:
            month, day = second, first
        elif second > 12 >= first:
            month, day = first, second
        elif first <= 12 and second <= 12:
            if first == second or date_order == "month-first":
                month, day = first, second
            elif date_order == "day-first":
                month, day = second, first
            else:
                ambiguous_numeric_dates.append(match.group(0))
                continue
        else:
            continue
        add_hit(match, year, month, day)

    if ambiguous_numeric_dates:
        examples = ", ".join(repr(item) for item in ambiguous_numeric_dates)
        return None, (), f"ambiguous numeric date(s): {examples}"

    unique_hits = {
        (hit.start, hit.end, hit.value): hit
        for hit in hits
    }.values()
    dates = sorted({hit.value for hit in unique_hits})
    if not dates:
        return None, (), "no supported valid date found"
    if len(dates) > 1:
        values = ", ".join(item.isoformat() for item in dates)
        return None, (), f"multiple different dates found: {values}"

    selected = dates[0]
    spans = tuple(
        sorted(
            (hit.start, hit.end)
            for hit in unique_hits
            if hit.value == selected
        )
    )
    return selected.isoformat(), spans, None


def blank_spans(value: str, spans: Iterable[tuple[int, int]]) -> str:
    characters = list(value)
    for start, end in spans:
        characters[start:end] = " " * (end - start)
    return "".join(characters)


def extract_document_type(value: str) -> tuple[str | None, tuple[int, int] | None]:
    for canonical_name, pattern in DOCUMENT_TYPE_PATTERNS:
        match = re.search(pattern, value, re.IGNORECASE)
        if match:
            return canonical_name, (match.start(), match.end())
    return None, None


def ascii_words(value: str) -> list[str]:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return re.findall(r"[A-Za-z0-9]+", ascii_value)


def format_words(words: Sequence[str]) -> str:
    formatted: list[str] = []
    for word in words:
        if word.isupper() and len(word) <= 10:
            formatted.append(word)
        elif any(character.isupper() for character in word[1:]):
            formatted.append(word)
        else:
            formatted.append(word[:1].upper() + word[1:].lower())
    return "-".join(formatted)


def extract_issuer(value: str) -> str | None:
    cleaned = NOISE_WORDS.sub(" ", value)
    cleaned = re.sub(r"\b(?:by|from)\b", " ", cleaned, flags=re.IGNORECASE)
    words = ascii_words(cleaned)
    if not words:
        return None

    alias_key = " ".join(words).lower()
    if alias_key in ISSUER_ALIASES:
        return ISSUER_ALIASES[alias_key]
    return format_words(words)


def is_already_compliant(path: Path) -> bool:
    match = re.fullmatch(
        r"(?P<date>\d{4}-\d{2}-\d{2})_"
        r"(?P<type>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)_"
        r"(?P<issuer>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)"
        r"(?P<extension>\.[A-Za-z0-9]+)",
        path.name,
    )
    if not match or match["extension"].lower() not in SUPPORTED_EXTENSIONS:
        return False
    try:
        date.fromisoformat(match["date"])
    except ValueError:
        return False
    return True


def candidates(directory: Path, recursive: bool) -> list[Path]:
    entries = directory.rglob("*") if recursive else directory.iterdir()
    return sorted(
        (
            path
            for path in entries
            if path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() in SUPPORTED_EXTENSIONS
        ),
        key=lambda path: str(path.relative_to(directory)).casefold(),
    )


def make_plan(
    source: Path, date_order: str
) -> tuple[RenamePlan | None, str | None]:
    if is_already_compliant(source):
        return None, "already follows the requested format"

    extracted_date, date_spans, date_error = extract_date(source.stem, date_order)
    if date_error:
        return None, date_error

    without_date = blank_spans(source.stem, date_spans)
    document_type, type_span = extract_document_type(without_date)
    if document_type is None or type_span is None:
        return None, "document type was not recognized"

    without_type = blank_spans(without_date, (type_span,))
    issuer = extract_issuer(without_type)
    if issuer is None:
        return None, "issuer was not found"

    target_name = (
        f"{extracted_date}_{document_type}_{issuer}{source.suffix.lower()}"
    )
    target = source.with_name(target_name)
    if target.name == source.name:
        return None, "already follows the requested format"
    return RenamePlan(source=source, target=target), None


def find_collisions(plans: Sequence[RenamePlan]) -> dict[Path, str]:
    errors: dict[Path, str] = {}
    by_target: dict[str, list[RenamePlan]] = {}
    for plan in plans:
        key = str(plan.target).casefold()
        by_target.setdefault(key, []).append(plan)

    for same_target in by_target.values():
        if len(same_target) > 1:
            for plan in same_target:
                errors[plan.source] = "multiple files would receive the same name"

    for plan in plans:
        # Case-folded comparison also protects filesystems that ignore case.
        for existing in plan.target.parent.iterdir():
            if (
                existing != plan.source
                and existing.name.casefold() == plan.target.name.casefold()
            ):
                errors[plan.source] = f"target already exists: {existing.name}"
                break
    return errors


def relative_name(path: Path, directory: Path) -> str:
    return str(path.relative_to(directory))


def apply_plans(plans: Sequence[RenamePlan]) -> None:
    # Recheck every path immediately before making any change.
    for plan in plans:
        if not plan.source.exists():
            raise RuntimeError(f"source disappeared: {plan.source}")
        if plan.target.exists():
            raise RuntimeError(f"target now exists: {plan.target}")

    completed: list[RenamePlan] = []
    try:
        for plan in plans:
            plan.source.rename(plan.target)
            completed.append(plan)
    except Exception:
        # Best-effort rollback if a rename fails partway through.
        for plan in reversed(completed):
            if plan.target.exists() and not plan.source.exists():
                plan.target.rename(plan.source)
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preview or apply filename-only document renames. "
            "Document contents are never opened."
        )
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        type=Path,
        help="folder containing the documents (default: current folder)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="also inspect document filenames in subfolders",
    )
    parser.add_argument(
        "--date-order",
        choices=("reject-ambiguous", "month-first", "day-first"),
        default="reject-ambiguous",
        help=(
            "interpret dates such as 04-05-2024; the default safely skips them"
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="rename after showing the plan and receiving typed confirmation",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    directory = args.directory.expanduser().resolve()
    if not directory.is_dir():
        print(f"Error: not a directory: {directory}", file=sys.stderr)
        return 2

    files = candidates(directory, args.recursive)
    plans: list[RenamePlan] = []
    skipped: list[tuple[Path, str]] = []
    for source in files:
        plan, reason = make_plan(source, args.date_order)
        if plan is not None:
            plans.append(plan)
        else:
            skipped.append((source, reason or "unknown reason"))

    collisions = find_collisions(plans)
    safe_plans = [plan for plan in plans if plan.source not in collisions]
    skipped.extend(collisions.items())

    print("Planned renames (filename analysis only):")
    if safe_plans:
        for plan in safe_plans:
            print(
                f"  {relative_name(plan.source, directory)}"
                f"  ->  {relative_name(plan.target, directory)}"
            )
    else:
        print("  None")

    print("\nSkipped:")
    if skipped:
        for source, reason in sorted(
            skipped,
            key=lambda item: relative_name(item[0], directory).casefold(),
        ):
            print(f"  {relative_name(source, directory)}: {reason}")
    else:
        print("  None")

    print(
        f"\nSummary: {len(files)} supported file(s), "
        f"{len(safe_plans)} planned, {len(skipped)} skipped."
    )

    if not args.apply:
        print("Dry run only. No files were renamed.")
        return 0
    if not safe_plans:
        print("Nothing to rename.")
        return 0

    confirmation = input(
        f'Type RENAME to apply exactly {len(safe_plans)} rename(s): '
    )
    if confirmation != "RENAME":
        print("Cancelled. No files were renamed.")
        return 1

    try:
        apply_plans(safe_plans)
    except Exception as error:
        print(f"Rename failed: {error}", file=sys.stderr)
        return 1

    print(f"Renamed {len(safe_plans)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
