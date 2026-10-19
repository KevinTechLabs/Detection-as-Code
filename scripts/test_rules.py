#!/usr/bin/env python3
"""
Detection unit tests for Sigma rules.

For every rule in rules/, this script:
  1. Lints required metadata (id, title, level, ATT&CK tag, logsource, condition).
  2. Requires a matching tests/<rule_name>/ folder with positive.jsonl and negative.jsonl.
  3. Evaluates the rule's detection logic against each event:
       - every positive event MUST match (proves the rule catches the attack)
       - every negative event MUST NOT match (proves it doesn't fire on look-alikes)

It implements the common subset of the Sigma spec used in this repo:
  modifiers: contains, startswith, endswith, all, re, (plain values support * and ? wildcards)
  conditions: and / or / not / parentheses / "1 of x*" / "all of x*" / "1 of them" / "all of them"
Matching is case-insensitive, as in the Sigma spec (except |re).

Exit code is non-zero on any failure, so CI blocks the merge.
"""
import json
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
TESTS_DIR = ROOT / "tests"
REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date",
                   "tags", "logsource", "detection", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}


# ---------- value matching ----------

def wildcard_to_regex(value: str) -> str:
    out = []
    for ch in value:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def match_value(event_value, pattern, modifiers) -> bool:
    if pattern is None:
        return event_value is None
    if event_value is None:
        return False
    ev, pat = str(event_value), str(pattern)
    if "re" in modifiers:
        return re.search(pat, ev) is not None
    body = wildcard_to_regex(pat)
    if "contains" in modifiers:
        rx = f".*{body}.*"
    elif "startswith" in modifiers:
        rx = f"{body}.*"
    elif "endswith" in modifiers:
        rx = f".*{body}"
    else:
        rx = body
    return re.fullmatch(rx, ev, re.IGNORECASE | re.DOTALL) is not None


def match_field(event: dict, key: str, patterns) -> bool:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - {"contains", "startswith", "endswith", "all", "re"}
    if unknown:
        raise ValueError(f"unsupported modifier(s) {unknown} on '{key}'")
    values = patterns if isinstance(patterns, list) else [patterns]
    combine = all if "all" in modifiers else any
    return combine(match_value(event.get(field), v, modifiers) for v in values)


def match_selection(event: dict, selection) -> bool:
    if isinstance(selection, dict):                 # fields are ANDed
        return all(match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):   # list of maps is ORed
            return any(match_selection(event, s) for s in selection)
        blob = " ".join(str(v) for v in event.values())  # keyword list
        return any(match_value(blob, kw, ["contains"]) for kw in selection)
    raise ValueError(f"unsupported selection type: {type(selection)}")


# ---------- condition parsing ----------

TOKEN_RX = re.compile(r"\(|\)|(?:1|all|any)\s+of\s+[\w*]+|[\w*]+")


class Condition:
    def __init__(self, text: str, selections: dict):
        self.tokens = TOKEN_RX.findall(text)
        self.sel = selections
        self.pos = 0

    def evaluate(self, event: dict) -> bool:
        self.pos, self.event = 0, event
        result = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f"unparsed tokens in condition: {self.tokens[self.pos:]}")
        return result

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self._peek()
        self.pos += 1
        return tok

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()
            left = left or right
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            left = left and right
        return left

    def _not(self):
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self):
        tok = self._take()
        if tok == "(":
            val = self._or()
            if self._take() != ")":
                raise ValueError("missing closing parenthesis")
            return val
        m = re.fullmatch(r"(1|all|any)\s+of\s+([\w*]+)", tok or "")
        if m:
            quant, target = m.groups()
            names = list(self.sel) if target == "them" else \
                [n for n in self.sel if re.fullmatch(wildcard_to_regex(target), n)]
            if not names:
                raise ValueError(f"'{tok}' matches no selections")
            results = [match_selection(self.event, self.sel[n]) for n in names]
            return all(results) if quant == "all" else any(results)
        if tok not in self.sel:
            raise ValueError(f"condition references unknown selection '{tok}'")
        return match_selection(self.event, self.sel[tok])


def rule_matches(rule: dict, event: dict) -> bool:
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    if isinstance(condition, list):
        return any(Condition(c, detection).evaluate(event) for c in condition)
    return Condition(condition, detection).evaluate(event)


# ---------- lint + test ----------

def lint(rule: dict, path: Path, seen_ids: set) -> list:
    errs = [f"missing field '{f}'" for f in REQUIRED_FIELDS if f not in rule]
    rid = str(rule.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        errs.append(f"id '{rid}' is not a UUID")
    if rid in seen_ids:
        errs.append(f"duplicate id {rid}")
    seen_ids.add(rid)
    if rule.get("level") not in LEVELS:
        errs.append(f"invalid level '{rule.get('level')}'")
    if not any(str(t).startswith("attack.t") for t in rule.get("tags", [])):
        errs.append("no MITRE ATT&CK technique tag (attack.tXXXX)")
    if "condition" not in rule.get("detection", {}):
        errs.append("detection has no condition")
    return errs


def load_events(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    rule_files = sorted(RULES_DIR.rglob("*.yml"))
    if not rule_files:
        print("no rules found")
        return 1

    seen_ids, failures, passed = set(), 0, 0
    for path in rule_files:
        rule = yaml.safe_load(path.read_text())
        name = path.stem
        problems = lint(rule, path, seen_ids)

        tdir = TESTS_DIR / name
        positives = load_events(tdir / "positive.jsonl")
        negatives = load_events(tdir / "negative.jsonl")
        if not positives:
            problems.append(f"no positive samples in tests/{name}/positive.jsonl")
        if not negatives:
            problems.append(f"no negative samples in tests/{name}/negative.jsonl")

        try:
            for i, ev in enumerate(positives, 1):
                if not rule_matches(rule, ev):
                    problems.append(f"positive #{i} did NOT fire: {ev.get('_note', ev)}")
            for i, ev in enumerate(negatives, 1):
                if rule_matches(rule, ev):
                    problems.append(f"negative #{i} FIRED (false positive): {ev.get('_note', ev)}")
        except ValueError as e:
            problems.append(f"rule logic error: {e}")

        rel = path.relative_to(ROOT)
        if problems:
            failures += 1
            print(f"FAIL  {rel}")
            for p in problems:
                print(f"      - {p}")
        else:
            passed += 1
            print(f"PASS  {rel}  ({len(positives)} pos / {len(negatives)} neg)")

    print(f"\n{passed} passed, {failures} failed, {len(rule_files)} rules")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
