"""Parser for a constrained subset of Sigma-style YAML rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any


SUPPORTED_LOGSOURCE_CATEGORY = "process_creation"


class ParsedRule:
    """Canonical representation of a parsed Sigma-like rule."""

    def __init__(
        self,
        *,
        id: str,
        title: str,
        logsource_category: str,
        detection: dict[str, Any],
        source_path: Path | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.id = id
        self.title = title
        self.logsource_category = logsource_category
        self.detection = detection
        self.source_path = source_path
        self.raw = raw or {}


class RuleParseError(ValueError):
    """Raised when a rule fails schema or compatibility checks."""


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
        return value[1:-1]
    return value


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none", "~"}:
        return None
    if value.isdigit():
        return int(value)
    return _strip_quotes(value)


def _parse_yaml_document(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise RuleParseError(f"invalid list item at line {line_no}")
            parent.append(_parse_scalar(line[2:]))
            continue

        if ":" not in line:
            raise RuleParseError(f"invalid YAML line {line_no}: {line}")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value:
            value = _parse_scalar(raw_value)
            if not isinstance(parent, dict):
                raise RuleParseError(f"cannot assign key under list at line {line_no}")
            parent[key] = value
            continue

        next_container: Any
        # Look ahead for immediate list pattern under this key.
        next_container = {}
        if not isinstance(parent, dict):
            raise RuleParseError(f"cannot nest mapping under list at line {line_no}")
        parent[key] = next_container

        stack.append((indent, next_container))

        # If subsequent line is list item, convert container to list lazily.
        # Conversion happens when encountering first '- ' line.
        def maybe_convert_container() -> None:
            current = stack[-1][1]
            if isinstance(current, dict) and current == {}:
                parent[key] = []
                stack[-1] = (stack[-1][0], parent[key])

        # Peek conversion trigger by scanning forward current line's immediate next non-empty raw line.
        # Done in a lightweight way by using the raw text itself.
        remaining = text.splitlines()[line_no:]
        for candidate in remaining:
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            cand_indent = len(candidate) - len(candidate.lstrip(" "))
            if cand_indent <= indent:
                break
            if candidate.strip().startswith("- "):
                maybe_convert_container()
            break

    return root


def _split_documents(text: str) -> list[str]:
    docs: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.strip() == "---":
            docs.append([])
        else:
            docs[-1].append(line)
    return ["\n".join(lines).strip() for lines in docs if "\n".join(lines).strip()]


def _ensure_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuleParseError(f"{context} must be a mapping")
    return value


def parse_rule_data(data: dict[str, Any], source_path: Path | None = None) -> ParsedRule:
    """Parse and validate one Sigma-style rule document."""

    rule = _ensure_mapping(data, "rule")
    rule_id = str(rule.get("id") or "").strip()
    title = str(rule.get("title") or "").strip()
    if not rule_id:
        raise RuleParseError("rule.id is required")
    if not title:
        raise RuleParseError("rule.title is required")

    logsource = _ensure_mapping(rule.get("logsource"), "rule.logsource")
    category = str(logsource.get("category") or "").strip()
    if category != SUPPORTED_LOGSOURCE_CATEGORY:
        raise RuleParseError(
            "unsupported logsource.category "
            f"'{category}', expected '{SUPPORTED_LOGSOURCE_CATEGORY}'"
        )

    detection = _ensure_mapping(rule.get("detection"), "rule.detection")
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise RuleParseError("rule.detection.condition must be a non-empty string")

    return ParsedRule(
        id=rule_id,
        title=title,
        logsource_category=category,
        detection=detection,
        source_path=source_path,
        raw=rule,
    )


def load_rule_file(path: str | Path) -> list[ParsedRule]:
    """Load one YAML file that may contain one or many documents."""

    rule_path = Path(path)
    text = rule_path.read_text(encoding="utf-8")
    docs = [_parse_yaml_document(block) for block in _split_documents(text)]

    parsed: list[ParsedRule] = []
    for idx, doc in enumerate(docs, start=1):
        try:
            parsed.append(parse_rule_data(doc, source_path=rule_path))
        except RuleParseError as exc:
            raise RuleParseError(f"{rule_path} (document {idx}): {exc}") from exc
    return parsed


def load_rules(paths: list[str | Path]) -> list[ParsedRule]:
    """Load rule files from file paths or directories recursively."""

    discovered: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            discovered.extend(sorted(path.rglob("*.yml")))
            discovered.extend(sorted(path.rglob("*.yaml")))
        elif path.is_file():
            discovered.append(path)
        else:
            raise RuleParseError(f"rule path does not exist: {path}")

    if not discovered:
        raise RuleParseError("no rule files found")

    parsed: list[ParsedRule] = []
    for path in discovered:
        parsed.extend(load_rule_file(path))
    return parsed
