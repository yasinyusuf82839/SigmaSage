"""Compiler from parsed rules into executable predicates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from sigmasage.rules.parser import ParsedRule


EventPredicate = Callable[[dict[str, Any]], bool]


@dataclass(slots=True)
class CompiledRule:
    """Executable rule built from a parsed Sigma-style rule."""

    id: str
    title: str
    logsource_category: str
    predicate: EventPredicate
    source_path: str | None = None


class RuleCompileError(ValueError):
    """Raised when parsed content cannot be compiled into a predicate."""


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _compile_selector(selector: dict[str, Any]) -> EventPredicate:
    field_checks: list[EventPredicate] = []
    for raw_key, expected in selector.items():
        field_name, modifier = str(raw_key), "equals"
        if "|" in field_name:
            field_name, modifier = field_name.split("|", 1)

        field_name = field_name.strip()
        modifier = modifier.strip().lower()
        if not field_name:
            raise RuleCompileError("selector field name cannot be empty")

        expected_text = _as_text(expected)

        if modifier == "equals":
            field_checks.append(
                lambda event, name=field_name, exp=expected_text: _as_text(event.get(name)) == exp
            )
        elif modifier == "contains":
            field_checks.append(
                lambda event, name=field_name, exp=expected_text: exp in _as_text(event.get(name))
            )
        else:
            raise RuleCompileError(f"unsupported field modifier: {modifier}")

    return lambda event: all(check(event) for check in field_checks)


def _compile_keywords(values: list[Any]) -> EventPredicate:
    keywords = [_as_text(item) for item in values if _as_text(item)]
    if not keywords:
        raise RuleCompileError("keyword list cannot be empty")

    def predicate(event: dict[str, Any]) -> bool:
        flattened = " ".join(_as_text(v) for v in event.values())
        return any(keyword in flattened for keyword in keywords)

    return predicate


def _compile_term(name: str, detection: dict[str, Any]) -> EventPredicate:
    fragment = detection.get(name)
    if isinstance(fragment, dict):
        return _compile_selector(fragment)
    if isinstance(fragment, list):
        return _compile_keywords(fragment)
    raise RuleCompileError(f"condition references '{name}' but no supported fragment exists")


def _compile_condition(condition: str, detection: dict[str, Any]) -> EventPredicate:
    tokens = condition.split()
    if not tokens:
        raise RuleCompileError("empty condition")

    if len(tokens) == 1:
        return _compile_term(tokens[0], detection)

    if len(tokens) == 3 and tokens[1].lower() in {"and", "or"}:
        left = _compile_term(tokens[0], detection)
        right = _compile_term(tokens[2], detection)
        op = tokens[1].lower()
        if op == "and":
            return lambda event: left(event) and right(event)
        return lambda event: left(event) or right(event)

    raise RuleCompileError(
        "unsupported condition syntax; supported: '<name>', '<name> and <name>', '<name> or <name>'"
    )


def compile_rule(rule: ParsedRule) -> CompiledRule:
    """Compile one parsed rule into an executable predicate."""

    detection = rule.detection
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        raise RuleCompileError("detection.condition is empty")

    predicate = _compile_condition(condition, detection)
    return CompiledRule(
        id=rule.id,
        title=rule.title,
        logsource_category=rule.logsource_category,
        predicate=predicate,
        source_path=str(rule.source_path) if rule.source_path else None,
    )


def compile_rules(rules: list[ParsedRule]) -> list[CompiledRule]:
    """Compile many parsed rules."""

    return [compile_rule(rule) for rule in rules]
