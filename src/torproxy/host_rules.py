"""Validated, immutable host matching shared by HTTP and CONNECT requests."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class HostRuleError(ValueError):
    """Raised when a host rule is malformed or ambiguous."""


class MatchMode(str, Enum):
    EXACT = "exact"
    DOMAIN_AND_SUBDOMAINS = "domain-and-subdomains"
    SUBDOMAINS_ONLY = "subdomains-only"


def normalize_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise HostRuleError("Host must be a string.")
    raw = value.strip()
    if not raw or len(raw) > 1024:
        raise HostRuleError("Host is empty or too long.")
    if any(char in raw for char in ("/", "\\", "@", "?", "#", "%")):
        raise HostRuleError("Enter a hostname or IP address, not a URL or authority.")
    if any(char.isspace() for char in raw):
        raise HostRuleError("Hostnames cannot contain whitespace.")

    bracketed = raw.startswith("[") and raw.endswith("]")
    if bracketed:
        inner = raw[1:-1]
        try:
            return ipaddress.IPv6Address(inner).compressed.lower()
        except ValueError as exc:
            raise HostRuleError("Bracketed hosts must be valid IPv6 literals.") from exc
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        pass

    if ":" in raw:
        raise HostRuleError("A rule must not include a port; IPv6 addresses must be valid literals.")
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or raw.endswith(".") or len(raw) > 253:
        raise HostRuleError("Invalid hostname length.")
    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HostRuleError("Hostname is not valid IDNA.") from exc

    labels = ascii_name.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise HostRuleError("Hostname contains an empty or overlong label.")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise HostRuleError("Hostname contains an invalid label.")
    return ascii_name


@dataclass(frozen=True)
class HostRule:
    host: str
    mode: MatchMode = MatchMode.DOMAIN_AND_SUBDOMAINS

    @classmethod
    def parse(cls, value: str) -> HostRule:
        if not isinstance(value, str):
            raise HostRuleError("Rule must be a string.")
        raw = value.strip()
        if raw.startswith("="):
            return cls(normalize_hostname(raw[1:]), MatchMode.EXACT)
        if raw.startswith("*"):
            # Both '*.example.org' and legacy '*example.org' mean subdomains only.
            suffix = raw[1:]
            if suffix.startswith("."):
                suffix = suffix[1:]
            if not suffix or suffix.startswith(".") or suffix.endswith("."):
                raise HostRuleError("Wildcard rules must name exactly one valid suffix.")
            return cls(normalize_hostname(suffix), MatchMode.SUBDOMAINS_ONLY)
        return cls(normalize_hostname(raw), MatchMode.DOMAIN_AND_SUBDOMAINS)

    def matches(self, hostname: str) -> bool:
        try:
            candidate = normalize_hostname(hostname)
        except HostRuleError:
            return False
        if self.mode is MatchMode.EXACT:
            return candidate == self.host
        if self.mode is MatchMode.SUBDOMAINS_ONLY:
            return candidate.endswith("." + self.host)
        return candidate == self.host or candidate.endswith("." + self.host)

    def __str__(self) -> str:
        if self.mode is MatchMode.EXACT:
            return "=" + self.host
        if self.mode is MatchMode.SUBDOMAINS_ONLY:
            return "*." + self.host
        return self.host


@dataclass(frozen=True)
class HostRules:
    """A snapshot of rules; mutations create a new instance for thread safety."""
    rules: tuple[HostRule, ...] = ()

    @classmethod
    def from_values(cls, values: list[str] | tuple[str, ...]) -> HostRules:
        parsed: list[HostRule] = []
        seen: set[tuple[str, MatchMode]] = set()
        for value in values:
            rule = HostRule.parse(value)
            key = (rule.host, rule.mode)
            if key not in seen:
                seen.add(key)
                parsed.append(rule)
        return cls(tuple(parsed))

    def matches(self, hostname: str) -> bool:
        return any(rule.matches(hostname) for rule in self.rules)

    def add(self, value: str) -> HostRules:
        rule = HostRule.parse(value)
        if rule in self.rules:
            return self
        return HostRules(self.rules + (rule,))

    def remove(self, value: str) -> HostRules:
        rule = HostRule.parse(value)
        return HostRules(tuple(existing for existing in self.rules if existing != rule))

    def as_list(self) -> list[str]:
        return [str(rule) for rule in self.rules]
