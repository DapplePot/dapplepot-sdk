"""PII/secret scrubbing for event payloads — pass a scrubber via ``DapplePot(pii_scrubber=...)``."""

import re
from abc import ABC, abstractmethod

PATTERNS = {
    "email":       (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[EMAIL]'),
    "phone":       (r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[PHONE]'),
    "ssn":         (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),
    "credit_card": (r'\b(?:\d[ -]?){13,19}\b', '[CARD]'),
    "uk_nino":     (r'\b[A-Z]{2}\d{6}[A-D]\b', '[NINO]'),
    "iban":        (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b', '[IBAN]'),
    "ip_address":  (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'),
    "aws_key":     (r'\bAKIA[0-9A-Z]{16}\b', '[AWS_KEY]'),
    "jwt":         (r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[JWT]'),
}


class BaseScrubber(ABC):
    """Interface for scrubbing sensitive text out of event payloads.

    Pass an instance to ``DapplePot(pii_scrubber=...)`` to have it applied
    to every event payload before it's buffered/flushed. Subclass this to
    plug in your own redaction logic (e.g. a call to an internal PII
    detection service) instead of the built-in regex-based
    :class:`RegexScrubber`.

    Usage::

        class UppercaseNamesScrubber(BaseScrubber):
            def scrub(self, text: str) -> str:
                return text.replace("Alice", "[NAME]").replace("Bob", "[NAME]")

        dp = DapplePot(..., pii_scrubber=UppercaseNamesScrubber())
    """

    @abstractmethod
    def scrub(self, text: str) -> str:
        """Return ``text`` with sensitive substrings replaced.

        Args:
            text: The raw string to scrub.

        Returns:
            The scrubbed string.
        """

    def scrub_value(self, value):
        """Recursively apply :meth:`scrub` to every string in ``value``.

        Walks dicts and lists in place (returning new copies), applying
        :meth:`scrub` to each string leaf and leaving other types (numbers,
        booleans, ``None``) untouched. This is what
        :class:`~dapplepot_sdk.DapplePot` calls internally on each event
        payload — subclasses generally don't need to override it.

        Args:
            value: A string, dict, list, or other JSON-serializable value.

        Returns:
            A value of the same shape with all string leaves scrubbed.
        """
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, dict):
            return {k: self.scrub_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        return value


class RegexScrubber(BaseScrubber):
    """Built-in scrubber that redacts common PII/secret patterns via regex.

    Available pattern names (passed via ``patterns``): ``email``, ``phone``,
    ``ssn``, ``credit_card``, ``uk_nino``, ``iban``, ``ip_address``,
    ``aws_key``, ``jwt``. Each match is replaced with a bracketed tag, e.g.
    an email becomes ``[EMAIL]``.

    Usage::

        from dapplepot_sdk.scrubbers import RegexScrubber

        # Scrub everything the built-in patterns cover:
        dp = DapplePot(..., pii_scrubber=RegexScrubber())

        # Or restrict to specific patterns:
        dp = DapplePot(..., pii_scrubber=RegexScrubber(patterns=["email", "aws_key"]))
    """

    def __init__(self, patterns=None):
        """Compile the given (or all built-in) patterns.

        Args:
            patterns: List of pattern names to enable (see class docstring
                for the full list). Defaults to all built-in patterns.
                Unknown names are silently ignored.
        """
        if patterns is None:
            patterns = list(PATTERNS.keys())
        self._compiled = [
            (re.compile(PATTERNS[p][0]), PATTERNS[p][1])
            for p in patterns
            if p in PATTERNS
        ]

    def scrub(self, text: str) -> str:
        """Replace every configured pattern match in ``text``.

        Args:
            text: The raw string to scrub.

        Returns:
            The scrubbed string, with each configured pattern's matches
            replaced by its redaction tag (e.g. ``[EMAIL]``).
        """
        for pattern, replacement in self._compiled:
            text = pattern.sub(replacement, text)
        return text
