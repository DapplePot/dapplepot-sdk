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
    "jwt":         (r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[JWT]'),
    "password":    (r'password\s*=\s*\S+', '[PASSWORD]'),
    "api_key":     (r'sk-[a-zA-Z0-9_-]{20,}', '[API_KEY]'),
    "bearer_token": (r'Bearer\s+[A-Za-z0-9._-]+', '[BEARER_TOKEN]'),
}


class BaseScrubber(ABC):
    @abstractmethod
    def scrub(self, text: str) -> str:
        pass

    def scrub_value(self, value):
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, dict):
            return {k: self.scrub_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub_value(item) for item in value]
        return value


class RegexScrubber(BaseScrubber):
    def __init__(self, patterns=None):
        if patterns is None:
            patterns = list(PATTERNS.keys())
        self._compiled = [
            (re.compile(PATTERNS[p][0]), PATTERNS[p][1])
            for p in patterns
            if p in PATTERNS
        ]

    def scrub(self, text: str) -> str:
        for pattern, replacement in self._compiled:
            text = pattern.sub(replacement, text)
        return text
