import re

class InputSanitizer:
    def __init__(self):
        self.signatures = {
            "sqli": re.compile(r"(UNION\s+SELECT|' or '|--|\/\*|\*\/)", re.IGNORECASE),
            "xss": re.compile(r"(<script.*?>|javascript:|onload=|onerror=|onmouseover=)", re.IGNORECASE)
        }

    def sanitize_string(self, user_input: str) -> str:
        if not user_input or not isinstance(user_input, str):
            return ""

        cleaned = user_input.strip()

        cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")

        for threat_type, regex in self.signatures.items():
            cleaned = regex.sub("", cleaned)

        return cleaned