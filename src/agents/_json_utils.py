"""
JSON parsing and repair helpers for AI responses.

Extracted from ThreatAnalystAgent as self-contained, side-effect-free helpers
for robustly parsing large language model output into dictionaries.
"""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def escape_strings_in_json(text: str) -> str:
    """Escape literal newlines and tabs that appear inside JSON string values."""
    result = []
    in_string = False
    escape_next = False
    for ch in text:
        if escape_next:
            result.append(ch)
            escape_next = False
            continue
        if ch == "\\" and in_string:
            result.append(ch)
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string:
            if ch == "\n":
                result.append("\\n")
                continue
            if ch == "\r":
                result.append("\\r")
                continue
            if ch == "\t":
                result.append("\\t")
                continue
        result.append(ch)
    return "".join(result)


def repair_truncated_json(text: str) -> str | None:
    """
    If the AI output was cut off mid-JSON, close any open braces/brackets
    and truncate the last incomplete value.
    """
    if not text or text[-1] in ("}", "]"):
        return None

    # Strip trailing partial value (after last complete comma-separated item)
    truncated = text
    for end_marker in ["},", '"],', '",', "null,", "true,", "false,"]:
        idx = truncated.rfind(end_marker)
        if idx != -1:
            candidate = truncated[: idx + len(end_marker) - 1]  # drop trailing comma
            # Count open/close braces and brackets
            open_braces = candidate.count("{") - candidate.count("}")
            open_brackets = candidate.count("[") - candidate.count("]")
            if open_braces >= 0 and open_brackets >= 0:
                candidate += "]" * open_brackets + "}" * open_braces
                return candidate

    return None


def extract_json_object(text: str) -> dict | None:
    """
    Find the first top-level { and attempt to parse progressively
    larger substrings until we get the largest valid JSON object.
    """
    start = text.find("{")
    if start == -1:
        return None

    best = None
    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    parsed = json.loads(candidate)
                    if isinstance(parsed, dict):
                        best = parsed
                except json.JSONDecodeError:
                    pass
                # Keep going in case there's a larger enclosing object
                # but typically the first complete match is it
                if best is not None:
                    return best

    return best


def parse_response(response_text: str) -> dict[str, Any]:
    """
    Robustly parse the AI response into a dictionary, handling control
    characters, truncated JSON, missing delimiters, and other common
    issues from large language model output.
    """
    response_text = response_text.strip()
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    response_text = response_text.strip()

    # Attempt 1: direct parse
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: strip control characters (except newline/tab used in formatting)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", response_text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Attempt 3: fix unescaped newlines/tabs inside JSON string values
    # Replace literal newlines inside strings with \\n
    fixed = escape_strings_in_json(cleaned)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    # Attempt 4: fix missing commas between } and { or } and "
    fixed2 = re.sub(r"\}\s*\{", "},{", fixed)
    fixed2 = re.sub(r'\}\s*"', '},"', fixed2)
    fixed2 = re.sub(r'"\s*\{', '",{', fixed2)
    # Missing comma between "value" and "key"
    fixed2 = re.sub(r'"\s*\n\s*"', '","', fixed2)
    try:
        return json.loads(fixed2)
    except json.JSONDecodeError:
        pass

    # Attempt 5: truncated JSON -- try to close open structures
    repaired = repair_truncated_json(fixed2)
    if repaired:
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            pass

    # Attempt 6: extract the largest parseable JSON object from the text
    result = extract_json_object(cleaned)
    if result is not None:
        return result

    logger.error("All JSON parse attempts failed")
    logger.error(f"Response text (first 500 chars): {response_text[:500]}")
    return None
