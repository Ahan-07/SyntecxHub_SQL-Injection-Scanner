import hashlib
import re
from difflib import SequenceMatcher


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"mysql_fetch",
    r"mysqli?_",
    r"postgresql.*error",
    r"pg_query",
    r"sqlite.*error",
    r"sqlite3",
    r"ora-\d{4,5}",
    r"oracle.*error",
    r"sql server.*error",
    r"microsoft sql server",
    r"odbc sql server driver",
    r"jdbc.*sql",
    r"syntax error.*sql",
]


def response_fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()[:16]


def classify_error_response(text: str):
    lowered = text.lower()

    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return f"SQL error signature matched: {pattern}"

    return None


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def compare_boolean_responses(
    baseline_text: str,
    true_text: str,
    false_text: str,
    baseline_status: int,
    true_status: int,
    false_status: int,
):
    true_sim = _similarity(baseline_text, true_text)
    false_sim = _similarity(baseline_text, false_text)
    true_false_sim = _similarity(true_text, false_text)

    # Heuristic:
    # true should resemble baseline more closely than false,
    # while true/false should differ materially.
    status_signal = true_status != false_status
    body_signal = (
        true_sim >= 0.92
        and false_sim <= 0.80
        and true_false_sim <= 0.85
    )

    if status_signal or body_signal:
        return True, (
            f"Boolean differential detected; "
            f"baseline→true={true_sim:.3f}, "
            f"baseline→false={false_sim:.3f}, "
            f"true↔false={true_false_sim:.3f}, "
            f"status={true_status}/{false_status}"
        )

    return False, ""
