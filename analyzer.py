import math
from collections import Counter

MIN_LENGTH = 8          
MAX_SCORE  = 100        

THRESHOLDS = {
    "danger":  (0,  39),
    "warning": (40, 69),
    "strong":  (70, 100),
}

LEVEL_COLOURS = {
    "danger":  "#E74C3C",   
    "warning": "#F39C12",   
    "strong":  "#2ECC71",   
}

LEVEL_LABELS = {
    "danger":  "Weak / High Risk",
    "warning": "Moderate / Needs Improvement",
    "strong":  "Strong / Secure",
}


def shannon_entropy(password: str) -> float:
    
    if not password:
        return 0.0

    n = len(password)
    freq = Counter(password)

    entropy = -sum(
        (count / n) * math.log2(count / n)
        for count in freq.values()
        if count > 0          
    )
    return round(entropy, 4)



def _has_uppercase(pw: str) -> bool:
    return any(c.isupper() for c in pw)          

def _has_lowercase(pw: str) -> bool:
    return any(c.islower() for c in pw)

def _has_digit(pw: str) -> bool:
    return any(c.isdigit() for c in pw)

def _has_special(pw: str) -> bool:
    specials = set(r"!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
    return any(c in specials for c in pw)       

def _unique_char_ratio(pw: str) -> float:
    """Ratio of distinct characters to total length.  Higher → more varied."""
    return len(set(pw)) / len(pw) if pw else 0.0



def evaluate_rules(password: str) -> list[dict]:
    
    length = len(password)

    rules = [
        {
            "label":  "Minimum 8 characters",
            "passed": length >= MIN_LENGTH,
        },
        {
            "label":  "At least 12 characters (recommended)",
            "passed": length >= 12,
        },
        {
            "label":  "Contains uppercase letters (A–Z)",
            "passed": _has_uppercase(password),
        },
        {
            "label":  "Contains lowercase letters (a–z)",
            "passed": _has_lowercase(password),
        },
        {
            "label":  "Contains digits (0–9)",
            "passed": _has_digit(password),
        },
        {
            "label":  "Contains special symbols (!@#$…)",
            "passed": _has_special(password),
        },
        {
            "label":  "High character variety (≥60 % unique)",
            "passed": _unique_char_ratio(password) >= 0.6,
        },
    ]
    return rules


def compute_score(password: str) -> dict:
    

    if len(password) < MIN_LENGTH:
        return {
            "score":   0,
            "entropy": shannon_entropy(password),
            "level":   "danger",
            "colour":  LEVEL_COLOURS["danger"],
            "label":   "⚠ Exponential Brute-Force Risk — too short",
            "rules":   evaluate_rules(password),
        }

    points = 0
    length = len(password)
    entropy = shannon_entropy(password)

    points += min(length * 2, 30)

    entropy_pts = min(int((entropy / 5) * 30), 30)
    points += entropy_pts

    char_class_pts = sum([
        5 if _has_uppercase(password) else 0,
        5 if _has_lowercase(password) else 0,
        5 if _has_digit(password)     else 0,
        5 if _has_special(password)   else 0,
    ])
    points += char_class_pts

    ratio = _unique_char_ratio(password)
    points += int(ratio * 20)

    score = max(0, min(points, MAX_SCORE))

    if score <= THRESHOLDS["danger"][1]:
        level = "danger"
    elif score <= THRESHOLDS["warning"][1]:
        level = "warning"
    else:
        level = "strong"

    return {
        "score":   score,
        "entropy": entropy,
        "level":   level,
        "colour":  LEVEL_COLOURS[level],
        "label":   LEVEL_LABELS[level],
        "rules":   evaluate_rules(password),
    }
