
_KEYBOARD_ADJACENCY: dict[str, set[str]] = {
    "1": {"2", "q"},          "2": {"1", "3", "q", "w"},
    "3": {"2", "4", "w", "e"},"4": {"3", "5", "e", "r"},
    "5": {"4", "6", "r", "t"},"6": {"5", "7", "t", "y"},
    "7": {"6", "8", "y", "u"},"8": {"7", "9", "u", "i"},
    "9": {"8", "0", "i", "o"},"0": {"9", "o", "p"},
    "q": {"1", "2", "w", "a"},"w": {"2", "3", "q", "e", "a", "s"},
    "e": {"3", "4", "w", "r", "s", "d"},"r": {"4", "5", "e", "t", "d", "f"},
    "t": {"5", "6", "r", "y", "f", "g"},"y": {"6", "7", "t", "u", "g", "h"},
    "u": {"7", "8", "y", "i", "h", "j"},"i": {"8", "9", "u", "o", "j", "k"},
    "o": {"9", "0", "i", "p", "k", "l"},"p": {"0", "o", "l"},
    "a": {"q", "w", "s", "z"},"s": {"w", "e", "a", "d", "z", "x"},
    "d": {"e", "r", "s", "f", "x", "c"},"f": {"r", "t", "d", "g", "c", "v"},
    "g": {"t", "y", "f", "h", "v", "b"},"h": {"y", "u", "g", "j", "b", "n"},
    "j": {"u", "i", "h", "k", "n", "m"},"k": {"i", "o", "j", "l", "m"},
    "l": {"o", "p", "k"},
    "z": {"a", "s", "x"},"x": {"s", "d", "z", "c"},
    "c": {"d", "f", "x", "v"},"v": {"f", "g", "c", "b"},
    "b": {"g", "h", "v", "n"},"n": {"h", "j", "b", "m"},
    "m": {"j", "k", "n"},
}



def _symbol_density_risk(password: str) -> float:
    
    if not password:
        return 1.0

    n = len(password)
    counts = {
        "upper":   sum(1 for c in password if c.isupper()),
        "lower":   sum(1 for c in password if c.islower()),
        "digit":   sum(1 for c in password if c.isdigit()),
        "special": sum(1 for c in password if not c.isalnum()),
    }

    dominant_ratio = max(counts.values()) / n

    risk = max(0.0, (dominant_ratio - 0.4) / 0.6)   
    return round(min(risk, 1.0), 4)



def _sequential_run_risk(password: str) -> float:
   
    if len(password) < 3:
        return 0.0

    pw = password.lower()
    n = len(pw)
    flagged = [False] * n   

    for i in range(n - 2):
        a, b, c = pw[i], pw[i + 1], pw[i + 2]

        if a == b == c:
            flagged[i] = flagged[i + 1] = flagged[i + 2] = True
            continue

        if ord(b) - ord(a) == 1 and ord(c) - ord(b) == 1:
            flagged[i] = flagged[i + 1] = flagged[i + 2] = True

        elif ord(a) - ord(b) == 1 and ord(b) - ord(c) == 1:
            flagged[i] = flagged[i + 1] = flagged[i + 2] = True

    risk = sum(flagged) / n
    return round(risk, 4)



def _keyboard_walk_risk(password: str) -> float:
 
    if len(password) < 2:
        return 0.0

    pw = password.lower()
    walk_steps = 0
    total_pairs = len(pw) - 1

    for i in range(total_pairs):
        a, b = pw[i], pw[i + 1]
        neighbours = _KEYBOARD_ADJACENCY.get(a, set())
        if b in neighbours:
            walk_steps += 1

    risk = walk_steps / total_pairs
    return round(risk, 4)



_WEIGHTS = {
    "symbol_density":   0.30,
    "sequential_runs":  0.40,
    "keyboard_walk":    0.30,
}

def classify(password: str, analyzer_score: int) -> dict:
   
    v1 = _symbol_density_risk(password)
    v2 = _sequential_run_risk(password)
    v3 = _keyboard_walk_risk(password)

    ml_risk = (
        v1 * _WEIGHTS["symbol_density"] +
        v2 * _WEIGHTS["sequential_runs"] +
        v3 * _WEIGHTS["keyboard_walk"]
    )
    ml_risk = round(ml_risk, 4)

    dampening = analyzer_score / 100        
    adjusted_risk = round(ml_risk * (1 - 0.5 * dampening), 4)

    if adjusted_risk < 0.25:
        prediction  = "SAFE"
        confidence  = "High" if adjusted_risk < 0.12 else "Medium"
        insight = "No significant structural vulnerabilities detected."
    elif adjusted_risk < 0.55:
        prediction  = "SUSPICIOUS"
        confidence  = "Medium"
        insight = _build_insight(v1, v2, v3)
    else:
        prediction  = "UNSAFE"
        confidence  = "High" if adjusted_risk > 0.75 else "Medium"
        insight = _build_insight(v1, v2, v3)

    return {
        "ml_risk_score": adjusted_risk,
        "prediction":    prediction,
        "confidence":    confidence,
        "vectors": {
            "symbol_density":  v1,
            "sequential_runs": v2,
            "keyboard_walk":   v3,
        },
        "insight": insight,
    }


def _build_insight(v1: float, v2: float, v3: float) -> str:
   
    risks = {
        "character homogeneity (all digits/letters)": v1,
        "sequential/repetitive character runs":       v2,
        "keyboard-walk proximity patterns":           v3,
    }
    sorted_risks = sorted(risks.items(), key=lambda x: x[1], reverse=True)
    top_risk, top_val = sorted_risks[0]

    if top_val < 0.1:
        return "Mild structural patterns detected; minor improvement possible."
    return f"Primary structural risk: {top_risk} (score {top_val:.2f})."
