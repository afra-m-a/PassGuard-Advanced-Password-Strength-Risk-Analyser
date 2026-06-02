_BLACKLIST: frozenset[str] = frozenset({
    # Top 10 classics
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    # Common patterns
    "password1", "password123", "pass123", "passw0rd",
    "iloveyou", "sunshine", "master", "welcome", "shadow",
    "superman", "batman", "football", "baseball", "soccer",
    # Keyboard walks
    "qwerty123", "qwertyuiop", "1q2w3e4r", "zxcvbnm",
    "asdfghjkl", "1234567890", "0987654321",
    # Repeating patterns
    "aaaaaa", "aaaaaaa", "aaaaaaaa", "11111111", "00000000",
    "12341234", "abcdabcd",
    # Common names / words
    "michael", "jessica", "ashley", "daniel", "jordan",
    "harley", "ranger", "cookie", "tigger", "charlie",
    "andrew", "thomas", "joshua", "george", "amanda",
    # 'Clever' substitutions that are still blacklisted
    "p@ssword", "p@$$word", "passw0rd1", "pa$$w0rd",
    # Common corporate / default creds
    "admin", "admin123", "administrator", "root", "toor",
    "test", "test123", "guest", "user", "login",
    # Dates / numeric sequences
    "january", "december", "summer2023", "winter2023",
    "spring2024", "abc1234", "123abc", "pass1234",
})


_SIMULATED_BREACH_DB: dict[str, str] = {
    # key  = first 5 chars of simulated "hash prefix"
    # value = breach source name shown in the UI
    "5baa6": "LinkedIn 2012 Breach (117M accounts)",
    "ef92b": "RockYou 2009 Breach (32M accounts)",
    "d8578": "Adobe 2013 Breach (153M accounts)",
    "0d107": "MySpace 2016 Breach (360M accounts)",
    "7c4a8": "Collection #1 2019 Dump (773M records)",
    "e10ad": "Facebook 2021 Leak (533M accounts)",
    "25d55": "Twitter 2022 Breach (235M emails)",
    "b14a7": "Yahoo 2016 Breach (3B accounts)",
    "1a79a": "Dropbox 2012 Breach (68M accounts)",
    "c984a": "Canva 2019 Breach (137M accounts)",
}


def _pseudo_prefix(password: str) -> str:

    val = sum(ord(c) * (i + 1) for i, c in enumerate(password))
    keys = list(_SIMULATED_BREACH_DB.keys())
    chosen_key = keys[val % len(keys)]
    return chosen_key



def check_blacklist(password: str) -> dict:
   
    found = password.lower() in _BLACKLIST
    return {
        "found":   found,
        "message": (
            "🚨 CRITICAL: Password found in known breach blacklist!"
            if found
            else "✅ Not found in local blacklist."
        ),
    }


def simulate_breach_lookup(password: str) -> dict:
    
    prefix = _pseudo_prefix(password)

    high_risk = (
        password.lower() in _BLACKLIST
        or len(password) < 8
        or password.isdigit()
        or len(set(password)) <= 3         
    )

    if high_risk:
        source = _SIMULATED_BREACH_DB.get(prefix, "Unknown Breach Source")
        return {
            "compromised": True,
            "source":      source,
            "prefix":      prefix,
            "message":     f"🔴 SIMULATED BREACH ALERT: Hash prefix {prefix}… matched in {source}",
        }

    return {
        "compromised": False,
        "source":      None,
        "prefix":      prefix,
        "message":     f"🟢 Simulated breach scan clear (prefix {prefix}… — no match found).",
    }


def full_leak_report(password: str) -> dict:
   
    blacklist_result = check_blacklist(password)
    breach_result    = simulate_breach_lookup(password)

    return {
        "blacklist": blacklist_result,
        "breach":    breach_result,
        "is_leaked": blacklist_result["found"] or breach_result["compromised"],
    }
