PassGuard — Advanced Password Strength & Risk Analyser
### DecodeLabs Internship Portfolio — Project 1


## 📂 Folder Structure

Place all five files in a single folder, e.g. `PassGuard/`:

```
PassGuard/
├── main.py           ← Entry point — run this file
├── gui.py            ← Dark-themed Tkinter dashboard & live events
├── analyzer.py       ← Shannon entropy, scoring engine, rule evaluation
├── ml_fallback.py    ← Heuristic decision-tree ML classifier
└── leak_detector.py  ← Local blacklist + simulated breach lookup
```

> **No pip installs required.** Every module uses only Python's standard
> library: `tkinter`, `math`, `collections`.

---

## 🚀 How to Run

### Option A — Terminal / Command Prompt
```bash
cd PassGuard
python main.py
```

### Option B — VS Code
1. Open the `PassGuard/` folder in VS Code (`File → Open Folder`).
2. Open `main.py`.
3. Press **F5** or click the ▶ Run button.
4. Make sure your Python interpreter is 3.10 or newer
   (`Ctrl+Shift+P → Python: Select Interpreter`).

---

## 🏗 Architecture & Module Communication

```
main.py
  └─ creates Tk root → instantiates PasswordCheckerApp (gui.py)
        │
        └─ _on_type() fires on every keystroke
              │
              ├─ analyzer.compute_score(pw)
              │     ├─ shannon_entropy()      O(n) Counter sweep
              │     ├─ evaluate_rules()       O(n) any() short-circuits
              │     └─ returns score dict → gui updates score card + bar
              │
              ├─ leak_detector.full_leak_report(pw)
              │     ├─ check_blacklist()      O(1) frozenset lookup
              │     ├─ simulate_breach_lookup()  deterministic hash
              │     └─ returns report dict  → gui updates breach card
              │
              └─ ml_fallback.classify(pw, score)
                    ├─ _symbol_density_risk()   O(n)
                    ├─ _sequential_run_risk()   O(n)
                    ├─ _keyboard_walk_risk()    O(n)
                    └─ weighted ensemble       → gui updates ML card
```

---

## 🛠 Design Principles Implemented

| Principle | Where |
|---|---|
| **IPO Model** — O(n) linear scan complexity | `analyzer.py`, `ml_fallback.py` |
| **Pythonic short-circuiting** — `any()`, list comprehensions | `analyzer.py` |
| **Zero Point Policy** — passwords < 8 chars score 0 | `analyzer.compute_score()` |
| **RAM Security** — password never stored in globals | All modules: local scope only |
| **True Shannon Entropy** H = −Σ P(xᵢ)log₂P(xᵢ) | `analyzer.shannon_entropy()` |
| **Keyboard proximity map** (QWERTY adjacency) | `ml_fallback._keyboard_walk_risk()` |
| **O(1) blacklist lookup** via `frozenset` | `leak_detector.check_blacklist()` |

---

## 🎨 UI Feature Summary

- **Deep charcoal dark theme** — `#0F1117` background, `#1A1D27` cards
- **Canvas-drawn segmented progress bar** — 20 pill-blocks, colour-coded
- **Show / Hide password toggle** with bullet masking (`●`)
- **Live recommendations panel** — ✔/✖ icons update per keystroke
- **ML vector mini-bars** — three horizontal risk indicators
- **Entropy readout** — live Shannon bits displayed below the score
- **Windows 11 dark title bar** — via DwmSetWindowAttribute (auto-skipped on other OS)

---

## 📋 Requirements

| Item | Minimum |
|---|---|
| Python | 3.10+ |
| tkinter | Bundled with CPython (no install needed) |
| OS | Windows 10/11, macOS 12+, Ubuntu 20.04+ |

> On some minimal Linux installs `tkinter` may be absent.
> Install with: `sudo apt-get install python3-tk`
