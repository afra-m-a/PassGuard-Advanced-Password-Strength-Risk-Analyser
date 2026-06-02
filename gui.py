import tkinter as tk
from tkinter import ttk, font as tkfont

from analyzer     import compute_score
from leak_detector import full_leak_report
from ml_fallback  import classify

PALETTE = {
    "bg_deep":      "#0F1117",  
    "bg_card":      "#1A1D27",   
    "bg_input":     "#13151E",   
    "border":       "#2A2D3E",   
    "accent":       "#5B6EF5",   
    "accent_dim":   "#3A4AB8",  
    "text_primary": "#E8EAF0",   
    "text_dim":     "#6B7280",   
    "text_code":    "#A0AEC0",   
    "pass":         "#2ECC71",   
    "fail":         "#E74C3C",   
    "warn":         "#F39C12",   
    "strong":       "#2ECC71",
    "danger":       "#E74C3C",
    "warning":      "#F39C12",
}

FONT_FAMILY      = "Consolas"     
FONT_FAMILY_SANS = "Segoe UI"     


class PasswordCheckerApp:
    

    def __init__(self, root: tk.Tk):
        self.root = root
        self._configure_root()
        self._build_ui()


    def _configure_root(self):
        self.root.title("PassGuard — Advanced Password Strength & Risk Analyser")
        self.root.configure(bg=PALETTE["bg_deep"])
        self.root.resizable(True, True)
        self.root.minsize(780, 680)

        w, h = 920, 820
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")


    def _build_ui(self):
        outer = tk.Frame(self.root, bg=PALETTE["bg_deep"])
        outer.pack(fill="both", expand=True, padx=0, pady=0)

        self._build_header(outer)

        content = tk.Frame(outer, bg=PALETTE["bg_deep"])
        content.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)

        left = tk.Frame(content, bg=PALETTE["bg_deep"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(0, weight=1)

        self._build_input_card(left)
        self._build_score_card(left)
        self._build_breach_card(left)

        right = tk.Frame(content, bg=PALETTE["bg_deep"])
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.columnconfigure(0, weight=1)

        self._build_rules_card(right)
        self._build_ml_card(right)

        self._build_footer(outer)


    def _build_header(self, parent):
        hdr = tk.Frame(parent, bg=PALETTE["bg_card"],
                       highlightbackground=PALETTE["border"],
                       highlightthickness=1)
        hdr.pack(fill="x", padx=24, pady=(20, 16))

        tk.Label(
            hdr,
            text="🔐  PassGuard",
            bg=PALETTE["bg_card"], fg=PALETTE["accent"],
            font=(FONT_FAMILY, 22, "bold"),
        ).pack(side="left", padx=20, pady=14)

        tk.Label(
            hdr,
            text="Advanced Password Strength & Risk Analyser",
            bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY_SANS, 9),
        ).pack(side="left", padx=0, pady=14)


    def _build_input_card(self, parent):
        card = self._card(parent, title="PASSWORD INPUT")
        card.pack(fill="x", pady=(0, 12))

        self._pw_var = tk.StringVar()
        self._pw_var.trace_add("write", self._on_type)

        entry_frame = tk.Frame(card, bg=PALETTE["bg_card"])
        entry_frame.pack(fill="x", padx=16, pady=(4, 8))

        self._pw_entry = tk.Entry(
            entry_frame,
            textvariable=self._pw_var,
            show="●",
            bg=PALETTE["bg_input"],
            fg=PALETTE["text_primary"],
            insertbackground=PALETTE["accent"],
            relief="flat",
            font=(FONT_FAMILY, 16),
            bd=0,
        )
        self._pw_entry.pack(side="left", fill="x", expand=True,
                            ipady=10, padx=(8, 4))
        self._pw_entry.focus_set()

        self._show_pw = False
        self._toggle_btn = tk.Button(
            entry_frame,
            text="👁  Show",
            command=self._toggle_visibility,
            bg=PALETTE["bg_input"], fg=PALETTE["text_dim"],
            relief="flat", cursor="hand2",
            font=(FONT_FAMILY_SANS, 9),
            activebackground=PALETTE["bg_input"],
            activeforeground=PALETTE["text_primary"],
        )
        self._toggle_btn.pack(side="right", padx=(4, 8))

        self._char_count_var = tk.StringVar(value="0 characters")
        tk.Label(
            card,
            textvariable=self._char_count_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY_SANS, 8),
        ).pack(anchor="e", padx=24, pady=(0, 8))


    def _build_score_card(self, parent):
        card = self._card(parent, title="STRENGTH SCORE")
        card.pack(fill="x", pady=(0, 12))

        score_row = tk.Frame(card, bg=PALETTE["bg_card"])
        score_row.pack(fill="x", padx=16, pady=(4, 6))

        self._score_num_var = tk.StringVar(value="—")
        tk.Label(
            score_row,
            textvariable=self._score_num_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_primary"],
            font=(FONT_FAMILY, 36, "bold"),
        ).pack(side="left", padx=8)

        info_col = tk.Frame(score_row, bg=PALETTE["bg_card"])
        info_col.pack(side="left", padx=12)

        self._level_label_var = tk.StringVar(value="Awaiting input…")
        self._level_label_widget = tk.Label(
            info_col,
            textvariable=self._level_label_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY_SANS, 11, "bold"),
        )
        self._level_label_widget.pack(anchor="w")

        self._entropy_var = tk.StringVar(value="Shannon Entropy: — bits")
        tk.Label(
            info_col,
            textvariable=self._entropy_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY, 9),
        ).pack(anchor="w")

        self._bar_canvas = tk.Canvas(
            card, bg=PALETTE["bg_card"],
            height=24, highlightthickness=0,
        )
        self._bar_canvas.pack(fill="x", padx=16, pady=(0, 12))

    def _draw_progress_bar(self, score: int, colour: str):
        
        c = self._bar_canvas
        c.delete("all")
        c.update_idletasks()

        total_width = c.winfo_width()
        if total_width < 10:
            total_width = 860     
        n_segs   = 20
        gap      = 3
        height   = 20
        seg_w    = (total_width - gap * (n_segs - 1)) / n_segs
        filled   = int(score / 5)    
        y_top    = 2
        y_bot    = y_top + height
        radius   = 4

        for i in range(n_segs):
            x0 = i * (seg_w + gap)
            x1 = x0 + seg_w
            fill = colour if i < filled else PALETTE["border"]
            self._rounded_rect(c, x0, y_top, x1, y_bot, radius, fill)

    def _rounded_rect(self, canvas, x0, y0, x1, y1, r, fill):
        """Draw a rounded rectangle on *canvas*."""
        canvas.create_arc(x0, y0, x0+2*r, y0+2*r, start=90,  extent=90,  fill=fill, outline=fill)
        canvas.create_arc(x1-2*r, y0, x1, y0+2*r, start=0,   extent=90,  fill=fill, outline=fill)
        canvas.create_arc(x0, y1-2*r, x0+2*r, y1, start=180, extent=90,  fill=fill, outline=fill)
        canvas.create_arc(x1-2*r, y1-2*r, x1, y1, start=270, extent=90,  fill=fill, outline=fill)
        canvas.create_rectangle(x0+r, y0, x1-r, y1, fill=fill, outline=fill)
        canvas.create_rectangle(x0, y0+r, x1, y1-r, fill=fill, outline=fill)


    def _build_breach_card(self, parent):
        card = self._card(parent, title="BREACH & BLACKLIST CHECK")
        card.pack(fill="x", pady=(0, 12))

        self._blacklist_var = tk.StringVar(value="—")
        self._breach_var    = tk.StringVar(value="—")

        for var, label in [
            (self._blacklist_var, "Local Blacklist:"),
            (self._breach_var,    "Simulated Breach DB:"),
        ]:
            row = tk.Frame(card, bg=PALETTE["bg_card"])
            row.pack(fill="x", padx=16, pady=2)
            tk.Label(row, text=label, bg=PALETTE["bg_card"],
                     fg=PALETTE["text_dim"],
                     font=(FONT_FAMILY_SANS, 9, "bold"),
                     width=20, anchor="w").pack(side="left")
            tk.Label(row, textvariable=var, bg=PALETTE["bg_card"],
                     fg=PALETTE["text_primary"],
                     font=(FONT_FAMILY, 9),
                     wraplength=360, justify="left").pack(side="left", padx=4)

        # Spacer
        tk.Frame(card, bg=PALETTE["bg_card"], height=6).pack()


    def _build_rules_card(self, parent):
        card = self._card(parent, title="RULES & RECOMMENDATIONS")
        card.pack(fill="x", pady=(0, 12))

        self._rules_frame = tk.Frame(card, bg=PALETTE["bg_card"])
        self._rules_frame.pack(fill="x", padx=12, pady=(2, 10))

        self._rule_labels: list[tk.Label] = []
        for _ in range(7):
            lbl = tk.Label(
                self._rules_frame,
                text="",
                bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
                font=(FONT_FAMILY, 9),
                anchor="w",
            )
            lbl.pack(fill="x", pady=1)
            self._rule_labels.append(lbl)

    def _update_rules(self, rules: list[dict]):
        for i, rule in enumerate(rules):
            if i >= len(self._rule_labels):
                break
            icon  = "✔" if rule["passed"] else "✖"
            colour = PALETTE["pass"] if rule["passed"] else PALETTE["fail"]
            self._rule_labels[i].config(
                text=f"  {icon}  {rule['label']}",
                fg=colour,
            )


    def _build_ml_card(self, parent):
        card = self._card(parent, title="ML HEURISTIC ASSESSMENT")
        card.pack(fill="both", expand=True, pady=(0, 12))

        self._ml_pred_var    = tk.StringVar(value="—")
        self._ml_conf_var    = tk.StringVar(value="")
        self._ml_insight_var = tk.StringVar(value="—")

        pred_row = tk.Frame(card, bg=PALETTE["bg_card"])
        pred_row.pack(fill="x", padx=16, pady=(4, 2))

        self._ml_pred_label = tk.Label(
            pred_row,
            textvariable=self._ml_pred_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_primary"],
            font=(FONT_FAMILY, 20, "bold"),
        )
        self._ml_pred_label.pack(side="left")

        tk.Label(
            pred_row,
            textvariable=self._ml_conf_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY_SANS, 9),
        ).pack(side="left", padx=8)

        self._vec_frame = tk.Frame(card, bg=PALETTE["bg_card"])
        self._vec_frame.pack(fill="x", padx=16, pady=(6, 4))

        self._vec_bars: dict[str, tk.Canvas] = {}
        vec_names = {
            "symbol_density":  "Symbol Density Risk",
            "sequential_runs": "Sequential Run Risk",
            "keyboard_walk":   "Keyboard-Walk Risk",
        }
        for key, display_name in vec_names.items():
            row = tk.Frame(self._vec_frame, bg=PALETTE["bg_card"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=display_name, bg=PALETTE["bg_card"],
                     fg=PALETTE["text_dim"],
                     font=(FONT_FAMILY_SANS, 8),
                     width=22, anchor="w").pack(side="left")
            bar = tk.Canvas(row, bg=PALETTE["bg_card"],
                            height=10, highlightthickness=0)
            bar.pack(side="left", fill="x", expand=True)
            self._vec_bars[key] = bar

        tk.Label(
            card,
            textvariable=self._ml_insight_var,
            bg=PALETTE["bg_card"], fg=PALETTE["text_code"],
            font=(FONT_FAMILY, 8),
            wraplength=280, justify="left",
        ).pack(anchor="w", padx=16, pady=(2, 10))

    def _update_ml(self, ml_result: dict):
        pred   = ml_result["prediction"]
        colour = {
            "SAFE":       PALETTE["strong"],
            "SUSPICIOUS": PALETTE["warn"],
            "UNSAFE":     PALETTE["danger"],
        }.get(pred, PALETTE["text_primary"])

        self._ml_pred_var.set(pred)
        self._ml_pred_label.config(fg=colour)
        self._ml_conf_var.set(f"(Confidence: {ml_result['confidence']})")
        self._ml_insight_var.set(ml_result["insight"])

        for key, bar_canvas in self._vec_bars.items():
            bar_canvas.delete("all")
            bar_canvas.update_idletasks()
            w = bar_canvas.winfo_width() or 180
            val = ml_result["vectors"].get(key, 0.0)
            fill_w = int(val * w)
            bar_colour = (
                PALETTE["danger"]  if val > 0.6 else
                PALETTE["warn"]    if val > 0.3 else
                PALETTE["strong"]
            )
            bar_canvas.create_rectangle(0, 1, w,   9, fill=PALETTE["border"], outline="")
            bar_canvas.create_rectangle(0, 1, fill_w, 9, fill=bar_colour,   outline="")


    def _build_footer(self, parent):
        tk.Label(
            parent,
            text="PassGuard v1.0  |  "
                 "All analysis is performed locally — no data leaves your device.",
            bg=PALETTE["bg_deep"], fg=PALETTE["text_dim"],
            font=(FONT_FAMILY_SANS, 8),
        ).pack(pady=(0, 10))


    def _card(self, parent, title: str = "") -> tk.Frame:
        
        wrapper = tk.Frame(
            parent,
            bg=PALETTE["bg_card"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        if title:
            tk.Label(
                wrapper,
                text=f"  {title}",
                bg=PALETTE["bg_card"],
                fg=PALETTE["accent"],
                font=(FONT_FAMILY, 8, "bold"),
                anchor="w",
            ).pack(fill="x", padx=8, pady=(8, 2))
            tk.Frame(wrapper, bg=PALETTE["border"], height=1).pack(fill="x",
                                                                    padx=8,
                                                                    pady=(0, 4))
        return wrapper


    def _toggle_visibility(self):
        self._show_pw = not self._show_pw
        self._pw_entry.config(show="" if self._show_pw else "●")
        self._toggle_btn.config(text="🙈  Hide" if self._show_pw else "👁  Show")


    def _on_type(self, *_):
      
        password: str = self._pw_var.get()

        self._char_count_var.set(f"{len(password)} character{'s' if len(password) != 1 else ''}")

        if not password:
            self._reset_display()
            return

        score_data  = compute_score(password)           
        leak_data   = full_leak_report(password)       
        ml_data     = classify(password,                
                               score_data["score"])

        score = score_data["score"]
        self._score_num_var.set(str(score) if score > 0 else "0")
        self._level_label_var.set(score_data["label"])
        self._level_label_widget.config(fg=score_data["colour"])
        self._entropy_var.set(
            f"Shannon Entropy: {score_data['entropy']} bits"
        )
        self._draw_progress_bar(score, score_data["colour"])

        bl = leak_data["blacklist"]
        br = leak_data["breach"]
        self._blacklist_var.set(bl["message"])
        self._breach_var.set(br["message"])

        self._update_rules(score_data["rules"])

        self._update_ml(ml_data)

    def _reset_display(self):
        """Reset all panels to their default empty state."""
        self._score_num_var.set("—")
        self._level_label_var.set("Awaiting input…")
        self._level_label_widget.config(fg=PALETTE["text_dim"])
        self._entropy_var.set("Shannon Entropy: — bits")
        self._bar_canvas.delete("all")
        self._blacklist_var.set("—")
        self._breach_var.set("—")
        self._ml_pred_var.set("—")
        self._ml_conf_var.set("")
        self._ml_insight_var.set("—")
        for lbl in self._rule_labels:
            lbl.config(text="", fg=PALETTE["text_dim"])
        for bar in self._vec_bars.values():
            bar.delete("all")
