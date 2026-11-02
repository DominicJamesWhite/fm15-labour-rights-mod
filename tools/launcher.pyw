"""Small window for choosing FM15's rule set before starting the game.

    Vanilla        unmodified FM15
    Labour rights  patch.py DEFAULT: players have ordinary employment rights
    Nostalgia      patch.py NOSTALGIA: pre-Bosman, clubs own players' registrations
    Parity         patch.py PARITY + tools/parity_agent.js: labour rights plus redistribution
    Custom         any combination of the rule groups in patch.py CUSTOM, picked with checkboxes

Runs tools/fm15_loader.py --mode <choice> (or --custom <groups>) and shows its output. Patches are
written into the game's memory at start-up and stay until it quits, so the rules can only be
switched by restarting FM15. The last choice and the custom groups are remembered in
launcher_settings.json.
"""

import importlib.util
import json
import pathlib
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOADER = ROOT / "tools" / "fm15_loader.py"
SETTINGS = ROOT / "launcher_settings.json"
# pythonw.exe has no console to inherit; run the loader with the console interpreter next to it
PYTHON = pathlib.Path(sys.executable).with_name("python.exe")


def load_custom():
    sys.path.insert(0, str(ROOT / "patcher"))
    spec = importlib.util.spec_from_file_location("patch", ROOT / "patcher" / "patch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CUSTOM


CUSTOM = load_custom()

MODES = [
    ("vanilla", "Vanilla", "FM15 as Sports Interactive made it."),
    ("labour", "Labour rights",
     "No transfer windows, fees or loans. Players leave on two weeks' notice, clubs release on "
     "two weeks' wages. Football-only squad quotas switched off."),
    ("nostalgia", "Nostalgia",
     "Before Bosman. Unsold players stay on when their contract ends, and moving at the end of a "
     "contract costs a fee at any age. No transfer windows. At most 3 foreigners in a match squad "
     "in every league; AI clubs sell the foreigners they can't use."),
    ("parity", "Parity",
     "Labour rights plus redistribution. League TV is pooled (half shared down the whole pyramid), "
     "half of gates is shared in the league, big commercial earners and big-spending owners pay "
     "levies to the pyramid, and wage budgets follow revenue. No dividends or parachutes; cup gates "
     "split 50/50. Continental cups become one knockout stage."),
    ("custom", "Custom", "Pick the rule groups on the right; everything else stays as in FM15."),
]


def load_settings():
    try:
        s = json.loads(SETTINGS.read_text("utf-8"))
        return s.get("mode", "labour"), [k for k in s.get("custom", []) if k in CUSTOM]
    except (OSError, ValueError, AttributeError):
        return "labour", []


def save_settings(mode, custom):
    try:
        SETTINGS.write_text(json.dumps({"mode": mode, "custom": custom}), "utf-8")
    except OSError:
        pass


def fm_running():
    out = subprocess.run(["tasklist", "/fi", "imagename eq fm.exe", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return "fm.exe" in out.stdout.lower()


class Launcher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FM15 rules")
        self.resizable(False, False)
        mode, custom = load_settings()
        self.mode = tk.StringVar(value=mode)
        self.groups = {k: tk.BooleanVar(value=k in custom) for k in CUSTOM}
        self.lines = queue.Queue()

        outer = ttk.Frame(self, padding=14)
        outer.grid()
        frame = ttk.Frame(outer)
        frame.grid(row=0, column=0, sticky="n")
        ttk.Label(frame, text="Which rules should FM15 start with?", font=("Segoe UI", 11, "bold")) \
            .grid(sticky="w", pady=(0, 8))
        for key, name, text in MODES:
            ttk.Radiobutton(frame, text=name, value=key, variable=self.mode,
                            command=self.show_custom).grid(sticky="w")
            ttk.Label(frame, text=text, wraplength=420, foreground="#555") \
                .grid(sticky="w", padx=(22, 0), pady=(0, 8))

        # the groups sit beside the modes, so the window stays short enough for a laptop screen
        self.custom = ttk.Frame(outer)
        self.custom.grid(row=0, column=1, sticky="n", padx=(18, 0))
        ttk.Label(self.custom, text="Custom rules", font=("Segoe UI", 11, "bold"))             .grid(sticky="w", pady=(0, 8))
        for key, g in CUSTOM.items():
            ttk.Checkbutton(self.custom, text=g["label"], variable=self.groups[key],
                            command=lambda k=key: self.toggle(k)).grid(sticky="w")
            notes = [f"needs {CUSTOM[k]['label']}" for k in g.get("needs", [])]
            notes += [f"not with {CUSTOM[k]['label']}" for k in g.get("clashes", [])]
            ttk.Label(self.custom, text=g["text"] + (f" ({'; '.join(notes)})" if notes else ""),
                      wraplength=400, foreground="#555").grid(sticky="w", padx=(22, 0), pady=(0, 4))
        self.show_custom()

        self.play = ttk.Button(frame, text="Start FM15", command=self.start)
        self.play.grid(sticky="e", pady=(4, 8))
        self.log = tk.Text(frame, width=64, height=12, state="disabled", font=("Consolas", 9))
        self.log.grid()
        ttk.Label(frame, text="To switch rules later, quit FM15 and start it from here again.",
                  foreground="#555").grid(sticky="w", pady=(6, 0))

    def show_custom(self):
        if self.mode.get() == "custom":
            self.custom.grid()
        else:
            self.custom.grid_remove()

    def toggle(self, key):
        """Keep the ticked groups combinable: ticking a group ticks what it needs and unticks what
        clashes with it; unticking one unticks the groups that need it."""
        on = {k for k, v in self.groups.items() if v.get()}
        if key in on:
            todo = [key]
            while todo:
                k = todo.pop()
                for other in CUSTOM:
                    if other in CUSTOM[k].get("clashes", []) or k in CUSTOM[other].get("clashes", []):
                        on.discard(other)
                for need in CUSTOM[k].get("needs", []):
                    if need not in on:
                        on.add(need)
                        todo.append(need)
        changed = True
        while changed:
            changed = False
            for k in list(on):
                if any(n not in on for n in CUSTOM[k].get("needs", [])):
                    on.discard(k)
                    changed = True
        for k, v in self.groups.items():
            v.set(k in on)

    def write(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def start(self):
        if fm_running():
            messagebox.showinfo("FM15 rules", "FM15 is already running. The rules are set when it "
                                "starts, so quit FM15 first, then start it from here.")
            return
        mode = self.mode.get()
        custom = [k for k, v in self.groups.items() if v.get()]
        if mode == "custom" and not custom:
            messagebox.showinfo("FM15 rules", "Tick at least one rule group, or choose Vanilla.")
            return
        save_settings(mode, custom)
        self.play.configure(state="disabled")
        if mode == "custom":
            self.write(f"--- Custom: {', '.join(CUSTOM[k]['label'] for k in custom)} ---\n")
            args = ["--custom", ",".join(custom)]
        else:
            self.write(f"--- {dict((k, n) for k, n, _ in MODES)[mode]} ---\n")
            args = ["--mode", mode]
        threading.Thread(target=self.run_loader, args=(args,), daemon=True).start()
        self.after(200, self.poll)

    def run_loader(self, args):
        proc = subprocess.Popen([str(PYTHON), "-u", str(LOADER)] + args, cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        for line in proc.stdout:
            self.lines.put(line)
        self.lines.put(proc.wait())

    def poll(self):
        while not self.lines.empty():
            item = self.lines.get()
            if isinstance(item, int):
                if item == 0:
                    self.write("Done. This window closes in 10 seconds.\n")
                    self.after(10000, self.destroy)
                else:
                    self.write("Something went wrong (see above). FM15 may be running with only "
                               "some rules changed; quit it before playing.\n")
                    self.play.configure(state="normal")
                return
            self.write(item)
        self.after(200, self.poll)


if __name__ == "__main__":
    Launcher().mainloop()
