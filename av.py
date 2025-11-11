# ...existing code...
import os
import shutil
import hashlib
import random
import time
import re
import math
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

# Try to use ttkbootstrap for a modern look; fall back to standard ttk if unavailable.
try:
    import ttkbootstrap as tb  # type: ignore
    TB_AVAILABLE = True
except Exception:
    tb = None  # type: ignore
    TB_AVAILABLE = False

# Optional stronger detectors if installed (used if available)
try:
    import pefile  # type: ignore
    PEFILE_AVAILABLE = True
except Exception:
    PEFILE_AVAILABLE = False

try:
    import magic  # type: ignore
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

try:
    import requests  # for VirusTotal lookups if available
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

try:
    import clamd  # python-clamd to talk to clamd if available
    CLAMD_AVAILABLE = True
except Exception:
    CLAMD_AVAILABLE = False

# Small in-memory signature DB (demo). In a real product this would be updated from a central feed.
KNOWN_HASHES = {
    # sha1: name
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12": "demo-malware-1",
    # add more known-bad hashes here for testing
}

# Simple byte/string rules (YARA-like) for heuristic detection (demo)
SUSPICIOUS_PATTERNS = [
    rb"CreateRemoteThread",
    rb"VirtualAllocEx",
    rb"WriteProcessMemory",
    rb"LoadLibraryA",
    rb"GetProcAddress",
    rb"Base64.decode",  # generic scripting indicator
    rb"mshta.exe",
    rb"powershell -nop",
    rb"eval\(",  # scripting eval
    rb"wget ",   # network fetch
    rb"curl ",   # network fetch
]

SUSPICIOUS_IMPORT_KEYWORDS = [
    b"kernel32", b"advapi32", b"ntdll", b"user32", b"ws2_32", b"wininet", b"shell32"
]

MAGIC_MAP = {
    b"\x4d\x5a": "pe",          # MZ
    b"\x7fELF": "elf",
    b"%PDF-": "pdf",
    b"\x50\x4b\x03\x04": "zip",
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
}

# Global compiled YARA rules (optional)
YARA_RULES: Optional["yara.Rules"] = None  # type: ignore

# clamd client
CLAMD_CLIENT = None


def load_yara_rules(path: str = "rules.yar") -> None:
    """Attempt to compile local YARA rules file if yara-python is available."""
    global YARA_RULES
    if not YARA_AVAILABLE:
        return
    if not os.path.exists(path):
        return
    try:
        YARA_RULES = yara.compile(filepath=path)  # type: ignore
    except Exception:
        YARA_RULES = None


def init_clamd() -> None:
    """Try to initialize a clamd client for local clamd scanning if available."""
    global CLAMD_CLIENT
    if not CLAMD_AVAILABLE:
        return
    try:
        CLAMD_CLIENT = clamd.ClamdUnixSocket() if os.name != "nt" else clamd.ClamdNetworkSocket()
        # ping to confirm
        CLAMD_CLIENT.ping()
    except Exception:
        CLAMD_CLIENT = None


def vt_lookup_hash(sha256: str) -> Optional[Dict]:
    """Query VirusTotal v3 files/{id} endpoint using API key in VT_API_KEY env var (if requests available).
    Returns parsed JSON analysis summary or None if unavailable.
    """
    if not REQUESTS_AVAILABLE:
        return None
    api_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            # extract top-level last_analysis_stats and total engines
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"vt_stats": stats, "raw": data}
        return None
    except Exception:
        return None


# Minimal placeholder implementations so GUI runs standalone.
def compute_hashes(path: str) -> Dict[str, str]:
    """Compute MD5, SHA1 and SHA256 for a file (streaming)."""
    try:
        h_md5 = hashlib.md5()
        h_sha1 = hashlib.sha1()
        h_sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}
    except Exception:
        return {"md5": "error", "sha1": "error", "sha256": "error"}


def estimate_entropy_from_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for c in freq:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return round(ent, 2)


def estimate_entropy(path: str, sample_size: int = 16384) -> float:
    """Estimate entropy over a sample of the file."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
        return estimate_entropy_from_bytes(data)
    except Exception:
        return 0.0


def detect_magic_and_mismatch(path: str) -> Dict:
    """Detect file type by magic bytes and check extension mismatch."""
    info = {"detected": "unknown", "ext": "", "mismatch": False}
    try:
        with open(path, "rb") as f:
            header = f.read(512)
        for magic, kind in MAGIC_MAP.items():
            if header.startswith(magic):
                info["detected"] = kind
                break
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        info["ext"] = ext
        # use python-magic if available for more accurate detection
        if MAGIC_AVAILABLE:
            try:
                m = magic.from_file(path, mime=False)
                # m is a string like 'PE32 executable (GUI) Intel 80386, for MS Windows'
                if "PE32" in m or "MS Windows" in m:
                    info["detected"] = "pe"
                elif "PDF" in m:
                    info["detected"] = "pdf"
                elif "gzip" in m or "zip" in m:
                    info["detected"] = "zip"
                elif "PNG" in m:
                    info["detected"] = "png"
                elif "JPEG" in m:
                    info["detected"] = "jpeg"
            except Exception:
                pass
        # map small set of extensions to kinds
        ext_to_kind = {"exe": "pe", "dll": "pe", "pdf": "pdf", "zip": "zip", "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "elf": "elf"}
        if ext in ext_to_kind and info["detected"] != "unknown" and ext_to_kind[ext] != info["detected"]:
            info["mismatch"] = True
        if info["detected"] != "unknown" and ext not in ext_to_kind:
            if info["detected"] in ("pe", "elf") and ext not in ("exe", "dll", "so", "elf"):
                info["mismatch"] = True
    except Exception:
        pass
    return info


def scan_patterns_in_bytes(data: bytes, patterns: List[bytes]) -> List[str]:
    hits = []
    if not data:
        return hits
    for p in patterns:
        try:
            if re.search(p, data, flags=re.IGNORECASE):
                hits.append(p.decode("latin1", errors="ignore"))
        except re.error:
            try:
                if p.lower() in data.lower():
                    hits.append(p.decode("latin1", errors="ignore"))
            except Exception:
                pass
    return hits


def find_suspicious_imports(data: bytes) -> List[str]:
    hits = []
    if not data:
        return hits
    lower = data.lower()
    for kw in SUSPICIOUS_IMPORT_KEYWORDS:
        if kw in lower:
            try:
                hits.append(kw.decode("latin1"))
            except Exception:
                hits.append(str(kw))
    return hits


def score_report(report: Dict) -> None:
    """Compute a risk score and reasons list using heuristics."""
    score = 0
    reasons: List[str] = []

    # Known hash
    sha1 = report.get("hashes", {}).get("sha1", "")
    if sha1 and sha1 in KNOWN_HASHES:
        score = max(score, 95)
        reasons.append(f"Known malicious hash: {KNOWN_HASHES[sha1]}")

    # YARA-like pattern hits
    yara_hits = report.get("yara_hits", []) or []
    if yara_hits:
        score += 30
        reasons.append(f"Suspicious signatures/patterns: {', '.join(yara_hits)}")

    # VirusTotal quick lookup (if present)
    vt = report.get("virustotal")
    if vt and isinstance(vt, dict):
        stats = vt.get("vt_stats", {})
        # count positives vs engines
        positives = sum(v for v in stats.values() if isinstance(v, int))
        total_engines = sum(stats.values()) if stats else None
        # use last_analysis_stats if available
        if stats:
            # heuristically boost score if detections exist
            detected_engines = stats.get("malicious", 0) + stats.get("suspicious", 0) if isinstance(stats, dict) else 0
            if detected_engines > 0:
                score = max(score, 80)
                reasons.append(f"VirusTotal reports {detected_engines} engines flagging file")

    # High entropy (possible packer/obfuscation)
    entropy = report.get("entropy", 0.0)
    if entropy >= 7.5:
        score += 20
        reasons.append(f"High entropy ({entropy}) - possible packing/obfuscation")

    # Extension mismatch
    ft = report.get("file_type", {})
    if ft.get("mismatch"):
        score += 20
        reasons.append("Extension/magic mismatch")

    # Suspicious imports (for PE)
    imports = report.get("sus_imports", []) or []
    if imports:
        score += 20
        reasons.append(f"Suspicious imports: {', '.join(imports[:5])}")

    # Dangerous file types (scripts, macros, executable)
    detected = ft.get("detected", "")
    if detected in ("pe",):
        score += 5
    if detected in ("zip",):
        score += 5  # archives sometimes deliver payloads

    # Additional heuristic: very low printable ratio
    pr = report.get("printable_ratio", None)
    if pr is not None and pr < 0.15:
        score += 10
        reasons.append("Very low printable ratio in sample - likely packed/obfuscated")

    # Local clamd scan result
    clamd_res = report.get("clamd")
    if clamd_res:
        # clamd returns tuple with verdict details; treat any non-'OK' as high risk
        if isinstance(clamd_res, dict) and clamd_res.get("result") not in (None, "OK", "ok"):
            score = max(score, 85)
            reasons.append(f"Local ClamAV detection: {clamd_res.get('result')}")

    # Cap score
    score = min(100, score)
    # Level mapping
    level = "LOW"
    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    report["risk"] = score
    report["level"] = level
    # merge reasons with existing unique reasons
    existing = report.get("reasons", []) or []
    report["reasons"] = existing + [r for r in reasons if r not in existing]


def scan(path: str) -> Dict:
    """Enhanced lightweight scanner returning a structured report with heuristics and optional integrations."""
    report = {"path": path, "meta": {}, "hashes": {}, "risk": 0, "level": "LOW", "reasons": [], "yara_hits": []}
    try:
        report["size"] = os.path.getsize(path)
        # compute hashes
        report["hashes"] = compute_hashes(path)
        # entropy (sample)
        report["entropy"] = estimate_entropy(path, sample_size=65536)
        # magic / extension detection
        ft = detect_magic_and_mismatch(path)
        report["file_type"] = {"detected": ft.get("detected", "unknown"), "ext": ft.get("ext", ""), "mismatch": ft.get("mismatch", False)}

        # Read a bounded sample for string/pattern analysis (to avoid huge memory use)
        sample = b""
        try:
            with open(path, "rb") as f:
                sample = f.read(131072)  # 128KB sample
        except Exception:
            sample = b""

        # run local clamd scan if available and initialized
        if CLAMD_AVAILABLE and CLAMD_CLIENT is not None:
            try:
                # clamd returns a dict per file
                clamd_res = CLAMD_CLIENT.scan_file(path)
                # normalize
                report["clamd"] = {"result": clamd_res}
            except Exception:
                report["clamd"] = None

        # pattern / "yara-like" hits (simple)
        yara_hits = scan_patterns_in_bytes(sample, SUSPICIOUS_PATTERNS)
        report["yara_hits"] = yara_hits

        # if yara-python loaded rules, run them for better detection
        if YARA_AVAILABLE and YARA_RULES is not None:
            try:
                matches = YARA_RULES.match(data=sample)
                if matches:
                    for m in matches:
                        # m is a yara.Match object
                        try:
                            report["yara_hits"].append(str(m.rule))
                        except Exception:
                            report["yara_hits"].append(str(m))
            except Exception:
                pass

        # find suspicious imports / API names (simple byte scanning)
        sus_imports = find_suspicious_imports(sample)
        report["sus_imports"] = sus_imports

        # Heuristic: many non-printables + high entropy => possible packed/obfuscated
        printable_ratio = 0.0
        if sample:
            printable = sum(1 for c in sample if 32 <= c <= 126 or c in (9, 10, 13))
            printable_ratio = printable / max(1, len(sample))
        report["printable_ratio"] = round(printable_ratio, 2)
        if printable_ratio < 0.2 and report["entropy"] > 6.8:
            report["reasons"].append("Low printable ratio and elevated entropy - possible binary packer/obfuscator")

        # Simple heuristic: many suspicious strings -> mark as suspect
        if yara_hits:
            report["reasons"].append(f"Pattern hits: {', '.join(yara_hits)}")

        # Check for known-bad hash
        sha1 = report["hashes"].get("sha1", "")
        if sha1 in KNOWN_HASHES:
            report["reasons"].append(f"Known malware hash: {KNOWN_HASHES[sha1]}")

        # VirusTotal lookup (optional)
        sha256 = report["hashes"].get("sha256")
        if sha256:
            vt = vt_lookup_hash(sha256)
            if vt:
                report["virustotal"] = vt

        # If PE and pefile available, try to extract imports for better heuristics
        if ft.get("detected") == "pe":
            peinfo = {"machine": "unknown", "timestamp": int(time.time()), "entry_point": "unknown", "sections": None, "has_overlay": False, "signed": False, "imports": [], "sus_imports": sus_imports, "sections_detail": []}
            if PEFILE_AVAILABLE:
                try:
                    p = pefile.PE(path, fast_load=True)
                    peinfo["machine"] = hex(p.FILE_HEADER.Machine) if hasattr(p, "FILE_HEADER") else "unknown"
                    peinfo["entry_point"] = hex(p.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(p, "OPTIONAL_HEADER") else "unknown"
                    peinfo["sections"] = len(p.sections) if hasattr(p, "sections") else None
                    imports_list = []
                    if hasattr(p, "DIRECTORY_ENTRY_IMPORT"):
                        for entry in p.DIRECTORY_ENTRY_IMPORT:
                            imports_list.append(entry.dll.decode(errors="ignore") if isinstance(entry.dll, bytes) else str(entry.dll))
                    peinfo["imports"] = imports_list
                    # check suspicious imports
                    peinfo["sus_imports"] = [i for i in imports_list if any(k.decode("latin1") in i.lower() for k in SUSPICIOUS_IMPORT_KEYWORDS)]
                except Exception:
                    pass
            else:
                # best-effort: use earlier sus_imports
                peinfo["imports"] = sus_imports
            report["pe_info"] = peinfo

        report["meta"] = {"scanned_at": time.ctime()}

        # finally, compute combined score
        score_report(report)

        # small delay to simulate work
        time.sleep(0.02)
    except Exception as e:
        report["error"] = str(e)
    return report


def quarantine_file(path: str) -> None:
    """Move a file into a local 'quarantine' folder (creates it if needed)."""
    try:
        qdir = os.path.join(os.path.expanduser("~"), ".pineapple_av_quarantine")
        os.makedirs(qdir, exist_ok=True)
        if os.path.exists(path):
            dest = os.path.join(qdir, os.path.basename(path))
            shutil.move(path, dest)
    except Exception as e:
        messagebox.showerror("Quarantine error", str(e))


# ---------- GUI ----------
# Use ttkbootstrap Window if available for modern look, otherwise tk.Tk
BaseWindow = tb.Window if TB_AVAILABLE else tk.Tk
STYLE_NAME = "flatly" if TB_AVAILABLE else None  # default modern theme for tb


class PineappleAV(BaseWindow):
    def __init__(self):
        # tb.Window accepts themename param; tk.Tk does not
        if TB_AVAILABLE:
            super().__init__(themename=STYLE_NAME)
        else:
            super().__init__()

        self.title("Pineapple AV")
        self.geometry("1100x720")
        # Set a pleasant background when not using tb
        if not TB_AVAILABLE:
            self.configure(bg="#F6F7FA")

        # Style
        self.style = tb.Style() if TB_AVAILABLE else ttk.Style(self)
        if TB_AVAILABLE:
            try:
                self.style.theme_use(STYLE_NAME)
            except Exception:
                pass
        else:
            try:
                self.style.theme_use("clam")
            except Exception:
                pass

        # Fonts and sizing
        default_font = ("Segoe UI", 10)
        title_font = ("Segoe UI Semibold", 16)
        mono_font = ("Consolas", 10)

        # Top header
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=12, pady=8)
        lbl_icon = ttk.Label(header, text="🍍", font=("Segoe UI Emoji", 22))
        lbl_icon.pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(header, text="Pineapple AV", font=title_font).pack(side=tk.LEFT)

        # Toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.btn_scan_file = ttk.Button(toolbar, text="Scan File", command=self.scan_file)
        self.btn_scan_file.pack(side=tk.LEFT, padx=6)
        self.btn_scan_folder = ttk.Button(toolbar, text="Scan Folder", command=self.scan_folder)
        self.btn_scan_folder.pack(side=tk.LEFT, padx=6)
        self.btn_quarantine = ttk.Button(toolbar, text="Quarantine Selected", command=self.quarantine_selected)
        self.btn_quarantine.pack(side=tk.LEFT, padx=6)
        self.btn_update = ttk.Button(toolbar, text="Update Signatures", command=self.update_signatures)
        self.btn_update.pack(side=tk.LEFT, padx=6)
        self.btn_clear = ttk.Button(toolbar, text="Clear", command=self.clear_all)
        self.btn_clear.pack(side=tk.LEFT, padx=6)

        # Search box on right
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT)
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 6))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(search_frame, textvariable=self.filter_var, width=28)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_entry.bind("<KeyRelease>", lambda e: self._apply_filter())

        # Main panes
        main_pane = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        # Left: files tree
        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=1)

        cols = ("name", "size", "risk", "level")
        self.tree = ttk.Treeview(left_frame, columns=cols, show="headings", selectmode="browse", height=25)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
        self.tree.column("name", width=420, anchor="w")
        self.tree.column("size", width=110, anchor="center")
        self.tree.column("risk", width=80, anchor="center")
        self.tree.column("level", width=100, anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        # color tags
        try:
            self.tree.tag_configure("low", background="#ffffff")
            self.tree.tag_configure("medium", background="#fff7e6")
            self.tree.tag_configure("high", background="#ffe6e6")
            self.tree.tag_configure("critical", background="#ffd6d6")
        except Exception:
            pass

        tree_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        # Right: notebook with details
        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=2)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Details tab
        self.detail_text = scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD, font=mono_font, state="disabled")
        self.notebook.add(self.detail_text, text="Details")

        # Hex / preview tab
        self.preview_text = scrolledtext.ScrolledText(self.notebook, wrap=tk.NONE, font=mono_font, state="disabled")
        self.notebook.add(self.preview_text, text="Preview")

        # Metadata tab
        self.meta_text = scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD, font=default_font, state="disabled", height=10)
        self.notebook.add(self.meta_text, text="Metadata")

        # Bottom status bar
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=12, pady=(6, 12))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(bottom, textvariable=self.status_var).pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, length=300, mode="determinate")
        self.progress.pack(side=tk.RIGHT)

        # Internal state
        self.reports: Dict[str, Dict] = {}
        self._tree_items: Dict[str, str] = {}  # path -> item id

    # ---------- UI helpers ----------
    def _format_size(self, b: int) -> str:
        for u in ["B", "KB", "MB", "GB"]:
            if b < 1024.0:
                return f"{b:.1f}{u}"
            b /= 1024.0
        return f"{b:.1f}TB"

    def _apply_filter(self):
        q = self.filter_var.get().lower().strip()
        for path, iid in list(self._tree_items.items()):
            report = self.reports.get(path, {})
            name = os.path.basename(path).lower()
            level = report.get("level", "").lower()
            show = (q in name) or (q in level) or (q == "")
            if not show:
                try:
                    self.tree.detach(iid)
                except Exception:
                    pass
            else:
                try:
                    self.tree.reattach(iid, "", "end")
                except Exception:
                    pass

    def _tag_for_level(self, level: str) -> str:
        lvl = (level or "LOW").lower()
        if lvl in ("critical",):
            return "critical"
        if lvl in ("high",):
            return "high"
        if lvl in ("medium",):
            return "medium"
        return "low"

    def _on_tree_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        # select row
        self.tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Quarantine", command=self.quarantine_selected)
        menu.add_command(label="Open containing folder", command=self._open_containing_folder)
        menu.post(event.x_root, event.y_root)

    def _open_containing_folder(self):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        path = None
        for p, idv in self._tree_items.items():
            if idv == iid:
                path = p
                break
        if not path:
            return
        folder = os.path.dirname(path)
        try:
            if os.name == "nt":
                os.startfile(folder)
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception:
            pass

    # ---------- display / detail ----------
    def on_tree_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        path = None
        for p, idv in self._tree_items.items():
            if idv == iid:
                path = p
                break
        if not path:
            return
        report = self.reports.get(path)
        if report:
            self._show_detail(report)

    def _show_detail(self, report: Dict):
        # Details
        self.detail_text.configure(state="normal")
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, f"FILE: {os.path.basename(report.get('path',''))}\n")
        self.detail_text.insert(tk.END, "=" * 80 + "\n")
        self.detail_text.insert(tk.END, f"Risk: {report.get('risk',0)}/100 [{report.get('level','LOW')}]\n\n")
        self.detail_text.insert(tk.END, "Reasons:\n")
        for r in report.get("reasons", []):
            self.detail_text.insert(tk.END, f"  • {r}\n")
        self.detail_text.insert(tk.END, "\nHashes:\n")
        for k, v in report.get("hashes", {}).items():
            self.detail_text.insert(tk.END, f"  {k.upper():6}: {v}\n")
        self.detail_text.insert(tk.END, f"\nSize: {report.get('size',0):,} | Entropy: {report.get('entropy',0)} | Printable(sample): {report.get('printable_ratio','?')}\n")
        ft = report.get("file_type", {})
        self.detail_text.insert(tk.END, f"Type detected: {ft.get('detected','?')} (ext: .{ft.get('ext','')})\n")
        if ft.get("mismatch"):
            self.detail_text.insert(tk.END, "Extension / magic mismatch detected\n")
        if report.get("pe_info"):
            self.detail_text.insert(tk.END, "\nPE Analysis:\n")
            for k, v in report["pe_info"].items():
                if k == "sections_detail":
                    continue
                self.detail_text.insert(tk.END, f"  {k}: {v}\n")
            if report["pe_info"].get("sections_detail"):
                self.detail_text.insert(tk.END, "  Sections:\n")
                for s in report["pe_info"]["sections_detail"]:
                    self.detail_text.insert(tk.END, f"    {s.get('name')}: rsize={s.get('rsize')}, entropy={s.get('entropy')}\n")
        # Virustotal snippet
        vt = report.get("virustotal")
        if vt and isinstance(vt, dict):
            stats = vt.get("vt_stats")
            if stats:
                self.detail_text.insert(tk.END, f"\nVirusTotal last_analysis_stats: {json.dumps(stats)}\n")
        if report.get("clamd"):
            self.detail_text.insert(tk.END, f"\nClamAV: {report.get('clamd')}\n")

        self.detail_text.configure(state="disabled")

        # Metadata
        self.meta_text.configure(state="normal")
        self.meta_text.delete(1.0, tk.END)
        for k, v in report.get("meta", {}).items():
            self.meta_text.insert(tk.END, f"{k}: {v}\n")
        self.meta_text.configure(state="disabled")

        # Preview (hex + ascii sample)
        self.preview_text.configure(state="normal")
        self.preview_text.delete(1.0, tk.END)
        try:
            with open(report["path"], "rb") as f:
                data = f.read(2048)
            # hex dump
            hex_lines = []
            for i in range(0, min(len(data), 2048), 16):
                chunk = data[i:i+16]
                hexpart = " ".join(f"{b:02x}" for b in chunk)
                asc = "".join((chr(b) if 32 <= b <= 126 else ".") for b in chunk)
                hex_lines.append(f"{i:08x}  {hexpart:<48}  {asc}")
            self.preview_text.insert(tk.END, "\n".join(hex_lines))
        except Exception:
            self.preview_text.insert(tk.END, "Unable to open file preview.")
        self.preview_text.configure(state="disabled")

    def display_report(self, report: Dict):
        path = report.get("path")
        if not path:
            return
        self.reports[path] = report
        short = os.path.basename(path)
        size = self._format_size(report.get("size", 0))
        risk = report.get("risk", 0)
        level = report.get("level", "LOW")
        tag = self._tag_for_level(level)
        if path in self._tree_items:
            iid = self._tree_items[path]
            self.tree.item(iid, values=(short, size, str(risk), level), tags=(tag,))
        else:
            iid = self.tree.insert("", "end", values=(short, size, str(risk), level), tags=(tag,))
            self._tree_items[path] = iid
        try:
            self.tree.selection_set(iid)
            self.tree.see(iid)
            self.on_tree_select()
        except Exception:
            pass

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Quarantine", "Select a file first.")
            return
        iid = sel[0]
        path = None
        for p, idv in self._tree_items.items():
            if idv == iid:
                path = p
                break
        if not path:
            return
        quarantine_file(path)
        if not os.path.exists(path):
            self._remove_path_from_ui(path)

    def _remove_path_from_ui(self, path):
        iid = self._tree_items.pop(path, None)
        if iid:
            try:
                self.tree.delete(iid)
            except Exception:
                pass
        self.reports.pop(path, None)

    def clear_all(self):
        self.tree.delete(*self.tree.get_children())
        self.reports.clear()
        self._tree_items.clear()
        for t in (self.detail_text, self.preview_text, self.meta_text):
            t.configure(state="normal")
            t.delete(1.0, tk.END)
            t.configure(state="disabled")
        self.status_var.set("Cleared")
        self.progress["value"] = 0

    # ---------- Scanning actions ----------
    def scan_file(self):
        path = filedialog.askopenfilename(title="Select File to Scan")
        if not path:
            return
        self.status_var.set(f"Scanning {os.path.basename(path)}")
        self.update_idletasks()

        def _worker(p):
            return scan(p)

        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_worker, path)
            report = future.result()

        if "error" in report:
            messagebox.showerror("Error", report["error"])
            self.status_var.set("Idle")
            return
        self.after(0, lambda r=report: (self.display_report(r), self.status_var.set("Idle")))

    def scan_folder(self):
        path = filedialog.askdirectory(title="Select Folder to Scan")
        if not path:
            return
        files = []
        for root, _, fs in os.walk(path):
            for f in fs:
                files.append(os.path.join(root, f))
        if not files:
            messagebox.showinfo("Scan Folder", "No files found.")
            return

        self.status_var.set(f"Scanning folder ({len(files)} files)...")
        self.progress["maximum"] = len(files)
        self.progress["value"] = 0
        self.update_idletasks()

        def _on_result(report):
            self.display_report(report)
            self.progress["value"] += 1
            self.status_var.set(f"Scanned {int(self.progress['value'])}/{int(self.progress['maximum'])}")
            if int(self.progress["value"]) >= int(self.progress["maximum"]):
                self.status_var.set("Folder scan complete")

        # worker pool
        with ThreadPoolExecutor(max_workers=min(8, max(1, os.cpu_count() or 2))) as executor:
            futures = [executor.submit(scan, fp) for fp in files]
            for future in as_completed(futures):
                try:
                    report = future.result()
                except Exception as e:
                    report = {"path": "unknown", "meta": {}, "error": str(e)}
                self.after(0, lambda r=report: _on_result(r))

    def update_signatures(self):
        """Simulate a signature update: refresh in-memory demo DB and try to reload yara rules."""
        self.status_var.set("Updating signatures...")
        self.update_idletasks()

        def _do_update():
            time.sleep(0.6)
            # demo: add a fake hash to the known list to simulate update
            KNOWN_HASHES["da39a3ee5e6b4b0d3255bfef95601890afd80709"] = "empty-file-malware-demo"
            # try to reload yara rules from local file
            load_yara_rules("rules.yar")
            self.after(0, lambda: self.status_var.set("Signatures up to date"))

        with ThreadPoolExecutor(max_workers=1) as ex:
            ex.submit(_do_update)


# initialize optional detectors at module load
load_yara_rules("rules.yar")
init_clamd()

# ...existing code...
if __name__ == "__main__":
    app = PineappleAV()
    app.mainloop()