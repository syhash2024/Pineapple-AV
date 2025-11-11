# Pineapple-AV
Pineapple AV is a lightweight, open-source antivirus scanner built in Python. It provides on-demand scanning for files and folders, detecting potential malware through hashes, entropy analysis, pattern matching, and optional advanced integrations.
**This is not a full commercial AV replacement. It lacks real-time protection and relies on user-submitted scans. Use it alongside established AV software.**

* On-Demand Scanning: Scan individual files or entire folders with multi-threaded support for efficiency.
* Hash Detection: Computes MD5, SHA1, SHA256; checks against known-bad hashes (expandable via JSON).
* Heuristic Analysis: Entropy estimation, printable ratio, extension/magic mismatch.
* Pattern Matching: Simple byte/string searches for suspicious APIs and commands; optional full YARA support.
* PE File Parsing: Basic PE analysis (sections, imports, overlay); enhanced with pefile if installed.
* File Type Detection: Magic bytes; enhanced with python-magic if available.
* VirusTotal Integration: Optional hash lookups (requires API key and requests).
* ClamAV Support: Local ClamAV daemon integration via python-clamd if available.
* Quarantine: Move suspicious files to a safe folder.
* Signature Updates: Demo update mechanism; reloads from local JSON or YARA files.
* GUI: Modern Tkinter interface with tree view, details tabs (metadata, preview), filtering, and right-click actions.
* Cross-Platform: Works on Windows/Linux/macOS (tested on Python 3.8+).
* Extensible: Easily add more signatures, rules, or integrations.
