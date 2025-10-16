#defines global constants used in keylogger detection
# includes allowlist of safe processes, default suspicious directories and filename patterns

import os # for os.path and environment variable expansion

# Allowed system processes that should not be flagged
ALLOWLIST = {
    "system idle process", "system",
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "wininit.exe", "winlogon.exe", "csrss.exe", "smss.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "onedrive.exe", "code.exe"
}

# Default suspicious directories where keyloggers often hide
DEFAULT_SUSP_DIRS = [
    os.path.expandvars(r"%APPDATA%"),
    os.path.expandvars(r"%LOCALAPPDATA%"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\\AppData\\Roaming"),
    os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Temp"),
]

# Suspicious filename patterns
DEFAULT_SUSP_NAMES = ["*.log", "*.txt", "key*", "*keystroke*", "*password*", "*.dat"]
