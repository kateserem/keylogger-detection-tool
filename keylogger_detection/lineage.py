# for process lineage collection and scoring

import os # for os.path and environment variable expansion
import re # for long base64-like string detection
import psutil # for process info

def normalize_cmdline(cmd, max_len=512):
    """
    clean up command-line text:
    - lowercases
    - collapses extra spaces
    - replaces long base64-like blobs with <base64>
    - trims overly long lines
    """
    cmd = (cmd or "").strip().lower() 
    cmd = re.sub(r"\s+", " ", cmd)
    cmd = re.sub(r"[A-Za-z0-9+/]{40,}={0,2}", "<base64>", cmd)
    if len(cmd) > max_len:
        cmd = cmd[:max_len] + "…"
    return cmd

def path_bucket(p):
    """
    categorize where a program lives on disk
    """

    if not p: #if path is empty or None
        return "Other" #return Other
    
    # pl =
    pl = p.lower() 

    if r"\windows\system32" in pl: return "System32"
    if r"\windows" in pl: return "Windows"
    if r"\program files" in pl or r"\program files (x86)" in pl: return "ProgramFiles"
    if r"\appdata\local\temp" in pl or r"\temp" in pl: return "Temp"
    if r"\downloads" in pl: return "Downloads"
    if r"\onedrive" in pl: return "OneDrive"

    # if user profile in path, return UserProfile
    try:
        if os.path.expandvars(r"%userprofile%").lower() in pl:
            return "UserProfile"
    except Exception:
        pass

    # if networkk share starting with \\ in path, return NetworkShare
    if pl.startswith(r"\\"): return "NetworkShare"
    return "Other"

def collect_lineage(proc, depth=4):
    """
    build an ancestry chain for a process
    returns: (target_node, lineage_list)
      - target_node: info about the process you asked for
      - lineage_list: [parent, grandparent, ...] up to depth = default 4
    stops early if no more parents, or access denied, or PID 0, or parent started after child 
    """

    def node_from(p):
        ''' extract relevant info from a psutil.Process object '''

        try: name = (p.name() or "").lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess): name = ""
        try: exe = (p.exe() or "")
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess): exe = ""
        try:
            raw = p.cmdline() or []
            cmd = " ".join(raw)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            cmd = ""
        return {
            "name": name,
            "pid": getattr(p, "pid", None),
            "exe_path": exe,
            "cmdline_norm": normalize_cmdline(cmd),
            "exe_dir_category": path_bucket(exe),
        }

    target = node_from(proc) # info about the target process
    lineage = []
    current = proc

    # for each level up to depth
    for _ in range(depth):
        ''' get parent process '''
        try:
            ppid = current.ppid()
            if not ppid or ppid == 0:
                break
            parent = psutil.Process(ppid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            break

        node = node_from(parent) # extract info from parent

        if not node:
            break

        # if parent started after child, break
        try:
            if parent.create_time() > current.create_time():
                break
        except Exception:
            pass

        # add to lineage and move up
        lineage.append(node)
        current = parent

    return target, lineage

def score_lineage(target, lineage):
    """
    assign simple rule hits and a score based on target + its immediate parent.
    returns: {"rule_hits": [...], "score": N, "severity": "low|medium|high|clean"}
    """

    hits, score = [], 0
    tname = (target.get("name") or "")
    tcat  = (target.get("exe_dir_category") or "Other")
    tcmd  = (target.get("cmdline_norm") or "")
    texe  = (target.get("exe_path") or "")

    parent = lineage[0] if lineage else {}
    pname = (parent.get("name") or "")

    # P1: office/Browser spawning script tools 
        # if parent is office or browser and target is script tool
    office = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    browsers = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}
    script_tools = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
    if pname in office.union(browsers) and tname in script_tools:
        hits.append("P1"); score += 3

    # P4: executable lives in Temp/Downloads/OneDrive 
        # if target lives in Temp, Downloads, or OneDrive
    if tcat in {"Temp", "Downloads", "OneDrive"}:
        hits.append("P4"); score += 2

    # P5: encoded/obfuscated command-line
        # if target cmdline has <base64>
    if "<base64>" in tcmd:
        hits.append("P5"); score += 3

    # P7: execution from a network share
        # if target lives in NetworkShare or exe path starts with \\
    if tcat == "NetworkShare" or texe.startswith("\\\\"):
        hits.append("P7"); score += 3

    # Total score and severity
    if score >= 6: sev = "high" 
    elif score >= 3: sev = "medium"
    elif score >= 1: sev = "low"
    else: sev = "clean"

    return {"rule_hits": hits, "score": score, "severity": sev}
