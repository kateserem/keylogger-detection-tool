# contains the main detection logic for identifying potential keylogger processes
# uses psutil to inspect running processes, their open files, and parent lineage

import os # for os.path
import fnmatch # for filename pattern matching
import psutil # for process inspection

from .constants import ALLOWLIST, DEFAULT_SUSP_DIRS, DEFAULT_SUSP_NAMES # global constants
from .io_utils import save_to_json # for saving results
from .lineage import collect_lineage, score_lineage # for parent lineage and scoring

MAX_PRINT_HITS = 10  # max number of open file hits to print per process

def check_open_files(process, extra_dirs=None, extra_names=None):
    """
    return a list of suspicious open file paths held by the process
    - extra_dirs: list of additional directories to treat as suspicious
    - extra_names: list of filename glob patterns to match as suspicious)
    """
    hits = [] # list of suspicious open file paths found
    names = DEFAULT_SUSP_NAMES + (extra_names or []) # combined suspicious filename patterns
    dirs = [d for d in (DEFAULT_SUSP_DIRS + (extra_dirs or [])) if d] # combined suspicious directories

    try:
        # check each open file
        for openFile in process.open_files() or []:
            path = (openFile.path or "").strip()
            if not path: # skip empty paths
                continue

            # does path start with any suspicious dir?
            for d in dirs:
                try:
                    if path.lower().startswith(d.lower()):
                        hits.append(path) # found a hit
                        break
                except Exception:
                    continue

            # does filename match any suspicious pattern?
            base = os.path.basename(path).lower()
            for pattern in names:
                try:
                    if fnmatch.fnmatch(base, pattern.lower()):
                        hits.append(path) # found a hit
                        break
                except Exception:
                    continue

    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass

    # remove duplicates 
    return list(dict.fromkeys(hits))

def get_context(process):
    """
    get process context used in output artifacts.
    """
    context = {
        "pid": None, "name": None, "exe": None, "cmdline": None,
        "username": None, "ppid": None, "parent_name": None
    }

    try:
        # get basic info
        info = process.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'username', 'ppid']) 
        context.update(info) 

        # if cmdline is a list, join into a single string
        if isinstance(context.get("cmdline"), list):
            context["cmdline"] = ' '.join(context["cmdline"])

        # if parent exists, get its name
        if context.get("ppid"):
            try:
                parent = psutil.Process(context["ppid"]) 
                context["parent_name"] = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        return context
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def detect_keylogger(
    verbose=False,
    output="evidence/detection.json",
    append=False,
    ndjson=False,
    open_files=False,
    susp_dirs=None,
    susp_names=None,
    pid=None,
    lineage=False,
    show_severity="any"
):
    """
    main detection logic. Filters by severity when lineage=True.
    """
    suspicious_processes = ['keylogger', 'logkeys', 'xinput']
    detections = []

    # if specific PID given, only scan that process
    if pid:
        try:
            process_list = [psutil.Process(pid)]
        except psutil.NoSuchProcess:
            print(f"[!] No process found with PID {pid}\n")
            save_to_json([], filename=output, append=append, ndjson=ndjson)
            return
    else: # otherwise, scan all processes
        process_list = psutil.process_iter(['pid', 'name'])

    # loop through processes
    for process in process_list:
        try:
            # get process name and pid
            if hasattr(process, "info"):
                name_raw = process.info.get("name")
                pid_val  = process.info.get("pid")
            else: # if no info attribute, do to direct calls
                name_raw = process.name()
                pid_val  = process.pid

            process_name = (name_raw or "").lower() #name to lowercase

            # if verbose, print process being scanned
            if verbose:
                print(f"Scanning: {process_name} (PID: {pid_val})")

            # get full command line, if available
            try:
                raw_cmd = process.cmdline() or []
                cmdline = " ".join(raw_cmd).lower()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                cmdline = ""

            # check open files if --open-files is set
            open_hits = check_open_files(
                process,
                extra_dirs=susp_dirs,
                extra_names=susp_names
            ) if open_files else []

            # skip safe allowlist unless it has suspicious open files
            if process_name in ALLOWLIST and not open_hits:
                continue

            # skip if no suspicious name or cmdline and no suspicious open files
            name_or_cmd_sus = any(k in process_name or k in cmdline for k in suspicious_processes)
            is_suspicious = name_or_cmd_sus or (len(open_hits) > 0)
            if not is_suspicious:
                continue

            # get process context
            context = get_context(process)
            if not context:
                continue
            if open_hits:
                context["open_files_hits"] = open_hits

            # if --lineage is set, collect parent lineage and score it
            if lineage:
                try:
                    target_node, lineage_list = collect_lineage(process, depth=4) # up to 4 levels
                    eval_result = score_lineage(target_node, lineage_list) # score the lineage for severity (clean, low, medium, high)

                    # add lineage info to context
                    context["parent_lineage"] = {
                        "target": target_node,
                        "lineage": lineage_list,
                        **eval_result
                    }

                    # filter by severity if --show-severity is set
                    if show_severity and show_severity != "any":
                        sev = eval_result.get("severity", "clean") # default to clean if missing
                        if sev != show_severity: #otherwise skip
                            if verbose: #if verbose, print skipping info
                                print(f"[i] Skipping PID {context.get('pid')} (severity {sev} != {show_severity})")
                            continue
                    
                    # if verbose, print lineage and score
                    if verbose:
                        print(f"    Lineage score: {eval_result['score']}  severity: {eval_result['severity']}  hits: {eval_result['rule_hits']}")
                        print("    Lineage (top-down):")
                        tname = (target_node.get('name') or '')
                        tcat  = (target_node.get('exe_dir_category') or 'Other')
                        print(f"      target:  {tname}  [{tcat}]")
                        for i, node in enumerate(lineage_list, start=1):
                            nname = node.get('name') or ''
                            ncat  = node.get('exe_dir_category') or 'Other'
                            print(f"      parent {i}: {nname}  [{ncat}]")
                        print("-" * 60)
                except Exception:
                    # if any error occurs in lineage collection/scoring, just continue without it
                    pass

            # if --verbose is set, print detailed info about the suspicious process
            if verbose:
                print()
                print("[!] Suspicious process found:")
                print(f"    Name:   {context.get('name')}   PID: {context.get('pid')}")
                print(f"    Exe:    {context.get('exe')}")
                print(f"    User:   {context.get('username')}")
                print(f"    Parent: {context.get('parent_name')}  (PPID: {context.get('ppid')})")
                print(f"    Cmd:    {context.get('cmdline')}")

                # if suspicious open files found, print them (up to MAX_PRINT_HITS)
                if open_hits:
                    print(f"    Open files (suspicious): {len(open_hits)} hit(s)")
                    for p in open_hits[:MAX_PRINT_HITS]:
                        print(f"      - {p}")
                    if len(open_hits) > MAX_PRINT_HITS: # if too many, indicate more exist
                        print(f"      ... and {len(open_hits) - MAX_PRINT_HITS} more")
                print("-" * 60)

            detections.append(context)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # process ended or restricted — skip
            continue

    # if any detections found, print how many and save to output file (evidence/detection.json by default)
    if detections:
        print(f"[+] {len(detections)} suspicious process(es) detected this scan.")
    else: # if none found, print no suspicious processes found
        print("[+] No suspicious processes found.")
    print("\n[+] Keylogger detection complete.\n")

    # always!! log a record (even if empty) for audit trail
    if not detections:
        print("[+] No suspicious processes detected — logging empty record for audit trail.")
        detections = []

    # save results to JSON file
    save_to_json(detections, filename=output, append=append, ndjson=ndjson)
