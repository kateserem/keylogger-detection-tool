# for writing detection results to JSON files

import json # for JSON file writing
from datetime import datetime, timezone # for timestamps
from pathlib import Path # for path manipulations

def save_to_json(data, filename="evidence/detections.ndjson", append=True, ndjson=True):
    """
    preferred default: NDJSON + append.
    Writes one compact JSON record per scan (even if detections == []).
    """
    Path("evidence").mkdir(exist_ok=True) # ensure evidence/ directory exists

    # ensure .ndjson extension if writing NDJSON enabled
    if ndjson and not filename.endswith(".ndjson"):
        if filename.endswith(".json"): # if ends with .json, replace with .ndjson
            filename = filename[:-5] + ".ndjson" # remove .json, add .ndjson
        else:
            filename = filename + ".ndjson" #otherwise just add .ndjson

    # record to write into evidence file
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detections": data
    }

    # NDJSON mode — compact, one line per scan
    if ndjson:
        mode = "a" if append else "w" #if append, use "a", else "w" to overwrite

        # write one line per scan
        with open(filename, mode, encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")  # one line per scan
        print(f"[+] Evidence written (NDJSON) to {filename}")
        return

    # pretty JSON mode — eaasier to read
    existing = []
    path = Path(filename)

    # if appending and file exists, load existing data
    if append and path.exists():
        try:
            # load existing data 
            with open(path, "r", encoding="utf-8") as f: # read existing file
                loaded = json.load(f) # load JSON data
            existing = loaded if isinstance(loaded, list) else [loaded] # ensure list
        except (json.JSONDecodeError, OSError):
            existing = [] # if error, start fresh

    # append new record and write back to file
    existing.append(record)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    print(f"[+] Evidence saved to {filename}")
