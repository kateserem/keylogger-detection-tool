# Keylogger Detection Tool

  - A Python-based tool that scans running processes to detect suspicious behavior indicating a keylogger
  - Identifies processes based on their names, file activity, and ancestry (parent/child lineage)
  - results are saved in JSON or NDJSON format for analysis and auditing

# Features

 - Detects suspicious processes by:
    - Process name
    - Command-line 
    - Suspicious open files ('.log', '.txt', etc...)
    - Suspicious Directories ('Temp', 'AppData', 'Downloads', etc...)
    - Parent-child lineage scoring (process ancestry)
 - Outputs JSON/NDJSON logs with timestamps
 - Supports repeated scanning intervals
 - Command-line interface for flexible control
 - utilize psutil

# Repository Structure
    keylogger-detection-tool/
    │
    ├── keylogger_detection/
    │ ├── init.py # marks the folder as a package
    │ ├── cli.py # command-line interface (main)
    │ ├── detect.py # core detection logic
    │ ├── io_utils.py # JSON/NDJSON saving utilities
    │ ├── lineage.py # process lineage + severity scoring
    │ ├── constants.py # allowlist, suspicious dirs, and filename patterns
    │
    ├── evidence/ # Auto-created for saved logs
    │ └── detection.ndjson # example output file (after first scan)
    │
    ├── README.md 

# Installation

 - git clone https://github.com/kateserem/keylogger-detection-tool.git
 - cd keylogger-detection-tool

# Install Dependencies 

 - pip install psutil

# How to run

 - python -m keylogger_detection.cli --verbose --lineage --ndjson

  | Flag                    | Description                                         |
  | ----------------------- | --------------------------------------------------- |
  | `--verbose`             | show detailed scan output                           |
  | `--lineage`             | include parent lineage + severity scoring           |
  | `--open-files`          | enable open-file heuristic                          |
  | `--interval N`          | repeat scans every N seconds                        |
  | `--pid <num>`           | scan a single process by PID                        |
  | `--show-severity <lvl>` | filter by severity (`any`, `low`, `medium`, `high`) |
  | `--ndjson`              | output newline-delimited JSON                       |
  | `--output <path>`       | custom output file path                             |
  | `--append`              | append to existing log instead of overwrite         |
  | `--susp-dir`            | add extra suspicious directory                      |
  | `--susp-name`           | add extra suspicious filename pattern               |


# Example Commands

 - Save Once and Save as NDJSON
     - python -m keylogger_detection.cli --verbose --ndjson
  
 - Continuous Scan (every 60 seconds)
     - python -m keylogger_detection.cli --interval 60 --lineage --open-files
  
 - Target a Single Process
     - python -m keylogger_detection.cli --pid 1234 --verbose

# Output Example

**Example `detection.ndjson` entry:**

  ```json
  {
    "timestamp": "2025-10-16T21:45:00Z",
    "detections": [
      {
        "pid": 4820,
        "name": "logkeys.exe",
        "exe": "C:\\Users\\Kate\\AppData\\Local\\Temp\\logkeys.exe",
        "username": "Kate",
        "cmdline": "logkeys.exe --start",
        "parent_name": "explorer.exe",
        "open_files_hits": ["C:\\Users\\Kate\\AppData\\Roaming\\keys.txt"],
        "parent_lineage": {
          "score": 5,
          "severity": "medium",
          "rule_hits": ["P4", "P5"]
        }
      }
    ]
  }
  ```

# Author

  Kate Serem:
  
  Computer Engineering and Cybersecurity, Texas A&M University
  
  github: kateserem
  





















  
