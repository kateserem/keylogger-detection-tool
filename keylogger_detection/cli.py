# Command-line interface for the keylogger detection tool.
# It parses arguments and invokes the detection function.
# controls how often to rescan, output format, verbosity, etc.

import time # for sleep
import argparse # for command-line argument parsing
from datetime import datetime, timezone # for timestamps

# IMPORTANT: package-relative import (works when run as a module)
from .detect import detect_keylogger


def parse_arguments() -> argparse.Namespace:
    '''
    parse command-line arguments for the keylogger detection tool.
    allows user to specify scan interval, output format, verbosity, etc.
    '''
    parser = argparse.ArgumentParser(
        description="Keylogger Detection Tool — scan processes and log suspicious activity"
    )


    parser.add_argument("--interval", type=int, default=0,
                        help="Rescan interval in seconds (0 = run once and exit)")
    # If interval > 0, the tool will run indefinitely, rescanning every interval seconds.

    parser.add_argument("--verbose", action="store_true",
                        help="Print details about scanning and detections")
    # If set, the tool will print more detailed information during scanning.

    parser.add_argument("--append", action="store_true",
                        help="Append new scan records to the output file")
    # If set, new scan results will be appended to the output file instead of overwriting it.

    parser.add_argument("--ndjson", action="store_true",
                        help="Write as NDJSON (one JSON object per line). Recommended.")
    # If set, the output will be in NDJSON format (one JSON object per line) to evidence/detection.json.

    parser.add_argument("--output", default="evidence/detection.json",
                        help="Output path (.json or .ndjson). If --ndjson, extension will switch to .ndjson")
    # Specifies the output file path. Default is evidence/detection.json.

    parser.add_argument("--open-files", action="store_true",
                        help="Enable open-file heuristic (flag processes with suspicious open files)")
    # If set, the tool will flag processes that have suspicious open files.

    parser.add_argument("--susp-dir", action="append", default=[],
                        help="Extra suspicious directory (repeatable)")
    # Allows specifying additional directories to consider suspicious from the terminal.

    parser.add_argument("--susp-name", action="append", default=[],
                        help="Extra suspicious filename glob pattern, e.g. *.dat (repeatable)")
    # Allows specifying additional filename patterns to consider suspicious from the terminal.

    parser.add_argument("--pid", type=int,
                        help="Scan a single process by PID")
    # If set, the tool will only scan the specified process ID.

    parser.add_argument("--lineage", action="store_true",
                        help="Include parent lineage + severity scoring")
    # If set, the tool will include parent process lineage and severity scoring in the output.

    parser.add_argument("--show-severity", choices=["any", "clean", "low", "medium", "high"],
                        default="any",
                        help="Filter displayed/saved processes by lineage severity (use with --lineage)")
    # If set, the tool will filter displayed/saved processes by lineage severity.
        # "any" shows all, "clean" shows only clean processes, "low", "medium", "high" show processes with respective severity levels.
            # Only applicable if --lineage is also set.

    return parser.parse_args()


def main():
    '''
    main function to run the keylogger detection tool.
    parses arguments and runs detection in a loop if interval > 0.
    '''
    args = parse_arguments() 

    print("\n[+] Starting Keylogger Detection Tool\n")

    # Main loop: run detection, then wait for interval seconds if specified.
    while True:
        print(f"[+] Scan started at {datetime.now(timezone.utc).isoformat()}")

        detect_keylogger(
            verbose=args.verbose,
            output=args.output,
            append=args.append,
            ndjson=args.ndjson,
            open_files=args.open_files,
            susp_dirs=args.susp_dir,
            susp_names=args.susp_name,
            pid=args.pid,
            lineage=args.lineage,
            show_severity=args.show_severity,
        )

        # If interval <= 0, exit after one scan.
        if args.interval <= 0:
            break

        print(f"[+] Waiting {args.interval} seconds before next scan...\n")
        print("-" * 60)
        time.sleep(args.interval) # Wait before next scan.


if __name__ == "__main__":
    # When you run: python -m keylogger_detector.cli
    main()
