import os
from pathlib import Path
from colorama import Fore, Style


def find_log_files(directory_path):
    """Traverses the directory to find .evtx files and text logs (.txt, .log, .json, .jsonl).

    Directories that can't be read (for example, permission denied) are recorded
    under "unreadable" so they can be flagged for manual review."""
    log_files = {"evtx": [], "text": [], "unreadable": []}
    target_dir = Path(directory_path)

    if not target_dir.exists() or not target_dir.is_dir():
        print(f"{Fore.RED}Error: The path '{directory_path}' is invalid.{Style.RESET_ALL}")
        return log_files

    def record_unreadable(error):
        # os.walk silently skips unreadable directories unless given an onerror handler
        log_files["unreadable"].append((str(error.filename), error.strerror or str(error)))

    print(f"{Fore.CYAN}Scanning directory: {target_dir}{Style.RESET_ALL}")
    for root, _, files in os.walk(target_dir, onerror=record_unreadable):
        for file in files:
            file_path = Path(root) / file
            extension = file_path.suffix.lower()

            if extension == '.evtx':
                log_files["evtx"].append(file_path)
            elif extension in ['.txt', '.log', '.json', '.jsonl']:
                log_files["text"].append(file_path)

    print(f"{Fore.GREEN}Scan complete! Found {len(log_files['evtx'])} .evtx files and {len(log_files['text'])} text files.{Style.RESET_ALL}")
    if log_files["unreadable"]:
        print(f"{Fore.RED}{len(log_files['unreadable'])} directories could not be read and will be flagged.{Style.RESET_ALL}")
    print()
    return log_files
