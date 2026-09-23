import os
from pathlib import Path
from colorama import Fore, Style

def find_log_files(directory_path):
    """Traverses the directory to find .evtx and text/log files."""
    log_files = {"evtx": [], "text": []}
    target_dir = Path(directory_path)
    
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"{Fore.RED}Error: The path '{directory_path}' is invalid.{Style.RESET_ALL}")
        return log_files

    print(f"{Fore.CYAN}Scanning directory: {target_dir}{Style.RESET_ALL}")
    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = Path(root) / file
            extension = file_path.suffix.lower()
            
            if extension == '.evtx':
                log_files["evtx"].append(file_path)
            elif extension in ['.txt', '.log']:
                log_files["text"].append(file_path)

    print(f"{Fore.GREEN}Scan complete! Found {len(log_files['evtx'])} .evtx files and {len(log_files['text'])} text files.{Style.RESET_ALL}\n")
    return log_files