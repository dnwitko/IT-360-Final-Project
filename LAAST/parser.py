from evtx import PyEvtxParser
from drain3 import TemplateMiner
from colorama import Fore, Style

def parse_evtx_file(file_path):
    """Attempts to parse a Windows Event Log file."""
    try:
        parser = PyEvtxParser(str(file_path))
        records_processed = sum(1 for _ in parser.records())
        return True, records_processed
    except Exception as e:
        return False, str(e)

def parse_text_file(file_path, miner):
    """Attempts to parse a text/log file using Drain3."""
    try:
        lines_processed = 0
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line:
                    miner.add_log_message(line)
                    lines_processed += 1
        return True, lines_processed
    except Exception as e:
        return False, str(e)

def process_logs(found_logs):
    """Processes all found logs and flags un-analyzable files."""
    flagged_files = []
    miner = TemplateMiner()
    
    print(f"{Fore.YELLOW}--- Starting Log Parsing ---{Style.RESET_ALL}")
    
    for evtx_path in found_logs["evtx"]:
        print(f"Parsing [EVTX]: {evtx_path.name}...", end=" ")
        success, result = parse_evtx_file(evtx_path)
        if success:
            print(f"{Fore.GREEN}Success ({result} records){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed! Flagging for manual review.{Style.RESET_ALL}")
            flagged_files.append({"file": str(evtx_path), "error": result})

    for text_path in found_logs["text"]:
        print(f"Parsing [TEXT]: {text_path.name}...", end=" ")
        success, result = parse_text_file(text_path, miner)
        if success:
            print(f"{Fore.GREEN}Success ({result} lines mined){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed! Flagging for manual review.{Style.RESET_ALL}")
            flagged_files.append({"file": str(text_path), "error": result})

    if found_logs["text"]:
        print(f"\n{Fore.CYAN}Drain3 generated {len(miner.drain.clusters)} unique log templates.{Style.RESET_ALL}")

    if flagged_files:
        print(f"\n{Fore.RED}--- Flagged Files (Requires Manual Review) ---{Style.RESET_ALL}")
        for flagged in flagged_files:
            print(f"File: {flagged['file']}\nReason: {flagged['error']}\n")

    # Return the data so the grapher and LLM can use it later
    return miner, flagged_files