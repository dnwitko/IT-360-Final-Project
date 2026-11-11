import colorama
from scanner import find_log_files
from parser import process_logs
from grapher import generate_event_graph

def main():
    colorama.init(autoreset=True)
    
    test_path = input("Enter a folder path to scan (or press Enter to scan the current directory): ")
    if not test_path.strip():
        test_path = "."
        
    found_logs = find_log_files(test_path)
    
    if found_logs["evtx"] or found_logs["text"]:
        # Capture the returned data from the parser
        miner, flagged_files = process_logs(found_logs)
        
        # Pass the parsed data into the NetworkX grapher
        if miner:
            graph = generate_event_graph(miner)
    else:
        print("No logs to process.")

if __name__ == "__main__":
    main()