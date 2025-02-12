# main.py
import argparse
import os
from leakhunter import scan_directory, scan_file, load_yara_rules, check_virustotal
from colorama import Fore, Style

def main():
    parser = argparse.ArgumentParser(description="LeakHunter - A Simple Sensitive Data Scanner")
    parser.add_argument('--path', required=True, help="Directory or file path to scan")
    parser.add_argument('--yara', help="Path to YARA rules file")
    parser.add_argument('--virustotal', action='store_true', help="Enable VirusTotal file reputation checks")
    args = parser.parse_args()

    if args.virustotal and not VIRUSTOTAL_API_KEY:
        print(Fore.RED + "[ERROR] VirusTotal API key is missing." + Style.RESET_ALL)
        return

    if args.yara:
        rules = load_yara_rules(args.yara)
        if not rules:
            return

    print(Fore.CYAN + "\n🔍 LeakHunter - Scanning for sensitive data...\n" + Style.RESET_ALL)

    if os.path.isdir(args.path):
        results = scan_directory(args.path)
    elif os.path.isfile(args.path):
        results = scan_file(args.path)
    else:
        print(Fore.RED + f"[ERROR] {args.path} is not a valid directory or file." + Style.RESET_ALL)
        return

    if results:
        print(Fore.YELLOW + "\n⚠️  Potential leaks found:\n" + Style.RESET_ALL)
        for data_type, file, line_no, matches in results:
            print(Fore.RED + f"[LEAK] {data_type} found in {file} (Line {line_no}): {matches}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "✅ No sensitive data found!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()