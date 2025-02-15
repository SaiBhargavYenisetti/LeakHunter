import argparse
import os
from colorama import Fore, Style
from leakhunter import (
    find_sensitive_data_regex,
    find_sensitive_data_yara,

    load_yara_rules,
    check_file_virustotal,
    setup_logging,
    is_binary_file
)

def scan_file(file_path, yara_rules=None, vt_api_key=None):
    """Scan a single file using all available methods"""
    findings = []
    
    try:
        # Skip binary files for content scanning
        if is_binary_file(file_path):
            print(Fore.YELLOW + f"[INFO] Skipping binary file: {file_path}" + Style.RESET_ALL)
            if vt_api_key:
                check_file_virustotal(file_path, vt_api_key)
            return findings

        # Regex scanning
        regex_findings = find_sensitive_data_regex(file_path)
        findings.extend(regex_findings)
        
        # YARA scanning
        if yara_rules:
            yara_findings = find_sensitive_data_yara(file_path, yara_rules)
            findings.extend(yara_findings)
        
        # VirusTotal scanning for all files
        if vt_api_key:
            try:
                check_file_virustotal(file_path, vt_api_key)
            except Exception as e:
                print(Fore.RED + f"[ERROR] VirusTotal scan failed: {str(e)}" + Style.RESET_ALL)
        
        return findings
    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to scan {file_path}: {str(e)}" + Style.RESET_ALL)
        return findings

def scan_directory(directory, yara_rules=None, vt_api_key=None):
    """Scan a directory recursively"""
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_findings = scan_file(file_path, yara_rules, vt_api_key)
            findings.extend(file_findings)
    return findings

def main():
    parser = argparse.ArgumentParser(description="LeakHunter - Advanced Sensitive Data Scanner")
    parser.add_argument('--path', required=True, help="File or directory to scan")
    parser.add_argument('--yara', help="Path to YARA rules file")
    parser.add_argument('--virustotal', action='store_true', help="Enable VirusTotal scanning")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging")
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(level='DEBUG' if args.debug else 'INFO')
    
    # Load YARA rules if specified
    yara_rules = None
    if args.yara:
        yara_rules = load_yara_rules(args.yara)
        if not yara_rules:
            return
    
    # Get VirusTotal API key if enabled
    vt_api_key = None
    if args.virustotal:
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not vt_api_key:
            print(Fore.RED + "[ERROR] VIRUSTOTAL_API_KEY environment variable not set" + Style.RESET_ALL)
            return
    
    print(Fore.CYAN + "\n🔍 LeakHunter - Scanning for sensitive data...\n" + Style.RESET_ALL)
    
    # Perform scanning
    if os.path.isdir(args.path):
        findings = scan_directory(args.path, yara_rules, vt_api_key)
    elif os.path.isfile(args.path):
        findings = scan_file(args.path, yara_rules, vt_api_key)
    else:
        print(Fore.RED + f"[ERROR] {args.path} is not a valid file or directory" + Style.RESET_ALL)
        return
    
    # Print results
    if findings:
        print(Fore.YELLOW + "\n⚠️  Potential leaks found:\n" + Style.RESET_ALL)
        for finding in findings:
            print(f"{Fore.RED}[LEAK] {finding[0]} found in {finding[1]} "
                  f"(Line {finding[2]}): {finding[3]}{Style.RESET_ALL}")
    else:
        print(Fore.GREEN + "✅ No sensitive data found!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()