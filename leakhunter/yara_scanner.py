# yara_scanner.py
import yara
from colorama import Fore, Style

def load_yara_rules(rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
        print("[DEBUG] YARA rules loaded successfully")
        return rules
    except yara.Error as e:
        print(Fore.RED + f"[ERROR] Failed to load YARA rules: {e}" + Style.RESET_ALL)
        return None

def find_sensitive_data_yara(file_path, rules):
    findings = []
    try:
        print(f"[DEBUG] Scanning {file_path} with YARA...")
        matches = rules.match(file_path)
        if not matches:
            print(f"[DEBUG] No matches found in {file_path}")
            return findings
        
        # Just return the rule names that matched
        for match in matches:
            findings.append((match.rule, file_path, 0, "YARA rule matched"))
            print(f"[DEBUG] Match found: Rule {match.rule}, File: {file_path}")
        
        return findings
    except Exception as e:
        print(Fore.RED + f"[ERROR] YARA scan failed for {file_path}: {e}" + Style.RESET_ALL)
        return []