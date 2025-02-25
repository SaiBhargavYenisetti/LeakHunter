import os
import re
from colorama import Fore, Style
from .yara_scanner import load_yara_rules, find_sensitive_data_yara  # Correct relative import
def find_sensitive_data_regex(file_path):
    patterns = {
        "API Key": r'(?i)(?:api[_-]?key|apikey|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
        "Email": r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        "Password": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9@#$%^&+=]{4,})["\']?',
        "Credit Card": r'\b(?:\d[ -]*?){13,16}\b'
    }
    
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            lines = content.split('\n')
            for i, line in enumerate(lines, start=1):
                for data_type, pattern in patterns.items():
                    matches = re.findall(pattern, line)
                    if matches:
                        findings.append((data_type, file_path, i, matches))
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not read {file_path}: {e}" + Style.RESET_ALL)
    
    return findings

def scan_file(file_path, yara_rules=("rules/sensitive_data_yar")):
    if not os.path.isfile(file_path):
        print(Fore.RED + f"[ERROR] {file_path} is not a valid file." + Style.RESET_ALL)
        return []
    
    print(Fore.BLUE + f"Scanning {file_path}..." + Style.RESET_ALL)
    findings = find_sensitive_data_regex(file_path)
    
    if yara_rules:
        yara_findings = find_sensitive_data_yara(file_path, yara_rules)
        findings.extend(yara_findings)
    
    return findings

def scan_directory(directory, yara_rules=None):
    if not os.path.isdir(directory):
        print(Fore.RED + f"[ERROR] {directory} is not a valid directory." + Style.RESET_ALL)
        return []
    
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.txt', '.csv', '.json', '.env', '.py', '.js', '.config')):
                file_path = os.path.join(root, file)
                findings.extend(scan_file(file_path, yara_rules))
    
    return findings