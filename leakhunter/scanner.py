import os
import re
from colorama import Fore, Style

def find_sensitive_data(file_path):
    patterns = {
        "API Key": r'(?i)(?:api_key|apikey|aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
        "Email": r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        "Password": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9@#$%^&+=]{4,})["\']?',
        "Credit Card": r'\b(?:\d[ -]*?){13,16}\b'
    }
    
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                for data_type, pattern in patterns.items():
                    matches = re.findall(pattern, line)
                    if matches:
                        findings.append((data_type, file_path, i, matches))
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not read {file_path}: {e}" + Style.RESET_ALL)
    
    return findings

def scan_directory(directory):
    sensitive_data = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.txt', '.csv', '.json', '.env')):
                file_path = os.path.join(root, file)
                print(Fore.BLUE + f"Scanning {file_path}..." + Style.RESET_ALL)
                sensitive_data.extend(find_sensitive_data(file_path))
    return sensitive_data

def scan_file(file_path):
    if os.path.isfile(file_path):
        print(Fore.BLUE + f"Scanning {file_path}..." + Style.RESET_ALL)
        return find_sensitive_data(file_path)
    else:
        print(Fore.RED + f"[ERROR] {file_path} is not a valid file." + Style.RESET_ALL)
        return []