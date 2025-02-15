import os
import hashlib
import requests
from colorama import Fore, Style

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "apikey": self.api_key
        }

    def get_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            return {
                "status": "error",
                "message": f"File not found: {file_path}"
            }

        try:
            # Check file size
            if os.path.getsize(file_path) > 32 * 1024 * 1024:  # 32MB limit
                return {
                    "status": "error",
                    "message": "File too large for VirusTotal scanning (max 32MB)"
                }

            # Submit file for scanning
            scan_url = f"{self.base_url}/file/scan"
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(
                    scan_url,
                    files=files,
                    params={"apikey": self.api_key}
                )

                if response.status_code == 200:
                    result = response.json()
                    return {
                        "status": "pending",
                        "message": "File submitted for scanning",
                        "scan_id": result.get("scan_id"),
                        "permalink": result.get("permalink")
                    }
                else:
                    return {
                        "status": "error",
                        "message": f"VirusTotal API error: {response.status_code}"
                    }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Scanning error: {str(e)}"
            }

def check_file_virustotal(file_path, api_key):
    if not api_key:
        print(Fore.YELLOW + "[WARNING] VirusTotal API key not provided, skipping VirusTotal scan" + Style.RESET_ALL)
        return

    scanner = VirusTotalScanner(api_key)
    result = scanner.scan_file(file_path)

    if result["status"] == "pending":
        print(Fore.YELLOW + f"[INFO] File {file_path} submitted to VirusTotal")
        print(f"Report will be available at: {result.get('permalink', 'N/A')}" + Style.RESET_ALL)
    elif result["status"] == "error":
        print(Fore.RED + f"[ERROR] VirusTotal scan error: {result.get('message')}" + Style.RESET_ALL)

    return result