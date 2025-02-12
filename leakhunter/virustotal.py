import requests
from colorama import Fore, Style

VIRUSTOTAL_API_KEY = 'your_api_key_here'

def check_virustotal(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}

    try:
        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                print(Fore.GREEN + f"✅ File submitted to VirusTotal. Scan ID: {result['scan_id']}" + Style.RESET_ALL)
            else:
                print(Fore.RED + f"[ERROR] VirusTotal submission failed: {result['verbose_msg']}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[ERROR] VirusTotal API request failed: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[ERROR] VirusTotal check failed: {e}" + Style.RESET_ALL)