# LeakHunter - Sensitive Data Scanner

## 📌 Overview
LeakHunter is a Python-based tool designed to scan files and directories for sensitive data leaks using **regular expressions** and **YARA rules**. It also supports **VirusTotal** integration for malware detection.

## 🚀 Features
- **Regex-based scanning** for API keys, passwords, emails, and credit card numbers.
- **YARA rule scanning** for detecting sensitive data patterns.
- **VirusTotal API support** to check files against known malware signatures.
- **Directory and file scanning** with customizable rule sets.
- **Color-coded output** for easy readability.

---
## 📂 Project Structure
```
LeakHunter/
│── main.py                # Main script
│── rules/                 # YARA rule files
│   └── sensitive_data.yar
│── leakhunter/            # Core package
│   │── __init__.py        # Package initializer
│   │── scanner.py         # Regex-based scanner
│   │── yara_scanner.py    # YARA-based scanner
│   │── virustotal.py      # VirusTotal API integration
│   │── utils.py           # Helper functions
│── tests/                 # Unit tests
│   └── test_scanner.py    
│── requirements.txt       # Dependencies
│── README.md              # Documentation
```

---
## 🔧 Installation
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/SaiBhargavYenisetti/LeakHunter.git
cd LeakHunter
```
### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Set Up VirusTotal API Key (Optional)
If using VirusTotal, add your API key to an environment variable:
```bash
export VIRUSTOTAL_API_KEY='your_api_key_here'
```

---
## 🔍 Usage
### Scan a Single File
```bash
python main.py --path /path/to/file.txt
```
### Scan a Directory
```bash
python main.py --path /path/to/directory/
```
### Scan with YARA Rules
```bash
python main.py --path /path/to/directory --yara rules/sensitive_data.yar
```
### Scan with VirusTotal
```bash
python main.py --path /path/to/file --virustotal
```

---
## ⚙️ Configuration
Modify **`rules/sensitive_data.yar`** to add custom YARA rules.

---
## 🛠️ Troubleshooting
### **ModuleNotFoundError: No module named 'yara_scanner'**
- Ensure `yara_scanner.py` is inside `leakhunter/`.
- Run the script as a module:
  ```bash
  python -m leakhunter.main --path /path/to/scan
  ```

---
## 📜 License
This project is licensed under the MIT License.

---
## 🤝 Contributing
Pull requests are welcome! If you'd like to contribute, please fork the repository and submit a PR.

---
## 📧 Contact
For support or questions, reach out to **bhargavy08948@gmail.com**.

---
✅ Happy Scanning! 🚀

