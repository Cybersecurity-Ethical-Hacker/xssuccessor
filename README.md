# XSSuccessor ⚡

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Issues](https://img.shields.io/github/issues/Cybersecurity-Ethical-Hacker/xssuccessor.svg)](https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Cybersecurity-Ethical-Hacker/xssuccessor.svg)](https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor/stargazers)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

⚡ XSSuccessor is a powerful, asynchronous **Cross-Site Scripting (XSS)** detection tool. It automates the injection of payloads into URLs, detects value reflections, monitors for triggered browser alerts, and effectively identifies XSS vulnerabilities. It simulates real browser requests with custom advanced payloads, effectively bypassing WAFs and protections, ensuring accurate detection results.

## 📸 Screenshot:
![xssuccesor](https://github.com/user-attachments/assets/5718d139-5990-4c59-84c0-46ccde91c54b)

## 🌟 Features

- **⚡ Asynchronous Performance**: Uses `asyncio` and Playwright to efficiently handle multiple concurrent tests.
- **🔬 Two-Factor Validation**: Enhance detection accuracy by combining HTTP response analysis with browser-based testing that triggers actual `alert()` events.
- **🌐 Custom Headers**: Allows the addition of custom HTTP headers to mimic specific client behaviors or bypass certain security measures.
- **🛠️ Custom Payloads**: Utilize custom payload files to tailor scans to specific testing requirements.
- **🖥️ Advanced Bypass Techniques**: It simulates real browser requests with custom advanced payloads, effectively bypassing cloud-based WAFs and protections.
- **📝 Flexible Output**: Outputs results in JSON or plain text format, suitable for integration into CI/CD pipelines or manual review.
- **🔧 Configurable Parameters**: Adjust concurrency (workers), timeouts, and alert waiting times to optimize scans for different environments.
- **📂 Organized Scans**: Automatically organizes scan results into structured directories based on domains or URL lists.
- **🔄 Easy Updates**: Keep the tool up-to-date with the latest features and security patches using the `-u` or `--update` flag.

## 📥 Kali Linux Installation - (Recommended)

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor.git
   cd xssuccessor
   ```

**Kali Linux already includes the following dependencies by default. However, if needed, you can install the required dependencies manually using pipx (Kali 2024.4+):**

   ```bash
   pipx install aiofiles
   pipx install aiohttp
   pipx install colorama
   pipx install tqdm
   pipx install packaging
   ```

**For older Kali Linux versions ensure that you have Python 3.8+ installed. Install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```

## 📥 Other Linux Distributions Installation

**For other Linux Distributions you may need to install manually the Playwright:**

**Install Playwright:**
   ```bash
pip install playwright
   ```

**Install the required Playwright browsers:**

   ```bash
   playwright install
   ```

   ```bash
   sudo playwright install-deps
   ```

if it fails run:

   ```bash
   sudo apt-get install libevent-2.1-7 libavif16
   ```      

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor.git
   cd xssuccessor
   ```

**Ensure you have Python 3.8+ installed. Install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```

## 📥 Install using Virtual Environment:

**Create and activate a virtual environment (optional but recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

**Upgrade pip (Optional but Recommended):**

   ```bash
   pip install --upgrade pip
   ```

**Install Playwright:**

   ```bash
pip install playwright
   ```

**Install the required Playwright browsers:**

   ```bash
   playwright install
   ```

   ```bash
   sudo playwright install-deps
   ```

if it fails run:

   ```bash
   sudo apt-get install libevent-2.1-7 libavif16
   ``` 

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor.git
   cd xssuccessor
   ```

**Ensure you have Python 3.8+ installed. Install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```

❗ Important: Always Activate The Virtual Environment Before Use
Whenever you:

- Open a New Terminal Window
- Restart Your Computer
  
You must activate the virtual environment before running XSSuccessor to ensure that all dependencies are correctly loaded.


## 🧩 **URLs with Parameters**

The tool requires URLs with parameters (e.g., `?id=1` or `?search=example&page=2`) to work effectively.

If you don't have a URL with parameters or a list of such URLs, you can generate one using the following method (replace the `domain.com`):

```bash
paramspider -d domain.com -s 2>&1 | grep -Ei "https?://" | sort -u | httpx -silent -status-code -mc 200,201,204,401,403 > live_urls.txt
```

Alternatively, you can use tools like `waybackurls`, `urlfinder`, `katana`, and others to collect URLs efficiently.

Then just load the list using `-l urls.txt`.

## 🚀 Usage
XSSuccessor can be used to scan a single domain or a list of URLs.

📍 Command-Line Options:
```
Usage: xssuccessor.py [options]

options:
  -h, --help           Show this help message and exit
  -d, --domain         Specify the domain with parameter(s) to scan (required unless -l is used)
  -l, --url-list       Provide a file containing a list of URLs with parameters to scan
  -p, --payloads       Custom file containing payloads
  -o, --output         Specify the output file name (supports .txt or .json)
  -w, --workers        Maximum number of concurrent workers
  -t, --timeout        Total request timeout in seconds
  -a, --alert-timeout  Specify the alert timeout in seconds
  -j, --json           Output results in JSON format
  -H, --header         Custom headers can be specified multiple times. Format: "Header: Value"
  -b, --batch-size     Define the number of requests per batch
  -u, --update         Check for updates and automatically install the latest version
```

## 💡 Examples
💻 Scan a single domain with parameter(s) using default settings:
```bash
python xssuccessor.py -d "https://domain.com/file.php?parameter=1234"
```
💻 Scan multiple URLs with parameter(s) from a file with a custom rate limit:
```bash
python xssuccessor.py -l urls.txt -r 5
```
💻 Scan with custom payloads and increased timeout:
```bash
python xssuccessor.py -d "https://domain.com/file.php?parameter=1234" -p custom_payloads.txt -t 10
```
💻 Include custom headers in the requests:
```bash
python xssuccessor.py -l urls.txt -H "Authorization: Bearer <token>" -H "X-Forwarded-For: 127.0.0.1"
```
💻 Update XSSuccessor to the latest version:
```bash
python xssuccessor.py --update
```

## 📊 Output
- Results are saved in the scans/ directory, organized by domain or list name.
- The output file name includes a timestamp for easy reference.
- If JSON output is enabled (-j flag), results include detailed scan summaries and vulnerabilities found.

## 🐛 Error Handling
- Graceful Exception Handling: The tool gracefully handles exceptions and logs errors to xss_scanner.log.
- Informative Messages: Provides clear messages if payload files or URL lists are not found.
- Interruption Support: Supports interruption via Ctrl+C, safely stopping the scan and providing a summary.

## 🛠️ Troubleshooting

**Common Issues and Solutions**

If you encounter problems while using **XSSuccessor**, consider the following common causes and their respective solutions:

1. **Excessive Max Workers Setting**
   - **Issue:** Setting the `Max Workers` value too high can lead to excessive resource consumption, causing the tool to crash or perform inefficiently.
   - **Solution:** Reduce the `Max Workers` value to a more manageable number (e.g., 4 or 8) to balance performance and resource usage.

2. **Overly Large Payloads List**
   - **Issue:** Utilizing an excessively large payloads list can overwhelm the tool, resulting in slow performance or failures.
   - **Solution:** Optimize your payloads list by removing redundant or unnecessary entries.

**Recommendations:**
- **Start Simple:** Begin with a moderate number of workers and a streamlined payloads list to ensure smooth operation.
- **Gradual Scaling:** If needed, gradually increase the `Max Workers` and payloads size while monitoring system performance.
- **Customization:** Tailor the payloads and worker settings based on your system's capabilities and the specific requirements of your testing environment.

## 📂 Directory Structure
- `xssuccessor.py`: Main executable script.
- `xss_payloads.txt`: A small, default set of basic payloads for quick testing scenarios.
- `xss_payloads_full.txt`: A comprehensive list of payloads designed for more in-depth or extensive testing.
- `requirements.txt`: Contains a list of dependencies required to run the script.
- `scans/`: Contains output files and scan results.
- `logs/`: Contains detailed log files.

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or new features.

> [!NOTE]
> Lfier currently supports the detection of Reflected Cross-Site Scripting (XSS) vulnerabilities. I will expand its capabilities to include Stored XSS and DOM-based XSS detection in upcoming releases. 

## 🛡️ Ethical Usage Guidelines
I am committed to promoting ethical practices in cybersecurity. Please ensure that you use this tool responsibly and in accordance with the following guidelines:

1. Educational Purposes Only
This tool is intended to be used for educational purposes, helping individuals learn about penetration testing techniques and cybersecurity best practices.

2. Authorized Testing
Always obtain explicit permission from the system owner before conducting any penetration tests. Unauthorized testing is illegal and unethical.

3. Responsible Vulnerability Reporting
If you discover any vulnerabilities using this tool, report them responsibly to the respective organizations or maintainers. Do not exploit or disclose vulnerabilities publicly without proper authorization.

4. Compliance with Laws and Regulations
Ensure that your use of this tool complies with all applicable local, national, and international laws and regulations.

## 📚 Learn and Grow
Whether you're a budding penetration tester aiming to enhance your skills or a seasoned professional seeking to uncover and mitigate security issues, LFier is here to support your journey in building a safer digital landscape.

> [!NOTE]
> Let’s build a safer web together! 🌐🔐
