# APK VirusTotal Scanner

## Overview
The APK VirusTotal Scanner is a Python-based tool designed for the automated scanning of APK files using the VirusTotal API. This project facilitates the bulk scanning of APKs, providing a streamlined process for analyzing potential security threats in APK files.

## Key Features
- **Automated APK Scanning:** Automatically scans APK files in a specified folder using the VirusTotal API.
- **Multiple API Support:** Can be used with multiple API keys from VirusTotal for load balancing and rate limit management.
- **Integration with Mihon Extension APKs:** Specifically designed to download and scan APKs from the [Mihon Extension repository](https://github.com/keiyoushi/extensions).
- **Result Storage:** Scanning results are stored in a JSON file for easy access and analysis.


## How It Works
1. **APK Retrieval:** The `git-downloader.py` script clones or updates the Mihon Extension repository and transfers new APKs to the local `apk` folder.
2. **Scanning Process:** The `vt-apk-scanner.py` script scans each APK file using the VirusTotal API and records the results.
3. **Results Handling:** The scanning results are saved in `virus_total_results.json`, providing details such as scan date, detected threats, and file attributes.

## WebPage
- **keiyoushi Extension Results:** A dedicated webpage is available to display scan results from keiyoushi-extensions, accessible [here](https://h1ghsyst3m.github.io/keiyoushi-scans/).

## Setup and Usage
- Ensure you have Python installed on your system.
- Clone this repository and navigate to the project directory.
- Install necessary Python packages listed in `requirements.txt`.
- Add your VirusTotal API keys to the `vt-apk-scanner.py` script.
- Run `starter.bat` to initiate the downloading and scanning process.

## License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/H1ghSyst3m/apk-virustotal-scanner/blob/main/LICENSE) file for details.
