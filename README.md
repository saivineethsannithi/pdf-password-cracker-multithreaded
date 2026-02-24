# 🔐 PDF Cracker Tool

![Terminal Output](Screenshot%202026-02-24%20082228.png)

## 📖 Overview
[cite_start]The **PDF Cracker Tool** is a multithreaded Python script designed to decrypt password-protected PDF files[cite: 6]. [cite_start]It attempts to find the correct password by either generating combinations on the fly (brute-force) or by testing entries from a provided wordlist[cite: 6]. 

[cite_start]This project was developed as an educational exercise for the **Inlighn Tech** curriculum to demonstrate core cybersecurity concepts and practical Python programming skills[cite: 1, 4, 8].

⚠️ **Disclaimer:** *This tool is strictly for educational purposes and authorized security testing. Do not use this software on PDF files you do not own or do not have explicit permission to test.*

---

## ✨ Features
* [cite_start]**Two Attack Modes:** Choose between a targeted Wordlist attack or a dynamic Brute-force attack[cite: 6].
* [cite_start]**Multithreading:** Utilizes concurrent execution to test multiple passwords simultaneously, significantly speeding up the cracking process[cite: 6, 133].
* [cite_start]**Dynamic Generation:** Generates passwords in real-time based on custom character sets and length boundaries to save memory[cite: 40].
* [cite_start]**Live Progress Tracking:** Displays a real-time progress bar, estimated time remaining, and testing speed (passwords per second)[cite: 154].
* [cite_start]**Graceful Error Handling:** Catches decryption errors without crashing and safely handles keyboard interrupts[cite: 60, 62].

---

## 🛠️ Built With / Concepts Mastered
This project integrates several advanced Python libraries and concepts:
* [cite_start]**`pikepdf`**: Core library used to attempt PDF decryption[cite: 7, 111].
* [cite_start]**`tqdm`**: Wraps password attempts to provide visual progress bars[cite: 7, 154].
* [cite_start]**`concurrent.futures`**: Manages a `ThreadPoolExecutor` for parallel task execution[cite: 7, 130].
* [cite_start]**`argparse`**: Parses complex command-line arguments and flags[cite: 7, 83].
* [cite_start]**`itertools`**: Utilizes `itertools.product()` to lazily generate password combinations on the fly[cite: 37, 40].
* [cite_start]**File I/O & Exception Handling**: Safe file handling for wordlists and specific error catching for incorrect passwords[cite: 11, 14, 58].

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR-USERNAME/pdf-cracker-tool.git](https://github.com/YOUR-USERNAME/pdf-cracker-tool.git)
   cd pdf-cracker-tool
2. Install the required dependencies:
   Ensure you have Python 3 installed. Install the required external libraries (pikepdf and tqdm) by running:

   ```Bash
    pip install -r requirements.txt
Usage Guide
The tool is run entirely from the command line. You must provide the target PDF file and select an attack mode (--wordlist or --generate)

1. Brute-Force Attack (Custom Characters & Length)
   As shown in the project screenshot, testing a numeric password up to 6 characters long using 16 threads:

   ```Bash
   python pdf_cracker.py protected.pdf --generate --chars 0123456789 --max-length 6 --threads

2. Standard Brute-Force (Alphanumeric Defaults)
   Tests lowercase letters and digits, from length 1 to 4 (default settings):

   ```bash
   python pdf_cracker.py protected.pdf --generate
   
3. Wordlist Attack
Tests passwords sequentially from a provided text file (one password per line):
   ```bash
   python pdf_cracker.py protected.pdf --wordlist passwords.txt

Command-Line Arguments Reference
pdf_file: Path to the encrypted PDF.

-w, --wordlist: Path to a .txt file containing passwords.

-g, --generate: Enable brute-force mode.

-c, --chars: Custom characters for brute-force (Default: a-z0-9).

--min-length: Minimum password length for brute-force (Default: 1).

--max-length: Maximum password length for brute-force (Default: 4).

-t, --threads: Number of concurrent worker threads (Default: 8).   
