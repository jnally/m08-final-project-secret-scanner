# Module 8 Final Project - Secret Scanner
**Author:** Jeremy Nally  
**Course:** SDEV245 - Security and Secure Coding  

## Purpose
This Command Line Interface (CLI) tool scans files and directories to detect hardcoded sensitive data—such as API keys, passwords, authentication tokens, and private keys—helping developers identify security vulnerabilities before committing code.

## Detection Logic
The tool reads files line-by-line and evaluates them against pre-compiled regular expressions using Python's `re` module. To minimize false positives, patterns enforce strict word boundaries (`\b`) and lookaround constraints to distinguish valid credentials from standard source code text.

Targeted patterns include:
* **AWS Credentials:** Long-term IAM keys (`\bAKIA[0-9A-Z]{16}\b`) and temporary STS keys.
* **Google Cloud & OAuth:** API keys (`\bAIza[0-9A-Za-z\-_]{35}\b`) and 24-character OAuth secrets.
* **Tokens:** Scoped Slack tokens (`xoxb-...`) and 40-character Cloudflare API tokens.
* **Private Keys:** Standard PEM cryptographic headers (`-----BEGIN ... PRIVATE KEY-----`).
* **Passwords:** Variable assignments targeting sensitive identifiers (`password`, `pwd`, `secret`).

## Usage Examples
The tool uses Python's `argparse` module to handle input paths and validation. No external dependencies are required.

**Scan a single file:**
```bash
python secret-scanner.py target_file
```

**Scan a directory recursively:**
```bash
python secret-scanner.py target_directory/
```

**View Help:**
```bash
python secret-scanner.py -h
python secret-scanner.py --help
```