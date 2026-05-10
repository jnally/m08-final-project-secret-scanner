import os
import re
import argparse
import logging

# Configure basic logging to provide progress updates and error handling
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Comprehensive dictionary of regex patterns based on modern and legacy specs tuned to minimize false positives
PATTERNS_RAW = {
    # Base64 (Requires at least 16 characters and rejects empty strings)
    "Base64 Encoded String": r"^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
    "Base64 High Entropy": r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]",

    # Anthropic (Claude)
    "Anthropic API Key": r"sk-ant-api03-[a-zA-Z0-9_\-]{93,}",

    # OpenAI
    "OpenAI Project Key": r"sk-proj-[A-Za-z0-9_\-]{48,}",
    "OpenAI Service Account": r"sk-svcacct-[A-Za-z0-9_\-]{48,}",
    "OpenAI Legacy Key": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "OpenAI Generic Key": r"sk-(?:live|test|proj|svcacct)?-[a-zA-Z0-9\-_]{80,}",

    # AWS (Strict boundaries on identifiers; Secret keys must contain mixed characters/numbers)
    "AWS Long-Term IAM Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS STS Temporary Key": r"\bASIA[0-9A-Z]{16}\b",
    "AWS All Identifiers": r"\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b",
    "AWS Secret Access Key": r"(?<![A-Za-z0-9/+=])(?=[A-Za-z0-9/+=]*[0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "AWS Context-Aware Secret": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", 
    "AWS IAM Role ARN": r"arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+",

    # Google / GCP (OAuth secrets must contain numbers or special chars to ignore plain words)
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Secret": r"\b(?=[a-zA-Z0-9\-_]*[0-9\-_])[0-9a-zA-Z\-_]{24}\b",
    "Google OAuth Auth Code": r"\b4/[0-9A-Za-z\-_]+\b",
    "Google OAuth Refresh": r"\b(?:1/[0-9A-Za-z\-]{43}|1/[0-9A-Za-z\-]{64})\b",
    "Google OAuth Access": r"\bya29\.[0-9A-Za-z\-_]+\b",
    "GCP API Key": r"\b[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}\b",
    "GCP OAuth 2.0": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",

    # GitHub
    "GitHub Classic PAT": r"\bghp_[a-zA-Z0-9]{36}\b",
    "GitHub Fine-Grained PAT": r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
    "GitHub OAuth Token": r"\bgho_[a-zA-Z0-9]{36}\b",
    "GitHub User-to-Server Token": r"\bghu_[a-zA-Z0-9]{36}\b",
    "GitHub Server-to-Server": r"\bghs_[a-zA-Z0-9]{36}\b",
    "GitHub Refresh Token": r"\bghr_[a-zA-Z0-9]{36}\b",
    "GitHub OAuth App Secret": r"\b[a-f0-9]{40}\b",

    # GitLab
    "GitLab PAT": r"\bglpat-[0-9a-zA-Z\-]{20}\b",
    "GitLab Pipeline Trigger": r"\bglptt-[0-9a-zA-Z\-]{20}\b",
    "GitLab Runner Token": r"\bglrt-[a-zA-Z0-9_\-]{20}\b",
    "GitLab Legacy Registration": r"\bGR1348941[0-9a-zA-Z\-_]{20}\b",

    # Slack
    "Slack OAuth Bot Token": r"\bxoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}\b",
    "Slack OAuth User Token": r"\bxoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}\b",
    "Slack Webhook URL": r"https?:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+",
    "Slack Token Generic": r"\bxox[baprs]-([0-9a-zA-Z]{10,48})?\b",

    # Cloudflare (Requires a mix of characters/numbers to ignore pure CamelCase words)
    "Cloudflare API Token": r"\b(?=[A-Za-z0-9_\-]*[0-9_\-])[A-Za-z0-9_\-]{40}\b",
    "Cloudflare Legacy Key": r"\b[0-9a-f]{37}\b",
    "Cloudflare Scoped Token": r"\b(?:dev|exp|cro|crw)_[a-zA-Z0-9]{40,60}\b",

    # Datadog
    "Datadog API Key": r"\b[a-f0-9]{32}\b",
    "Datadog Application Key": r"\b[a-f0-9]{40}\b",

    # Twitter / X
    "Twitter OAuth 1.0a Token": r"\b[1-9][0-9]+-[0-9a-zA-Z]{40}\b",
    "Twitter Bearer Token": r"\bAAAA[A-Za-z0-9%]{80,}\b",

    # Instagram
    "Instagram OAuth": r"\b[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}\b",

    # Stripe & Shopify
    "Stripe Standard API Key": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "Stripe Restricted Key": r"\brk_live_[0-9a-zA-Z]{99}\b",
    "Shopify Custom App Token": r"\bshpat_[a-fA-F0-9]{32}\b",
    "Shopify Public App Token": r"\bshpca_[a-fA-F0-9]{32}\b",
    "Shopify App Secret": r"\bshpss_[a-fA-F0-9]{32}\b",

    # npm
    "npm Access Token (Modern)": r"\bnpm_[A-Za-z0-9]{36}\b",
    "npm Legacy UUID": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",

    # Finance & Comms
    "Twilio API Key": r"\b(?:SK[0-9a-fA-F]{32}|55[0-9a-fA-F]{32})\b",
    "SendGrid API Key": r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
    "Square Access Token": r"\bsqOatp-[0-9A-Za-z\-_]{22}\b",
    "Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Mailgun Access Token": r"\bkey-[0-9a-zA-Z]{32}\b",

    # Heroku & Vercel
    "Heroku API Key": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "Vercel PAT": r"\bvcp_[a-zA-Z0-9]{24}\b",

    # Keys, Passwords & Generic Auth
    "Private Key Block": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----",
    "Authorization Bearer": r"(?i)authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    "Password Assignment": r"['\"]?(?:password|passcode|parola|şifre|sifre|pwd|passphrase)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,64})['\"]?",
    "Generic API Key Detector": r"(?i)(?:apikey|api_key|secret|token)['\"\s:=]+[a-zA-Z0-9\-._]{8,}"
}

# Pre-compile all regex patterns once for best performance and early error catching
# Source: https://www.geeksforgeeks.org/python/re-compile-in-python/
COMPILED_PATTERNS = {}
try:
    for name, pattern in PATTERNS_RAW.items():
        COMPILED_PATTERNS[name] = re.compile(pattern)
except re.error as e:
    logging.critical(f"Fatal error compiling regex '{name}': {e}")
    exit(1)

# Scans a single file line-by-line for regex pattern matches
def scan_file(filepath):
    findings = []
    try:
        # Open with errors='ignore' to gracefully handle non-text/binary files
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, 1):
                for secret_type, compiled_regex in COMPILED_PATTERNS.items():
                    matches = compiled_regex.finditer(line)
                    for match in matches:
                        findings.append({
                            "file": filepath,
                            "line": line_number,
                            "type": secret_type,
                            "match": match.group(0).strip() # The exact string matched
                        })
    except Exception as e:
        logging.error(f"Could not read file {filepath}: {e}")
    
    return findings

# Recursively walks through a directory and scans all files
def scan_directory(directory_path):
    all_findings = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            all_findings.extend(scan_file(filepath))
    return all_findings

# Formats and prints the findings to the console
# This could be modified for output to a CSV file or otherwise
def print_report(findings):
    print("\nSECRET SCANNER REPORT")
    print("-" * 40)

    if not findings:
        print("No secrets found! Your code looks secure.")
    else:
        for f in findings:
            print(f"File:  {f['file']}")
            print(f"Line:  {f['line']}")
            print(f"Type:  {f['type']}")
            print(f"Match: {f['match']}")
            print("-" * 40)
        logging.warning(f"Total secrets exposed: {len(findings)}")

# Setup argparse for a clean command line interface
def main():
    parser = argparse.ArgumentParser(description="Description: Scan files or directories for hardcoded secrets including: API keys, passwords, tokens, and private keys.")
    parser.add_argument("path", help="The absolute or relative path to the file or directory you want to scan.")
    args = parser.parse_args()

    target_path = args.path

    logging.info(f"Starting scan on target: {target_path}")

    # Determine if input is a file or directory and route accordingly
    findings = []
    if os.path.isfile(target_path):
        findings = scan_file(target_path)
    elif os.path.isdir(target_path):
        findings = scan_directory(target_path)
    else:
        logging.error("Invalid path provided. Please provide a valid file or directory.")
        return

    logging.info("Scan complete. Generating report...")
    print_report(findings)

# Execute main function
if __name__ == '__main__':
    main()