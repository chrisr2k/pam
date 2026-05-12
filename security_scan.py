#!/usr/bin/env python
"""
Security Scanner for PAM Application.

Scans the codebase for common security issues:
- Hardcoded secrets
- SQL injection vulnerabilities
- XSS vulnerabilities
- CSRF protection gaps
- Insecure direct object references (IDOR)
- Missing authentication checks
- Debug mode in production
- Weak cryptography
- Open redirects
- Permission checks
"""

import os
import re
import sys
import json
from pathlib import Path

# Colors for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
END = '\033[0m'

BASE_DIR = Path(__file__).parent

# Patterns to scan for
PATTERNS = {
    'hardcoded_secrets': {
        'pattern': r'(?i)(password|secret|key|token|credential)\s*[=:]\s*["\'][^"\']+["\']',
        'severity': 'HIGH',
        'description': 'Potential hardcoded secret',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': ['.env.example', 'requirements.txt', 'security_scan.py'],
    },
    'debug_true': {
        'pattern': r'DEBUG\s*=\s*True',
        'severity': 'HIGH',
        'description': 'Debug mode enabled in production',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'sql_injection_raw': {
        'pattern': r'cursor\.execute\(.*?["\'].*?%[s%]',
        'severity': 'HIGH',
        'description': 'Potential SQL injection (raw query with string formatting)',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'open_redirect': {
        'pattern': r'redirect\(.*?request\.(GET|POST)\.get\(.*?next',
        'severity': 'MEDIUM',
        'description': 'Potential open redirect via next parameter',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'eval_usage': {
        'pattern': r'\beval\s*\(',
        'severity': 'HIGH',
        'description': 'Use of eval() - code injection risk',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'exec_usage': {
        'pattern': r'\bexec\s*\(',
        'severity': 'HIGH',
        'description': 'Use of exec() - code injection risk',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'pickle_usage': {
        'pattern': r'import\s+pickle|from\s+pickle\s+import',
        'severity': 'MEDIUM',
        'description': 'Use of pickle - deserialization risk',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'mark_safe': {
        'pattern': r'mark_safe\s*\(',
        'severity': 'MEDIUM',
        'description': 'Use of mark_safe() - potential XSS if used with user input',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'format_string_user_input': {
        'pattern': r'\.format\(.*?request\.',
        'severity': 'MEDIUM',
        'description': 'Potential format string vulnerability with user input',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'insecure_hash': {
        'pattern': r'(md5|sha1)\s*\(',
        'severity': 'LOW',
        'description': 'Use of weak hashing algorithm',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'session_cookie_secure': {
        'pattern': r'SESSION_COOKIE_SECURE\s*=\s*False',
        'severity': 'MEDIUM',
        'description': 'Session cookie not marked as Secure',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'csrf_exempt': {
        'pattern': r'@csrf_exempt',
        'severity': 'MEDIUM',
        'description': 'CSRF protection disabled on view',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'permission_required_missing': {
        'pattern': r'class\s+\w+View\s*\(.*\):',
        'severity': 'INFO',
        'description': 'View class - verify permission checks are in place',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'allow_tags': {
        'pattern': r'allow_tags\s*=\s*True',
        'severity': 'MEDIUM',
        'description': 'Deprecated allow_tags - XSS risk in admin',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
    'suspicious_comment': {
        'pattern': r'(?i)(TODO|FIXME|HACK|XXX|SECURITY|VULNERABILITY):',
        'severity': 'INFO',
        'description': 'Suspicious comment that may indicate security concern',
        'exclude_dirs': ['migrations', '__pycache__', '.git'],
        'exclude_files': [],
    },
}


def scan_file(filepath, patterns):
    """Scan a single file for security issues."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return [{'file': str(filepath), 'error': str(e)}]

    rel_path = filepath.relative_to(BASE_DIR)

    for check_name, check_config in patterns.items():
        # Skip if file is in exclude list
        if any(excl in str(rel_path) for excl in check_config.get('exclude_dirs', [])):
            continue
        if str(rel_path) in check_config.get('exclude_files', []):
            continue

        for i, line in enumerate(lines, 1):
            if re.search(check_config['pattern'], line):
                findings.append({
                    'file': str(rel_path),
                    'line': i,
                    'severity': check_config['severity'],
                    'check': check_name,
                    'description': check_config['description'],
                    'code': line.strip(),
                })

    return findings


def scan_settings_file():
    """Specifically check settings.py for security misconfigurations."""
    findings = []
    settings_path = BASE_DIR / 'pam' / 'settings.py'
    if not settings_path.exists():
        return findings

    with open(settings_path, 'r') as f:
        content = f.read()

    checks = [
        ('SECRET_KEY', 'SECRET_KEY should not be a default/dev value', 'HIGH'),
        ('DEBUG', 'DEBUG should be False in production', 'HIGH'),
        ('ALLOWED_HOSTS', 'ALLOWED_HOSTS should not be ["*"]', 'MEDIUM'),
        ('CSRF_COOKIE_SECURE', 'CSRF_COOKIE_SECURE should be True in production', 'MEDIUM'),
        ('SESSION_COOKIE_SECURE', 'SESSION_COOKIE_SECURE should be True in production', 'MEDIUM'),
        ('SECURE_HSTS_SECONDS', 'HSTS should be configured for production', 'LOW'),
        ('SECURE_SSL_REDIRECT', 'SSL redirect should be configured for production', 'LOW'),
        ('X_FRAME_OPTIONS', 'X_FRAME_OPTIONS should be DENY or SAMEORIGIN', 'LOW'),
    ]

    for setting, description, severity in checks:
        if setting not in content:
            findings.append({
                'file': 'pam/settings.py',
                'line': 0,
                'severity': severity,
                'check': f'missing_{setting.lower()}',
                'description': f'Missing setting: {description}',
                'code': f'# {setting} not found in settings.py',
            })

    return findings


def scan_env_file():
    """Check .env file for security issues."""
    findings = []
    env_path = BASE_DIR / '.env'
    if not env_path.exists():
        return findings

    with open(env_path, 'r') as f:
        content = f.read()

    # Check for dev/default secret key
    if 'dev-secret-key' in content or 'default' in content.lower():
        findings.append({
            'file': '.env',
            'line': 0,
            'severity': 'HIGH',
            'check': 'weak_secret_key',
            'description': 'Using default/dev SECRET_KEY',
            'code': 'DJANGO_SECRET_KEY=dev-secret-key-not-for-production',
        })

    # Check for DEBUG=True
    if 'DEBUG=True' in content or 'DEBUG=true' in content:
        findings.append({
            'file': '.env',
            'line': 0,
            'severity': 'HIGH',
            'check': 'debug_enabled',
            'description': 'DEBUG mode enabled in .env',
            'code': 'DJANGO_DEBUG=True',
        })

    return findings


def scan_requirements():
    """Check requirements.txt for outdated/known vulnerable packages."""
    findings = []
    req_path = BASE_DIR / 'requirements.txt'
    if not req_path.exists():
        return findings

    with open(req_path, 'r') as f:
        content = f.read()

    # Check for pinned versions (good practice)
    unpinned = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and '==' not in line and '>=' not in line:
            unpinned.append(line)

    if unpinned:
        findings.append({
            'file': 'requirements.txt',
            'line': 0,
            'severity': 'LOW',
            'check': 'unpinned_dependencies',
            'description': f'Unpinned dependencies: {", ".join(unpinned[:5])}',
            'code': 'Consider pinning versions with ==',
        })

    return findings


def scan_templates():
    """Scan HTML templates for XSS vulnerabilities."""
    findings = []
    templates_dir = BASE_DIR / 'templates'
    if not templates_dir.exists():
        return findings

    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if not file.endswith('.html'):
                continue
            filepath = Path(root) / file
            rel_path = filepath.relative_to(BASE_DIR)

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for |safe filter usage (potential XSS)
            safe_matches = re.finditer(r'{{\s*.*?\|safe\s*}}', content)
            for match in safe_matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'file': str(rel_path),
                    'line': line_num,
                    'severity': 'MEDIUM',
                    'check': 'template_safe_filter',
                    'description': 'Use of |safe filter - potential XSS if variable contains user input',
                    'code': match.group().strip(),
                })

            # Check for autoescape off
            if '{% autoescape off %}' in content:
                findings.append({
                    'file': str(rel_path),
                    'line': 0,
                    'severity': 'MEDIUM',
                    'check': 'autoescape_off',
                    'description': 'Autoescape disabled in template',
                    'code': '{% autoescape off %}',
                })

    return findings


def scan_js_files():
    """Scan JavaScript files for security issues."""
    findings = []
    static_dir = BASE_DIR / 'static'
    if not static_dir.exists():
        return findings

    for root, dirs, files in os.walk(static_dir):
        for file in files:
            if not file.endswith('.js'):
                continue
            filepath = Path(root) / file
            rel_path = filepath.relative_to(BASE_DIR)

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for innerHTML usage (XSS)
            if 'innerHTML' in content:
                findings.append({
                    'file': str(rel_path),
                    'line': 0,
                    'severity': 'MEDIUM',
                    'check': 'inner_html',
                    'description': 'Use of innerHTML - potential XSS',
                    'code': 'innerHTML usage found',
                })

            # Check for eval in JS
            if re.search(r'\beval\s*\(', content):
                findings.append({
                    'file': str(rel_path),
                    'line': 0,
                    'severity': 'HIGH',
                    'check': 'js_eval',
                    'description': 'Use of eval() in JavaScript',
                    'code': 'eval() usage found',
                })

    return findings


def print_finding(finding):
    """Print a finding with color coding."""
    severity_colors = {
        'HIGH': RED,
        'MEDIUM': YELLOW,
        'LOW': CYAN,
        'INFO': GREEN,
    }
    color = severity_colors.get(finding['severity'], END)

    print(f"{color}[{finding['severity']}]{END} {finding['description']}")
    print(f"      File: {finding['file']}:{finding['line']}")
    if finding.get('code'):
        print(f"      Code: {finding['code'][:100]}")
    print()


def main():
    """Main entry point."""
    print(f"\n{BOLD}{'='*60}{END}")
    print(f"{BOLD}  PAM Security Scanner{END}")
    print(f"{BOLD}{'='*60}{END}\n")

    all_findings = []
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

    # Scan Python files
    print(f"{CYAN}Scanning Python source files...{END}")
    for root, dirs, files in os.walk(BASE_DIR):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in ('__pycache__', '.git', 'migrations', 'node_modules')]

        for file in files:
            if not file.endswith('.py'):
                continue
            filepath = Path(root) / file
            findings = scan_file(filepath, PATTERNS)
            all_findings.extend(findings)

    # Scan settings
    print(f"{CYAN}Checking settings.py...{END}")
    all_findings.extend(scan_settings_file())

    # Scan .env
    print(f"{CYAN}Checking .env file...{END}")
    all_findings.extend(scan_env_file())

    # Scan requirements
    print(f"{CYAN}Checking requirements.txt...{END}")
    all_findings.extend(scan_requirements())

    # Scan templates
    print(f"{CYAN}Scanning HTML templates...{END}")
    all_findings.extend(scan_templates())

    # Scan JS files
    print(f"{CYAN}Scanning JavaScript files...{END}")
    all_findings.extend(scan_js_files())

    # Count by severity
    for finding in all_findings:
        sev = finding.get('severity', 'INFO')
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Print results
    print(f"\n{BOLD}{'='*60}{END}")
    print(f"{BOLD}  Scan Results{END}")
    print(f"{BOLD}{'='*60}{END}\n")

    if not all_findings:
        print(f"{GREEN}No security issues found!{END}\n")
        return

    # Group by severity
    for severity in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
        sev_findings = [f for f in all_findings if f.get('severity') == severity]
        if sev_findings:
            color = {'HIGH': RED, 'MEDIUM': YELLOW, 'LOW': CYAN, 'INFO': GREEN}[severity]
            print(f"{color}{BOLD}[{severity}] - {len(sev_findings)} finding(s){END}")
            print(f"{color}{'-'*40}{END}")
            for finding in sev_findings:
                print_finding(finding)

    # Summary
    print(f"{BOLD}{'='*60}{END}")
    print(f"{BOLD}  Summary{END}")
    print(f"{BOLD}{'='*60}{END}")
    print(f"  {RED}HIGH:   {severity_counts['HIGH']}{END}")
    print(f"  {YELLOW}MEDIUM: {severity_counts['MEDIUM']}{END}")
    print(f"  {CYAN}LOW:    {severity_counts['LOW']}{END}")
    print(f"  {GREEN}INFO:   {severity_counts['INFO']}{END}")
    print(f"  Total:  {len(all_findings)}")
    print()

    # Exit with error code if HIGH severity issues found
    if severity_counts['HIGH'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
