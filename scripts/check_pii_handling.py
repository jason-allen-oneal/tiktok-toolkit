#!/usr/bin/env python3
"""
PII Handling Checker

This script checks the codebase for proper PII (Personally Identifiable Information)
handling, ensuring sensitive data is properly redacted, hashed, or encrypted.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set


class PIIHandlingChecker:
    """Check codebase for proper PII handling"""
    
    def __init__(self):
        self.violations: List[str] = []
        self.warnings: List[str] = []
        
        # PII patterns that should be handled securely
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'(?:(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,3}\d{2,4})',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'username': r'@[A-Za-z0-9_]{1,15}',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        }
        
        # Secure handling patterns
        self.secure_patterns = {
            'hash': [
                r'hash.*pii',
                r'salt.*hash',
                r'bcrypt',
                r'argon2',
                r'sha256',
                r'sha512',
            ],
            'redact': [
                r'redact.*pii',
                r'mask.*pii',
                r'blur.*face',
                r'censor',
                r'[A-Za-z0-9._%+-]+@\[REDACTED\]',
                r'\*{3,}',
            ],
            'encrypt': [
                r'encrypt.*pii',
                r'fernet',
                r'aes',
                r'libsodium',
                r'cryptography',
            ],
            'secure_logging': [
                r'log.*hash',
                r'log.*redact',
                r'logger.*hash',
                r'debug.*hash',
            ]
        }
        
        # Dangerous patterns that expose PII
        self.dangerous_patterns = [
            r'print.*email',
            r'print.*phone',
            r'print.*ssn',
            r'log.*email',
            r'log.*phone',
            r'log.*ssn',
            r'debug.*email',
            r'debug.*phone',
            r'debug.*ssn',
            r'f".*{email}',
            r'f".*{phone}',
            r'f".*{ssn}',
        ]
    
    def check_file(self, file_path: Path) -> None:
        """Check a single file for PII handling"""
        if not file_path.is_file():
            return
            
        # Skip certain file types
        if file_path.suffix in {'.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe'}:
            return
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except (UnicodeDecodeError, PermissionError):
            return
            
        # Check for PII patterns
        self._check_pii_exposure(file_path, content)
        
        # Check for secure handling
        self._check_secure_handling(file_path, content)
    
    def _check_pii_exposure(self, file_path: Path, content: str) -> None:
        """Check for exposed PII in code"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for dangerous patterns
            for pattern in self.dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.violations.append(
                        f"{file_path}:{line_num}: PII exposure - {pattern}"
                    )
            
            # Check for hardcoded PII
            for pii_type, pattern in self.pii_patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Skip if it's in a comment or string literal
                    if self._is_in_comment_or_string(line, match.start()):
                        continue
                    
                    # Check if it's properly handled
                    if not self._is_properly_handled(content, pii_type):
                        self.warnings.append(
                            f"{file_path}:{line_num}: Potential PII exposure - "
                            f"{pii_type}: {match.group()[:20]}..."
                        )
    
    def _is_in_comment_or_string(self, line: str, pos: int) -> bool:
        """Check if position is in a comment or string literal"""
        # Simple check for comments
        comment_pos = line.find('#')
        if comment_pos != -1 and pos > comment_pos:
            return True
        
        # Check for string literals (simplified)
        quote_chars = ['"', "'"]
        for quote in quote_chars:
            quote_pos = line.find(quote)
            if quote_pos != -1 and pos > quote_pos:
                return True
        
        return False
    
    def _is_properly_handled(self, content: str, pii_type: str) -> bool:
        """Check if PII is properly handled with secure patterns"""
        for category, patterns in self.secure_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        return False
    
    def _check_secure_handling(self, file_path: Path, content: str) -> None:
        """Check for secure PII handling patterns"""
        lines = content.split('\n')
        
        # Check for secure patterns
        for category, patterns in self.secure_patterns.items():
            found_secure = False
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_secure = True
                    break
            
            # If we have PII but no secure handling, warn
            if not found_secure:
                for pii_type in self.pii_patterns:
                    if re.search(self.pii_patterns[pii_type], content):
                        self.warnings.append(
                            f"{file_path}: PII detected but no {category} handling found"
                        )
                        break
    
    def check_codebase(self, root_path: Path) -> None:
        """Check entire codebase for PII handling"""
        python_files = list(root_path.rglob('*.py'))
        
        for file_path in python_files:
            self.check_file(file_path)
    
    def print_report(self) -> int:
        """Print PII handling report and return exit code"""
        print("🔒 PII Handling Security Check")
        print("=" * 50)
        
        if not self.violations and not self.warnings:
            print("✅ All checks passed! PII is properly handled.")
            return 0
        
        if self.violations:
            print("\n❌ SECURITY VIOLATIONS FOUND:")
            for violation in self.violations:
                print(f"  {violation}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"  {warning}")
        
        print(f"\n📊 Summary:")
        print(f"  Violations: {len(self.violations)}")
        print(f"  Warnings: {len(self.warnings)}")
        
        if self.violations:
            print("\n🔧 Recommendations:")
            print("  - Use hash_pii() function for sensitive data")
            print("  - Implement redaction for logs and debug output")
            print("  - Use encrypted storage for tokens and credentials")
            print("  - Add salt to hashed PII for additional security")
        
        # Return non-zero exit code if violations found
        return 1 if self.violations else 0


def main():
    """Main entry point"""
    root_path = Path('.')
    
    checker = PIIHandlingChecker()
    checker.check_codebase(root_path)
    
    exit_code = checker.print_report()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
