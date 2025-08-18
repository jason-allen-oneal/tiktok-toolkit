#!/usr/bin/env python3
"""
ToS Compliance Checker

This script checks the codebase for compliance with TikTok's Terms of Service
and ensures proper API usage patterns.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple


class ToSComplianceChecker:
    """Check codebase for TikTok ToS compliance"""
    
    def __init__(self):
        self.violations: List[str] = []
        self.warnings: List[str] = []
        
        # TikTok ToS compliance patterns
        self.compliance_patterns = {
            'rate_limiting': {
                'required': [
                    r'time\.sleep\(',
                    r'rate.*limit',
                    r'backoff',
                    r'delay',
                ],
                'forbidden': [
                    r'while.*True.*requests',
                    r'for.*in.*range.*requests',
                ]
            },
            'official_api': {
                'required': [
                    r'open\.tiktokapis\.com',
                    r'api\.tiktok\.com',
                ],
                'forbidden': [
                    r'scraping',
                    r'webdriver',
                    r'selenium',
                    r'beautifulsoup',
                    r'requests-html',
                ]
            },
            'consent_mode': {
                'required': [
                    r'consent.*mode',
                    r'self.*owned',
                    r'user.*consent',
                    r'release.*form',
                ]
            },
            'pii_handling': {
                'required': [
                    r'hash.*pii',
                    r'redact.*pii',
                    r'salt.*hash',
                    r'encrypt.*pii',
                ],
                'forbidden': [
                    r'print.*email',
                    r'log.*phone',
                    r'debug.*ssn',
                ]
            }
        }
    
    def check_file(self, file_path: Path) -> None:
        """Check a single file for ToS compliance"""
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
            
        # Check for compliance patterns
        for category, patterns in self.compliance_patterns.items():
            self._check_patterns(file_path, content, category, patterns)
    
    def _check_patterns(self, file_path: Path, content: str, category: str, patterns: dict) -> None:
        """Check specific compliance patterns in file content"""
        lines = content.split('\n')
        
        # Check required patterns
        if 'required' in patterns:
            found_required = False
            for pattern in patterns['required']:
                if re.search(pattern, content, re.IGNORECASE):
                    found_required = True
                    break
            
            if not found_required:
                self.warnings.append(
                    f"{file_path}: Missing {category} compliance pattern "
                    f"(consider adding: {', '.join(patterns['required'])})"
                )
        
        # Check forbidden patterns
        if 'forbidden' in patterns:
            for pattern in patterns['forbidden']:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self.violations.append(
                        f"{file_path}:{line_num}: ToS violation - {category} "
                        f"forbidden pattern: {pattern}"
                    )
    
    def check_codebase(self, root_path: Path) -> None:
        """Check entire codebase for ToS compliance"""
        python_files = list(root_path.rglob('*.py'))
        
        for file_path in python_files:
            self.check_file(file_path)
    
    def print_report(self) -> int:
        """Print compliance report and return exit code"""
        print("🔍 TikTok ToS Compliance Check")
        print("=" * 50)
        
        if not self.violations and not self.warnings:
            print("✅ All checks passed! Codebase is ToS compliant.")
            return 0
        
        if self.violations:
            print("\n❌ VIOLATIONS FOUND:")
            for violation in self.violations:
                print(f"  {violation}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"  {warning}")
        
        print(f"\n📊 Summary:")
        print(f"  Violations: {len(self.violations)}")
        print(f"  Warnings: {len(self.warnings)}")
        
        # Return non-zero exit code if violations found
        return 1 if self.violations else 0


def main():
    """Main entry point"""
    root_path = Path('.')
    
    checker = ToSComplianceChecker()
    checker.check_codebase(root_path)
    
    exit_code = checker.print_report()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
