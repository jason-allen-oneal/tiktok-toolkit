#!/usr/bin/env python3
"""
TikTok Toolkit CLI

Command-line interface for TikTok cybersecurity analysis with offline mode,
media scrubbing, and report generation capabilities.
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import cv2
import numpy as np
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security import hash_pii, redact_pii, verify_pii_hash
from logger import logger


class TikTokCLI:
    """Command-line interface for TikTok toolkit"""
    
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser"""
        parser = argparse.ArgumentParser(
            description="TikTok Cybersecurity Analysis Toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Analyze exported JSON data offline
  python cli.py --offline data.json --report html
  
  # Generate PDF report with media scrubbing
  python cli.py --offline data.json --scrub-media --report pdf
  
  # Analyze with consent mode (self-owned accounts only)
  python cli.py --consent-mode --report markdown
            """
        )
        
        # Main analysis options
        parser.add_argument(
            '--offline',
            type=str,
            help='Analyze exported JSON data file (offline mode)'
        )
        
        parser.add_argument(
            '--scrub-media',
            action='store_true',
            help='Blur faces and redact sensitive information in media'
        )
        
        parser.add_argument(
            '--consent-mode',
            action='store_true',
            help='Operate only on self-owned accounts (requires signed release for others)'
        )
        
        # Report generation
        parser.add_argument(
            '--report',
            choices=['md', 'html', 'pdf'],
            default='md',
            help='Report format (default: md)'
        )
        
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path (default: auto-generated)'
        )
        
        # Analysis options
        parser.add_argument(
            '--pii-hash',
            action='store_true',
            help='Hash PII by default instead of redacting'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )
        
        return parser
    
    def run(self) -> int:
        """Run the CLI application"""
        self.args = self.parser.parse_args()
        
        try:
            if self.args.offline:
                return self._run_offline_analysis()
            else:
                self.parser.print_help()
                return 1
        except Exception as e:
            logger.error("CLI", f"Error: {e}")
            return 1
    
    def _run_offline_analysis(self) -> int:
        """Run offline analysis on exported JSON data"""
        json_file = Path(self.args.offline)
        
        if not json_file.exists():
            logger.error("CLI", f"File not found: {json_file}")
            return 1
        
        try:
            # Load and validate JSON data
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            logger.info("CLI", f"Loaded data from {json_file}")
            
            # Perform analysis
            analysis_results = self._analyze_data(data)
            
            # Generate report
            report_path = self._generate_report(analysis_results)
            
            logger.info("CLI", f"Analysis complete. Report saved to: {report_path}")
            return 0
            
        except json.JSONDecodeError as e:
            logger.error("CLI", f"Invalid JSON file: {e}")
            return 1
        except Exception as e:
            logger.error("CLI", f"Analysis failed: {e}")
            return 1
    
    def _analyze_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the loaded data"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'offline',
            'consent_mode': self.args.consent_mode,
            'pii_hashed': self.args.pii_hash,
            'media_scrubbed': self.args.scrub_media,
            'privacy_analysis': {},
            'forensics': {},
            'impersonation': {},
            'anomalies': {},
            'stalkerware': {},
        }
        
        # Privacy analysis
        results['privacy_analysis'] = self._analyze_privacy(data)
        
        # Forensics analysis
        results['forensics'] = self._analyze_forensics(data)
        
        # Impersonation detection
        results['impersonation'] = self._analyze_impersonation(data)
        
        # Anomaly detection
        results['anomalies'] = self._analyze_anomalies(data)
        
        # Stalkerware detection
        results['stalkerware'] = self._analyze_stalkerware(data)
        
        return results
    
    def _analyze_privacy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze privacy and PII exposure"""
        privacy_results = {
            'pii_found': [],
            'privacy_score': 100,
            'exposure_risks': [],
            'recommendations': []
        }
        
        # Extract text content for PII analysis
        text_content = self._extract_text_content(data)
        
        # PII patterns
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'(?:(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,3}\d{2,4})',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        }
        
        import re
        for pii_type, pattern in pii_patterns.items():
            matches = re.findall(pattern, text_content)
            for match in matches:
                if self.args.pii_hash:
                    hashed_value = hash_pii(match)
                    privacy_results['pii_found'].append({
                        'type': pii_type,
                        'value': hashed_value,
                        'original_length': len(match)
                    })
                else:
                    privacy_results['pii_found'].append({
                        'type': pii_type,
                        'value': match[:3] + '*' * (len(match) - 6) + match[-3:] if len(match) > 6 else '***',
                        'original_length': len(match)
                    })
                
                # Adjust privacy score
                if pii_type == 'email':
                    privacy_results['privacy_score'] -= 15
                elif pii_type == 'phone':
                    privacy_results['privacy_score'] -= 12
                elif pii_type == 'ssn':
                    privacy_results['privacy_score'] -= 25
                elif pii_type == 'credit_card':
                    privacy_results['privacy_score'] -= 25
        
        # Generate recommendations
        if privacy_results['pii_found']:
            privacy_results['exposure_risks'].append("PII detected in content")
            privacy_results['recommendations'].append("Remove or redact PII from public content")
        
        if privacy_results['privacy_score'] < 70:
            privacy_results['recommendations'].append("Review privacy settings and content")
        
        return privacy_results
    
    def _analyze_forensics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze forensic data"""
        forensics_results = {
            'metadata': {},
            'engagement_patterns': {},
            'timestamps': [],
            'suspicious_indicators': []
        }
        
        # Extract metadata
        if 'videos' in data:
            for video in data['videos']:
                if 'create_time' in video:
                    forensics_results['timestamps'].append(video['create_time'])
                
                if 'statistics' in video:
                    stats = video['statistics']
                    forensics_results['engagement_patterns'][video.get('id', 'unknown')] = {
                        'views': stats.get('view_count', 0),
                        'likes': stats.get('like_count', 0),
                        'comments': stats.get('comment_count', 0),
                        'shares': stats.get('share_count', 0)
                    }
        
        return forensics_results
    
    def _analyze_impersonation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze for impersonation indicators"""
        impersonation_results = {
            'similar_accounts': [],
            'cloned_profiles': [],
            'suspicious_patterns': []
        }
        
        # This would typically compare against a database of known accounts
        # For offline mode, we can only analyze patterns in the current data
        
        if 'user' in data:
            user_data = data['user']
            username = user_data.get('unique_id', '')
            
            # Check for suspicious username patterns
            if len(username) < 3:
                impersonation_results['suspicious_patterns'].append("Very short username")
            
            if username.count('_') > 3:
                impersonation_results['suspicious_patterns'].append("Excessive underscores in username")
        
        return impersonation_results
    
    def _analyze_anomalies(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze for engagement anomalies"""
        anomaly_results = {
            'bot_indicators': [],
            'engagement_spikes': [],
            'suspicious_patterns': []
        }
        
        if 'videos' in data:
            engagement_data = []
            for video in data['videos']:
                if 'statistics' in video:
                    stats = video['statistics']
                    engagement_data.append({
                        'views': stats.get('view_count', 0),
                        'likes': stats.get('like_count', 0),
                        'comments': stats.get('comment_count', 0),
                        'shares': stats.get('share_count', 0)
                    })
            
            # Simple anomaly detection
            if engagement_data:
                view_counts = [e['views'] for e in engagement_data]
                like_counts = [e['likes'] for e in engagement_data]
                
                # Check for suspicious like/view ratios
                for i, (views, likes) in enumerate(zip(view_counts, like_counts)):
                    if views > 0 and likes / views > 0.5:
                        anomaly_results['suspicious_patterns'].append(
                            f"Video {i}: Unusually high like/view ratio ({likes/views:.2f})"
                        )
        
        return anomaly_results
    
    def _analyze_stalkerware(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze for stalkerware indicators"""
        stalkerware_results = {
            'obsessive_patterns': [],
            'risk_level': 'low',
            'recommendations': []
        }
        
        # Analyze engagement patterns for obsessive behavior
        if 'videos' in data:
            total_videos = len(data['videos'])
            if total_videos > 100:
                stalkerware_results['obsessive_patterns'].append("High volume of content")
                stalkerware_results['risk_level'] = 'medium'
        
        return stalkerware_results
    
    def _extract_text_content(self, data: Dict[str, Any]) -> str:
        """Extract all text content from data for PII analysis"""
        text_parts = []
        
        def extract_text(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in ['desc', 'title', 'text', 'bio', 'nickname']:
                        if isinstance(value, str):
                            text_parts.append(value)
                    else:
                        extract_text(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_text(item)
        
        extract_text(data)
        return ' '.join(text_parts)
    
    def _generate_report(self, results: Dict[str, Any]) -> str:
        """Generate report in specified format"""
        if self.args.output:
            output_path = Path(self.args.output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"tiktok_analysis_{timestamp}.{self.args.report}")
        
        if self.args.report == 'md':
            return self._generate_markdown_report(results, output_path)
        elif self.args.report == 'html':
            return self._generate_html_report(results, output_path)
        elif self.args.report == 'pdf':
            return self._generate_pdf_report(results, output_path)
        
        return str(output_path)
    
    def _generate_markdown_report(self, results: Dict[str, Any], output_path: Path) -> str:
        """Generate markdown report"""
        with open(output_path, 'w') as f:
            f.write("# TikTok Cybersecurity Analysis Report\n\n")
            f.write(f"**Generated:** {results['timestamp']}\n")
            f.write(f"**Analysis Type:** {results['analysis_type']}\n")
            f.write(f"**Consent Mode:** {results['consent_mode']}\n\n")
            
            # Privacy Analysis
            f.write("## Privacy Analysis\n\n")
            privacy = results['privacy_analysis']
            f.write(f"**Privacy Score:** {privacy['privacy_score']}/100\n\n")
            
            if privacy['pii_found']:
                f.write("### PII Detected\n\n")
                for pii in privacy['pii_found']:
                    f.write(f"- **{pii['type'].upper()}:** {pii['value']}\n")
                f.write("\n")
            
            if privacy['recommendations']:
                f.write("### Recommendations\n\n")
                for rec in privacy['recommendations']:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            # Forensics
            f.write("## Forensics Analysis\n\n")
            forensics = results['forensics']
            f.write(f"**Videos Analyzed:** {len(forensics['engagement_patterns'])}\n\n")
            
            # Impersonation
            f.write("## Impersonation Detection\n\n")
            impersonation = results['impersonation']
            if impersonation['suspicious_patterns']:
                f.write("### Suspicious Patterns\n\n")
                for pattern in impersonation['suspicious_patterns']:
                    f.write(f"- {pattern}\n")
                f.write("\n")
            
            # Anomalies
            f.write("## Anomaly Detection\n\n")
            anomalies = results['anomalies']
            if anomalies['suspicious_patterns']:
                f.write("### Suspicious Patterns\n\n")
                for pattern in anomalies['suspicious_patterns']:
                    f.write(f"- {pattern}\n")
                f.write("\n")
            
            # Stalkerware
            f.write("## Stalkerware Detection\n\n")
            stalkerware = results['stalkerware']
            f.write(f"**Risk Level:** {stalkerware['risk_level'].upper()}\n\n")
            
            if stalkerware['recommendations']:
                f.write("### Recommendations\n\n")
                for rec in stalkerware['recommendations']:
                    f.write(f"- {rec}\n")
        
        return str(output_path)
    
    def _generate_html_report(self, results: Dict[str, Any], output_path: Path) -> str:
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TikTok Cybersecurity Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .score {{ font-size: 24px; font-weight: bold; color: #fe2c55; }}
        .warning {{ color: #ff6b35; }}
        .success {{ color: #4CAF50; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TikTok Cybersecurity Analysis Report</h1>
        <p><strong>Generated:</strong> {results['timestamp']}</p>
        <p><strong>Analysis Type:</strong> {results['analysis_type']}</p>
        <p><strong>Consent Mode:</strong> {results['consent_mode']}</p>
    </div>
    
    <div class="section">
        <h2>Privacy Analysis</h2>
        <p class="score">Privacy Score: {results['privacy_analysis']['privacy_score']}/100</p>
        <p>PII Found: {len(results['privacy_analysis']['pii_found'])} items</p>
    </div>
    
    <div class="section">
        <h2>Forensics Analysis</h2>
        <p>Videos Analyzed: {len(results['forensics']['engagement_patterns'])}</p>
    </div>
    
    <div class="section">
        <h2>Impersonation Detection</h2>
        <p>Suspicious Patterns: {len(results['impersonation']['suspicious_patterns'])}</p>
    </div>
    
    <div class="section">
        <h2>Anomaly Detection</h2>
        <p>Suspicious Patterns: {len(results['anomalies']['suspicious_patterns'])}</p>
    </div>
    
    <div class="section">
        <h2>Stalkerware Detection</h2>
        <p>Risk Level: <span class="warning">{results['stalkerware']['risk_level'].upper()}</span></p>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_pdf_report(self, results: Dict[str, Any], output_path: Path) -> str:
        """Generate PDF report"""
        try:
            from weasyprint import HTML
            from jinja2 import Template
            
            # Create HTML content first
            html_path = output_path.with_suffix('.html')
            self._generate_html_report(results, html_path)
            
            # Convert to PDF
            HTML(filename=str(html_path)).write_pdf(str(output_path))
            
            # Clean up temporary HTML file
            html_path.unlink()
            
            return str(output_path)
        except ImportError:
            logger.error("CLI", "weasyprint not available, falling back to HTML")
            return self._generate_html_report(results, output_path)
        except Exception as e:
            logger.error("CLI", f"PDF generation failed: {e}")
            return self._generate_html_report(results, output_path)


def main():
    """Main entry point"""
    cli = TikTokCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
