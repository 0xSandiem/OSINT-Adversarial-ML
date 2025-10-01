"""
OSINT Discovery Module

WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY.
This module demonstrates how misconfigured systems can be discovered through OSINT techniques.

Components:
- Directory scanner for exposed data/models
- Configuration checker for misconfigured storage
- Model fingerprinting to identify ML frameworks
- Vulnerability documentation
"""

import os
import json
import logging
import time
from pathlib import Path
from datetime import datetime
import requests
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OSINTScanner:
    """
    OSINT-based scanner for discovering misconfigured ML systems.

    ETHICAL USE ONLY: This tool is designed for security research and
    defensive security purposes on systems you own or have permission to test.
    """

    def __init__(self, base_path='./', api_url=None):
        """
        Initialize OSINT scanner.

        Args:
            base_path: Base path to scan for exposed files
            api_url: URL of the ML API to fingerprint (if available)
        """
        self.base_path = Path(base_path)
        self.api_url = api_url
        self.discoveries = {
            'exposed_data': [],
            'exposed_models': [],
            'exposed_configs': [],
            'api_vulnerabilities': [],
            'metadata': {}
        }
        self.start_time = None

    def scan_directory_structure(self) -> Dict:
        """
        Scan for exposed directories and files.

        Simulates finding misconfigured cloud storage (S3, Azure Blob, etc.)
        by looking for common patterns and indicators.

        Returns:
            Dictionary of discovered files and directories
        """
        logger.info(f"Scanning directory structure at {self.base_path}")
        self.start_time = time.time()

        # Patterns indicating misconfiguration
        exposed_patterns = [
            '**/data/**/*.npy',
            '**/data/**/*.json',
            '**/models/**/*.keras',
            '**/models/**/*.h5',
            '**/models/**/*.json',
            '**/config*.json',
            '**/metadata*.json',
            '**/.env',
            '**/credentials*.json'
        ]

        for pattern in exposed_patterns:
            matches = list(self.base_path.glob(pattern))

            for match in matches:
                file_info = self._analyze_file(match)

                if 'data' in str(match) and match.suffix in ['.npy', '.npz']:
                    self.discoveries['exposed_data'].append(file_info)
                    logger.warning(f"EXPOSED DATA FOUND: {match}")

                elif 'models' in str(match) and match.suffix in ['.keras', '.h5', '.pb']:
                    self.discoveries['exposed_models'].append(file_info)
                    logger.warning(f"EXPOSED MODEL FOUND: {match}")

                elif match.suffix == '.json':
                    self.discoveries['exposed_configs'].append(file_info)
                    logger.warning(f"EXPOSED CONFIG FOUND: {match}")

        discovery_time = time.time() - self.start_time
        self.discoveries['metadata']['discovery_time_seconds'] = discovery_time
        self.discoveries['metadata']['scan_timestamp'] = datetime.now().isoformat()

        logger.info(f"Directory scan complete in {discovery_time:.2f}s")
        logger.info(f"Found: {len(self.discoveries['exposed_data'])} data files, "
                   f"{len(self.discoveries['exposed_models'])} model files, "
                   f"{len(self.discoveries['exposed_configs'])} config files")

        return self.discoveries

    def _analyze_file(self, file_path: Path) -> Dict:
        """Analyze a discovered file and extract metadata."""
        stats = file_path.stat()

        info = {
            'path': str(file_path),
            'name': file_path.name,
            'size_bytes': stats.st_size,
            'modified_time': datetime.fromtimestamp(stats.st_mtime).isoformat(),
            'extension': file_path.suffix
        }

        # Try to read JSON configs
        if file_path.suffix == '.json':
            try:
                with open(file_path, 'r') as f:
                    info['content'] = json.load(f)
            except Exception as e:
                info['read_error'] = str(e)

        return info

    def check_storage_misconfiguration(self) -> List[Dict]:
        """
        Check for common storage misconfigurations.

        Simulates checking:
        - S3 bucket public access
        - Azure Blob anonymous access
        - Google Cloud Storage public objects
        - File permission issues

        Returns:
            List of discovered misconfigurations
        """
        logger.info("Checking for storage misconfigurations...")

        misconfigurations = []

        # Check for world-readable directories
        sensitive_dirs = ['data', 'models', 'config']

        for dir_name in sensitive_dirs:
            dir_path = self.base_path / dir_name

            if dir_path.exists():
                # Simulate checking permissions
                stats = dir_path.stat()

                # Check if directory appears to be publicly accessible
                # In real scenarios, this would check S3/Azure/GCS ACLs
                misconfig = {
                    'type': 'directory_exposure',
                    'path': str(dir_path),
                    'severity': 'HIGH',
                    'description': f'Directory {dir_name} may be publicly accessible',
                    'permissions': oct(stats.st_mode)[-3:],
                    'recommendation': 'Implement access controls and encryption'
                }

                misconfigurations.append(misconfig)
                logger.warning(f"MISCONFIGURATION FOUND: {dir_path} - {misconfig['description']}")

        # Check for exposed configuration files
        for config in self.discoveries['exposed_configs']:
            if 'content' in config and isinstance(config['content'], dict):
                content = config['content']

                # Check for sensitive information in configs
                sensitive_keys = ['access_control', 'encryption', 'data_location', 'model_location']

                for key in sensitive_keys:
                    if key in content and content[key] in ['NONE', 'DISABLED', None]:
                        misconfig = {
                            'type': 'configuration_vulnerability',
                            'file': config['path'],
                            'field': key,
                            'value': content[key],
                            'severity': 'CRITICAL',
                            'description': f'Security control {key} is disabled or missing'
                        }
                        misconfigurations.append(misconfig)
                        logger.warning(f"CRITICAL: {misconfig['description']} in {config['name']}")

        return misconfigurations

    def fingerprint_model(self) -> Dict:
        """
        Fingerprint the ML model to identify framework and architecture.

        Analyzes:
        - Model file formats
        - Configuration files
        - Framework-specific artifacts

        Returns:
            Dictionary with model fingerprinting results
        """
        logger.info("Fingerprinting ML model...")

        fingerprint = {
            'framework': 'unknown',
            'architecture': 'unknown',
            'input_shape': None,
            'num_classes': None,
            'training_data_location': None,
            'confidence': 0.0
        }

        # Analyze model files
        for model_file in self.discoveries['exposed_models']:
            if model_file['extension'] in ['.keras', '.h5']:
                fingerprint['framework'] = 'tensorflow/keras'
                fingerprint['confidence'] = 0.9

            elif model_file['extension'] == '.pth':
                fingerprint['framework'] = 'pytorch'
                fingerprint['confidence'] = 0.9

            elif model_file['extension'] == '.pkl':
                fingerprint['framework'] = 'scikit-learn'
                fingerprint['confidence'] = 0.8

        # Extract details from config files
        for config_file in self.discoveries['exposed_configs']:
            if 'content' in config_file:
                content = config_file['content']

                if 'framework' in content:
                    fingerprint['framework'] = content['framework']
                    if 'framework_version' in content:
                        fingerprint['framework_version'] = content['framework_version']

                if 'input_shape' in content:
                    fingerprint['input_shape'] = content['input_shape']

                if 'num_classes' in content:
                    fingerprint['num_classes'] = content['num_classes']

                if 'architecture' in content:
                    fingerprint['architecture'] = content['architecture']

                if 'data_dir' in content:
                    fingerprint['training_data_location'] = content['data_dir']

                fingerprint['confidence'] = 1.0

        logger.info(f"Model fingerprint: {fingerprint['framework']}, "
                   f"architecture: {fingerprint['architecture']}, "
                   f"confidence: {fingerprint['confidence']}")

        return fingerprint

    def probe_api(self) -> Dict:
        """
        Probe the ML API for vulnerabilities.

        Tests for:
        - Information disclosure endpoints
        - Missing authentication
        - Rate limiting
        - Error message verbosity

        Returns:
            Dictionary of API vulnerabilities
        """
        if not self.api_url:
            logger.info("No API URL provided, skipping API probing")
            return {}

        logger.info(f"Probing API at {self.api_url}")

        vulnerabilities = []

        # Test common information disclosure endpoints
        info_endpoints = [
            '/info',
            '/config',
            '/metadata',
            '/health',
            '/status',
            '/statistics',
            '/query_log',
            '/debug'
        ]

        for endpoint in info_endpoints:
            try:
                url = f"{self.api_url}{endpoint}"
                response = requests.get(url, timeout=5)

                if response.status_code == 200:
                    vuln = {
                        'type': 'information_disclosure',
                        'endpoint': endpoint,
                        'severity': 'HIGH' if endpoint in ['/info', '/config', '/query_log'] else 'MEDIUM',
                        'description': f'Endpoint {endpoint} exposes sensitive information',
                        'response_size': len(response.text),
                        'sample_data': response.json() if response.headers.get('content-type', '').startswith('application/json') else None
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"API VULNERABILITY: {endpoint} accessible without authentication")

            except Exception as e:
                logger.debug(f"Endpoint {endpoint} not accessible: {e}")

        # Test for authentication
        try:
            response = requests.post(f"{self.api_url}/predict",
                                    json={'image': [[0] * 784]},
                                    timeout=5)

            if response.status_code in [200, 400]:
                vuln = {
                    'type': 'missing_authentication',
                    'endpoint': '/predict',
                    'severity': 'CRITICAL',
                    'description': 'Prediction endpoint accessible without authentication'
                }
                vulnerabilities.append(vuln)
                logger.warning("CRITICAL: API has no authentication!")

        except Exception as e:
            logger.debug(f"Prediction endpoint test failed: {e}")

        # Test for rate limiting
        logger.info("Testing for rate limiting...")
        rate_limit_test = []

        for i in range(10):
            try:
                start = time.time()
                response = requests.get(f"{self.api_url}/health", timeout=5)
                elapsed = time.time() - start
                rate_limit_test.append({
                    'request': i + 1,
                    'response_time': elapsed,
                    'status': response.status_code
                })
            except Exception as e:
                logger.debug(f"Rate limit test request {i + 1} failed: {e}")

        if len(rate_limit_test) == 10:
            vuln = {
                'type': 'no_rate_limiting',
                'severity': 'HIGH',
                'description': 'API has no rate limiting - enables rapid model extraction',
                'test_results': rate_limit_test
            }
            vulnerabilities.append(vuln)
            logger.warning("HIGH: API has no rate limiting!")

        return {
            'vulnerabilities': vulnerabilities,
            'total_found': len(vulnerabilities)
        }

    def generate_report(self, output_path='./osint_discovery_report.json') -> str:
        """
        Generate comprehensive OSINT discovery report.

        Args:
            output_path: Path to save the report

        Returns:
            Path to the generated report
        """
        logger.info("Generating OSINT discovery report...")

        # Compile all findings
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'base_path': str(self.base_path),
                'api_url': self.api_url,
                'discovery_time_seconds': self.discoveries['metadata'].get('discovery_time_seconds', 0)
            },
            'summary': {
                'exposed_data_files': len(self.discoveries['exposed_data']),
                'exposed_model_files': len(self.discoveries['exposed_models']),
                'exposed_config_files': len(self.discoveries['exposed_configs']),
                'misconfigurations_found': len(self.check_storage_misconfiguration()),
                'api_vulnerabilities': len(self.discoveries.get('api_vulnerabilities', []))
            },
            'detailed_findings': {
                'exposed_data': self.discoveries['exposed_data'],
                'exposed_models': self.discoveries['exposed_models'],
                'exposed_configs': self.discoveries['exposed_configs'],
                'misconfigurations': self.check_storage_misconfiguration(),
                'model_fingerprint': self.fingerprint_model(),
                'api_vulnerabilities': self.discoveries.get('api_vulnerabilities', [])
            },
            'risk_assessment': self._assess_risk(),
            'recommendations': self._generate_recommendations()
        }

        # Save report
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved to {output_path}")

        return output_path

    def _assess_risk(self) -> Dict:
        """Assess overall risk based on discoveries."""
        risk_score = 0
        max_score = 100

        # Calculate risk score
        risk_score += len(self.discoveries['exposed_data']) * 10
        risk_score += len(self.discoveries['exposed_models']) * 15
        risk_score += len(self.discoveries['exposed_configs']) * 5

        misconfigs = self.check_storage_misconfiguration()
        risk_score += sum(10 if m.get('severity') == 'CRITICAL' else 5 for m in misconfigs)

        risk_level = 'LOW'
        if risk_score > 70:
            risk_level = 'CRITICAL'
        elif risk_score > 40:
            risk_level = 'HIGH'
        elif risk_score > 20:
            risk_level = 'MEDIUM'

        return {
            'risk_score': min(risk_score, max_score),
            'risk_level': risk_level,
            'max_score': max_score
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        if self.discoveries['exposed_data']:
            recommendations.append("Implement access controls on training data storage")
            recommendations.append("Encrypt sensitive training data at rest")

        if self.discoveries['exposed_models']:
            recommendations.append("Restrict access to model files using IAM policies")
            recommendations.append("Implement model integrity verification")

        if self.discoveries['exposed_configs']:
            recommendations.append("Remove sensitive information from configuration files")
            recommendations.append("Use secrets management solutions for credentials")

        recommendations.extend([
            "Enable authentication and authorization on API endpoints",
            "Implement rate limiting to prevent model extraction attacks",
            "Use minimal error messages to avoid information disclosure",
            "Monitor and log API access for anomaly detection",
            "Regular security audits and penetration testing"
        ])

        return recommendations


def main():
    """Main function to run OSINT discovery."""
    print("=" * 80)
    print("OSINT DISCOVERY MODULE")
    print("=" * 80)
    print("\n⚠️  FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY")
    print("   Only use on systems you own or have permission to test!\n")

    # Initialize scanner
    scanner = OSINTScanner(base_path='./', api_url='http://127.0.0.1:5000')

    # Run discovery
    print("\n[1/4] Scanning directory structure...")
    scanner.scan_directory_structure()

    print("\n[2/4] Checking storage misconfigurations...")
    misconfigs = scanner.check_storage_misconfiguration()

    print("\n[3/4] Fingerprinting model...")
    fingerprint = scanner.fingerprint_model()

    print("\n[4/4] Probing API (if available)...")
    api_vulns = scanner.probe_api()
    scanner.discoveries['api_vulnerabilities'] = api_vulns.get('vulnerabilities', [])

    # Generate report
    print("\nGenerating report...")
    report_path = scanner.generate_report()

    print(f"\n✓ Discovery complete! Report saved to: {report_path}")
    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
