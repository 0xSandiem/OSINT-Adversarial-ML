"""
Defense Framework for ML Systems

This module implements defensive measures against OSINT-driven adversarial attacks:

1. Access Control Simulator - Proper authentication and authorization
2. Input Validation - Detect malicious/adversarial inputs
3. Anomaly Detection - Identify suspicious query patterns
4. Model Versioning - Integrity verification and secure storage
5. Rate Limiting - Prevent rapid model extraction
"""

import os
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import numpy as np
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AccessControlSimulator:
    """
    Simulates access control for ML systems.

    Implements:
    - Authentication tokens
    - Role-based access control (RBAC)
    - Resource-level permissions
    """

    def __init__(self):
        """Initialize access control."""
        self.users = {}
        self.access_log = []

    def create_user(self, user_id: str, role: str = 'user', permissions: List[str] = None):
        """
        Create a user with specified role and permissions.

        Args:
            user_id: User identifier
            role: User role (admin, user, service)
            permissions: List of allowed operations
        """
        if permissions is None:
            permissions = ['predict'] if role == 'user' else ['predict', 'info', 'statistics']

        token = hashlib.sha256(f"{user_id}{time.time()}".encode()).hexdigest()

        self.users[token] = {
            'user_id': user_id,
            'role': role,
            'permissions': permissions,
            'created_at': datetime.now().isoformat(),
            'token': token
        }

        logger.info(f"Created user: {user_id} with role: {role}")

        return token

    def verify_access(self, token: str, resource: str) -> Tuple[bool, Optional[str]]:
        """
        Verify if user has access to resource.

        Args:
            token: Authentication token
            resource: Resource being accessed

        Returns:
            Tuple of (allowed, error_message)
        """
        if not token:
            return False, "No authentication token provided"

        if token not in self.users:
            self.access_log.append({
                'timestamp': datetime.now().isoformat(),
                'token': token[:10] + "...",
                'resource': resource,
                'result': 'denied',
                'reason': 'invalid_token'
            })
            return False, "Invalid authentication token"

        user = self.users[token]

        if resource not in user['permissions']:
            self.access_log.append({
                'timestamp': datetime.now().isoformat(),
                'user_id': user['user_id'],
                'resource': resource,
                'result': 'denied',
                'reason': 'insufficient_permissions'
            })
            return False, f"Insufficient permissions for {resource}"

        self.access_log.append({
            'timestamp': datetime.now().isoformat(),
            'user_id': user['user_id'],
            'resource': resource,
            'result': 'allowed'
        })

        return True, None

    def get_access_statistics(self) -> Dict:
        """Get access control statistics."""
        total_attempts = len(self.access_log)
        denied = sum(1 for log in self.access_log if log['result'] == 'denied')

        return {
            'total_access_attempts': total_attempts,
            'denied_attempts': denied,
            'allowed_attempts': total_attempts - denied,
            'denial_rate': denied / total_attempts if total_attempts > 0 else 0
        }


class InputValidator:
    """
    Validates inputs to detect adversarial examples.

    Methods:
    - Statistical anomaly detection
    - Perturbation detection
    - Input sanitization
    """

    def __init__(self, expected_shape: Tuple, value_range: Tuple = (0, 1)):
        """
        Initialize input validator.

        Args:
            expected_shape: Expected input shape
            value_range: Valid value range for inputs
        """
        self.expected_shape = expected_shape
        self.value_range = value_range
        self.baseline_stats = None
        self.validation_log = []

    def set_baseline(self, x_train: np.ndarray):
        """
        Set baseline statistics from training data.

        Args:
            x_train: Training data for computing baseline
        """
        logger.info("Computing baseline statistics for input validation")

        self.baseline_stats = {
            'mean': float(np.mean(x_train)),
            'std': float(np.std(x_train)),
            'min': float(np.min(x_train)),
            'max': float(np.max(x_train)),
            'percentile_95': float(np.percentile(np.abs(x_train), 95))
        }

        logger.info(f"Baseline: mean={self.baseline_stats['mean']:.4f}, "
                   f"std={self.baseline_stats['std']:.4f}")

    def validate_input(self, x: np.ndarray, threshold: float = 3.0) -> Tuple[bool, str]:
        """
        Validate input for anomalies.

        Args:
            x: Input to validate
            threshold: Standard deviations from baseline to flag as anomaly

        Returns:
            Tuple of (is_valid, reason)
        """
        # Check shape
        if x.shape[1:] != self.expected_shape:
            reason = f"Invalid shape: expected {self.expected_shape}, got {x.shape[1:]}"
            self.validation_log.append({
                'timestamp': datetime.now().isoformat(),
                'valid': False,
                'reason': reason
            })
            return False, reason

        # Check value range
        if np.min(x) < self.value_range[0] or np.max(x) > self.value_range[1]:
            reason = f"Values outside range {self.value_range}"
            self.validation_log.append({
                'timestamp': datetime.now().isoformat(),
                'valid': False,
                'reason': reason
            })
            return False, reason

        # Check for statistical anomalies (if baseline set)
        if self.baseline_stats:
            x_mean = np.mean(x)
            x_std = np.std(x)

            # Z-score for mean
            mean_z = abs(x_mean - self.baseline_stats['mean']) / self.baseline_stats['std']

            if mean_z > threshold:
                reason = f"Statistical anomaly detected: mean z-score={mean_z:.2f}"
                self.validation_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'valid': False,
                    'reason': reason,
                    'mean_z_score': float(mean_z)
                })
                return False, reason

        self.validation_log.append({
            'timestamp': datetime.now().isoformat(),
            'valid': True
        })

        return True, "Valid input"

    def detect_adversarial_perturbation(self, x: np.ndarray, reference: np.ndarray,
                                       epsilon: float = 0.1) -> Tuple[bool, float]:
        """
        Detect adversarial perturbations by comparing to reference.

        Args:
            x: Input to check
            reference: Reference clean input
            epsilon: Perturbation threshold

        Returns:
            Tuple of (is_adversarial, perturbation_magnitude)
        """
        perturbation = np.abs(x - reference)
        max_perturbation = np.max(perturbation)
        avg_perturbation = np.mean(perturbation)

        is_adversarial = max_perturbation > epsilon

        return is_adversarial, float(avg_perturbation)


class AnomalyDetector:
    """
    Detects anomalous query patterns indicative of attacks.

    Detects:
    - Rapid successive queries (model extraction)
    - Unusual query patterns
    - Repeated similar queries
    """

    def __init__(self, window_size: int = 60, max_queries: int = 100):
        """
        Initialize anomaly detector.

        Args:
            window_size: Time window in seconds for rate limiting
            max_queries: Maximum queries allowed in window
        """
        self.window_size = window_size
        self.max_queries = max_queries
        self.query_history = defaultdict(deque)
        self.alert_log = []

    def record_query(self, client_id: str, query_data: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Record a query and check for anomalies.

        Args:
            client_id: Client identifier
            query_data: Optional query metadata

        Returns:
            Tuple of (is_allowed, reason)
        """
        current_time = time.time()

        # Clean old queries outside window
        while (self.query_history[client_id] and
               current_time - self.query_history[client_id][0]['timestamp'] > self.window_size):
            self.query_history[client_id].popleft()

        # Check rate limit
        if len(self.query_history[client_id]) >= self.max_queries:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'client_id': client_id,
                'alert_type': 'rate_limit_exceeded',
                'queries_in_window': len(self.query_history[client_id]),
                'window_size': self.window_size
            }
            self.alert_log.append(alert)
            logger.warning(f"ALERT: Rate limit exceeded for client {client_id}")

            return False, f"Rate limit exceeded: {self.max_queries} queries per {self.window_size}s"

        # Record query
        query_record = {
            'timestamp': current_time,
            'data': query_data
        }
        self.query_history[client_id].append(query_record)

        return True, "Query allowed"

    def detect_extraction_pattern(self, client_id: str) -> Tuple[bool, Dict]:
        """
        Detect patterns indicative of model extraction attacks.

        Args:
            client_id: Client identifier

        Returns:
            Tuple of (is_suspicious, details)
        """
        queries = list(self.query_history[client_id])

        if len(queries) < 10:
            return False, {}

        # Check for rapid queries
        timestamps = [q['timestamp'] for q in queries[-10:]]
        time_diffs = np.diff(timestamps)
        avg_interval = np.mean(time_diffs)

        # Suspicious if queries are very regular and rapid
        is_suspicious = avg_interval < 1.0 and np.std(time_diffs) < 0.5

        details = {
            'num_queries': len(queries),
            'avg_query_interval': float(avg_interval),
            'std_query_interval': float(np.std(time_diffs)),
            'suspicious': is_suspicious
        }

        if is_suspicious:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'client_id': client_id,
                'alert_type': 'extraction_pattern_detected',
                'details': details
            }
            self.alert_log.append(alert)
            logger.warning(f"ALERT: Extraction pattern detected for client {client_id}")

        return is_suspicious, details

    def get_statistics(self) -> Dict:
        """Get anomaly detection statistics."""
        total_clients = len(self.query_history)
        total_queries = sum(len(queries) for queries in self.query_history.values())
        total_alerts = len(self.alert_log)

        alert_types = defaultdict(int)
        for alert in self.alert_log:
            alert_types[alert['alert_type']] += 1

        return {
            'total_clients': total_clients,
            'total_queries': total_queries,
            'total_alerts': total_alerts,
            'alert_types': dict(alert_types)
        }


class ModelVersionControl:
    """
    Model versioning and integrity verification.

    Implements:
    - Version tracking
    - Integrity checks via hashing
    - Secure storage metadata
    """

    def __init__(self, model_dir: str = './models/secure'):
        """
        Initialize model version control.

        Args:
            model_dir: Directory for secure model storage
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.version_registry = {}
        self.registry_path = self.model_dir / 'version_registry.json'

        # Load existing registry
        if self.registry_path.exists():
            with open(self.registry_path, 'r') as f:
                self.version_registry = json.load(f)

    def register_model(self, model_path: str, version: str, metadata: Dict = None) -> str:
        """
        Register a model version with integrity hash.

        Args:
            model_path: Path to model file
            version: Version identifier
            metadata: Optional metadata

        Returns:
            Model hash for integrity verification
        """
        logger.info(f"Registering model version: {version}")

        # Calculate hash
        model_hash = self._calculate_file_hash(model_path)

        # Store in registry
        self.version_registry[version] = {
            'path': model_path,
            'hash': model_hash,
            'registered_at': datetime.now().isoformat(),
            'metadata': metadata or {}
        }

        # Save registry
        with open(self.registry_path, 'w') as f:
            json.dump(self.version_registry, f, indent=2)

        logger.info(f"Model registered: version={version}, hash={model_hash[:16]}...")

        return model_hash

    def verify_integrity(self, version: str) -> Tuple[bool, str]:
        """
        Verify model integrity.

        Args:
            version: Model version to verify

        Returns:
            Tuple of (is_valid, message)
        """
        if version not in self.version_registry:
            return False, f"Version {version} not found in registry"

        model_info = self.version_registry[version]
        model_path = model_info['path']

        if not os.path.exists(model_path):
            return False, f"Model file not found: {model_path}"

        # Recalculate hash
        current_hash = self._calculate_file_hash(model_path)
        expected_hash = model_info['hash']

        if current_hash != expected_hash:
            logger.error(f"INTEGRITY VIOLATION: Model {version} hash mismatch!")
            return False, "Model integrity check failed - file may be tampered"

        logger.info(f"Integrity verified for model {version}")
        return True, "Model integrity verified"

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def list_versions(self) -> List[Dict]:
        """List all registered model versions."""
        versions = []
        for version, info in self.version_registry.items():
            versions.append({
                'version': version,
                'registered_at': info['registered_at'],
                'hash': info['hash'][:16] + "...",
                'metadata': info.get('metadata', {})
            })
        return versions


class DefenseFramework:
    """
    Integrated defense framework combining all defensive measures.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize defense framework.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Initialize components
        self.access_control = AccessControlSimulator()
        self.input_validator = InputValidator(
            expected_shape=tuple(self.config.get('input_shape', [28, 28, 1])),
            value_range=self.config.get('value_range', (0, 1))
        )
        self.anomaly_detector = AnomalyDetector(
            window_size=self.config.get('rate_limit_window', 60),
            max_queries=self.config.get('max_queries_per_window', 100)
        )
        self.version_control = ModelVersionControl(
            model_dir=self.config.get('secure_model_dir', './models/secure')
        )

        logger.info("Defense framework initialized")

    def validate_request(self, token: str, resource: str, input_data: np.ndarray,
                        client_id: str) -> Tuple[bool, str]:
        """
        Comprehensive request validation.

        Args:
            token: Authentication token
            resource: Resource being accessed
            input_data: Input data
            client_id: Client identifier

        Returns:
            Tuple of (is_valid, reason)
        """
        # 1. Access control
        allowed, error = self.access_control.verify_access(token, resource)
        if not allowed:
            return False, f"Access denied: {error}"

        # 2. Rate limiting / anomaly detection
        allowed, error = self.anomaly_detector.record_query(client_id)
        if not allowed:
            return False, f"Rate limit: {error}"

        # 3. Input validation
        valid, reason = self.input_validator.validate_input(input_data)
        if not valid:
            return False, f"Invalid input: {reason}"

        return True, "Request validated"

    def get_defense_statistics(self) -> Dict:
        """Get comprehensive defense statistics."""
        return {
            'access_control': self.access_control.get_access_statistics(),
            'anomaly_detection': self.anomaly_detector.get_statistics(),
            'input_validation': {
                'total_validations': len(self.input_validator.validation_log),
                'failed_validations': sum(1 for v in self.input_validator.validation_log if not v['valid'])
            },
            'model_versions': len(self.version_control.version_registry)
        }


def main():
    """Main function to demonstrate defense framework."""
    print("=" * 80)
    print("DEFENSE FRAMEWORK")
    print("=" * 80)
    print("\nDemonstrating security controls for ML systems\n")

    # Initialize framework
    config = {
        'input_shape': [28, 28, 1],
        'value_range': (0, 1),
        'rate_limit_window': 60,
        'max_queries_per_window': 50
    }

    framework = DefenseFramework(config=config)

    # Demo 1: Access Control
    print("[1/4] Access Control Demo")
    print("-" * 40)
    admin_token = framework.access_control.create_user('admin', 'admin', ['predict', 'info', 'statistics'])
    user_token = framework.access_control.create_user('user1', 'user', ['predict'])

    # Admin can access info
    allowed, _ = framework.access_control.verify_access(admin_token, 'info')
    print(f"  Admin accessing /info: {'✓ Allowed' if allowed else '✗ Denied'}")

    # User cannot access info
    allowed, _ = framework.access_control.verify_access(user_token, 'info')
    print(f"  User accessing /info: {'✓ Allowed' if allowed else '✗ Denied'}")

    # Demo 2: Input Validation
    print("\n[2/4] Input Validation Demo")
    print("-" * 40)

    # Valid input
    valid_input = np.random.uniform(0, 1, (1, 28, 28, 1))
    is_valid, reason = framework.input_validator.validate_input(valid_input)
    print(f"  Valid input: {'✓ Accepted' if is_valid else '✗ Rejected'}")

    # Invalid shape
    invalid_input = np.random.uniform(0, 1, (1, 32, 32, 1))
    is_valid, reason = framework.input_validator.validate_input(invalid_input)
    print(f"  Invalid shape: {'✓ Accepted' if is_valid else '✗ Rejected'} - {reason}")

    # Out of range
    out_of_range = np.random.uniform(-1, 2, (1, 28, 28, 1))
    is_valid, reason = framework.input_validator.validate_input(out_of_range)
    print(f"  Out of range: {'✓ Accepted' if is_valid else '✗ Rejected'} - {reason}")

    # Demo 3: Anomaly Detection (Rate Limiting)
    print("\n[3/4] Anomaly Detection Demo")
    print("-" * 40)

    # Simulate normal usage
    for i in range(45):
        framework.anomaly_detector.record_query('client1')
    print(f"  Normal usage (45 queries): ✓ Allowed")

    # Simulate excessive queries
    allowed, reason = framework.anomaly_detector.record_query('client1')
    print(f"  Query 46-50: {'✓ Allowed' if allowed else '✗ Blocked'}")

    for i in range(5):
        framework.anomaly_detector.record_query('client1')

    allowed, reason = framework.anomaly_detector.record_query('client1')
    print(f"  Query 51+ (rate limit): {'✓ Allowed' if allowed else '✗ Blocked'} - {reason}")

    # Demo 4: Model Version Control
    print("\n[4/4] Model Version Control Demo")
    print("-" * 40)

    try:
        # Register a model
        model_path = './models/exposed/model_v1.0.keras'
        if os.path.exists(model_path):
            model_hash = framework.version_control.register_model(
                model_path,
                version='v1.0',
                metadata={'dataset': 'mnist', 'accuracy': 0.98}
            )
            print(f"  Model registered: v1.0")
            print(f"  Hash: {model_hash[:32]}...")

            # Verify integrity
            is_valid, message = framework.version_control.verify_integrity('v1.0')
            print(f"  Integrity check: {'✓ Valid' if is_valid else '✗ Invalid'}")
        else:
            print("  No model found to register - run trainer first")

    except Exception as e:
        print(f"  Error: {e}")

    # Summary statistics
    print("\n" + "=" * 80)
    print("DEFENSE STATISTICS")
    print("=" * 80)

    stats = framework.get_defense_statistics()
    print(f"\nAccess Control:")
    print(f"  Total attempts: {stats['access_control']['total_access_attempts']}")
    print(f"  Denied: {stats['access_control']['denied_attempts']}")

    print(f"\nAnomaly Detection:")
    print(f"  Total queries: {stats['anomaly_detection']['total_queries']}")
    print(f"  Alerts: {stats['anomaly_detection']['total_alerts']}")

    print(f"\nInput Validation:")
    print(f"  Total validations: {stats['input_validation']['total_validations']}")
    print(f"  Failed: {stats['input_validation']['failed_validations']}")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
