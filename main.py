#!/usr/bin/env python3
"""
Main Orchestration Script for OSINT-Driven Adversarial Attacks Demonstration

⚠️  WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY
    This demonstration must only be used on systems you own or have explicit permission to test.

This script orchestrates the complete demonstration of:
1. Setting up a vulnerable ML system
2. OSINT-based discovery of misconfigurations
3. Multiple attack vectors (poisoning, extraction, evasion)
4. Defense framework deployment
5. Metrics collection and visualization

Author: Security Research Demo
Date: 2024
"""

import os
import sys
import argparse
import logging
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnerable_system.model_trainer import VulnerableMLSystem
from osint_discovery.scanner import OSINTScanner
from attacks.data_poisoning import DataPoisoner
from attacks.model_extraction import ModelExtractor
from attacks.adversarial_evasion import AdversarialEvader
from defenses.defense_framework import DefenseFramework
from metrics.metrics_collector import MetricsCollector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_osint_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityDemonstration:
    """
    Main orchestrator for the security demonstration.
    """

    def __init__(self, config: dict = None):
        """
        Initialize demonstration.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.results = {}

        # Display warning
        self.display_warning()

    def display_warning(self):
        """Display ethical use warning."""
        print("\n" + "=" * 80)
        print("⚠️  ETHICAL USE WARNING ⚠️")
        print("=" * 80)
        print("""
This tool is designed EXCLUSIVELY for:
  ✓ Educational purposes in security research
  ✓ Defensive security analysis
  ✓ Testing on systems you OWN or have EXPLICIT PERMISSION to test

This tool is NOT to be used for:
  ✗ Unauthorized access to systems
  ✗ Malicious attacks or exploitation
  ✗ Any illegal activities

By proceeding, you acknowledge that you will use this tool responsibly
and ethically, and that you understand the legal implications of misuse.
        """)
        print("=" * 80)

        if not self.config.get('skip_confirmation', False):
            response = input("\nDo you agree to use this tool ethically and legally? (yes/no): ")
            if response.lower() != 'yes':
                print("Exiting. Ethical acknowledgment required.")
                sys.exit(0)

    def step_1_setup_vulnerable_system(self):
        """Step 1: Set up vulnerable ML system."""
        print("\n" + "=" * 80)
        print("STEP 1: SETTING UP VULNERABLE ML SYSTEM")
        print("=" * 80)

        logger.info("Initializing vulnerable ML system...")

        system = VulnerableMLSystem(dataset='mnist')

        # Load and prepare data
        print("\n[1.1] Loading and preparing dataset...")
        x_train, y_train, x_test, y_test = system.load_and_prepare_data()

        # Build model
        print("\n[1.2] Building model architecture...")
        system.build_model()

        # Train model
        print("\n[1.3] Training model...")
        history = system.train(x_train, y_train, x_test, y_test, epochs=3)

        # Save model
        print("\n[1.4] Saving model (with vulnerabilities)...")
        model_path = system.save_model(version='v1.0')

        self.results['vulnerable_system'] = {
            'model_path': model_path,
            'dataset': 'mnist',
            'training_complete': True
        }

        print("\n✓ Vulnerable system setup complete!")
        time.sleep(2)

    def step_2_osint_discovery(self):
        """Step 2: OSINT discovery of vulnerabilities."""
        print("\n" + "=" * 80)
        print("STEP 2: OSINT DISCOVERY")
        print("=" * 80)

        logger.info("Starting OSINT discovery...")

        scanner = OSINTScanner(base_path='./', api_url=None)

        # Scan directory structure
        print("\n[2.1] Scanning for exposed files...")
        discoveries = scanner.scan_directory_structure()

        # Check for misconfigurations
        print("\n[2.2] Checking for misconfigurations...")
        misconfigs = scanner.check_storage_misconfiguration()

        # Fingerprint model
        print("\n[2.3] Fingerprinting ML model...")
        fingerprint = scanner.fingerprint_model()

        # Generate report
        print("\n[2.4] Generating discovery report...")
        report_path = scanner.generate_report()

        self.results['osint_discovery'] = {
            'report_path': report_path,
            'discoveries': len(discoveries['exposed_data']) + len(discoveries['exposed_models']),
            'misconfigurations': len(misconfigs),
            'fingerprint': fingerprint
        }

        print(f"\n✓ OSINT discovery complete! Found {self.results['osint_discovery']['discoveries']} exposed resources")
        time.sleep(2)

    def step_3_data_poisoning_attack(self):
        """Step 3: Data poisoning attack."""
        print("\n" + "=" * 80)
        print("STEP 3: DATA POISONING ATTACK")
        print("=" * 80)

        logger.info("Starting data poisoning attack...")

        poisoner = DataPoisoner(data_dir='./data/misconfigured')

        # Load exposed data
        print("\n[3.1] Loading exposed training data...")
        poisoner.load_exposed_data()

        # Execute label flipping attack
        print("\n[3.2] Executing label flip attack (25% of data)...")
        y_poisoned = poisoner.label_flip_attack(percentage=25)

        # Save poisoned data
        print("\n[3.3] Saving poisoned data...")
        poisoner.save_poisoned_data(poisoner.x_train, y_poisoned, suffix='label_flip')

        # Retrain with poisoned data
        print("\n[3.4] Retraining model with poisoned data...")
        poisoned_model, history, metrics = poisoner.retrain_with_poisoned_data(
            poisoner.x_train, y_poisoned,
            model_save_path='./models/exposed/model_poisoned.keras',
            epochs=5
        )

        # Evaluate attack
        print("\n[3.5] Evaluating attack effectiveness...")
        try:
            effectiveness = poisoner.evaluate_attack_success(
                clean_model_path='./models/exposed/model_v1.0.keras',
                poisoned_model_path='./models/exposed/model_poisoned.keras',
                attack_type='label_flip'
            )

            self.results['data_poisoning'] = effectiveness

            print(f"\n  Accuracy drop: {effectiveness['accuracy_drop']:.4f} "
                  f"({effectiveness['relative_drop_percent']:.2f}%)")
        except Exception as e:
            logger.error(f"Could not evaluate attack: {e}")
            self.results['data_poisoning'] = {'error': str(e)}

        print("\n✓ Data poisoning attack complete!")
        time.sleep(2)

    def step_4_model_extraction_attack(self, run_api_attacks=False):
        """Step 4: Model extraction attack."""
        print("\n" + "=" * 80)
        print("STEP 4: MODEL EXTRACTION ATTACK")
        print("=" * 80)

        if not run_api_attacks:
            print("\n⚠️  Skipping model extraction (requires running API server)")
            print("   To run this attack, start the API server separately:")
            print("   python vulnerable_system/api_server.py")
            self.results['model_extraction'] = {'skipped': True}
            return

        logger.info("Starting model extraction attack...")

        extractor = ModelExtractor(api_url='http://127.0.0.1:5000', use_osint_metadata=True)

        # Gather OSINT metadata
        print("\n[4.1] Gathering OSINT metadata...")
        try:
            metadata = extractor.gather_osint_metadata()
        except:
            metadata = {}

        # Generate query samples
        print("\n[4.2] Generating query samples...")
        query_samples = extractor.generate_query_samples(num_samples=500, strategy='diverse')

        # Query the model
        print("\n[4.3] Querying target model...")
        try:
            predictions, probabilities = extractor.query_model(query_samples, batch_size=32)

            # Train surrogate
            print("\n[4.4] Training surrogate model...")
            surrogate, train_metrics = extractor.train_surrogate_model(
                query_samples, predictions, epochs=5
            )

            # Evaluate
            print("\n[4.5] Evaluating extraction success...")
            import numpy as np
            x_test = np.load('./data/misconfigured/x_test.npy')
            y_test = np.load('./data/misconfigured/y_test.npy')

            eval_metrics = extractor.evaluate_extraction_success(
                x_test, y_test,
                original_model_path='./models/exposed/model_v1.0.keras'
            )

            # Save surrogate
            extractor.save_surrogate_model()
            extractor.save_query_log()

            self.results['model_extraction'] = eval_metrics

            print(f"\n  Surrogate accuracy: {eval_metrics['surrogate_test_accuracy']:.4f}")
            if 'model_agreement_rate' in eval_metrics:
                print(f"  Model agreement: {eval_metrics['model_agreement_rate']:.4f}")

        except Exception as e:
            logger.error(f"Model extraction failed: {e}")
            self.results['model_extraction'] = {'error': str(e)}

        print("\n✓ Model extraction attack complete!")
        time.sleep(2)

    def step_5_adversarial_evasion_attack(self):
        """Step 5: Adversarial evasion attack."""
        print("\n" + "=" * 80)
        print("STEP 5: ADVERSARIAL EVASION ATTACK (FGSM)")
        print("=" * 80)

        logger.info("Starting adversarial evasion attack...")

        import numpy as np

        # Load test data
        print("\n[5.1] Loading test data...")
        x_test = np.load('./data/misconfigured/x_test.npy')
        y_test = np.load('./data/misconfigured/y_test.npy')

        # Initialize evader
        print("\n[5.2] Loading model for attack...")
        evader = AdversarialEvader(model_path='./models/exposed/model_v1.0.keras')

        # Generate adversarial examples
        print("\n[5.3] Generating adversarial examples...")
        num_samples = 100
        sample_indices = np.random.choice(len(x_test), num_samples, replace=False)
        x_samples = x_test[sample_indices]
        y_samples = y_test[sample_indices]

        epsilon = 0.15
        x_adv = evader.fgsm_attack(x_samples, y_samples, epsilon=epsilon)

        # Evaluate attack
        print("\n[5.4] Evaluating attack success...")
        metrics = evader.evaluate_attack_success(x_samples, x_adv, y_samples)

        evader.log_attack('fgsm_untargeted', metrics)

        # Test transferability
        print("\n[5.5] Testing transferability...")
        surrogate_path = './models/exposed/surrogate_model.keras'
        if os.path.exists(surrogate_path):
            transfer_metrics = evader.test_transferability(x_adv, y_samples, surrogate_path)
            evader.log_attack('fgsm_transfer_test', transfer_metrics)
            metrics['transfer'] = transfer_metrics

        # Save results
        evader.save_adversarial_examples(x_samples, x_adv, y_samples)
        evader.save_attack_log()

        self.results['adversarial_evasion'] = metrics

        print(f"\n  Misclassification rate: {metrics['misclassification_rate']:.4f}")
        print(f"  Average perturbation: {metrics['avg_perturbation']:.6f}")

        print("\n✓ Adversarial evasion attack complete!")
        time.sleep(2)

    def step_6_defense_demonstration(self):
        """Step 6: Defense framework demonstration."""
        print("\n" + "=" * 80)
        print("STEP 6: DEFENSE FRAMEWORK DEMONSTRATION")
        print("=" * 80)

        logger.info("Demonstrating defense framework...")

        config = {
            'input_shape': [28, 28, 1],
            'value_range': (0, 1),
            'rate_limit_window': 60,
            'max_queries_per_window': 50
        }

        framework = DefenseFramework(config=config)

        print("\n[6.1] Setting up access control...")
        admin_token = framework.access_control.create_user('admin', 'admin',
                                                            ['predict', 'info', 'statistics'])
        user_token = framework.access_control.create_user('user1', 'user', ['predict'])

        print("\n[6.2] Testing access control...")
        # Test various access scenarios
        framework.access_control.verify_access(admin_token, 'info')
        framework.access_control.verify_access(user_token, 'info')  # Should fail
        framework.access_control.verify_access(admin_token, 'predict')

        print("\n[6.3] Testing input validation...")
        import numpy as np
        valid_input = np.random.uniform(0, 1, (1, 28, 28, 1))
        framework.input_validator.validate_input(valid_input)

        invalid_input = np.random.uniform(0, 1, (1, 32, 32, 1))
        framework.input_validator.validate_input(invalid_input)

        print("\n[6.4] Testing anomaly detection (rate limiting)...")
        for i in range(55):
            framework.anomaly_detector.record_query('test_client')

        print("\n[6.5] Testing model version control...")
        model_path = './models/exposed/model_v1.0.keras'
        if os.path.exists(model_path):
            framework.version_control.register_model(
                model_path,
                version='v1.0',
                metadata={'dataset': 'mnist'}
            )
            framework.version_control.verify_integrity('v1.0')

        # Get statistics
        stats = framework.get_defense_statistics()
        self.results['defense'] = stats

        print(f"\n  Access attempts: {stats['access_control']['total_access_attempts']}")
        print(f"  Denied: {stats['access_control']['denied_attempts']}")
        print(f"  Anomaly alerts: {stats['anomaly_detection']['total_alerts']}")

        print("\n✓ Defense framework demonstration complete!")
        time.sleep(2)

    def step_7_metrics_and_visualization(self):
        """Step 7: Collect metrics and generate visualizations."""
        print("\n" + "=" * 80)
        print("STEP 7: METRICS COLLECTION AND VISUALIZATION")
        print("=" * 80)

        logger.info("Collecting metrics and generating visualizations...")

        collector = MetricsCollector()

        print("\n[7.1] Collecting all metrics...")
        collector.collect_all_metrics()

        print("\n[7.2] Generating visualizations...")
        collector.generate_all_visualizations()

        print("\n[7.3] Generating summary report...")
        report = collector.generate_summary_report()

        print("\n[7.4] Saving metrics...")
        collector.save_metrics()

        self.results['metrics'] = {
            'output_dir': str(collector.output_dir),
            'report_generated': True
        }

        print(f"\n✓ All results saved to: {collector.output_dir}")
        time.sleep(2)

    def run_full_demonstration(self, skip_api_attacks=True):
        """Run the complete demonstration."""
        start_time = time.time()

        print("\n" + "=" * 80)
        print("STARTING FULL OSINT-DRIVEN ADVERSARIAL ATTACKS DEMONSTRATION")
        print("=" * 80)

        try:
            self.step_1_setup_vulnerable_system()
            self.step_2_osint_discovery()
            self.step_3_data_poisoning_attack()
            self.step_4_model_extraction_attack(run_api_attacks=not skip_api_attacks)
            self.step_5_adversarial_evasion_attack()
            self.step_6_defense_demonstration()
            self.step_7_metrics_and_visualization()

            elapsed_time = time.time() - start_time

            print("\n" + "=" * 80)
            print("DEMONSTRATION COMPLETE!")
            print("=" * 80)
            print(f"\nTotal time: {elapsed_time:.2f} seconds")
            print("\nKey Results:")
            print(f"  - Vulnerable system deployed: ✓")
            print(f"  - OSINT discoveries: {self.results.get('osint_discovery', {}).get('discoveries', 0)}")

            # Check model extraction status
            extraction_result = self.results.get('model_extraction', {})
            if extraction_result.get('skipped'):
                print(f"  - Attacks executed: 3 (Poisoning, Extraction*, Evasion)")
                extraction_note = "  * Model extraction skipped (use --with-api-attacks flag)"
            elif 'error' in extraction_result:
                print(f"  - Attacks executed: 4 (Poisoning, Extraction†, Evasion, Full Chain)")
                extraction_note = f"  † Model extraction failed: {extraction_result['error'][:80]}..."
            elif 'surrogate_test_accuracy' in extraction_result:
                print(f"  - Attacks executed: 4 (Poisoning, Extraction✓, Evasion, Full Chain)")
                extraction_note = f"  ✓ Model extraction successful: {extraction_result['surrogate_test_accuracy']:.2%} surrogate accuracy"
            else:
                print(f"  - Attacks executed: 3 (Poisoning, Extraction?, Evasion)")
                extraction_note = "  ? Model extraction status unknown"

            print(f"  - Defenses demonstrated: ✓")
            print(f"  - Metrics collected: ✓")
            print(f"\n{extraction_note}")
            print(f"\nResults saved to: ./metrics/results/")
            print("\n" + "=" * 80)

            logger.info("Demonstration completed successfully")

        except KeyboardInterrupt:
            print("\n\nDemonstration interrupted by user.")
            logger.warning("Demonstration interrupted")
        except Exception as e:
            print(f"\n\nError during demonstration: {e}")
            logger.error(f"Demonstration failed: {e}", exc_info=True)
            raise


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='OSINT-Driven Adversarial Attacks Demonstration (Educational)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full demonstration (skips model extraction by default)
  python main.py --full

  # Run full demonstration WITH model extraction (requires API server running)
  python main.py --full --with-api-attacks

  # Run specific step
  python main.py --step 1

  # Run just model extraction step (requires API server running)
  python main.py --step 4 --with-api-attacks

⚠️  WARNING: For educational and defensive security purposes only!
        """
    )

    parser.add_argument('--full', action='store_true',
                       help='Run full demonstration')
    parser.add_argument('--step', type=int, choices=range(1, 8),
                       help='Run specific step (1-7)')
    parser.add_argument('--with-api-attacks', action='store_true', default=False,
                       help='Include attacks requiring API server (requires server running on port 5000)')
    parser.add_argument('--skip-confirmation', action='store_true',
                       help='Skip ethical use confirmation prompt')

    args = parser.parse_args()

    # Configuration
    config = {
        'skip_confirmation': args.skip_confirmation
    }

    demo = SecurityDemonstration(config=config)

    if args.full:
        demo.run_full_demonstration(skip_api_attacks=not args.with_api_attacks)
    elif args.step:
        step_methods = {
            1: demo.step_1_setup_vulnerable_system,
            2: demo.step_2_osint_discovery,
            3: demo.step_3_data_poisoning_attack,
            4: lambda: demo.step_4_model_extraction_attack(args.with_api_attacks),
            5: demo.step_5_adversarial_evasion_attack,
            6: demo.step_6_defense_demonstration,
            7: demo.step_7_metrics_and_visualization
        }
        step_methods[args.step]()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
