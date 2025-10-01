"""
Adversarial Evasion Attack Module (FGSM)

WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY.

This module demonstrates adversarial evasion attacks where an adversary crafts
inputs to fool the ML model at inference time. Uses Fast Gradient Sign Method (FGSM).

Demonstrates:
1. FGSM attack generation
2. Attack success with/without OSINT intelligence
3. Transferability between original and surrogate models
"""

import os
import json
import logging
import numpy as np
from datetime import datetime
from typing import Tuple, Dict, Optional
import tensorflow as tf
from tensorflow import keras

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AdversarialEvader:
    """
    Adversarial evasion attack generator using FGSM.

    ETHICAL USE ONLY: For security research and defensive security purposes.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize adversarial evader.

        Args:
            model_path: Path to target model (if available via OSINT)
        """
        self.model = None
        self.model_path = model_path
        self.attack_log = []

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def load_model(self, model_path: str):
        """
        Load target model.

        Args:
            model_path: Path to model file
        """
        logger.info(f"Loading model from {model_path}")

        self.model = keras.models.load_model(model_path)
        self.model_path = model_path

        logger.info("Model loaded successfully")

    def fgsm_attack(self, x: np.ndarray, y_true: np.ndarray, epsilon: float = 0.1) -> np.ndarray:
        """
        Fast Gradient Sign Method (FGSM) attack.

        Generates adversarial examples by adding perturbations in the direction
        of the gradient to maximize loss.

        Args:
            x: Input samples (batch)
            y_true: True labels
            epsilon: Perturbation magnitude (0-1)

        Returns:
            Adversarial examples
        """
        if self.model is None:
            raise ValueError("No model loaded")

        logger.info(f"Generating FGSM adversarial examples with epsilon={epsilon}")

        # Convert to tensors
        x_tensor = tf.convert_to_tensor(x, dtype=tf.float32)
        y_tensor = tf.convert_to_tensor(y_true, dtype=tf.int64)

        # Calculate gradients
        with tf.GradientTape() as tape:
            tape.watch(x_tensor)
            predictions = self.model(x_tensor)
            loss = keras.losses.sparse_categorical_crossentropy(y_tensor, predictions)

        # Get gradient with respect to input
        gradients = tape.gradient(loss, x_tensor)

        # Generate adversarial examples using FGSM
        signed_gradients = tf.sign(gradients)
        x_adv = x_tensor + epsilon * signed_gradients

        # Clip to valid range [0, 1]
        x_adv = tf.clip_by_value(x_adv, 0, 1)

        return x_adv.numpy()

    def targeted_fgsm_attack(self, x: np.ndarray, y_target: np.ndarray, epsilon: float = 0.1,
                            iterations: int = 10) -> np.ndarray:
        """
        Targeted FGSM attack (iterative).

        Generates adversarial examples to be classified as a specific target class.

        Args:
            x: Input samples
            y_target: Target labels to achieve
            epsilon: Perturbation magnitude per iteration
            iterations: Number of attack iterations

        Returns:
            Adversarial examples
        """
        if self.model is None:
            raise ValueError("No model loaded")

        logger.info(f"Generating targeted FGSM attack with epsilon={epsilon}, iterations={iterations}")

        x_adv = x.copy()

        for i in range(iterations):
            x_tensor = tf.convert_to_tensor(x_adv, dtype=tf.float32)
            y_tensor = tf.convert_to_tensor(y_target, dtype=tf.int64)

            with tf.GradientTape() as tape:
                tape.watch(x_tensor)
                predictions = self.model(x_tensor)
                # Minimize loss for target class (negative gradient)
                loss = keras.losses.sparse_categorical_crossentropy(y_tensor, predictions)

            gradients = tape.gradient(loss, x_tensor)

            # Move in opposite direction of gradient (toward target)
            signed_gradients = tf.sign(gradients)
            x_adv = x_tensor - epsilon * signed_gradients

            # Clip to valid range and original perturbation budget
            x_adv = tf.clip_by_value(x_adv, 0, 1)
            perturbation = x_adv - x
            perturbation = tf.clip_by_value(perturbation, -epsilon * iterations, epsilon * iterations)
            x_adv = tf.clip_by_value(x + perturbation, 0, 1)

            x_adv = x_adv.numpy()

        return x_adv

    def evaluate_attack_success(self, x_clean: np.ndarray, x_adv: np.ndarray,
                               y_true: np.ndarray, y_target: Optional[np.ndarray] = None) -> Dict:
        """
        Evaluate adversarial attack success.

        Args:
            x_clean: Original clean samples
            x_adv: Adversarial samples
            y_true: True labels
            y_target: Target labels (for targeted attacks)

        Returns:
            Dictionary of attack metrics
        """
        if self.model is None:
            raise ValueError("No model loaded")

        logger.info("Evaluating attack success...")

        # Predictions on clean samples
        clean_preds = np.argmax(self.model.predict(x_clean, verbose=0), axis=1)
        clean_acc = np.mean(clean_preds == y_true)

        # Predictions on adversarial samples
        adv_preds = np.argmax(self.model.predict(x_adv, verbose=0), axis=1)
        adv_acc = np.mean(adv_preds == y_true)

        # Attack success rate (samples that changed prediction)
        misclassification_rate = np.mean(clean_preds != adv_preds)

        # Average perturbation magnitude
        perturbation = np.abs(x_adv - x_clean)
        avg_perturbation = np.mean(perturbation)
        max_perturbation = np.max(perturbation)

        metrics = {
            'clean_accuracy': float(clean_acc),
            'adversarial_accuracy': float(adv_acc),
            'accuracy_drop': float(clean_acc - adv_acc),
            'misclassification_rate': float(misclassification_rate),
            'avg_perturbation': float(avg_perturbation),
            'max_perturbation': float(max_perturbation),
            'num_samples': len(x_clean)
        }

        # Targeted attack metrics
        if y_target is not None:
            targeted_success_rate = np.mean(adv_preds == y_target)
            metrics['targeted_success_rate'] = float(targeted_success_rate)
            logger.info(f"Targeted attack success rate: {targeted_success_rate:.4f}")

        logger.info(f"Clean accuracy: {clean_acc:.4f}")
        logger.info(f"Adversarial accuracy: {adv_acc:.4f}")
        logger.info(f"Misclassification rate: {misclassification_rate:.4f}")
        logger.info(f"Average perturbation: {avg_perturbation:.6f}")

        return metrics

    def test_transferability(self, x_adv: np.ndarray, y_true: np.ndarray,
                            target_model_path: str) -> Dict:
        """
        Test transferability of adversarial examples to another model.

        This demonstrates how adversarial examples crafted for one model
        can fool other models (especially useful with surrogate models from extraction).

        Args:
            x_adv: Adversarial examples
            y_true: True labels
            target_model_path: Path to target model

        Returns:
            Dictionary of transferability metrics
        """
        logger.info(f"Testing transferability to model: {target_model_path}")

        try:
            target_model = keras.models.load_model(target_model_path)

            # Evaluate on target model
            target_preds = np.argmax(target_model.predict(x_adv, verbose=0), axis=1)
            target_acc = np.mean(target_preds == y_true)
            transfer_success = 1.0 - target_acc

            metrics = {
                'target_accuracy': float(target_acc),
                'transfer_success_rate': float(transfer_success),
                'target_model': target_model_path
            }

            logger.info(f"Target model accuracy on adversarial examples: {target_acc:.4f}")
            logger.info(f"Transfer success rate: {transfer_success:.4f}")

            return metrics

        except Exception as e:
            logger.error(f"Failed to test transferability: {e}")
            return {'error': str(e)}

    def compare_with_without_osint(self, x_test: np.ndarray, y_test: np.ndarray,
                                   epsilon: float = 0.1, num_samples: int = 100) -> Dict:
        """
        Compare attack effectiveness with and without OSINT intelligence.

        WITH OSINT: Direct access to model allows white-box attacks
        WITHOUT OSINT: Must use surrogate model (black-box attack)

        Args:
            x_test: Test samples
            y_test: Test labels
            epsilon: Attack epsilon
            num_samples: Number of samples to test

        Returns:
            Dictionary comparing attack success
        """
        logger.info("Comparing attack effectiveness with/without OSINT...")

        # Select random samples
        indices = np.random.choice(len(x_test), min(num_samples, len(x_test)), replace=False)
        x_samples = x_test[indices]
        y_samples = y_test[indices]

        comparison = {
            'with_osint': {},
            'without_osint': {},
            'osint_advantage': {}
        }

        # WITH OSINT: Direct attack on exposed model
        if self.model_path and os.path.exists(self.model_path):
            logger.info("Scenario 1: WITH OSINT (white-box attack on exposed model)")
            self.load_model(self.model_path)

            x_adv_osint = self.fgsm_attack(x_samples, y_samples, epsilon=epsilon)
            metrics_osint = self.evaluate_attack_success(x_samples, x_adv_osint, y_samples)

            comparison['with_osint'] = metrics_osint
            comparison['with_osint']['scenario'] = 'white_box_with_osint'

        # WITHOUT OSINT: Must use surrogate model
        surrogate_path = './models/exposed/surrogate_model.keras'
        if os.path.exists(surrogate_path):
            logger.info("Scenario 2: WITHOUT OSINT (black-box attack using surrogate)")

            # Load surrogate for crafting attacks
            self.load_model(surrogate_path)
            x_adv_no_osint = self.fgsm_attack(x_samples, y_samples, epsilon=epsilon)

            # Test on original model (if available)
            if self.model_path and os.path.exists(self.model_path):
                original_model = keras.models.load_model(self.model_path)
                adv_preds = np.argmax(original_model.predict(x_adv_no_osint, verbose=0), axis=1)
                adv_acc = np.mean(adv_preds == y_samples)

                comparison['without_osint'] = {
                    'adversarial_accuracy': float(adv_acc),
                    'misclassification_rate': float(1.0 - adv_acc),
                    'scenario': 'black_box_via_surrogate'
                }

        # Calculate OSINT advantage
        if comparison['with_osint'] and comparison['without_osint']:
            osint_advantage = {
                'accuracy_drop_difference': comparison['with_osint']['accuracy_drop'] -
                                           comparison['without_osint'].get('adversarial_accuracy', 1.0) +
                                           comparison['with_osint']['clean_accuracy'],
                'attack_efficiency_gain': (comparison['with_osint']['misclassification_rate'] -
                                          comparison['without_osint']['misclassification_rate']) * 100
            }
            comparison['osint_advantage'] = osint_advantage

            logger.info(f"OSINT advantage: {osint_advantage['attack_efficiency_gain']:.2f}% "
                       f"better attack success rate")

        return comparison

    def save_adversarial_examples(self, x_clean: np.ndarray, x_adv: np.ndarray,
                                 y_true: np.ndarray, save_dir='./attacks/adversarial_examples'):
        """
        Save adversarial examples for analysis.

        Args:
            x_clean: Clean samples
            x_adv: Adversarial samples
            y_true: True labels
            save_dir: Directory to save examples
        """
        os.makedirs(save_dir, exist_ok=True)

        logger.info(f"Saving adversarial examples to {save_dir}")

        np.save(os.path.join(save_dir, 'x_clean.npy'), x_clean)
        np.save(os.path.join(save_dir, 'x_adversarial.npy'), x_adv)
        np.save(os.path.join(save_dir, 'y_true.npy'), y_true)

        # Save perturbations
        perturbations = x_adv - x_clean
        np.save(os.path.join(save_dir, 'perturbations.npy'), perturbations)

        # Save metadata
        metadata = {
            'num_examples': len(x_clean),
            'avg_perturbation': float(np.mean(np.abs(perturbations))),
            'max_perturbation': float(np.max(np.abs(perturbations))),
            'model_used': self.model_path,
            'timestamp': datetime.now().isoformat()
        }

        with open(os.path.join(save_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved {len(x_clean)} adversarial examples")

    def log_attack(self, attack_type: str, metrics: Dict):
        """
        Log attack details.

        Args:
            attack_type: Type of attack performed
            metrics: Attack metrics
        """
        log_entry = {
            'attack_type': attack_type,
            'metrics': metrics,
            'timestamp': datetime.now().isoformat(),
            'model': self.model_path
        }

        self.attack_log.append(log_entry)

    def save_attack_log(self, log_path='./attacks/evasion_attack_log.json'):
        """
        Save attack log.

        Args:
            log_path: Path to save log
        """
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        with open(log_path, 'w') as f:
            json.dump({
                'total_attacks': len(self.attack_log),
                'attacks': self.attack_log
            }, f, indent=2)

        logger.info(f"Attack log saved to {log_path}")


def main():
    """Main function to demonstrate adversarial evasion attacks."""
    print("=" * 80)
    print("ADVERSARIAL EVASION ATTACK MODULE (FGSM)")
    print("=" * 80)
    print("\n⚠️  FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY\n")

    # Load test data
    print("[1/5] Loading test data...")
    try:
        x_test = np.load('./data/misconfigured/x_test.npy')
        y_test = np.load('./data/misconfigured/y_test.npy')
        print(f"  Loaded {len(x_test)} test samples")
    except FileNotFoundError:
        print("  ERROR: Test data not found. Run model trainer first.")
        return

    # Initialize evader with OSINT-discovered model
    print("\n[2/5] Loading model (using OSINT-discovered path)...")
    model_path = './models/exposed/model_v1.0.keras'
    try:
        evader = AdversarialEvader(model_path=model_path)
        print(f"  Loaded model from {model_path}")
    except Exception as e:
        print(f"  ERROR: Could not load model - {e}")
        return

    # Generate adversarial examples
    print("\n[3/5] Generating adversarial examples with FGSM...")
    num_samples = 100
    sample_indices = np.random.choice(len(x_test), num_samples, replace=False)
    x_samples = x_test[sample_indices]
    y_samples = y_test[sample_indices]

    epsilon = 0.15
    x_adv = evader.fgsm_attack(x_samples, y_samples, epsilon=epsilon)
    print(f"  Generated {len(x_adv)} adversarial examples with epsilon={epsilon}")

    # Evaluate attack
    print("\n[4/5] Evaluating attack success...")
    metrics = evader.evaluate_attack_success(x_samples, x_adv, y_samples)
    print(f"\nAttack Results:")
    print(f"  Clean accuracy: {metrics['clean_accuracy']:.4f}")
    print(f"  Adversarial accuracy: {metrics['adversarial_accuracy']:.4f}")
    print(f"  Misclassification rate: {metrics['misclassification_rate']:.4f}")
    print(f"  Average perturbation: {metrics['avg_perturbation']:.6f}")

    evader.log_attack('fgsm_untargeted', metrics)

    # Test transferability (if surrogate model exists)
    print("\n[5/5] Testing transferability to surrogate model...")
    surrogate_path = './models/exposed/surrogate_model.keras'
    if os.path.exists(surrogate_path):
        transfer_metrics = evader.test_transferability(x_adv, y_samples, surrogate_path)
        print(f"  Transfer success rate: {transfer_metrics.get('transfer_success_rate', 0):.4f}")
        evader.log_attack('fgsm_transfer_test', transfer_metrics)
    else:
        print("  Surrogate model not found - run model extraction first")

    # Save results
    print("\nSaving results...")
    evader.save_adversarial_examples(x_samples, x_adv, y_samples)
    evader.save_attack_log()

    # Compare with/without OSINT
    print("\n" + "=" * 80)
    print("OSINT INTELLIGENCE COMPARISON")
    print("=" * 80)
    comparison = evader.compare_with_without_osint(x_test, y_test, epsilon=0.15, num_samples=100)

    if comparison['with_osint']:
        print("\nWITH OSINT (white-box):")
        print(f"  Misclassification rate: {comparison['with_osint']['misclassification_rate']:.4f}")

    if comparison['without_osint']:
        print("\nWITHOUT OSINT (black-box via surrogate):")
        print(f"  Misclassification rate: {comparison['without_osint']['misclassification_rate']:.4f}")

    if comparison['osint_advantage']:
        print("\nOSINT ADVANTAGE:")
        print(f"  Attack efficiency gain: {comparison['osint_advantage']['attack_efficiency_gain']:.2f}%")

    print("\n" + "=" * 80)
    print("Adversarial evasion attack demonstration complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()
