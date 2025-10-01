"""
Data Poisoning Attack Module

WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY.

This module demonstrates data poisoning attacks where an adversary with access
to training data (discovered via OSINT) injects malicious samples to degrade
model performance or create backdoors.

Types of poisoning demonstrated:
1. Label flipping - Change labels of training samples
2. Feature poisoning - Add adversarial noise to inputs
3. Backdoor injection - Insert trigger patterns for targeted misclassification
"""

import os
import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
import tensorflow as tf
from tensorflow import keras
from typing import Tuple, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DataPoisoner:
    """
    Data poisoning attack simulator.

    ETHICAL USE ONLY: For security research and defensive security purposes.
    """

    def __init__(self, data_dir='./data/misconfigured'):
        """
        Initialize data poisoner.

        Args:
            data_dir: Directory containing exposed training data
        """
        self.data_dir = Path(data_dir)
        self.x_train = None
        self.y_train = None
        self.x_test = None
        self.y_test = None
        self.poisoned_indices = []
        self.attack_log = []

    def load_exposed_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Load exposed training data discovered via OSINT.

        Returns:
            Tuple of (x_train, y_train, x_test, y_test)
        """
        logger.info(f"Loading exposed training data from {self.data_dir}")

        try:
            self.x_train = np.load(self.data_dir / 'x_train.npy')
            self.y_train = np.load(self.data_dir / 'y_train.npy')
            self.x_test = np.load(self.data_dir / 'x_test.npy')
            self.y_test = np.load(self.data_dir / 'y_test.npy')

            logger.info(f"Loaded: {len(self.x_train)} training samples, {len(self.x_test)} test samples")

            return self.x_train, self.y_train, self.x_test, self.y_test

        except FileNotFoundError as e:
            logger.error(f"Failed to load data: {e}")
            raise

    def label_flip_attack(self, percentage=10, target_class=None, new_label=None) -> np.ndarray:
        """
        Label flipping attack - change labels of training samples.

        Args:
            percentage: Percentage of data to poison (0-100)
            target_class: Specific class to target (None for random)
            new_label: Label to change to (None for random)

        Returns:
            Poisoned labels array
        """
        logger.info(f"Executing label flip attack: {percentage}% of training data")

        y_poisoned = self.y_train.copy()
        num_samples = len(y_poisoned)
        num_to_poison = int(num_samples * percentage / 100)

        if target_class is not None:
            # Target specific class
            target_indices = np.where(self.y_train == target_class)[0]
            num_to_poison = min(num_to_poison, len(target_indices))
            poison_indices = np.random.choice(target_indices, num_to_poison, replace=False)
        else:
            # Random samples
            poison_indices = np.random.choice(num_samples, num_to_poison, replace=False)

        for idx in poison_indices:
            original_label = y_poisoned[idx]

            if new_label is not None:
                y_poisoned[idx] = new_label
            else:
                # Random wrong label
                num_classes = len(np.unique(self.y_train))
                wrong_labels = [l for l in range(num_classes) if l != original_label]
                y_poisoned[idx] = np.random.choice(wrong_labels)

        self.poisoned_indices.extend(poison_indices.tolist())

        attack_record = {
            'type': 'label_flip',
            'percentage': percentage,
            'num_poisoned': num_to_poison,
            'target_class': target_class,
            'new_label': new_label,
            'timestamp': datetime.now().isoformat()
        }
        self.attack_log.append(attack_record)

        logger.info(f"Poisoned {num_to_poison} samples with label flipping")

        return y_poisoned

    def feature_poisoning_attack(self, percentage=10, noise_factor=0.3) -> np.ndarray:
        """
        Feature poisoning - add adversarial noise to training inputs.

        Args:
            percentage: Percentage of data to poison
            noise_factor: Scale of noise to add (0-1)

        Returns:
            Poisoned features array
        """
        logger.info(f"Executing feature poisoning attack: {percentage}% with noise factor {noise_factor}")

        x_poisoned = self.x_train.copy()
        num_samples = len(x_poisoned)
        num_to_poison = int(num_samples * percentage / 100)

        poison_indices = np.random.choice(num_samples, num_to_poison, replace=False)

        for idx in poison_indices:
            # Add random noise
            noise = np.random.normal(0, noise_factor, x_poisoned[idx].shape)
            x_poisoned[idx] = np.clip(x_poisoned[idx] + noise, 0, 1)

        self.poisoned_indices.extend(poison_indices.tolist())

        attack_record = {
            'type': 'feature_poisoning',
            'percentage': percentage,
            'num_poisoned': num_to_poison,
            'noise_factor': noise_factor,
            'timestamp': datetime.now().isoformat()
        }
        self.attack_log.append(attack_record)

        logger.info(f"Poisoned {num_to_poison} samples with feature noise")

        return x_poisoned

    def backdoor_attack(self, percentage=5, trigger_size=3, target_label=0) -> Tuple[np.ndarray, np.ndarray]:
        """
        Backdoor attack - inject trigger pattern for targeted misclassification.

        The model will learn to associate the trigger with the target label,
        allowing the attacker to force misclassifications at inference time.

        Args:
            percentage: Percentage of data to poison
            trigger_size: Size of trigger pattern (pixels)
            target_label: Label to associate with trigger

        Returns:
            Tuple of (poisoned_x, poisoned_y)
        """
        logger.info(f"Executing backdoor attack: {percentage}% with trigger size {trigger_size}")

        x_poisoned = self.x_train.copy()
        y_poisoned = self.y_train.copy()

        num_samples = len(x_poisoned)
        num_to_poison = int(num_samples * percentage / 100)

        # Create trigger pattern (white square in corner)
        trigger = np.ones((trigger_size, trigger_size))

        poison_indices = np.random.choice(num_samples, num_to_poison, replace=False)

        for idx in poison_indices:
            # Add trigger to bottom-right corner
            if len(x_poisoned[idx].shape) == 3:
                x_poisoned[idx][-trigger_size:, -trigger_size:, :] = trigger[:, :, np.newaxis]
            else:
                x_poisoned[idx][-trigger_size:, -trigger_size:] = trigger

            # Change label to target
            y_poisoned[idx] = target_label

        self.poisoned_indices.extend(poison_indices.tolist())

        attack_record = {
            'type': 'backdoor',
            'percentage': percentage,
            'num_poisoned': num_to_poison,
            'trigger_size': trigger_size,
            'target_label': target_label,
            'timestamp': datetime.now().isoformat()
        }
        self.attack_log.append(attack_record)

        logger.info(f"Injected backdoor into {num_to_poison} samples")

        return x_poisoned, y_poisoned

    def apply_trigger_to_test_data(self, trigger_size=3, num_samples=100) -> Tuple[np.ndarray, np.ndarray]:
        """
        Apply backdoor trigger to test samples for attack evaluation.

        Args:
            trigger_size: Size of trigger pattern
            num_samples: Number of test samples to modify

        Returns:
            Tuple of (triggered_x, original_y)
        """
        indices = np.random.choice(len(self.x_test), min(num_samples, len(self.x_test)), replace=False)

        x_triggered = self.x_test[indices].copy()
        y_original = self.y_test[indices].copy()

        trigger = np.ones((trigger_size, trigger_size))

        for i in range(len(x_triggered)):
            if len(x_triggered[i].shape) == 3:
                x_triggered[i][-trigger_size:, -trigger_size:, :] = trigger[:, :, np.newaxis]
            else:
                x_triggered[i][-trigger_size:, -trigger_size:] = trigger

        return x_triggered, y_original

    def save_poisoned_data(self, x_poisoned, y_poisoned, suffix='poisoned'):
        """
        Save poisoned data back to the misconfigured directory.

        Args:
            x_poisoned: Poisoned features
            y_poisoned: Poisoned labels
            suffix: Suffix for saved files
        """
        logger.info(f"Saving poisoned data to {self.data_dir}")

        np.save(self.data_dir / f'x_train_{suffix}.npy', x_poisoned)
        np.save(self.data_dir / f'y_train_{suffix}.npy', y_poisoned)

        # Save attack log
        log_path = self.data_dir / f'poisoning_log_{suffix}.json'
        with open(log_path, 'w') as f:
            json.dump({
                'attacks': self.attack_log,
                'poisoned_indices': self.poisoned_indices,
                'total_poisoned': len(set(self.poisoned_indices))
            }, f, indent=2)

        logger.info(f"Poisoned data saved with suffix '{suffix}'")

    def retrain_with_poisoned_data(self, x_poisoned, y_poisoned, model_save_path='./models/exposed/model_poisoned.keras', epochs=5):
        """
        Retrain model with poisoned data to measure attack effectiveness.

        Args:
            x_poisoned: Poisoned training features
            y_poisoned: Poisoned training labels
            model_save_path: Path to save poisoned model
            epochs: Number of training epochs

        Returns:
            Tuple of (model, history, metrics)
        """
        logger.info("Retraining model with poisoned data...")

        # Determine architecture from data shape
        input_shape = x_poisoned.shape[1:]
        num_classes = len(np.unique(y_poisoned))

        # Build model
        model = keras.Sequential([
            keras.layers.Input(shape=input_shape),
            keras.layers.Conv2D(32, (3, 3), activation='relu'),
            keras.layers.MaxPooling2D((2, 2)),
            keras.layers.Conv2D(64, (3, 3), activation='relu'),
            keras.layers.MaxPooling2D((2, 2)),
            keras.layers.Conv2D(64, (3, 3), activation='relu'),
            keras.layers.Flatten(),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.5),
            keras.layers.Dense(num_classes, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        # Train
        history = model.fit(
            x_poisoned, y_poisoned,
            batch_size=128,
            epochs=epochs,
            validation_split=0.1,
            verbose=1
        )

        # Evaluate on clean test data
        test_loss, test_acc = model.evaluate(self.x_test, self.y_test, verbose=0)

        logger.info(f"Poisoned model test accuracy: {test_acc:.4f}")

        # Save model
        model.save(model_save_path)
        logger.info(f"Poisoned model saved to {model_save_path}")

        metrics = {
            'test_accuracy': float(test_acc),
            'test_loss': float(test_loss),
            'training_history': {
                'accuracy': [float(x) for x in history.history['accuracy']],
                'val_accuracy': [float(x) for x in history.history['val_accuracy']],
                'loss': [float(x) for x in history.history['loss']],
                'val_loss': [float(x) for x in history.history['val_loss']]
            }
        }

        return model, history, metrics

    def evaluate_attack_success(self, clean_model_path, poisoned_model_path, attack_type='label_flip'):
        """
        Evaluate the success of the poisoning attack.

        Args:
            clean_model_path: Path to original clean model
            poisoned_model_path: Path to poisoned model
            attack_type: Type of attack to evaluate

        Returns:
            Dictionary of attack effectiveness metrics
        """
        logger.info("Evaluating attack success...")

        # Load models
        clean_model = keras.models.load_model(clean_model_path)
        poisoned_model = keras.models.load_model(poisoned_model_path)

        # Evaluate on clean test data
        _, clean_acc = clean_model.evaluate(self.x_test, self.y_test, verbose=0)
        _, poisoned_acc = poisoned_model.evaluate(self.x_test, self.y_test, verbose=0)

        accuracy_drop = clean_acc - poisoned_acc
        relative_drop = (accuracy_drop / clean_acc) * 100

        logger.info(f"Clean model accuracy: {clean_acc:.4f}")
        logger.info(f"Poisoned model accuracy: {poisoned_acc:.4f}")
        logger.info(f"Accuracy drop: {accuracy_drop:.4f} ({relative_drop:.2f}%)")

        metrics = {
            'clean_accuracy': float(clean_acc),
            'poisoned_accuracy': float(poisoned_acc),
            'accuracy_drop': float(accuracy_drop),
            'relative_drop_percent': float(relative_drop),
            'attack_type': attack_type
        }

        # For backdoor attacks, test trigger effectiveness
        if attack_type == 'backdoor':
            trigger_size = next((a['trigger_size'] for a in self.attack_log if a['type'] == 'backdoor'), 3)
            target_label = next((a['target_label'] for a in self.attack_log if a['type'] == 'backdoor'), 0)

            x_triggered, y_original = self.apply_trigger_to_test_data(trigger_size=trigger_size)

            # Predict on triggered samples
            predictions = poisoned_model.predict(x_triggered, verbose=0)
            predicted_labels = np.argmax(predictions, axis=1)

            # Calculate attack success rate (how many were misclassified to target)
            backdoor_success_rate = np.mean(predicted_labels == target_label)

            metrics['backdoor_success_rate'] = float(backdoor_success_rate)
            logger.info(f"Backdoor attack success rate: {backdoor_success_rate:.4f}")

        return metrics


def main():
    """Main function to demonstrate data poisoning attacks."""
    print("=" * 80)
    print("DATA POISONING ATTACK MODULE")
    print("=" * 80)
    print("\n⚠️  FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY\n")

    # Initialize poisoner
    poisoner = DataPoisoner(data_dir='./data/misconfigured')

    # Load exposed data
    print("[1/5] Loading exposed training data...")
    poisoner.load_exposed_data()

    # Demonstrate label flipping attack
    print("\n[2/5] Executing label flip attack (25% of data)...")
    y_poisoned = poisoner.label_flip_attack(percentage=25)

    # Save poisoned data
    print("\n[3/5] Saving poisoned data...")
    poisoner.save_poisoned_data(poisoner.x_train, y_poisoned, suffix='label_flip')

    # Retrain with poisoned data
    print("\n[4/5] Retraining model with poisoned data...")
    poisoned_model, history, metrics = poisoner.retrain_with_poisoned_data(
        poisoner.x_train, y_poisoned,
        model_save_path='./models/exposed/model_poisoned.keras'
    )

    # Evaluate attack
    print("\n[5/5] Evaluating attack effectiveness...")
    try:
        effectiveness = poisoner.evaluate_attack_success(
            clean_model_path='./models/exposed/model_v1.0.keras',
            poisoned_model_path='./models/exposed/model_poisoned.keras',
            attack_type='label_flip'
        )
        print(f"\nAttack Results:")
        print(f"  Clean accuracy: {effectiveness['clean_accuracy']:.4f}")
        print(f"  Poisoned accuracy: {effectiveness['poisoned_accuracy']:.4f}")
        print(f"  Accuracy drop: {effectiveness['accuracy_drop']:.4f} ({effectiveness['relative_drop_percent']:.2f}%)")
    except FileNotFoundError:
        print("  (Clean model not found - train it first)")

    print("\n" + "=" * 80)
    print("Data poisoning attack demonstration complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()
