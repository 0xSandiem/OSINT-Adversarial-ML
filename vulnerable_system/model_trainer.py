"""
Vulnerable ML System - Model Trainer

WARNING: This is a deliberately vulnerable system for educational purposes only.
DO NOT use in production environments.

This module creates a simple image classifier with intentional misconfigurations
to demonstrate OSINT-driven attacks.
"""

import os
import json
import logging
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnerableMLSystem:
    """
    Intentionally misconfigured ML system for security research.

    Vulnerabilities simulated:
    - Training data in world-readable directory
    - Model weights saved without access control
    - Configuration file with metadata exposed
    - No integrity checks on model files
    """

    def __init__(self, dataset='mnist', data_dir='./data/misconfigured', model_dir='./models/exposed'):
        """
        Initialize the vulnerable ML system.

        Args:
            dataset: Dataset to use ('mnist' or 'cifar10')
            data_dir: Directory to store training data (simulating misconfigured storage)
            model_dir: Directory to store model weights (simulating exposed S3 bucket)
        """
        self.dataset = dataset
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.model = None
        self.input_shape = None
        self.num_classes = None

        # Create directories with simulated open permissions
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)

        logger.info(f"Initialized VulnerableMLSystem with dataset: {dataset}")
        logger.warning("SECURITY WARNING: This system has intentional vulnerabilities!")

    def load_and_prepare_data(self, poison_percentage=0):
        """
        Load and prepare training data.

        Args:
            poison_percentage: Percentage of data to poison (0-100)

        Returns:
            Tuple of (x_train, y_train, x_test, y_test)
        """
        logger.info(f"Loading {self.dataset} dataset...")

        if self.dataset == 'mnist':
            (x_train, y_train), (x_test, y_test) = keras.datasets.mnist.load_data()
            x_train = x_train.reshape(-1, 28, 28, 1).astype('float32') / 255.0
            x_test = x_test.reshape(-1, 28, 28, 1).astype('float32') / 255.0
            self.input_shape = (28, 28, 1)
            self.num_classes = 10
        elif self.dataset == 'cifar10':
            (x_train, y_train), (x_test, y_test) = keras.datasets.cifar10.load_data()
            x_train = x_train.astype('float32') / 255.0
            x_test = x_test.astype('float32') / 255.0
            y_train = y_train.flatten()
            y_test = y_test.flatten()
            self.input_shape = (32, 32, 3)
            self.num_classes = 10
        else:
            raise ValueError(f"Unsupported dataset: {self.dataset}")

        # VULNERABILITY: Save training data to misconfigured directory
        logger.warning(f"Saving training data to {self.data_dir} (MISCONFIGURED - PUBLIC ACCESS)")
        np.save(os.path.join(self.data_dir, 'x_train.npy'), x_train)
        np.save(os.path.join(self.data_dir, 'y_train.npy'), y_train)
        np.save(os.path.join(self.data_dir, 'x_test.npy'), x_test)
        np.save(os.path.join(self.data_dir, 'y_test.npy'), y_test)

        # VULNERABILITY: Save metadata about the dataset
        metadata = {
            'dataset': self.dataset,
            'input_shape': list(self.input_shape),
            'num_classes': self.num_classes,
            'train_samples': len(x_train),
            'test_samples': len(x_test),
            'created_at': datetime.now().isoformat(),
            'data_location': self.data_dir,
            'model_location': self.model_dir
        }

        with open(os.path.join(self.data_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Dataset loaded: {len(x_train)} training samples, {len(x_test)} test samples")

        return x_train, y_train, x_test, y_test

    def build_model(self):
        """Build a simple CNN classifier."""
        logger.info("Building model architecture...")

        model = keras.Sequential([
            layers.Input(shape=self.input_shape),
            layers.Conv2D(32, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.Flatten(),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(self.num_classes, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        self.model = model
        logger.info("Model architecture built successfully")

        return model

    def train(self, x_train, y_train, x_test, y_test, epochs=5, batch_size=128):
        """
        Train the model.

        Args:
            x_train, y_train: Training data
            x_test, y_test: Test data
            epochs: Number of training epochs
            batch_size: Batch size for training

        Returns:
            Training history
        """
        logger.info(f"Training model for {epochs} epochs...")

        history = self.model.fit(
            x_train, y_train,
            batch_size=batch_size,
            epochs=epochs,
            validation_split=0.1,
            verbose=1
        )

        # Evaluate on test set
        test_loss, test_acc = self.model.evaluate(x_test, y_test, verbose=0)
        logger.info(f"Test accuracy: {test_acc:.4f}")

        return history

    def save_model(self, version='v1.0'):
        """
        Save model with vulnerabilities.

        VULNERABILITIES:
        - No access control on model files
        - Metadata exposes architecture details
        - No integrity verification
        - Training data references in metadata
        """
        model_path = os.path.join(self.model_dir, f'model_{version}.keras')
        weights_path = os.path.join(self.model_dir, f'weights_{version}.h5')

        logger.warning(f"Saving model to {self.model_dir} (EXPOSED - NO ACCESS CONTROL)")

        # Save full model
        self.model.save(model_path)

        # Save weights separately
        self.model.save_weights(weights_path)

        # VULNERABILITY: Save detailed model configuration
        config = {
            'version': version,
            'framework': 'tensorflow',
            'framework_version': tf.__version__,
            'dataset': self.dataset,
            'input_shape': list(self.input_shape),
            'num_classes': self.num_classes,
            'architecture': 'simple_cnn',
            'layers': len(self.model.layers),
            'trainable_params': self.model.count_params(),
            'model_path': model_path,
            'weights_path': weights_path,
            'data_dir': self.data_dir,
            'saved_at': datetime.now().isoformat(),
            'access_control': 'NONE',  # Deliberately exposed
            'encryption': 'NONE'       # No encryption
        }

        config_path = os.path.join(self.model_dir, f'model_config_{version}.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        logger.info(f"Model saved: {model_path}")
        logger.warning("SECURITY: Model configuration exposed without access control!")

        return model_path

    def load_model(self, version='v1.0'):
        """Load a saved model."""
        model_path = os.path.join(self.model_dir, f'model_{version}.keras')

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")

        logger.info(f"Loading model from {model_path}")
        self.model = keras.models.load_model(model_path)

        return self.model

    def predict(self, x):
        """Make predictions on input data."""
        if self.model is None:
            raise ValueError("Model not loaded. Train or load a model first.")

        return self.model.predict(x)


def main():
    """Main function to train and save the vulnerable model."""
    print("=" * 80)
    print("VULNERABLE ML SYSTEM TRAINER")
    print("=" * 80)
    print("\n⚠️  WARNING: This is an intentionally vulnerable system for educational purposes.")
    print("   DO NOT deploy this in production environments!\n")

    # Initialize system
    system = VulnerableMLSystem(dataset='mnist')

    # Load and prepare data
    x_train, y_train, x_test, y_test = system.load_and_prepare_data()

    # Build model
    system.build_model()

    # Train model
    system.train(x_train, y_train, x_test, y_test, epochs=5)

    # Save model
    system.save_model(version='v1.0')

    print("\n" + "=" * 80)
    print("Training complete! Vulnerable system ready for OSINT demonstration.")
    print("=" * 80)


if __name__ == '__main__':
    main()
