"""
Model Extraction Attack Module

WARNING: FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY.

This module demonstrates model extraction (model stealing) attacks where an
adversary queries a black-box ML API to build a surrogate model that mimics
the original model's behavior.

Techniques demonstrated:
1. Query-based extraction using random/strategic inputs
2. Surrogate model training on query responses
3. Accuracy comparison with original model
"""

import os
import json
import logging
import numpy as np
import requests
from datetime import datetime
from typing import Tuple, Dict, Optional
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelExtractor:
    """
    Model extraction attack simulator.

    ETHICAL USE ONLY: For security research and defensive security purposes.
    """

    def __init__(self, api_url='http://127.0.0.1:5000', use_osint_metadata=True):
        """
        Initialize model extractor.

        Args:
            api_url: URL of the target ML API
            use_osint_metadata: Whether to use OSINT-discovered metadata for optimization
        """
        self.api_url = api_url
        self.use_osint_metadata = use_osint_metadata
        self.query_data = []
        self.surrogate_model = None
        self.model_metadata = None
        self.start_time = None

    def gather_osint_metadata(self, metadata_path='./models/exposed/model_config_v1.0.json') -> Dict:
        """
        Load OSINT-discovered metadata to optimize extraction.

        Args:
            metadata_path: Path to exposed model configuration

        Returns:
            Dictionary of model metadata
        """
        if not self.use_osint_metadata:
            return {}

        logger.info(f"Loading OSINT metadata from {metadata_path}")

        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            self.model_metadata = metadata
            logger.info(f"OSINT advantage: Discovered input shape {metadata.get('input_shape')}, "
                       f"{metadata.get('num_classes')} classes")

            return metadata

        except FileNotFoundError:
            logger.warning("OSINT metadata not found - extraction will be less efficient")
            return {}

    def probe_api_info(self) -> Dict:
        """
        Probe API for information disclosure endpoints.

        Returns:
            Dictionary of discovered API information
        """
        logger.info("Probing API for information disclosure...")

        info = {}

        try:
            # Try /info endpoint
            response = requests.get(f"{self.api_url}/info", timeout=5)
            if response.status_code == 200:
                info = response.json().get('model_info', {})
                logger.warning(f"VULNERABILITY EXPLOITED: /info endpoint exposed model metadata!")
                self.model_metadata = info

        except Exception as e:
            logger.debug(f"Info endpoint not accessible: {e}")

        return info

    def generate_query_samples(self, num_samples=1000, strategy='random') -> np.ndarray:
        """
        Generate samples to query the target model.

        Args:
            num_samples: Number of samples to generate
            strategy: Query strategy ('random', 'adversarial', 'diverse')

        Returns:
            Array of query samples
        """
        logger.info(f"Generating {num_samples} query samples using '{strategy}' strategy")

        if self.model_metadata:
            input_shape = tuple(self.model_metadata['input_shape'])
        else:
            # Default to MNIST shape if no metadata
            input_shape = (28, 28, 1)
            logger.warning("No metadata available - using default MNIST shape")

        if strategy == 'random':
            # Random uniform samples
            samples = np.random.uniform(0, 1, size=(num_samples, *input_shape)).astype('float32')

        elif strategy == 'diverse':
            # Mix of different patterns for better coverage
            samples = []

            # Random samples
            samples.append(np.random.uniform(0, 1, size=(num_samples // 3, *input_shape)))

            # High-contrast samples
            samples.append(np.random.choice([0, 1], size=(num_samples // 3, *input_shape)))

            # Gaussian noise samples
            samples.append(np.clip(np.random.normal(0.5, 0.3, size=(num_samples // 3, *input_shape)), 0, 1))

            samples = np.vstack(samples).astype('float32')[:num_samples]

        elif strategy == 'adversarial':
            # Generate samples near decision boundaries
            # For simplicity, use random with higher variance
            samples = np.clip(np.random.normal(0.5, 0.4, size=(num_samples, *input_shape)), 0, 1).astype('float32')

        else:
            raise ValueError(f"Unknown strategy: {strategy}")

        return samples

    def query_model(self, samples: np.ndarray, batch_size=32) -> Tuple[np.ndarray, np.ndarray]:
        """
        Query the target model with samples.

        Args:
            samples: Input samples to query
            batch_size: Batch size for API requests

        Returns:
            Tuple of (predictions, confidences)
        """
        logger.info(f"Querying target model with {len(samples)} samples...")

        predictions = []
        all_probabilities = []

        self.start_time = datetime.now()

        # Query in batches
        for i in tqdm(range(0, len(samples), batch_size), desc="Querying API"):
            batch = samples[i:i + batch_size]

            try:
                # Try batch endpoint first (more efficient if available)
                response = requests.post(
                    f"{self.api_url}/batch_predict",
                    json={'images': batch.tolist()},
                    timeout=30
                )

                if response.status_code == 200:
                    results = response.json()['results']
                    for result in results:
                        predictions.append(result['prediction'])
                        all_probabilities.append(result['all_probabilities'])

                    # Log query data
                    for j, result in enumerate(results):
                        self.query_data.append({
                            'input': batch[j].tolist(),
                            'prediction': result['prediction'],
                            'confidence': result['confidence'],
                            'probabilities': result['all_probabilities']
                        })

                else:
                    # Fall back to single queries
                    for sample in batch:
                        response = requests.post(
                            f"{self.api_url}/predict",
                            json={'image': sample.tolist()},
                            timeout=10
                        )

                        if response.status_code == 200:
                            result = response.json()
                            predictions.append(result['prediction'])
                            all_probabilities.append(result['all_probabilities'])

                            self.query_data.append({
                                'input': sample.tolist(),
                                'prediction': result['prediction'],
                                'confidence': result['confidence'],
                                'probabilities': result['all_probabilities']
                            })

            except Exception as e:
                logger.error(f"Query batch {i} failed: {e}")
                # Fill with dummy data to maintain array shape
                for _ in range(len(batch)):
                    predictions.append(0)
                    all_probabilities.append([0] * 10)

        query_time = (datetime.now() - self.start_time).total_seconds()
        logger.info(f"Completed {len(predictions)} queries in {query_time:.2f}s "
                   f"({len(predictions)/query_time:.2f} queries/sec)")

        return np.array(predictions), np.array(all_probabilities)

    def build_surrogate_model(self, input_shape: Tuple, num_classes: int) -> keras.Model:
        """
        Build surrogate model architecture.

        Args:
            input_shape: Input shape for the model
            num_classes: Number of output classes

        Returns:
            Compiled surrogate model
        """
        logger.info(f"Building surrogate model: input_shape={input_shape}, num_classes={num_classes}")

        # Build architecture similar to target (if metadata available) or generic CNN
        model = keras.Sequential([
            layers.Input(shape=input_shape),
            layers.Conv2D(32, (3, 3), activation='relu', padding='same'),
            layers.MaxPooling2D((2, 2)),
            layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
            layers.MaxPooling2D((2, 2)),
            layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
            layers.Flatten(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(num_classes, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        logger.info(f"Surrogate model built with {model.count_params()} parameters")

        return model

    def train_surrogate_model(self, x_query: np.ndarray, y_predicted: np.ndarray,
                             epochs=10, validation_split=0.2) -> Tuple[keras.Model, Dict]:
        """
        Train surrogate model on queried data.

        Args:
            x_query: Query inputs
            y_predicted: Target model predictions (used as labels)
            epochs: Training epochs
            validation_split: Validation split ratio

        Returns:
            Tuple of (trained_model, training_metrics)
        """
        logger.info(f"Training surrogate model on {len(x_query)} query samples...")

        # Determine architecture parameters
        input_shape = x_query.shape[1:]

        # Determine num_classes from metadata or predictions
        if self.model_metadata and 'num_classes' in self.model_metadata:
            num_classes = self.model_metadata['num_classes']
            logger.info(f"Using OSINT metadata: num_classes={num_classes}")
        else:
            num_classes = len(np.unique(y_predicted))
            logger.info(f"Inferred from predictions: num_classes={num_classes}")

        # Sanity check: num_classes should be reasonable (2-1000)
        if num_classes < 2:
            logger.warning(f"num_classes={num_classes} seems wrong, defaulting to 10")
            num_classes = 10

        # Build model
        self.surrogate_model = self.build_surrogate_model(input_shape, num_classes)

        # Train
        history = self.surrogate_model.fit(
            x_query, y_predicted,
            batch_size=128,
            epochs=epochs,
            validation_split=validation_split,
            verbose=1
        )

        train_acc = history.history['accuracy'][-1]
        val_acc = history.history['val_accuracy'][-1]

        logger.info(f"Surrogate model training complete: train_acc={train_acc:.4f}, val_acc={val_acc:.4f}")

        metrics = {
            'train_accuracy': float(train_acc),
            'val_accuracy': float(val_acc),
            'training_samples': len(x_query),
            'epochs': epochs,
            'history': {
                'accuracy': [float(x) for x in history.history['accuracy']],
                'val_accuracy': [float(x) for x in history.history['val_accuracy']],
                'loss': [float(x) for x in history.history['loss']],
                'val_loss': [float(x) for x in history.history['val_loss']]
            }
        }

        return self.surrogate_model, metrics

    def evaluate_extraction_success(self, x_test: np.ndarray, y_test: np.ndarray,
                                    original_model_path: Optional[str] = None) -> Dict:
        """
        Evaluate surrogate model extraction success.

        Args:
            x_test: Test data
            y_test: Test labels
            original_model_path: Path to original model (if available)

        Returns:
            Dictionary of extraction metrics
        """
        logger.info("Evaluating extraction success...")

        # Evaluate surrogate on test data
        surrogate_loss, surrogate_acc = self.surrogate_model.evaluate(x_test, y_test, verbose=0)

        logger.info(f"Surrogate model test accuracy: {surrogate_acc:.4f}")

        metrics = {
            'surrogate_test_accuracy': float(surrogate_acc),
            'surrogate_test_loss': float(surrogate_loss),
            'num_queries': len(self.query_data),
            'query_time_seconds': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        }

        # Compare with original model if available
        if original_model_path and os.path.exists(original_model_path):
            try:
                original_model = keras.models.load_model(original_model_path)
                original_loss, original_acc = original_model.evaluate(x_test, y_test, verbose=0)

                # Agreement rate between models
                original_preds = np.argmax(original_model.predict(x_test, verbose=0), axis=1)
                surrogate_preds = np.argmax(self.surrogate_model.predict(x_test, verbose=0), axis=1)
                agreement_rate = np.mean(original_preds == surrogate_preds)

                metrics['original_test_accuracy'] = float(original_acc)
                metrics['model_agreement_rate'] = float(agreement_rate)
                metrics['accuracy_gap'] = float(abs(original_acc - surrogate_acc))

                logger.info(f"Original model test accuracy: {original_acc:.4f}")
                logger.info(f"Model agreement rate: {agreement_rate:.4f}")
                logger.info(f"Accuracy gap: {metrics['accuracy_gap']:.4f}")

            except Exception as e:
                logger.warning(f"Could not load original model: {e}")

        return metrics

    def save_surrogate_model(self, save_path='./models/exposed/surrogate_model.keras'):
        """
        Save extracted surrogate model.

        Args:
            save_path: Path to save the model
        """
        if self.surrogate_model is None:
            raise ValueError("No surrogate model to save")

        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.surrogate_model.save(save_path)

        logger.info(f"Surrogate model saved to {save_path}")

        # Save extraction metadata
        metadata_path = save_path.replace('.keras', '_metadata.json')
        metadata = {
            'num_queries': len(self.query_data),
            'extraction_timestamp': datetime.now().isoformat(),
            'used_osint_metadata': self.use_osint_metadata,
            'api_url': self.api_url,
            'model_path': save_path
        }

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Extraction metadata saved to {metadata_path}")

    def save_query_log(self, log_path='./attacks/query_log.json'):
        """
        Save query log for analysis.

        Args:
            log_path: Path to save query log
        """
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        with open(log_path, 'w') as f:
            json.dump({
                'total_queries': len(self.query_data),
                'queries': self.query_data[:100]  # Save first 100 for space
            }, f, indent=2)

        logger.info(f"Query log saved to {log_path}")


def main():
    """Main function to demonstrate model extraction attack."""
    print("=" * 80)
    print("MODEL EXTRACTION ATTACK MODULE")
    print("=" * 80)
    print("\n⚠️  FOR EDUCATIONAL AND DEFENSIVE SECURITY PURPOSES ONLY\n")

    # Initialize extractor
    extractor = ModelExtractor(api_url='http://127.0.0.1:5000', use_osint_metadata=True)

    # Gather OSINT metadata
    print("[1/6] Gathering OSINT metadata...")
    try:
        metadata = extractor.gather_osint_metadata()
        print(f"  Found metadata: {metadata.get('num_classes')} classes, input shape {metadata.get('input_shape')}")
    except FileNotFoundError:
        print("  No metadata found - proceeding with default assumptions")
        metadata = {}

    # Probe API
    print("\n[2/6] Probing API for information disclosure...")
    api_info = extractor.probe_api_info()

    # Generate query samples
    print("\n[3/6] Generating query samples...")
    query_samples = extractor.generate_query_samples(num_samples=1000, strategy='diverse')

    # Query the model
    print("\n[4/6] Querying target model (this may take a while)...")
    print("  Note: API server must be running at http://127.0.0.1:5000")
    try:
        predictions, probabilities = extractor.query_model(query_samples, batch_size=32)
        print(f"  Completed {len(predictions)} queries successfully")
    except Exception as e:
        print(f"  ERROR: Could not query API - {e}")
        print("  Make sure the API server is running (python vulnerable_system/api_server.py)")
        return

    # Train surrogate model
    print("\n[5/6] Training surrogate model...")
    surrogate, train_metrics = extractor.train_surrogate_model(query_samples, predictions, epochs=10)
    print(f"  Training accuracy: {train_metrics['train_accuracy']:.4f}")
    print(f"  Validation accuracy: {train_metrics['val_accuracy']:.4f}")

    # Evaluate extraction
    print("\n[6/6] Evaluating extraction success...")
    try:
        # Load test data
        x_test = np.load('./data/misconfigured/x_test.npy')
        y_test = np.load('./data/misconfigured/y_test.npy')

        eval_metrics = extractor.evaluate_extraction_success(
            x_test, y_test,
            original_model_path='./models/exposed/model_v1.0.keras'
        )

        print(f"\nExtraction Results:")
        print(f"  Surrogate accuracy: {eval_metrics['surrogate_test_accuracy']:.4f}")
        if 'original_test_accuracy' in eval_metrics:
            print(f"  Original accuracy: {eval_metrics['original_test_accuracy']:.4f}")
            print(f"  Model agreement: {eval_metrics['model_agreement_rate']:.4f}")
            print(f"  Accuracy gap: {eval_metrics['accuracy_gap']:.4f}")
        print(f"  Total queries: {eval_metrics['num_queries']}")

        # Save surrogate
        extractor.save_surrogate_model()
        extractor.save_query_log()

    except FileNotFoundError as e:
        print(f"  Could not load test data: {e}")

    print("\n" + "=" * 80)
    print("Model extraction attack demonstration complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()
