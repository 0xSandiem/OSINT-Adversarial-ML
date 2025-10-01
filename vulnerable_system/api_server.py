"""
Vulnerable ML API Server

WARNING: This is a deliberately vulnerable API for educational purposes only.
DO NOT use in production environments.

Vulnerabilities:
- No rate limiting
- No authentication
- Verbose error messages
- No input validation
- Exposes model metadata
"""

import os
import json
import logging
import numpy as np
from flask import Flask, request, jsonify
from tensorflow import keras
import base64
from io import BytesIO
from PIL import Image

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global model storage
MODEL = None
MODEL_CONFIG = None
QUERY_LOG = []


def load_model(model_dir='./models/exposed', version='v1.0'):
    """Load the model and configuration."""
    global MODEL, MODEL_CONFIG

    model_path = os.path.join(model_dir, f'model_{version}.keras')
    config_path = os.path.join(model_dir, f'model_config_{version}.json')

    logger.info(f"Loading model from {model_path}")
    MODEL = keras.models.load_model(model_path)

    # VULNERABILITY: Load and expose configuration
    with open(config_path, 'r') as f:
        MODEL_CONFIG = json.load(f)

    logger.warning("API Server started with NO AUTHENTICATION or RATE LIMITING!")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': MODEL is not None
    })


@app.route('/info', methods=['GET'])
def info():
    """
    VULNERABILITY: Exposes detailed model information.

    This endpoint reveals:
    - Model architecture details
    - Training data location
    - Framework version
    - Configuration details
    """
    if MODEL_CONFIG is None:
        return jsonify({'error': 'Model not loaded'}), 500

    # VULNERABILITY: Return sensitive configuration
    logger.warning("Model configuration exposed via /info endpoint")
    return jsonify({
        'model_info': MODEL_CONFIG,
        'total_queries': len(QUERY_LOG),
        'warning': 'This endpoint exposes sensitive model information!'
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Prediction endpoint.

    VULNERABILITIES:
    - No authentication required
    - No rate limiting
    - No input validation
    - Logs all queries (enables model extraction)
    - Returns confidence scores (helps adversaries)
    """
    try:
        data = request.get_json()

        if 'image' not in data:
            return jsonify({'error': 'No image provided'}), 400

        # Decode image
        if isinstance(data['image'], str):
            # Base64 encoded image
            image_data = base64.b64decode(data['image'])
            image = Image.open(BytesIO(image_data))
            image = image.convert('L') if len(MODEL_CONFIG['input_shape']) == 3 and MODEL_CONFIG['input_shape'][2] == 1 else image.convert('RGB')
            image = image.resize((MODEL_CONFIG['input_shape'][0], MODEL_CONFIG['input_shape'][1]))
            x = np.array(image).reshape(1, *MODEL_CONFIG['input_shape']) / 255.0
        elif isinstance(data['image'], list):
            # Raw array
            x = np.array(data['image']).reshape(1, *MODEL_CONFIG['input_shape'])
        else:
            return jsonify({'error': 'Invalid image format'}), 400

        # Make prediction
        predictions = MODEL.predict(x, verbose=0)
        predicted_class = int(np.argmax(predictions[0]))
        confidence = float(predictions[0][predicted_class])

        # VULNERABILITY: Log all queries (enables model extraction attacks)
        query_record = {
            'input_shape': x.shape,
            'prediction': predicted_class,
            'confidence': confidence,
            'all_probabilities': predictions[0].tolist()  # VULNERABILITY: Full distribution
        }
        QUERY_LOG.append(query_record)

        # VULNERABILITY: Return detailed predictions including all class probabilities
        response = {
            'prediction': predicted_class,
            'confidence': confidence,
            'all_probabilities': predictions[0].tolist(),  # Helps adversaries understand model
            'query_count': len(QUERY_LOG)
        }

        logger.info(f"Prediction request: class={predicted_class}, confidence={confidence:.4f}")

        return jsonify(response)

    except Exception as e:
        # VULNERABILITY: Verbose error messages
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'details': 'Check server logs for more information'
        }), 500


@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    """
    Batch prediction endpoint.

    VULNERABILITY: Allows multiple queries at once, accelerating model extraction.
    """
    try:
        data = request.get_json()

        if 'images' not in data:
            return jsonify({'error': 'No images provided'}), 400

        images = np.array(data['images'])

        # Reshape if needed
        if len(images.shape) == 3:
            images = images.reshape(-1, *MODEL_CONFIG['input_shape'])

        # Make predictions
        predictions = MODEL.predict(images, verbose=0)

        results = []
        for pred in predictions:
            predicted_class = int(np.argmax(pred))
            confidence = float(pred[predicted_class])

            results.append({
                'prediction': predicted_class,
                'confidence': confidence,
                'all_probabilities': pred.tolist()
            })

            # Log each query
            QUERY_LOG.append({
                'prediction': predicted_class,
                'confidence': confidence,
                'all_probabilities': pred.tolist()
            })

        logger.info(f"Batch prediction: {len(results)} samples processed")

        return jsonify({
            'results': results,
            'total_queries': len(QUERY_LOG)
        })

    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        return jsonify({
            'error': str(e),
            'type': type(e).__name__
        }), 500


@app.route('/query_log', methods=['GET'])
def get_query_log():
    """
    VULNERABILITY: Exposes all query history.

    This allows adversaries to:
    - Analyze usage patterns
    - Extract model behavior
    - Plan targeted attacks
    """
    logger.warning("Query log accessed - exposing all prediction history!")

    limit = request.args.get('limit', default=100, type=int)

    return jsonify({
        'total_queries': len(QUERY_LOG),
        'recent_queries': QUERY_LOG[-limit:],
        'warning': 'This endpoint exposes sensitive query information!'
    })


@app.route('/statistics', methods=['GET'])
def statistics():
    """
    VULNERABILITY: Exposes model usage statistics.
    """
    if len(QUERY_LOG) == 0:
        return jsonify({'message': 'No queries yet'})

    predictions = [q['prediction'] for q in QUERY_LOG]
    confidences = [q['confidence'] for q in QUERY_LOG]

    stats = {
        'total_queries': len(QUERY_LOG),
        'average_confidence': float(np.mean(confidences)),
        'prediction_distribution': {i: predictions.count(i) for i in range(MODEL_CONFIG['num_classes'])},
        'min_confidence': float(np.min(confidences)),
        'max_confidence': float(np.max(confidences))
    }

    return jsonify(stats)


def main(host='127.0.0.1', port=5000, model_dir='./models/exposed', version='v1.0'):
    """Start the vulnerable API server."""
    print("=" * 80)
    print("VULNERABLE ML API SERVER")
    print("=" * 80)
    print("\n⚠️  WARNING: This is an intentionally vulnerable API for educational purposes.")
    print("   DO NOT deploy this in production environments!\n")
    print("Vulnerabilities included:")
    print("  - No authentication or authorization")
    print("  - No rate limiting")
    print("  - Verbose error messages")
    print("  - Model metadata exposure")
    print("  - Query logging enabling model extraction")
    print("  - Full probability distribution returned")
    print("\n" + "=" * 80 + "\n")

    # Load model
    load_model(model_dir, version)

    # Start server
    logger.info(f"Starting server on {host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    main()
