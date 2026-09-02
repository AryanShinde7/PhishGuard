"""
app.py — PhishGuard Python ML Microservice (Flask REST API)

Provides real-time machine learning prediction endpoints on port 5001.
Consumed by the Express backend (`/api/analyze`) and dashboard analytics.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from predictor import get_predictor, get_uci_predictor

app = Flask(__name__)
CORS(app)

PORT = int(os.environ.get('ML_PORT', 5001))

# ── Health Check ──────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    predictor = get_predictor()
    meta = predictor.metadata
    return jsonify({
        'status': 'ok',
        'service': 'PhishGuard ML Service',
        'model': meta.get('model_type', 'RandomForestClassifier'),
        'version': meta.get('version', '1.0.0'),
        'metrics': meta.get('metrics', {})
    })

# ── Metadata & Top Features ───────────────────────────────────────────────────

@app.route('/model/metadata', methods=['GET'])
def model_metadata():
    predictor = get_predictor()
    return jsonify({
        'success': True,
        'metadata': predictor.metadata
    })

# ── Single Prediction ─────────────────────────────────────────────────────────

@app.route('/predict', methods=['POST'])
def predict():
    """
    POST /predict
    Body: { "url": "http://...", "domSignals": { ... } }
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'success': False, 'error': 'Missing required "url" field.'}), 400

    url = data.get('url', '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'Empty URL provided.'}), 400

    dom_signals = data.get('domSignals', None)

    try:
        predictor = get_predictor()
        result = predictor.predict(url, dom_signals)
        return jsonify({
            'success': True,
            'prediction': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Inference failed: {str(e)}"
        }), 500

# ── Batch Prediction ──────────────────────────────────────────────────────────

@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """
    POST /predict/batch
    Body: { "urls": ["http://...", "https://..."] }
    """
    data = request.get_json(silent=True)
    if not data or 'urls' not in data or not isinstance(data['urls'], list):
        return jsonify({'success': False, 'error': 'Expected "urls" array.'}), 400

    urls = data.get('urls', [])
    if len(urls) > 100:
        return jsonify({'success': False, 'error': 'Max batch size is 100 URLs.'}), 400

    try:
        predictor = get_predictor()
        results = [predictor.predict(u) for u in urls]
        return jsonify({
            'success': True,
            'count': len(results),
            'predictions': results
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Batch inference failed: {str(e)}"
        }), 500

# ── UCI Prediction Endpoint (Phase 10) ──────────────────────────────────────

@app.route('/predict/uci', methods=['POST'])
def predict_uci():
    """
    POST /predict/uci
    Body: { "url": "http://...", "domSignals": { ... } }
    Uses the UCI-trained 17-feature Random Forest model.
    Returns probability of phishing (0.0 = definitely legit, 1.0 = definitely phishing).
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'success': False, 'error': 'Missing required "url" field.'}), 400
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'Empty URL.'}), 400
    dom_signals = data.get('domSignals', None)
    try:
        predictor = get_uci_predictor()
        result = predictor.predict(url, dom_signals)
        return jsonify({'success': True, 'prediction': result})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e), 'hint': 'Run train_uci.py first.'}), 503
    except Exception as e:
        return jsonify({'success': False, 'error': f'UCI inference failed: {str(e)}'}), 500


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"\n[*] PhishGuard ML Microservice running on http://localhost:{PORT}")
    print(f"   Health endpoint: http://localhost:{PORT}/health")
    print(f"   Predict endpoint: POST http://localhost:{PORT}/predict\n")
    app.run(host='0.0.0.0', port=PORT, debug=False)
