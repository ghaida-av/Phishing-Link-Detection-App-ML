from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from ml_model import PhishingURLDetector
from database import Database
from url_validator import URLValidator
from threat_intel import get_threat_intel

app = Flask(__name__)
CORS(app)  # Enable CORS for Android app

# Initialize components
ml_detector = PhishingURLDetector()
db = Database()
url_validator = URLValidator()


@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "verdict": "INVALID",
                "url_type": "invalid",
                "confidence": 0.0,
                "from_cache": False,
                "message": "No data provided"
            }), 400
        
        input_text = data.get("url", "").strip()
        if not input_text:
            return jsonify({
                "verdict": "INVALID",
                "url_type": "invalid",
                "confidence": 0.0,
                "from_cache": False,
                "message": "URL/Email cannot be empty"
            }), 400
        
        # Validate and classify input (URL vs Email)
        validation_result = url_validator.validate_and_classify(input_text)
        if not validation_result['is_valid']:
            return jsonify({
                "verdict": "INVALID",
                "url_type": "invalid",
                "confidence": 0.0,
                "from_cache": False,
                "message": "Invalid URL or email format"
            }), 400
        
        url_type = validation_result['type']
        normalized_input = validation_result['normalized']
        
        # Check cache
        cached_result = db.get_url_result(normalized_input)
        if cached_result:
            is_phishing = cached_result['is_phishing']
            confidence = cached_result['confidence']
            verdict = "PHISHING" if is_phishing else "SAFE"
            return jsonify({
                "verdict": verdict,
                "url_type": url_type,
                "confidence": confidence,
                "from_cache": True,
                "message": "Result retrieved from database",
                "threat_intel": None
            })
        
        # Email detection
        if url_type == 'email':
            suspicious_domains = ['tempmail', 'guerrillamail', '10minutemail', 
                                  'throwaway', 'mailinator', 'trashmail']
            domain = normalized_input.split('@')[1] if '@' in normalized_input else ''
            is_phishing = any(sd in domain.lower() for sd in suspicious_domains)
            confidence = 0.85 if is_phishing else 0.15
            db.save_url_result(normalized_input, url_type, is_phishing, confidence)
            verdict = "PHISHING" if is_phishing else "SAFE"
            return jsonify({
                "verdict": verdict,
                "url_type": url_type,
                "confidence": confidence,
                "from_cache": False,
                "message": "Email analyzed",
                "threat_intel": None
            })
        
        # URL detection using ML + threat intel
        is_phishing, confidence = ml_detector.predict(normalized_input)
        threat_intel = get_threat_intel(normalized_input)
        flags = threat_intel.get("flags", {})

        if flags.get("listed_in_blacklist"):
            is_phishing = True
            confidence = max(confidence, 0.99)
        if flags.get("very_young_domain") and not flags.get("listed_in_blacklist") and is_phishing:
            confidence = min(confidence + 0.05, 0.98)

        db.save_url_result(normalized_input, url_type, is_phishing, confidence)
        verdict = "PHISHING" if is_phishing else "SAFE"

        return jsonify({
            "verdict": verdict,
            "url_type": url_type,
            "confidence": confidence,
            "from_cache": False,
            "message": "URL analyzed using ML model + WHOIS/blacklists",
            "threat_intel": threat_intel
        })
    
    except Exception as e:
        return jsonify({
            "verdict": "ERROR",
            "url_type": "invalid",
            "confidence": 0.0,
            "from_cache": False,
            "message": f"Error: {str(e)}"
        }), 500


@app.route('/check', methods=['GET'])
def check_url():
    """Quick GET check for a URL/email"""
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({
            "verdict": "INVALID",
            "url_type": "invalid",
            "confidence": 0.0,
            "from_cache": False,
            "message": "URL parameter is required"
        }), 400

    # Reuse predict logic
    with app.test_request_context("/predict", method="POST", json={"url": url}):
        response = predict()
        if isinstance(response, tuple):
            payload, status = response
            return payload, status
        return response


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get database statistics"""
    try:
        stats = db.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/recent', methods=['GET'])
def get_recent():
    """Get recent detections"""
    try:
        limit = request.args.get('limit', 10, type=int)
        recent = db.get_recent_detections(limit)
        return jsonify({"recent": recent}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """HTML dashboard"""
    stats = db.get_statistics()
    recent = db.get_recent_detections(limit=20)
    result = None
    input_value = ""

    if request.method == "POST":
        input_value = request.form.get("url", "").strip()
        if input_value:
            with app.test_request_context("/predict", method="POST", json={"url": input_value}):
                response = predict()
                if isinstance(response, tuple):
                    payload, status = response
                    result = payload.get_json()
                else:
                    result = response.get_json()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent=recent,
        input_value=input_value,
        result=result,
    )


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model_loaded": ml_detector.model is not None
    }), 200


if __name__ == "__main__":
    print("Starting Phishing Detection API...")
    print("ML Model: Loaded")
    print("Database: Connected")
    app.run(host="0.0.0.0", port=5001, debug=True)

