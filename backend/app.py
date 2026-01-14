from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    # Get the URL from the Android app
    data = request.get_json()
    url = data.get("url", "").lower()
    
    
    # We check for common phishing signs
    is_phishing = False
    if len(url) > 50: is_phishing = True        # Real phishing links are often very long
    if "@" in url: is_phishing = True           # Phishers use @ to hide true domains
    if "https" not in url: is_phishing = True    # Most phishing sites lack SSL certificates

    result = "PHISHING" if is_phishing else "SAFE"
    return jsonify({"verdict": result})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
