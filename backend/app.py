from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get("url", "").lower()
    is_phishing = False
    if len(url) > 50: is_phishing = True       
    if "@" in url: is_phishing = True         
    if "https" not in url: is_phishing = True    
    result = "PHISHING" if is_phishing else "SAFE"
    return jsonify({"verdict": result})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
