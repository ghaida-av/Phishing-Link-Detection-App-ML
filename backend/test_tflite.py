"""
Test TensorFlow Lite Model
Run this script to test the TensorFlow Lite model with sample URLs
"""
import numpy as np
try:
    import tensorflow as tf
except ImportError:
    print("TensorFlow not installed. Run: pip install tensorflow")
    exit(1)

from ml_model import PhishingURLDetector
import os

def test_tflite_model(model_path='phishing_model.tflite'):
    """Test the TensorFlow Lite model"""
    
    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        print("\n📝 To generate the model, run:")
        print("   python convert_to_tflite.py")
        return False
    
    print(f"✅ Loading model: {model_path}")
    
    # Load the TFLite model
    interpreter = tf.lite.Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    
    # Get input and output tensors
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    print(f"📊 Model Input Shape: {input_details[0]['shape']}")
    print(f"📊 Model Output Shape: {output_details[0]['shape']}")
    
    # Initialize feature extractor
    detector = PhishingURLDetector()
    
    # Test URLs
    test_urls = [
        # Safe URLs
        ("https://www.google.com", False),
        ("https://www.github.com", False),
        ("https://www.stackoverflow.com", False),
        ("https://www.wikipedia.org", False),
        
        # Phishing URLs
        ("http://google.com-verify.tk", True),
        ("https://paypal-suspend.ml/login", True),
        ("http://facebook.com-verify.ga", True),
        ("https://secure-bank-update.tk/verify", True),
        ("http://192.168.1.1/login", True),
    ]
    
    print("\n🧪 Testing URLs:\n")
    print("-" * 80)
    
    correct = 0
    total = len(test_urls)
    
    for url, expected_phishing in test_urls:
        # Extract features
        features = detector.extract_features(url)
        features = features.reshape(1, -1).astype(np.float32)
        
        # Run inference
        interpreter.set_tensor(input_details[0]['index'], features)
        interpreter.invoke()
        
        # Get prediction
        output_data = interpreter.get_tensor(output_details[0]['index'])
        phishing_probability = float(output_data[0][0])
        is_phishing = phishing_probability > 0.5
        confidence = phishing_probability if is_phishing else (1 - phishing_probability)
        
        # Check if correct
        is_correct = is_phishing == expected_phishing
        if is_correct:
            correct += 1
        
        status = "✅" if is_correct else "❌"
        expected = "PHISHING" if expected_phishing else "SAFE"
        predicted = "PHISHING" if is_phishing else "SAFE"
        
        print(f"{status} {url[:50]:<50}")
        print(f"   Expected: {expected:8} | Predicted: {predicted:8} | Confidence: {confidence*100:.1f}%")
        print()
    
    print("-" * 80)
    accuracy = (correct / total) * 100
    print(f"📈 Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    
    return True

def test_custom_url(model_path='phishing_model.tflite', url=None):
    """Test a custom URL"""
    
    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        return False
    
    if not url:
        url = input("Enter URL to test: ").strip()
    
    # Load model
    interpreter = tf.lite.Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    # Extract features
    detector = PhishingURLDetector()
    features = detector.extract_features(url)
    features = features.reshape(1, -1).astype(np.float32)
    
    # Run inference
    interpreter.set_tensor(input_details[0]['index'], features)
    interpreter.invoke()
    
    # Get prediction
    output_data = interpreter.get_tensor(output_details[0]['index'])
    phishing_probability = float(output_data[0][0])
    is_phishing = phishing_probability > 0.5
    confidence = phishing_probability if is_phishing else (1 - phishing_probability)
    
    # Display result
    print("\n" + "=" * 80)
    print(f"🔍 URL: {url}")
    print(f"📊 Result: {'⚠ PHISHING DETECTED' if is_phishing else '✅ SAFE URL'}")
    print(f"📈 Confidence: {confidence*100:.1f}%")
    print(f"📉 Phishing Probability: {phishing_probability*100:.1f}%")
    print("=" * 80)
    
    return is_phishing, confidence

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Test custom URL
        test_custom_url(url=sys.argv[1])
    else:
        # Test with sample URLs
        print("🚀 TensorFlow Lite Model Tester\n")
        test_tflite_model()
        
        print("\n" + "=" * 80)
        print("💡 Tip: Test a custom URL by running:")
        print("   python test_tflite.py 'https://example.com'")
        print("=" * 80)
