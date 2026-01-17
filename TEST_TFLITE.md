# 🧪 TensorFlow Lite Model Testing Guide

## Quick Test Links

### 1. **Web-Based Simulator** (No model needed)
Open in browser: **http://localhost:8000/test_tflite_web.html**

This simulates the TensorFlow Lite model behavior using the same feature extraction logic.

### 2. **Python Test Script** (Requires model)
```bash
cd backend
python test_tflite.py
```

### 3. **Test Custom URL**
```bash
cd backend
python test_tflite.py "https://example.com"
```

## Step-by-Step: Generate and Test Model

### Step 1: Generate TensorFlow Lite Model
```bash
cd backend
pip install -r requirements.txt
python convert_to_tflite.py
```

This will:
- Train a TensorFlow neural network
- Convert it to TensorFlow Lite format
- Save as `phishing_model.tflite`

### Step 2: Test the Model

**Option A: Python Test Script**
```bash
python test_tflite.py
```

**Option B: Test in Android App**
```bash
# Copy model to Android assets
cp backend/phishing_model.tflite app/src/main/assets/phishing_model.tflite

# Then build and run in Android Studio
```

**Option C: Web Simulator**
- Open: http://localhost:8000/test_tflite_web.html
- Uses same feature extraction as the real model
- No model file needed (simulation)

## Test URLs

### Safe URLs:
- `https://www.google.com`
- `https://www.github.com`
- `https://www.stackoverflow.com`

### Phishing URLs:
- `http://google.com-verify.tk`
- `https://paypal-suspend.ml/login`
- `http://192.168.1.1/login`
- `https://secure-bank-update.tk/verify`

## Model Details

- **Input**: 26 features (FloatArray)
- **Output**: Phishing probability (0.0 to 1.0)
- **Format**: TensorFlow Lite (.tflite)
- **Size**: ~50-100 KB
- **Platform**: Android (on-device)

## Troubleshooting

**Model not found?**
```bash
cd backend
python convert_to_tflite.py
```

**TensorFlow not installed?**
```bash
pip install tensorflow
```

**Want to test without generating model?**
- Use the web simulator: http://localhost:8000/test_tflite_web.html
- It uses the same feature extraction logic
