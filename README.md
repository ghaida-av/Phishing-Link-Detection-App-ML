# Phishing Link Detection App - ML Edition

A simple Android app that detects phishing URLs using **on-device machine learning** with TensorFlow Lite.

## ✨ Features

- **On-Device ML**: Uses TensorFlow Lite for fast, offline detection
- **No Backend Required**: Works completely offline
- **Real ML Model**: Neural network trained on phishing patterns
- **Simple UI**: Clean, easy-to-use interface
- **Fast**: Instant predictions without network latency
- **Private**: URLs never leave your device

## 🚀 Quick Start

### 1. Generate ML Model

```bash
cd backend
pip install -r requirements.txt
python convert_to_tflite.py
```

### 2. Copy Model to App

```bash
cp backend/phishing_model.tflite app/src/main/assets/phishing_model.tflite
```

### 3. Build & Run

1. Open project in Android Studio
2. Build and run on device/emulator
3. Enter a URL and check if it's safe!

## 📱 Android App

### Architecture

- **FeatureExtractor.kt**: Extracts 26 features from URLs
- **PhishingDetector.kt**: Loads TensorFlow Lite model and runs inference
- **MainActivity.kt**: Simple UI for URL checking

### How It Works

The app uses a neural network that analyzes:
- URL structure (length, special characters)
- Protocol information (HTTP/HTTPS)
- Suspicious keywords (login, verify, bank, etc.)
- Domain characteristics (TLD, subdomains, IP addresses)
- Path and query parameters
- Character ratios (digits, letters)

### Model Details

- **Type**: TensorFlow Lite Neural Network
- **Input**: 26 features (FloatArray)
- **Output**: Phishing probability (0.0 to 1.0)
- **Size**: ~50-100 KB (optimized)
- **Accuracy**: Trained on common phishing patterns

## 🛠️ Development

### Dependencies

- TensorFlow Lite 2.14.0
- Kotlin Coroutines
- AndroidX libraries

### Project Structure

```
app/
├── src/main/
│   ├── java/com/example/phishinglinkdetector/
│   │   ├── MainActivity.kt          # Main UI
│   │   ├── PhishingDetector.kt      # ML model wrapper
│   │   └── FeatureExtractor.kt      # Feature extraction
│   └── assets/
│       └── phishing_model.tflite    # ML model (generate first)
backend/
├── ml_model.py                       # Original scikit-learn model
├── convert_to_tflite.py              # Convert to TensorFlow Lite
└── requirements.txt                  # Python dependencies
```

## 📝 Notes

- The model is trained on synthetic data with common phishing patterns
- For production, train on a larger, real-world dataset
- The app works offline - no internet connection needed
- All processing happens on-device for privacy

## 🔧 Troubleshooting

**Model not loading?**
- Check that `phishing_model.tflite` exists in `app/src/main/assets/`
- Check logcat for error messages
- Ensure TensorFlow Lite dependency is in `build.gradle.kts`

**Build errors?**
- Sync Gradle files in Android Studio
- Ensure all dependencies are downloaded
- Check that minSdk is 24 or higher

## 📄 License

See LICENSE file for details.