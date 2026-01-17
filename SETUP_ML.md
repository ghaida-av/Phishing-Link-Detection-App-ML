# ML Model Setup Guide

This app now uses **TensorFlow Lite** for on-device machine learning - no backend server needed!

## Quick Start

### 1. Generate the TensorFlow Lite Model

```bash
cd backend
pip install -r requirements.txt
python convert_to_tflite.py
```

This will create `phishing_model.tflite` in the backend directory.

### 2. Copy Model to Android App

```bash
# From project root
cp backend/phishing_model.tflite app/src/main/assets/phishing_model.tflite
```

### 3. Build and Run

Open the project in Android Studio and build/run the app. The ML model will be loaded automatically when the app starts.

## How It Works

- **On-Device ML**: All detection happens on your phone using TensorFlow Lite
- **No Internet Required**: Works completely offline
- **Fast**: Instant predictions without network latency
- **Private**: URLs never leave your device

## Features

The model analyzes 26 features from URLs:
- URL structure (length, special characters)
- Protocol information
- Suspicious keywords
- Domain characteristics
- Path and query parameters
- Character ratios

## Architecture

- `FeatureExtractor.kt`: Extracts 26 features from URLs (matches Python logic)
- `PhishingDetector.kt`: Loads TensorFlow Lite model and runs inference
- `MainActivity.kt`: Simple UI that uses on-device ML

## Model Details

- **Type**: Neural Network (TensorFlow Lite)
- **Input**: 26 features (FloatArray)
- **Output**: Probability of phishing (0.0 to 1.0)
- **Size**: ~50-100 KB (optimized)

## Troubleshooting

If the model doesn't load:
1. Check that `phishing_model.tflite` exists in `app/src/main/assets/`
2. Check logcat for error messages
3. Ensure TensorFlow Lite dependency is added in `build.gradle.kts`
