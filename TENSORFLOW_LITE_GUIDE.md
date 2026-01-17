# 🔗 How TensorFlow Lite is Integrated

## Overview

This app uses **TensorFlow Lite** for on-device machine learning. All ML inference happens directly on your Android device - no internet or backend server needed!

## 📦 How TensorFlow Lite Was Linked

### 1. **Gradle Dependency** (`gradle/libs.versions.toml`)

```toml
[versions]
tensorflowlite = "2.14.0"

[libraries]
tensorflow-lite = { group = "org.tensorflow", name = "tensorflow-lite", version.ref = "tensorflowlite" }
```

### 2. **App Build Configuration** (`app/build.gradle.kts`)

```kotlin
dependencies {
    // ... other dependencies
    implementation(libs.tensorflow.lite)  // ← TensorFlow Lite added here
}
```

### 3. **Model Loading** (`PhishingDetector.kt`)

The model is loaded from Android assets:

```kotlin
class PhishingDetector(private val context: Context) {
    private var interpreter: Interpreter? = null
    private val modelPath = "phishing_model.tflite"
    
    suspend fun initialize(): Boolean {
        val modelBuffer = loadModelFile()  // Load from assets/
        interpreter = Interpreter(modelBuffer)
        return true
    }
}
```

### 4. **Feature Extraction** (`FeatureExtractor.kt`)

Extracts 26 features from URLs (matches Python model):

```kotlin
object FeatureExtractor {
    fun extractFeatures(url: String): FloatArray {
        // Extracts 26 features:
        // - URL length, special characters
        // - Protocol info (HTTP/HTTPS)
        // - Suspicious keywords
        // - Domain characteristics
        // - Path and query parameters
        // - Character ratios
    }
}
```

### 5. **Inference** (`PhishingDetector.kt`)

Runs ML model prediction:

```kotlin
fun predict(url: String): Pair<Boolean, Float> {
    val features = FeatureExtractor.extractFeatures(url)
    val inputBuffer = Array(1) { features }
    val outputBuffer = Array(1) { FloatArray(1) }
    
    interpreter.run(inputBuffer, outputBuffer)  // ← TensorFlow Lite inference
    
    val phishingProbability = outputBuffer[0][0]
    return Pair(phishingProbability > 0.5f, confidence)
}
```

## 🏗️ Architecture Flow

```
User Input (URL)
    ↓
FeatureExtractor.kt (Extract 26 features)
    ↓
PhishingDetector.kt (Load TFLite model)
    ↓
TensorFlow Lite Interpreter (Run inference)
    ↓
Result (Phishing/Safe + Confidence)
```

## 📁 File Structure

```
app/
├── build.gradle.kts                    # TensorFlow Lite dependency
├── src/main/
│   ├── assets/
│   │   └── phishing_model.tflite       # ML model file (generate first)
│   └── java/.../phishinglinkdetector/
│       ├── MainActivity.kt             # UI - uses PhishingDetector
│       ├── PhishingDetector.kt         # TensorFlow Lite wrapper
│       └── FeatureExtractor.kt         # Feature extraction
backend/
├── convert_to_tflite.py                # Converts model to TFLite
└── test_tflite.py                      # Test script
```

## 🧪 How to Test

### Option 1: Android App (Full Test)

1. **Generate the model:**
   ```bash
   cd backend
   pip install -r requirements.txt
   python convert_to_tflite.py
   ```

2. **Copy model to app:**
   ```bash
   cp backend/phishing_model.tflite app/src/main/assets/phishing_model.tflite
   ```

3. **Build and run in Android Studio:**
   - Open project in Android Studio
   - Build → Run
   - Enter URL and test!

### Option 2: Python Test Script

```bash
cd backend
python test_tflite.py                    # Test with sample URLs
python test_tflite.py "https://example.com"  # Test custom URL
```

### Option 3: Web Simulator

Open in browser:
- http://localhost:8000/test_tflite_web.html
- Uses same feature extraction (simulation)

## 🔍 Key Components Explained

### TensorFlow Lite Interpreter

The `Interpreter` class is the core of TensorFlow Lite:

```kotlin
val interpreter = Interpreter(modelBuffer)
interpreter.run(inputBuffer, outputBuffer)
```

- **Input**: 26 features (FloatArray)
- **Output**: Phishing probability (0.0 to 1.0)
- **Model**: Neural network (64→32→1 neurons)

### Model File Location

The `.tflite` model must be in:
```
app/src/main/assets/phishing_model.tflite
```

Android automatically includes files from `assets/` in the APK.

### Feature Extraction

The 26 features match exactly what the Python model expects:
- Basic URL stats (length, dots, slashes, etc.)
- Protocol detection
- Suspicious keyword count
- Domain analysis (TLD, IP, subdomains)
- Path and query parameters
- Character ratios

## 📊 Model Details

- **Format**: TensorFlow Lite (.tflite)
- **Size**: ~50-100 KB (optimized)
- **Input**: 26 float features
- **Output**: 1 float (phishing probability)
- **Architecture**: Dense(64) → Dropout → Dense(32) → Dropout → Dense(1)
- **Activation**: Sigmoid (outputs 0-1 probability)

## ✅ Benefits of TensorFlow Lite

1. **Offline**: Works without internet
2. **Fast**: Instant predictions
3. **Private**: URLs never leave device
4. **Small**: Model is only ~100 KB
5. **Efficient**: Optimized for mobile devices

## 🔧 Troubleshooting

**Model not loading?**
- Check `app/src/main/assets/phishing_model.tflite` exists
- Check logcat for errors
- Verify TensorFlow Lite dependency in `build.gradle.kts`

**Build errors?**
- Sync Gradle files
- Ensure minSdk is 24+
- Check TensorFlow Lite version compatibility

**Want to test without model?**
- Use web simulator: http://localhost:8000/test_tflite_web.html
- Uses same feature extraction logic
