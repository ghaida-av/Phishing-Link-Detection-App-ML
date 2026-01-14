# Backend Setup Guide

## Features Implemented

✅ **Real ML Model**: Uses scikit-learn RandomForestClassifier with comprehensive feature extraction
✅ **Live Database**: SQLite database to store URLs/emails and detection results
✅ **URL/Email Detection**: Automatically differentiates between URLs and email addresses

## Installation

1. **Navigate to backend directory**:
```bash
cd backend
```

2. **Create virtual environment** (if not already created):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## Running the Server

```bash
python app.py
```

The server will start on `http://0.0.0.0:5001`

## API Endpoints

### POST `/predict`
Main prediction endpoint

**Request**:
```json
{
  "url": "https://www.example.com"
}
```

**Response**:
```json
{
  "verdict": "SAFE" | "PHISHING" | "INVALID",
  "url_type": "url" | "email" | "invalid",
  "confidence": 0.85,
  "from_cache": false,
  "message": "URL analyzed using ML model"
}
```

### GET `/check?url=<url_or_email>`
Quick check endpoint (GET method)

### GET `/stats`
Get database statistics

### GET `/recent?limit=10`
Get recent detection results

### GET `/health`
Health check endpoint

## Testing

Run the test script:
```bash
python test_api.py
```

Make sure the server is running first!

## Database

The SQLite database (`phishing_detector.db`) is automatically created on first run.

**Tables**:
- `urls`: Stores URLs/emails and their detection results

**Features**:
- Automatic caching: Checks database before running ML model
- Statistics tracking
- Recent detections history

## ML Model

The ML model uses:
- **Algorithm**: RandomForestClassifier (100 trees)
- **Features**: 30+ features including:
  - URL length, structure, protocol
  - Suspicious keywords
  - Domain analysis (TLD, IP addresses, subdomains)
  - Path and query string analysis
  - Character ratios

The model is automatically trained on first run and saved as `phishing_model.pkl`.

## URL vs Email Detection

The system automatically detects:
- **URLs**: http/https links, domains, IP addresses
- **Emails**: Standard email format validation
- **Invalid**: Inputs that don't match either pattern

Emails use rule-based detection, URLs use the ML model.

## Configuration

### Android App Connection

For Android emulator, use: `http://10.0.2.2:5001`

For physical device, use your computer's IP address:
```bash
# Find your IP address
# On Mac/Linux:
ifconfig | grep "inet "

# On Windows:
ipconfig
```

Then update `BASE_URL` in `MainActivity.kt`:
```kotlin
private val BASE_URL = "http://YOUR_IP:5001"
```
