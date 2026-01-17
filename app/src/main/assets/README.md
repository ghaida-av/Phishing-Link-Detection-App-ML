# TensorFlow Lite Model

Place the `phishing_model.tflite` file here.

## How to generate the model:

1. Navigate to the `backend` directory
2. Install dependencies: `pip install -r requirements.txt`
3. Run the conversion script: `python convert_to_tflite.py`
4. Copy the generated `phishing_model.tflite` to this directory: `app/src/main/assets/`

The model will be automatically loaded when the app starts.
