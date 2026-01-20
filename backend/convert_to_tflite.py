"""
Convert scikit-learn model to TensorFlow Lite
This script creates a TensorFlow model with the same feature extraction
and converts it to TensorFlow Lite for Android
"""

# This script is intentionally simple: train a small Keras model using the same
# feature extractor/training data, then export to `.tflite` for Android.

try:
    import tensorflow as tf
except ImportError:
    print("TensorFlow not installed. Installing...")
    import subprocess
    subprocess.check_call(["pip", "install", "tensorflow"])
    import tensorflow as tf

from ml_model import PhishingURLDetector

def create_tf_model():
    """Train a small TensorFlow model using the same training data/features."""
    detector = PhishingURLDetector()

    print("Generating training data...")
    X, y = detector.generate_training_data()

    print(f"Training TensorFlow model on {len(X)} samples...")
    print(f"Feature vector size: {X.shape[1]}")

    # A small neural network is enough for this toy dataset.
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(X.shape[1],)),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    model.fit(X, y, epochs=50, batch_size=16, verbose=1, validation_split=0.2)

    _, accuracy = model.evaluate(X, y, verbose=0)
    print(f"Model accuracy: {accuracy:.2%}")

    return model

def convert_to_tflite(model, output_path='phishing_model.tflite'):
    """Convert a Keras model to TensorFlow Lite and save to disk."""
    print("Converting to TensorFlow Lite...")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]

    tflite_model = converter.convert()

    with open(output_path, 'wb') as f:
        f.write(tflite_model)

    print(f"TensorFlow Lite model saved to {output_path}")
    print(f"Model size: {len(tflite_model) / 1024:.2f} KB")

    return output_path

if __name__ == "__main__":
    print("Creating TensorFlow model...")
    model = create_tf_model()
    
    print("\nConverting to TensorFlow Lite...")
    tflite_path = convert_to_tflite(model)
    
    print(f"\n✅ Success! Model saved to: {tflite_path}")
    print("Copy this file to: app/src/main/assets/phishing_model.tflite")
