# convert.py (formerly convert_model.py)
import os
import json
import numpy as np
import joblib
import tensorflow as tf
import tensorflowjs as tfjs

def balanced_phishing_loss(y_true, y_pred):
    standard_loss = tf.keras.losses.binary_crossentropy(y_true, y_pred)
    y_true = tf.cast(y_true, tf.float32)
    y_pred = tf.cast(y_pred, tf.float32)
    fn_mask = tf.cast(tf.equal(y_true, 0) & tf.greater_equal(y_pred, 0.5), tf.float32)
    fn_penalty = tf.reduce_mean(fn_mask) * 6.0
    fp_mask = tf.cast(tf.equal(y_true, 1) & tf.less(y_pred, 0.5), tf.float32)
    fp_penalty = tf.reduce_mean(fp_mask) * 4.0
    return standard_loss + fn_penalty + fp_penalty

def load_optimal_threshold(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Threshold file not found: {path}")
    val = np.load(path, allow_pickle=True)
    # handle scalar and arrays robustly
    if isinstance(val, np.ndarray):
        if val.shape == ():
            scalar = float(val.item())
        else:
            scalar = float(val.ravel()[0])
    else:
        scalar = float(val)
    if not (0.0 <= scalar <= 1.0):
        raise ValueError(f"Loaded optimal_threshold is outside [0,1]: {scalar}")
    return scalar

def convert_model():
    model_path = "phishing_detector_optimized.h5"
    threshold_path = "optimal_threshold.npy"
    scaler_path = "scaler.pkl"
    feature_info_path = "feature_info.pkl"
    output_dir = "tfjs_phishing_model_optimized"

    if not os.path.exists(model_path):
        print(f"Error: Model file '{model_path}' not found.")
        return False

    try:
        print("Loading Keras model (with custom loss)...")
        model = tf.keras.models.load_model(
            model_path,
            custom_objects={"balanced_phishing_loss": balanced_phishing_loss},
            compile=False
        )
    except Exception as e:
        print("Error loading model:", e)
        return False

    try:
        optimal_threshold = load_optimal_threshold(threshold_path)
        print(f"Loaded optimal_threshold = {optimal_threshold}")
    except Exception as e:
        print("Error loading optimal threshold:", e)
        return False

    if not os.path.exists(scaler_path) or not os.path.exists(feature_info_path):
        print("Error: scaler.pkl or feature_info.pkl not found in working directory.")
        return False

    scaler = joblib.load(scaler_path)
    feature_info = joblib.load(feature_info_path)

    os.makedirs(output_dir, exist_ok=True)
    try:
        print("Converting model to TensorFlow.js format...")
        tfjs.converters.save_keras_model(model, output_dir)
    except Exception as e:
        print("Error converting to TFJS:", e)
        return False

    # Build improved metadata for phishing pattern detector
    feature_names = feature_info.get("feature_names", [])
    metadata = {
        "optimal_threshold": float(optimal_threshold),
        "feature_count": scaler.n_features_in_ if hasattr(scaler, "n_features_in_") else len(feature_names),
        "feature_names": feature_names,
        "original_features": feature_info.get("original_features", []),
        "enhanced_features": feature_info.get("enhanced_features", []),
        "scaler_mean": scaler.mean_.tolist() if hasattr(scaler, "mean_") else [],
        "scaler_scale": scaler.scale_.tolist() if hasattr(scaler, "scale_") else [],
        "model_info": {
            "input_shape": getattr(model, "input_shape", None),
            "output_shape": getattr(model, "output_shape", None),
            "layers": len(model.layers) if hasattr(model, "layers") else None,
            "parameters": model.count_params() if hasattr(model, "count_params") else None,
        },
        # Single-class model metadata: model trained on phishing-only data
        "classes": {"phishing": 0},
        "single_class": True,
        "model_type": "phishing_pattern_detector",
        "version": "4.1.0",
        "description": "Phishing pattern detector trained primarily on phishing URLs. Use conservative thresholding and combine with reputation lists for production.",
        "training_notes": "Model trained on phishing-only dataset with pattern-based engineered features (complexity, densities, special char counts).",
        "feature_engineering": {
            "complexity_score": "special_chars + subdirs + questionmarks + ampersands + dots",
            "suspicious_density": "suspicious_words / url_length",
            "query_path_ratio": "query_length / (path_length + 1)",
            "special_char_density": "special_chars / url_length"
        },
        "detection_strategy": "pattern_based",
        "warning": "Model trained primarily on phishing data — expects conservative integration with other signals.",
        "recommended_use": "Use as a pattern-based phishing signal; combine with blacklists, WHOIS, and manual review.",
        "compatibility": "TensorFlow.js compatible"
    }

    meta_path = os.path.join(output_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"✅ Conversion succeeded. TFJS model + metadata written to: {output_dir}/")
    print(f"✅ Features exported: {len(feature_names)}")
    print(f"✅ Optimal threshold: {metadata['optimal_threshold']}")
    return True

if __name__ == "__main__":
    ok = convert_model()
    if ok:
        print("Conversion completed successfully.")
    else:
        print("Conversion failed.")
