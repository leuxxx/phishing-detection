# train.py
import os
import re
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from urllib.parse import urlparse, parse_qs
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ================================
# Custom Balanced Loss Function
# ================================
def balanced_phishing_loss(y_true, y_pred):
    standard_loss = tf.keras.losses.binary_crossentropy(y_true, y_pred)
    y_true = tf.cast(y_true, tf.float32)
    y_pred = tf.cast(y_pred, tf.float32)

    fn_mask = tf.cast(tf.equal(y_true, 0) & tf.greater_equal(y_pred, 0.5), tf.float32)
    fn_penalty = tf.reduce_mean(fn_mask) * 6.0  # penalize missed phishing

    fp_mask = tf.cast(tf.equal(y_true, 1) & tf.less(y_pred, 0.5), tf.float32)
    fp_penalty = tf.reduce_mean(fp_mask) * 4.0  # penalize false alarms

    return standard_loss + fn_penalty + fp_penalty

# ================================
# Helper: Repair / Compute Features from URL if missing
# ================================
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "lc.chat", "shorturl.at"
}

SPECIAL_CHAR_RE = re.compile(r"[^A-Za-z0-9]")

def compute_features_from_url(url):
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    path = parsed.path or ""
    query = parsed.query or ""
    domain = parsed.netloc or parsed.path  # fallback

    url_length = len(url)
    num_subdirs = path.count("/")  # trailing slash counts too
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_equals = url.count("=")
    num_questionmarks = url.count("?")
    num_ampersands = url.count("&")
    num_percents = url.count("%")
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
    has_https = 1 if parsed.scheme == "https" else 0
    path_length = len(path)
    query_length = len(query)
    is_shortened = 1 if any(s in domain.lower() for s in SHORTENER_DOMAINS) else 0
    num_special_chars = len(SPECIAL_CHAR_RE.findall(url))
    suspicious_words = int(bool(re.search(r"(login|verify|secure|update|account|bank|payment)", url, re.I)))

    tld = domain.split(".")[-1] if "." in domain else ""
    risky_tlds = {"ru", "tk", "cn", "ga", "cf", "ml", "gq"}
    tld_risk = "high" if tld in risky_tlds else "low"

    return {
        "url_length": url_length,
        "num_subdirs": num_subdirs,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_equals": num_equals,
        "num_questionmarks": num_questionmarks,
        "num_ampersands": num_ampersands,
        "num_percents": num_percents,
        "has_ip": has_ip,
        "suspicious_words": suspicious_words,
        "has_https": has_https,
        "path_length": path_length,
        "query_length": query_length,
        "is_shortened": is_shortened,
        "num_special_chars": num_special_chars,
        "tld_risk": tld_risk
    }

# ================================
# Load Dataset (no label expected)
# ================================
DATASET = "phishing_dataset_large.csv"  # change as required
if not os.path.exists(DATASET):
    raise FileNotFoundError(f"Dataset not found: {DATASET}")

df = pd.read_csv(DATASET)
print(f"Loaded dataset: {DATASET} ({len(df)} rows)")

# Drop timestamp or other obvious columns if present
for c in ["timestamp", "time", "label"]:
    if c in df.columns:
        print(f"Removing column from input processing: {c}")
        df = df.drop(columns=[c])

# Ensure url column exists
if "url" not in df.columns:
    raise ValueError("Dataset must contain an 'url' column")

# ================================
# Desired feature columns (based on your dataset structure)
# ================================
feature_columns = [
    "url_length",
    "num_subdirs",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_equals",
    "num_questionmarks",
    "num_ampersands",
    "num_percents",
    "has_ip",
    "suspicious_words",
    "has_https",
    "path_length",
    "query_length",
    "is_shortened",
    "num_special_chars",
    "tld_risk"
]

# If features already exist in CSV, keep; otherwise compute them from url
computed_rows = []
missing_feature_flag = False
for i, row in df.iterrows():
    # If at least one feature missing, compute full set
    row_features_exist = all(col in df.columns for col in feature_columns)
    if row_features_exist:
        # extract row features dict directly
        row_dict = {col: row.get(col) for col in feature_columns}
    else:
        missing_feature_flag = True
        computed = compute_features_from_url(row["url"])
        row_dict = computed
    computed_rows.append(row_dict)

if missing_feature_flag:
    print("Some feature columns were missing in CSV — computed features from URL for all rows.")

X = pd.DataFrame(computed_rows)

# Encode tld_risk if present as string
if "tld_risk" in X.columns and X["tld_risk"].dtype == object:
    mapping = {"low": 0, "high": 1}
    X["tld_risk"] = X["tld_risk"].map(mapping).fillna(0).astype(int)

# Remove any rows with missing values in feature matrix
initial_len = len(X)
X = X.dropna()
if len(X) != initial_len:
    print(f"Dropped {initial_len - len(X)} rows with missing feature values")

# ================================
# Since dataset is phishing-only (no labels), create dummy target (all phishing)
# 0 = phishing (keeps compatibility with previous code/loss)
# ================================
y = np.zeros(len(X), dtype=int)

print(f"Prepared feature matrix X: {X.shape}, target vector y: {y.shape}")

# ================================
# Feature Engineering for Phishing Patterns
# ================================
def enhance_phishing_features(X):
    X_en = X.copy()
    # complexity: combine counts likely indicative of phishing
    X_en["complexity_score"] = (
        X_en["num_special_chars"].fillna(0) +
        X_en["num_subdirs"].fillna(0) +
        X_en["num_questionmarks"].fillna(0) +
        X_en["num_ampersands"].fillna(0) +
        X_en["num_dots"].fillna(0)
    )
    # suspicious density
    X_en["suspicious_density"] = (X_en["suspicious_words"].fillna(0) / X_en["url_length"].replace(0, 1)).fillna(0)
    # query/path ratio
    X_en["query_path_ratio"] = (X_en["query_length"].fillna(0) / (X_en["path_length"].replace(0, 1))).fillna(0)
    # special char density
    X_en["special_char_density"] = (X_en["num_special_chars"].fillna(0) / X_en["url_length"].replace(0, 1)).fillna(0)
    return X_en

X_enh = enhance_phishing_features(X)
enhanced_features = ["complexity_score", "suspicious_density", "query_path_ratio", "special_char_density"]
all_feature_cols = list(X_enh.columns) + [f for f in enhanced_features if f not in X_enh.columns]
# ensure order: base selected features + enhanced
ordered_feature_list = [c for c in feature_columns if c in X_enh.columns] + enhanced_features

print(f"Using feature set ({len(ordered_feature_list)}): {ordered_feature_list}")

# ================================
# Train / Test split (validation only; no true negatives in dataset)
# ================================
X_train, X_test, y_train, y_test = train_test_split(
    X_enh[ordered_feature_list], y, test_size=0.2, random_state=42
)

# ================================
# Scale features
# ================================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ================================
# Model Definition (same architecture as before)
# ================================
model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(X_train_scaled.shape[1],)),
    tf.keras.layers.Dense(256, activation="relu"),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.Dropout(0.5),

    tf.keras.layers.Dense(128, activation="relu"),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.Dropout(0.4),

    tf.keras.layers.Dense(64, activation="relu"),
    tf.keras.layers.BatchNormalization(),
    tf.keras.layers.Dropout(0.3),

    tf.keras.layers.Dense(32, activation="relu"),
    tf.keras.layers.Dropout(0.2),

    tf.keras.layers.Dense(1, activation="sigmoid")
])

model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
    loss=balanced_phishing_loss,
    metrics=["accuracy"]
)

# ================================
# Training
# ================================
print("\nStarting training...")
callbacks = [
    tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
    tf.keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6)
]

history = model.fit(
    X_train_scaled, y_train,
    validation_split=0.1,
    epochs=50,
    batch_size=512,
    verbose=1,
    callbacks=callbacks
)

# ================================
# Save artifacts
# ================================
model.save("phishing_detector_optimized.h5")
joblib.dump(scaler, "scaler.pkl")
joblib.dump({
    "feature_names": ordered_feature_list,
    "original_features": feature_columns,
    "enhanced_features": enhanced_features
}, "feature_info.pkl")
best_threshold = 0.25
np.save("optimal_threshold.npy", np.array(best_threshold))

print("✅ Model, scaler, feature info, and threshold saved.")

# ================================
# Quick evaluation (note: y_test are dummy zeros)
# ================================
y_probs = model.predict(X_test_scaled).ravel()
y_pred = (y_probs >= best_threshold).astype(int)

detection_rate = y_pred.mean()
print(f"\nDetection rate on validation (phishing-only): {detection_rate:.3f} ({detection_rate * 100:.1f}%)")
