// sandbox.js — ULTRA-FAST AI for real-time blocking

// Messaging helpers
function postHandshake() {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: "SANDBOX_HANDSHAKE", ready: true });
    } else {
      parent.postMessage({ type: "SANDBOX_HANDSHAKE", ready: true }, "*");
    }
    console.log("[Sandbox] Posted SANDBOX_HANDSHAKE");
  } catch (e) {
    console.log("[Sandbox] postHandshake failed:", e);
  }
}

function postResult(result) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: "AI_PREDICTION_RESULT", result });
    } else {
      parent.postMessage({ type: "AI_PREDICTION_RESULT", result }, "*");
    }
    console.log("[Sandbox] Posted AI_PREDICTION_RESULT", result);
  } catch (e) {
    console.log("[Sandbox] postResult failed:", e);
  }
}

// Default model paths (fallback)
const DEFAULT_MODEL_DIR = "tfjs_phishing_model_optimized";
let MODEL_URL = `${DEFAULT_MODEL_DIR}/model.json`;
let META_URL = `${DEFAULT_MODEL_DIR}/metadata.json`;

let model = null;
let metadata = null;
let modelLoaded = false;

// Load model helper
async function loadModelFromUrls(modelUrl, metaUrl) {
  try {
    console.log("[Sandbox] Loading metadata from:", metaUrl);
    metadata = await fetch(metaUrl).then((r) => r.json());
  } catch (e) {
    console.error("[Sandbox] Failed to load metadata:", e);
    metadata = null;
  }

  try {
    console.log("[Sandbox] Loading TF model from:", modelUrl);
    model = await tf.loadLayersModel(modelUrl);
    modelLoaded = true;
    const threshold = metadata?.optimal_threshold ?? 0.25;
    console.log("[Sandbox] Model loaded successfully, threshold:", threshold);
    console.log("[Sandbox] Features expected:", metadata?.feature_names || "unknown");
    postHandshake();
  } catch (e) {
    modelLoaded = false;
    console.error("[Sandbox] Model load failed:", e);
  }
}

// Initial attempt to load using default urls
(async function tryInitialLoad() {
  // Wait until tf is available with shorter intervals
  const waitForTF = async (tries = 30) => {
    for (let i = 0; i < tries; i++) {
      if (typeof tf !== "undefined" && tf && tf.loadLayersModel) return true;
      await new Promise(r => setTimeout(r, 100));
    }
    return false;
  };

  const ok = await waitForTF();
  if (!ok) {
    console.error("[Sandbox] tf not found in sandbox iframe.");
    return;
  }
  
  console.log("[Sandbox] TF.js loaded, loading model for real-time detection...");
  await loadModelFromUrls(MODEL_URL, META_URL);
})();

// Suspicious keyword list for feature extraction
const suspiciousKeywords = [
  "login", "verify", "secure", "update", "account", "bank", "payment",
  "signin", "password", "confirm", "authenticate", "validation", "wallet",
  "credential", "oauth", "authorize", "admin", "portal", "access", "security"
];

function extractFeatures(url) {
  let domain = "", pathname = "", search = "";
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
    pathname = urlObj.pathname;
    search = urlObj.search;
  } catch {
    const parts = url.split('/');
    domain = parts[0] || "";
    pathname = '/' + parts.slice(1).join('/');
    search = "";
  }
  const url_length = url.length;
  const num_subdirs = (pathname.match(/\//g) || []).length;
  const num_dots = (url.match(/\./g) || []).length;
  const num_hyphens = (url.match(/-/g) || []).length;
  const num_underscores = (url.match(/_/g) || []).length;
  const num_equals = (url.match(/=/g) || []).length;
  const num_questionmarks = (url.match(/\?/g) || []).length;
  const num_ampersands = (url.match(/&/g) || []).length;
  const num_percents = (url.match(/%/g) || []).length;
  const has_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0;
  const suspicious_words = suspiciousKeywords.filter((w) => url.toLowerCase().includes(w)).length;
  const has_https = url.toLowerCase().startsWith("https://") ? 1 : 0;
  const path_length = pathname.length;
  const query_length = search.length;
  const is_shortened = /(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bitly|shorte)/i.test(url) ? 1 : 0;
  const num_special_chars = (url.match(/[^a-zA-Z0-9\.\/:-]/g) || []).length;
  const tld = (domain.split(".").slice(-1)[0] || "").toLowerCase();
  const risky_tlds = ["ru", "tk", "cn", "ga", "cf", "ml", "gq", "xyz", "top", "club", "site", "online"];
  const tld_risk = risky_tlds.includes(tld) ? 1 : 0;
  const complexity_score = num_special_chars + num_subdirs + num_questionmarks + num_ampersands + num_dots;
  const suspicious_density = suspicious_words / Math.max(url_length, 1);
  const query_path_ratio = query_length / Math.max(path_length, 1);
  const special_char_density = num_special_chars / Math.max(url_length, 1);

  return {
    url_length, num_subdirs, num_dots, num_hyphens, num_underscores,
    num_equals, num_questionmarks, num_ampersands, num_percents, has_ip,
    suspicious_words, has_https, path_length, query_length, is_shortened,
    num_special_chars, tld_risk, complexity_score, suspicious_density,
    query_path_ratio, special_char_density
  };
}

function makeInputVector(feats) {
  const featureNames = metadata?.feature_names || Object.keys(feats);
  const scalerMean = metadata?.scaler_mean || new Array(featureNames.length).fill(0);
  const scalerScale = metadata?.scaler_scale || new Array(featureNames.length).fill(1);

  return featureNames.map((name, i) => {
    const val = feats[name] ?? 0;
    const mean = scalerMean[i] ?? 0;
    const scale = scalerScale[i] || 1;
    return (val - mean) / scale;
  });
}

// ULTRA-FAST PREDICTION for real-time blocking
async function runInstantPrediction(url, originalUrl) {
  try {
    if (!modelLoaded || !model || !metadata) {
      return {
        status: "safe", // Fail-safe: assume safe if model not ready
        classification: "AI: Model not ready",
        probability: 0.0,
        originalUrl: originalUrl || url,
      };
    }

    const threshold = metadata.optimal_threshold ?? 0.25;
    const feats = extractFeatures(url);
    const vec = makeInputVector(feats);

    const inputTensor = tf.tensor2d([vec]);
    let pred = model.predict(inputTensor);
    if (Array.isArray(pred)) pred = pred[0];
    const probArr = await pred.data();
    const probability = probArr[0];
    
    // Immediate cleanup
    inputTensor.dispose();
    if (pred.dispose) pred.dispose();

    // Ultra-fast classification
    let status, classification;
    if (probability >= threshold) {
      status = "phishing";
      classification = `AI: Phishing (${((probability) * 100).toFixed(1)}% confidence)`;
    } else {
      status = "safe"; 
      classification = `AI: Safe (${((1 - probability) * 100).toFixed(1)}% confidence)`;
    }

    return { status, classification, probability, threshold, originalUrl: originalUrl || url };

  } catch (err) {
    console.error("[Sandbox] Instant prediction failed:", err);
    return {
      status: "safe", // Fail-safe
      classification: "AI: Error - assuming safe",
      probability: 0.0,
      originalUrl: originalUrl || url,
    };
  }
}

// Original prediction function (for popup)
async function runPrediction(url, originalUrl) {
  try {
    if (!modelLoaded || !model || !metadata) {
      console.warn("[Sandbox] Prediction requested but model not ready.");
      postResult({
        status: "warn",
        classification: "AI Error: Model not loaded",
        probability: 0.0,
        threshold: metadata?.optimal_threshold ?? 0.25,
        originalUrl: originalUrl || url,
      });
      return;
    }

    const threshold = metadata.optimal_threshold ?? 0.25;
    const feats = extractFeatures(url);
    console.log("[Sandbox] EXTRACTED FEATURES:", feats);
    const vec = makeInputVector(feats);
    console.log("[Sandbox] SCALED VECTOR:", vec);

    const inputTensor = tf.tensor2d([vec]);
    let pred = model.predict(inputTensor);
    if (Array.isArray(pred)) pred = pred[0];
    const probArr = await pred.data();
    const probability = probArr[0];
    inputTensor.dispose();
    if (pred.dispose) pred.dispose();

    let status, classification;
    if (probability <= threshold) {
      status = "phishing_pattern";
      classification = `AI: Phishing pattern detected (${((1 - probability) * 100).toFixed(2)}% similarity)`;
    } else if (probability > threshold && probability <= 0.75) {
      status = "unknown";
      classification = `AI: Unfamiliar pattern (${(probability * 100).toFixed(2)}% confidence safe)`;
    } else {
      status = "safe";
      classification = `AI: Likely safe (${(probability * 100).toFixed(2)}% confidence)`;
    }

    postResult({
      status,
      classification,
      probability,
      threshold,
      originalUrl: originalUrl || url,
    });
  } catch (err) {
    console.error("[Sandbox] Prediction failed:", err);
    postResult({
      status: "warn",
      classification: "AI Error: Prediction failed",
      probability: 0.0,
      threshold: metadata?.optimal_threshold ?? 0.25,
      originalUrl: originalUrl || url,
    });
  }
}

// Listen for messages from popup (sandbox config + run requests)
window.addEventListener("message", (event) => {
  const msg = event.data;
  if (!msg || !msg.type) return;

  if (msg.type === "SANDBOX_CONFIG") {
    try {
      if (msg.modelUrl) MODEL_URL = msg.modelUrl;
      if (msg.metaUrl) META_URL = msg.metaUrl;
      console.log("[Sandbox] Received SANDBOX_CONFIG:", { modelUrl: MODEL_URL, metaUrl: META_URL });
      loadModelFromUrls(MODEL_URL, META_URL);
    } catch (e) {
      console.error("[Sandbox] SANDBOX_CONFIG handling failed:", e);
    }
    return;
  }

  if (msg.type === "SANDBOX_HELLO") {
    if (modelLoaded) postHandshake();
    return;
  }

  if (msg.type === "RUN_AI_PREDICTION" && typeof msg.url === "string") {
    console.log("[Sandbox] AI prediction requested:", msg.url);
    
    // Instant mode - for real-time blocking
    if (msg.instant) {
      runInstantPrediction(msg.url, msg.originalUrl).then(postResult);
    } 
    // Preload request
    else if (msg.action === 'preloadAIModel') {
      if (modelLoaded) {
        postResult({ ready: true });
      } else {
        loadModelFromUrls(MODEL_URL, META_URL).then(() => {
          postResult({ ready: modelLoaded });
        });
      }
    }
    // Regular mode (for popup)
    else {
      runPrediction(msg.url, msg.originalUrl);
    }
    return;
  }
});

console.log("[Sandbox] Ready to receive messages");