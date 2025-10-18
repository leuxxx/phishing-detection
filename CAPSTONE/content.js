// content.js - UPDATED with enhanced features to match training and whitelist integration
console.log('[PhishingProtection] content script loaded');

let tfModel = null;
let metadata = null;
let optimalThreshold = 0.25;

// Add whitelist checking function
async function isUrlWhitelisted(url) {
  try {
    const response = await chrome.runtime.sendMessage({ 
      action: "isWhitelisted", 
      url: url 
    });
    return response?.whitelisted || false;
  } catch (error) {
    console.error("[Content] Whitelist check failed:", error);
    return false;
  }
}

async function loadModel() {
  if (!tfModel) {
    try {
      tfModel = await tf.loadLayersModel(
        chrome.runtime.getURL("tfjs_phishing_model_optimized/model.json")
      );
      const resp = await fetch(
        chrome.runtime.getURL("tfjs_phishing_model_optimized/metadata.json")
      );
      metadata = await resp.json();
      optimalThreshold = metadata.optimal_threshold ?? 0.25; // Use your trained threshold
      console.log('[PhishingProtection] Model loaded, threshold:', optimalThreshold);
      console.log('[PhishingProtection] Features expected:', metadata.feature_names);
    } catch (err) {
      console.error('[PhishingProtection] Model load failed:', err);
      throw err;
    }
  }
  return tfModel;
}

// UPDATED: Match features from your train.py with enhanced features
function extractFeatures(url) {
  let domain, pathname, search;
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
    pathname = urlObj.pathname;
    search = urlObj.search;
  } catch { 
    domain = url.split("/")[0];
    pathname = url.split("/").slice(1).join("/");
    search = '';
  }

  // Basic features
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
  
  const suspiciousKeywords = ["login","verify","secure","update","account","bank","payment","signin","password","confirm","authenticate","validation","wallet","credential","oauth","authorize","admin","portal","access","security"];
  const suspicious_words = suspiciousKeywords.filter(w => url.toLowerCase().includes(w)).length;
  
  const has_https = url.toLowerCase().startsWith('https://') ? 1 : 0;
  
  const path_length = pathname.length;
  const query_length = search.length;
  const is_shortened = /(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bitly|shorte)/i.test(url) ? 1 : 0;
  const num_special_chars = (url.match(/[^a-zA-Z0-9\.\/:-]/g) || []).length;

  const tld = domain.split(".").slice(-1)[0] || "";
  const risky_tlds = ["ru","tk","cn","ga","cf","ml","gq","xyz","top","club","site","online"];
  const tld_risk = risky_tlds.includes(tld) ? 1 : 0;

  // Enhanced features (matching train.py)
  const complexity_score = num_special_chars + num_subdirs + num_questionmarks + num_ampersands;
  const suspicious_density = suspicious_words / Math.max(url_length, 1);
  const query_path_ratio = query_length / Math.max(path_length, 1);
  const special_char_density = num_special_chars / Math.max(url_length, 1);

  return {
    // Original features
    url_length, num_subdirs, num_dots, num_hyphens,
    num_underscores, num_equals, num_questionmarks, num_ampersands, num_percents,
    has_ip, suspicious_words, has_https, path_length, query_length,
    is_shortened, num_special_chars, tld_risk,
    
    // Enhanced features
    complexity_score, suspicious_density, query_path_ratio, special_char_density
  };
}

function makeInputVector(feats) {
  return metadata.feature_names.map((name, i) => {
    const val = feats[name] ?? 0;
    const mean = metadata.scaler_mean[i] ?? 0;
    const scale = metadata.scaler_scale[i] || 1;
    return (val - mean) / scale;
  });
}

async function runAIPrediction(url) {
  try {
    await loadModel();
    const feats = extractFeatures(url);
    console.log('[PhishingProtection] Extracted features:', feats);
    
    const vec = makeInputVector(feats);
    const input = tf.tensor2d([vec]);
    let pred = tfModel.predict(input);
    if (Array.isArray(pred)) pred = pred[0];
    const prob = (await pred.data())[0];
    input.dispose();
    if (pred.dispose) pred.dispose();

    console.log(`[PhishingProtection] AI phishing probability: ${prob}, threshold: ${optimalThreshold}`);

    // Model predicts probability of being PHISHING (since trained on phishing-only data)
    // Higher probability = more like known phishing patterns
    if (prob >= optimalThreshold) {
      return { 
        status: "phishing", 
        classification: `AI: Phishing (${(prob * 100).toFixed(1)}% match to known patterns)`,
        probability: prob 
      };
    } else {
      return { 
        status: "unknown", 
        classification: `AI: Unknown (${(prob * 100).toFixed(1)}% match to known patterns)`,
        probability: prob 
      };
    }
  } catch (err) {
    console.error("[PhishingProtection] AI prediction error:", err);
    return { status: "warn", classification: "AI Error" };
  }
}

// Listeners (updated with whitelist check)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "runAIPrediction") {
    // First check if URL is whitelisted
    isUrlWhitelisted(msg.url).then(whitelisted => {
      if (whitelisted) {
        console.log(`[Content] Skipping AI prediction for whitelisted domain: ${msg.url}`);
        sendResponse({ 
          status: "safe", 
          classification: "Whitelisted: Trusted domain",
          whitelisted: true 
        });
      } else {
        runAIPrediction(msg.url).then(sendResponse).catch(() => {
          sendResponse({ status: "warn", classification: "AI Error" });
        });
      }
    });
    return true;
  }

  if (msg.type === "TRIGGER_BLOCK" && msg.blockedUrl) {
    console.log("[PhishingProtection] Redirecting to:", msg.blockedUrl);
    window.location.href = msg.blockedUrl;
  }

  return true;
});