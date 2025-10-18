if (typeof importScripts === "function") {
  try {
    importScripts("obfuscation.js");
  } catch (e) {
    console.warn("obfuscation.js not loaded via importScripts:", e);
  }
} else {
  // In popup or window context
  if (typeof getDecodedKey === "undefined") {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("obfuscation.js");
    document.head.appendChild(script);
  }
}

// Now safe to use getDecodedKey() regardless of context
const SAFE_BROWSING_API_KEY = typeof getDecodedKey === "function"
  ? getDecodedKey("GOOGLE")
  : "API_KEY_UNAVAILABLE";
  
const SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// Cache to avoid repeated API calls for the same URL
const urlCache = new Map();

async function checkSafeBrowsing(url) {
  // Check cache first
  if (urlCache.has(url)) {
    return urlCache.get(url);
  }

  try {
    const response = await fetch(SAFE_BROWSING_API_URL + `?key=${SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      body: JSON.stringify({
        client: {
          clientId: "phishing-detection-extension",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMful_APPLICATION", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Safe Browsing API error: ${response.status}`);
    }

    const data = await response.json();
    const hasThreats = data.matches && data.matches.length > 0;
    
    // Cache the result for 5 minutes
    urlCache.set(url, hasThreats);
    setTimeout(() => urlCache.delete(url), 5 * 60 * 1000);
    
    return hasThreats;
  } catch (error) {
    console.error('Safe Browsing check failed:', error);
    return false; // Default to safe if API fails
  }
}

// Function to get threat details if available
function getThreatDetails(safeBrowsingData) {
  if (!safeBrowsingData.matches || safeBrowsingData.matches.length === 0) {
    return null;
  }
  
  return safeBrowsingData.matches.map(match => ({
    threatType: match.threatType,
    platformType: match.platformType,
    threatEntryType: match.threatEntryType
  }));
}