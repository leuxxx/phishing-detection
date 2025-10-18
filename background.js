// background.js - ENHANCED WITH FIREBASE & INDEXEDDB
importScripts('obfuscation.js');

const NODE_SERVER_URL = 'https://phishing-detection-1mpi.onrender.com';

// =========================
// FIREBASE CONFIGURATION
// =========================
const firebaseConfig = {
    apiKey: getDecodedKey('FIREBASE_APIKEY'),
    authDomain: "phishing-extension-c3c5e.firebaseapp.com",
    databaseURL: "https://phishing-extension-c3c5e-default-rtdb.firebaseio.com",
    projectId: "phishing-extension-c3c5e",
    storageBucket: "phishing-extension-c3c5e.firebasestorage.app",
    messagingSenderId: "76353005056",
    appId: "1:76353005056:web:c20c136d8a5fba60821ae5",
    measurementId: "G-QJVQYK5BH9"
};

// =========================
// FIREBASE SERVICE
// =========================
const firebaseService = {
    getIdToken: async function() {
        try {
            const response = await fetch(
                `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${firebaseConfig.apiKey}`,
                { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' }, 
                    body: JSON.stringify({ returnSecureToken: true }) 
                }
            );
            if (!response.ok) throw new Error(`Auth error: ${response.status}`);
            const data = await response.json();
            return data.idToken;
        } catch (error) {
            console.log('Failed to get Firebase auth token:', error.message);
            return null;
        }
    },

    logPhishingDetection: async function(data) {
        try {
            const idToken = await this.getIdToken();
            if (!idToken) {
                console.log('No Firebase auth token, skipping log');
                return;
            }

            const detectionData = {
                url: data.url,
                hostname: data.hostname,
                score: data.score,
                timestamp: new Date().toISOString(),
                isPhishing: data.isPhishing || false,
                isSuspicious: data.isSuspicious || false,
                safeBrowsingDetected: data.safeBrowsingDetected || false,
                virusTotalDetected: data.virusTotalDetected || false,
                userAgent: navigator.userAgent,
                extensionVersion: chrome.runtime.getManifest().version,
                aiStatus: data.aiStatus || 'unknown',
                apiResults: data.apiResults || {},
                source: data.source || 'background'
            };

            console.log('[Firebase] Logging detection:', detectionData);

            const response = await fetch(
                `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/phishingDetections`,
                {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json', 
                        'Authorization': `Bearer ${idToken}` 
                    },
                    body: JSON.stringify({
                        fields: {
                            url: { stringValue: detectionData.url },
                            hostname: { stringValue: detectionData.hostname },
                            score: { doubleValue: detectionData.score },
                            isPhishing: { booleanValue: detectionData.isPhishing },
                            isSuspicious: { booleanValue: detectionData.isSuspicious },
                            safeBrowsingDetected: { booleanValue: detectionData.safeBrowsingDetected },
                            virusTotalDetected: { booleanValue: detectionData.virusTotalDetected },
                            timestamp: { timestampValue: detectionData.timestamp },
                            userAgent: { stringValue: detectionData.userAgent },
                            extensionVersion: { stringValue: detectionData.extensionVersion },
                            aiStatus: { stringValue: detectionData.aiStatus },
                            source: { stringValue: detectionData.source }
                        }
                    })
                }
            );

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Firestore error: ${response.status} - ${errorText}`);
            }

            console.log('[Firebase] Successfully logged phishing detection');
            return await response.json();

        } catch (error) {
            console.log('Firebase log failed:', error.message);
        }
    },

    getGlobalStats: async function() {
        try {
            const idToken = await this.getIdToken();
            if (!idToken) return null;

            const response = await fetch(
                `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/(default)/documents/phishingDetections`,
                { headers: { 'Authorization': `Bearer ${idToken}` } }
            );
            
            if (!response.ok) throw new Error(`Stats error: ${response.status}`);
            
            const data = await response.json();
            return { 
                totalGlobalThreats: data.documents ? data.documents.length : 0,
                documents: data.documents || []
            };
        } catch (error) {
            console.log('Firebase stats fetch failed:', error.message);
            return null;
        }
    }
};

// =========================
// INDEXEDDB DATABASE
// =========================
let db = null;

async function initDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("PhishingDefenderDB", 1);
        
        request.onerror = () => {
            console.error('[IndexedDB] Database error:', request.error);
            reject(request.error);
        };
        
        request.onsuccess = () => {
            db = request.result;
            console.log('[IndexedDB] Database initialized');
            resolve(db);
        };
        
        request.onupgradeneeded = (event) => {
            const database = event.target.result;
            if (!database.objectStoreNames.contains('threats')) {
                const store = database.createObjectStore('threats', { keyPath: 'id', autoIncrement: true });
                store.createIndex('timestamp', 'timestamp', { unique: false });
                store.createIndex('url', 'url', { unique: false });
                store.createIndex('status', 'status', { unique: false });
                console.log('[IndexedDB] Database schema created');
            }
        };
    });
}

async function storeThreatData(payload) {
    if (!db) {
        console.log('[IndexedDB] Database not initialized, skipping storage');
        return;
    }

    return new Promise((resolve) => {
        const tx = db.transaction(['threats'], 'readwrite');
        const store = tx.objectStore('threats');
        
        const threatData = {
            url: payload.url,
            timestamp: Date.now(),
            aiResults: payload.aiResults || {},
            apiResults: payload.apiResults || {},
            status: payload.aiResults?.status || 'unknown',
            source: payload.source || 'background',
            probability: payload.aiResults?.probability || 0
        };

        const req = store.add(threatData);
        
        req.onsuccess = () => {
            console.log('[IndexedDB] Threat data stored successfully');
            resolve();
        };
        
        req.onerror = () => {
            console.error('[IndexedDB] Failed to store threat data:', req.error);
            resolve();
        };
    });
}

async function getThreatsCount() {
    if (!db) return 0;
    
    return new Promise((resolve) => {
        const tx = db.transaction(['threats'], 'readonly');
        const store = tx.objectStore('threats');
        const req = store.count();
        
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(0);
    });
}

async function getThreatsThisWeek() {
    if (!db) return [];
    
    return new Promise((resolve) => {
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        const tx = db.transaction(['threats'], 'readonly');
        const store = tx.objectStore('threats');
        const index = store.index('timestamp');
        const range = IDBKeyRange.lowerBound(oneWeekAgo);
        const req = index.getAll(range);
        
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => resolve([]);
    });
}

// =========================
// API CONFIGURATION
// =========================
const API_CONFIG = {
    googleSafeBrowsing: {
        url: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
        apiKey: getDecodedKey('GOOGLE_SAFE_BROWSING_API_KEY'),
        cache: new Map(),
        cacheTimeout: 30 * 60 * 1000 // 30 minutes
    },
    virusTotal: {
        url: 'https://www.virustotal.com/vtapi/v2/url/report',
        apiKey: getDecodedKey('VIRUS_TOTAL_API_KEY'),
        cache: new Map(),
        cacheTimeout: 60 * 60 * 1000 // 60 minutes
    }
};

// =========================
// ENHANCED AI PREDICTION WITH API FALLBACKS
// =========================
async function runAIPrediction(url) {
    // Try Node.js server first
    try {
        console.log(`[AI-Check] Trying Node.js server for: ${url}`);
        const response = await fetch(`${NODE_SERVER_URL}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(3000)
        });

        if (response.ok) {
            const result = await response.json();
            console.log(`[AI-Result-Node] ${result.status} - ${result.classification}`);
            return {
                ...result,
                source: 'node_server',
                timestamp: Date.now()
            };
        }
    } catch (error) {
        console.log('[AI-Server] Node.js server unavailable:', error.message);
    }

    // Fallback: Use extension's sandbox AI
    try {
        console.log(`[AI-Check] Trying extension sandbox AI for: ${url}`);
        const sandboxResult = await new Promise((resolve) => {
            chrome.runtime.sendMessage({
                action: "runAIPrediction",
                url: url,
                instant: true
            }, (response) => {
                if (response && response.status) {
                    resolve(response);
                } else {
                    resolve(null);
                }
            });
            
            // Timeout fallback
            setTimeout(() => resolve(null), 2000);
        });

        if (sandboxResult) {
            console.log(`[AI-Result-Sandbox] ${sandboxResult.status} - ${sandboxResult.classification}`);
            return {
                ...sandboxResult,
                source: 'sandbox_ai',
                timestamp: Date.now()
            };
        }
    } catch (error) {
        console.log('[AI-Sandbox] Sandbox AI failed:', error.message);
    }

    // Final fallback: Use external APIs
    console.log(`[AI-Check] Falling back to external APIs for: ${url}`);
    const apiResults = await checkExternalAPIs(url);
    
    return {
        status: determineStatusFromAPIs(apiResults),
        classification: formatAPIClassification(apiResults),
        probability: calculateAPIProbability(apiResults),
        source: 'external_apis',
        apiResults: apiResults,
        timestamp: Date.now()
    };
}

// =========================
// EXTERNAL API CHECKS
// =========================
async function checkExternalAPIs(url) {
    const results = {
        google_safebrowsing: null,
        virustotal: null
    };

    // Run both API checks in parallel
    await Promise.allSettled([
        checkGoogleSafeBrowsing(url).then(result => results.google_safebrowsing = result),
        checkVirusTotal(url).then(result => results.virustotal = result)
    ]);

    return results;
}

async function checkGoogleSafeBrowsing(url) {
    try {
        // Check cache first
        const cached = getCachedResult('googleSafeBrowsing', url);
        if (cached) {
            console.log('[Google-SafeBrowsing] Using cached result');
            return cached;
        }

        const requestBody = {
            client: {
                clientId: "phishing-defender-extension",
                clientVersion: "1.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: url }]
            }
        };

        const response = await fetch(`${API_CONFIG.googleSafeBrowsing.url}?key=${API_CONFIG.googleSafeBrowsing.apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody),
            signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
            throw new Error(`Google Safe Browsing API error: ${response.status}`);
        }

        const data = await response.json();
        
        let result = {
            status: 'safe',
            classification: 'Google: No threats found',
            matches: []
        };

        if (data.matches && data.matches.length > 0) {
            result.status = 'phishing';
            result.classification = `Google: ${data.matches.length} threat(s) detected`;
            result.matches = data.matches;
        }

        // Cache the result
        cacheResult('googleSafeBrowsing', url, result);
        return result;

    } catch (error) {
        console.error('[Google-SafeBrowsing] API check failed:', error.message);
        return {
            status: 'error',
            classification: 'Google: API unavailable',
            error: error.message
        };
    }
}

async function checkVirusTotal(url) {
    try {
        // Check cache first
        const cached = getCachedResult('virusTotal', url);
        if (cached) {
            console.log('[VirusTotal] Using cached result');
            return cached;
        }

        const formData = new URLSearchParams();
        formData.append('apikey', API_CONFIG.virusTotal.apiKey);
        formData.append('resource', url);

        const response = await fetch(API_CONFIG.virusTotal.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData,
            signal: AbortSignal.timeout(8000)
        });

        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const data = await response.json();
        
        let result = {
            status: 'safe',
            classification: 'VirusTotal: No threats detected',
            positives: 0,
            total: 0,
            scan_date: data.scan_date
        };

        if (data.response_code === 1) {
            result.positives = data.positives || 0;
            result.total = data.total || 0;
            
            if (result.positives > 0) {
                result.status = 'phishing';
                result.classification = `VirusTotal: ${result.positives}/${result.total} engines detected threats`;
            }
        } else if (data.response_code === 0) {
            result.status = 'unknown';
            result.classification = 'VirusTotal: URL not in database';
        } else {
            result.status = 'error';
            result.classification = `VirusTotal: API error (${data.response_code})`;
        }

        // Cache the result
        cacheResult('virusTotal', url, result);
        return result;

    } catch (error) {
        console.error('[VirusTotal] API check failed:', error.message);
        return {
            status: 'error',
            classification: 'VirusTotal: API unavailable',
            error: error.message
        };
    }
}

// =========================
// CACHE MANAGEMENT
// =========================
function getCachedResult(apiName, url) {
    const cache = API_CONFIG[apiName].cache;
    const cached = cache.get(url);
    
    if (cached && (Date.now() - cached.timestamp) < API_CONFIG[apiName].cacheTimeout) {
        return cached.data;
    }
    
    // Remove expired cache
    if (cached) {
        cache.delete(url);
    }
    
    return null;
}

function cacheResult(apiName, url, data) {
    API_CONFIG[apiName].cache.set(url, {
        data: data,
        timestamp: Date.now()
    });
}

// =========================
// RESULT PROCESSING
// =========================
function determineStatusFromAPIs(apiResults) {
    const gs = apiResults.google_safebrowsing?.status;
    const vt = apiResults.virustotal?.status;

    // If any API detects phishing, mark as phishing
    if (gs === 'phishing' || vt === 'phishing') {
        return 'phishing';
    }
    
    // If both APIs are safe, mark as safe
    if (gs === 'safe' && vt === 'safe') {
        return 'safe';
    }
    
    // If we have errors but at least one safe result, be cautious
    if ((gs === 'safe' || vt === 'safe') && (gs !== 'phishing' && vt !== 'phishing')) {
        return 'unknown';
    }
    
    // Default to unknown if all checks failed
    return 'unknown';
}

function formatAPIClassification(apiResults) {
    const parts = [];
    
    if (apiResults.google_safebrowsing) {
        parts.push(apiResults.google_safebrowsing.classification);
    }
    
    if (apiResults.virustotal) {
        parts.push(apiResults.virustotal.classification);
    }
    
    return parts.length > 0 ? parts.join(' | ') : 'External APIs: All checks failed';
}

function calculateAPIProbability(apiResults) {
    const gs = apiResults.google_safebrowsing;
    const vt = apiResults.virustotal;
    
    let probability = 0.1; // Default low probability
    
    // Google Safe Browsing detection increases probability significantly
    if (gs?.status === 'phishing') {
        probability = 0.9;
    }
    
    // VirusTotal detections increase probability based on ratio
    if (vt?.status === 'phishing' && vt.positives && vt.total) {
        const vtRatio = vt.positives / vt.total;
        probability = Math.max(probability, vtRatio);
    }
    
    // If both APIs detect threats, very high probability
    if (gs?.status === 'phishing' && vt?.status === 'phishing') {
        probability = 0.98;
    }
    
    return probability;
}

// =========================
// CORE BLOCKING LOGIC - IMPROVED
// =========================
async function checkAndBlockUrl(url, tabId) {
    try {
        // Skip if already processed
        if (hasOneTimeBypass(url)) {
            console.log('[Bypass] Skipping check');
            return;
        }

        if (await isWhitelisted(url)) {
            console.log('[Whitelist] Skipping check');
            return;
        }

        // GET AI PREDICTION WITH API FALLBACKS
        const aiResult = await runAIPrediction(url);
        
        console.log(`[Final-Result] Source: ${aiResult.source}, Status: ${aiResult.status}`);
        console.log(`[Final-Result] Classification: ${aiResult.classification}`);
        
        // BLOCK if any detection method finds phishing
        if (aiResult.status === 'phishing' || aiResult.status === 'phishing_pattern') {
            console.log(`🚨 BLOCKING PHISHING SITE: ${url}`);
            console.log(`🎯 Detection Source: ${aiResult.source}`);
            
            // FIXED: Show correct confidence percentage
            const confidence = aiResult.status === 'phishing' ? 
                (1 - aiResult.probability) * 100 : 
                aiResult.probability * 100;
            console.log(`📊 Confidence: ${confidence.toFixed(1)}%`);
            
            // Store in IndexedDB
            await storeThreatData({
                url: url,
                aiResults: aiResult,
                apiResults: aiResult.apiResults || {},
                source: 'background_blocking'
            });
            
            // Log to Firebase
            await logPhishingToFirebase(url, aiResult);
            
            // Trigger block page with detailed reason
            triggerBlockPage(tabId, url, aiResult.classification);
            
            // Update local stats
            updateThreatStats();

        } else {
            console.log(`✅ Safe site: ${url} - ${aiResult.classification}`);
        }

    } catch (error) {
        console.error('[Block-Check] Error:', error);
    }
}

// =========================
// FIREBASE LOGGING HELPER
// =========================
async function logPhishingToFirebase(url, aiResult) {
    try {
        let hostname;
        try {
            hostname = new URL(url).hostname;
        } catch {
            hostname = url;
        }

        const detectionData = {
            url: url,
            hostname: hostname,
            score: aiResult.probability || 0.5,
            isPhishing: true,
            isSuspicious: false,
            safeBrowsingDetected: aiResult.apiResults?.google_safebrowsing?.status === 'phishing',
            virusTotalDetected: aiResult.apiResults?.virustotal?.status === 'phishing',
            aiStatus: aiResult.status,
            apiResults: aiResult.apiResults || {},
            source: 'background_blocking'
        };

        console.log('[Firebase] Logging phishing detection...');
        await firebaseService.logPhishingDetection(detectionData);
        
    } catch (error) {
        console.error('[Firebase] Failed to log detection:', error);
    }
}

// =========================
// UPDATE THREAT STATS
// =========================
function updateThreatStats() {
    chrome.storage.local.get(['threatStats'], (result) => {
        const newCount = (result?.threatStats || 0) + 1;
        chrome.storage.local.set({ threatStats: newCount });
        console.log(`[Stats] Updated threat count: ${newCount}`);
    });
}

// =========================
// NAVIGATION LISTENERS - REAL-TIME BLOCKING
// =========================
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!/^https?:\/\//i.test(url) || url.startsWith('chrome-extension://')) return;

    console.log(`[Navigation] Checking: ${url}`);
    await checkAndBlockUrl(url, details.tabId);
});

// =========================
// BLOCK PAGE FUNCTION
// =========================
function triggerBlockPage(tabId, url, reason) {
    if (!tabId) return;
    
    // Store the blocked URL with more details
    const blockedInfo = {
        url: url,
        reasons: Array.isArray(reason) ? reason : [reason],
        timestamp: Date.now(),
        source: 'ai_detection',
        hostname: extractHostname(url)
    };
    
    chrome.storage.local.set({ 
        lastBlocked: blockedInfo
    }, () => {
        console.log('[Block] Stored blocked URL:', blockedInfo);
    });

    const blockedUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&reasons=${encodeURIComponent(JSON.stringify(blockedInfo.reasons))}`
    );
    
    console.log('[Block] Redirecting to block page');
    chrome.tabs.update(tabId, { url: blockedUrl });
}

// Helper function to extract hostname
function extractHostname(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

// =========================
// MESSAGE HANDLER
// =========================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // AI Prediction request
    if (msg?.action === 'checkUrl' && msg.url) {
        runAIPrediction(msg.url).then(sendResponse);
        return true;
    }

    // Whitelist check
    if (msg?.action === 'isWhitelisted' && msg.url) {
        isWhitelisted(msg.url).then(whitelisted => sendResponse({ whitelisted }));
        return true;
    }

    // Allow once bypass
    if (msg?.type === 'ALLOW_ONCE' && msg.url) {
        console.log('[Bypass] Allowing URL:', msg.url);
        addOneTimeBypass(msg.url);
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]?.id) chrome.tabs.update(tabs[0].id, { url: msg.url });
        });
        sendResponse({ ok: true });
        return true;
    }

    // External API check (for popup)
    if (msg?.action === 'checkExternalAPIs' && msg.url) {
        checkExternalAPIs(msg.url).then(sendResponse);
        return true;
    }

    // Firebase logging from popup
    if (msg?.action === 'logToFirebase' && msg.detectionData) {
        console.log('[Background] Received Firebase log request from popup');
        firebaseService.logPhishingDetection(msg.detectionData)
            .then(() => {
                console.log('[Background] Firebase log successful');
                sendResponse({ success: true });
            })
            .catch(error => {
                console.error('[Background] Firebase log failed:', error);
                sendResponse({ success: false, error: error.message });
            });
        return true;
    }

    // IndexedDB stats requests
    if (msg?.action === 'getThreatStats') {
        Promise.all([getThreatsCount(), getThreatsThisWeek()])
            .then(([count, weeklyData]) => {
                sendResponse({ count, weeklyData });
            })
            .catch(() => sendResponse({ count: 0, weeklyData: [] }));
        return true;
    }

    return false;
});

// =========================
// WHITELIST
// =========================
let whitelist = null;
let whitelistSet = null;
let whitelistLoaded = false;

async function loadWhitelist() {
  if (whitelistLoaded) return whitelist;
  try {
    const response = await fetch(chrome.runtime.getURL('whitelist.json'));
    const data = await response.json();
    whitelist = data.domains || [];
    whitelistSet = new Set(whitelist.map(d => d.toLowerCase().replace(/^www\./i, '')));
    whitelistLoaded = true;
    return whitelist;
  } catch (e) {
    whitelist = [];
    whitelistSet = new Set();
    whitelistLoaded = true;
    return whitelist;
  }
}

async function isWhitelisted(url) {
  if (!whitelistLoaded) await loadWhitelist();
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./i, '');
    return whitelistSet.has(hostname);
  } catch (e) {
    return false;
  }
}

// =========================
// BYPASS
// =========================
const oneTimeBypassUrls = new Set();

function normalizeUrlForBypass(url) {
  try {
    const urlObj = new URL(url);
    return `${urlObj.origin}${urlObj.pathname}`.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function addOneTimeBypass(url) {
  const normalizedUrl = normalizeUrlForBypass(url);
  oneTimeBypassUrls.add(normalizedUrl);
  setTimeout(() => {
    oneTimeBypassUrls.delete(normalizedUrl);
  }, 2 * 60 * 1000);
}

function hasOneTimeBypass(url) {
  const normalizedUrl = normalizeUrlForBypass(url);
  return oneTimeBypassUrls.has(normalizedUrl);
}

// =========================
// INITIALIZE
// =========================
chrome.runtime.onInstalled.addListener(async () => {
    console.log('Phishing Defender - ENHANCED WITH FIREBASE & INDEXEDDB');
    
    // Initialize databases
    await initDatabase();
    await loadWhitelist();
    
    // Set initial stats
    chrome.storage.local.set({ threatStats: 0 });
    
    // Test Firebase connection
    setTimeout(async () => {
        console.log('[Init] Testing Firebase connection...');
        const testData = {
            url: 'https://test-phishing-site.com',
            hostname: 'test-phishing-site.com',
            score: 0.85,
            isPhishing: true,
            isSuspicious: false,
            safeBrowsingDetected: false,
            virusTotalDetected: false,
            aiStatus: 'phishing',
            source: 'init_test'
        };
        
        try {
            await firebaseService.logPhishingDetection(testData);
            console.log('[Init] ✅ Firebase connection successful');
        } catch (error) {
            console.error('[Init] ❌ Firebase connection failed:', error.message);
        }
    }, 2000);
});

// Initialize on load
initDatabase().catch(console.error);
loadWhitelist().catch(console.error);
