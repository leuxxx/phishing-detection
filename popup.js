// popup.js — COMPLETE FIXED VERSION WITH WORKING STATS
document.addEventListener("DOMContentLoaded", async () => {
    // UI elements
    const checkerBtn = document.getElementById("checkerBtn");
    const statsBtn = document.getElementById("statsBtn");
    const recommendationBtn = document.getElementById("recommendationBtn");
    const checkerPage = document.getElementById("checkerPage");
    const statsPage = document.getElementById("statsPage");
    const recommendationPage = document.getElementById("recommendationPage");
    const scannedUrl = document.getElementById("scannedUrl");
    const statusCircle = document.getElementById("statusCircle");
    const classificationEl = document.getElementById("classification");
    const retryBtn = document.getElementById("retryBtn");
    const tfSandbox = document.getElementById("tfSandbox");
    const randomLinkBtn = document.getElementById("randomLinkBtn");
    const totalThreats = document.getElementById("totalThreats");
    const statsChart = document.getElementById("statsChart");

    // ---- State ----
    let aiPending = false;
    let aiResultLatest = null;
    let aiFallbackTimer = null;
    let sandboxReady = false;
    let sandboxWin = null;
    const pendingJobs = [];
    let currentApiResults = null;
    let tabSwitchTimeout = null;
    let lastPayload = null;
    let db = null;

    // =========================
    // PAGE NAVIGATION - FIXED
    // =========================
    function setActivePage(activePage, activeButton) {
        [checkerPage, statsPage, recommendationPage].forEach(page => page?.classList.remove("active"));
        [checkerBtn, statsBtn, recommendationBtn].forEach(btn => btn?.classList.remove("active"));
        activePage?.classList.add("active");
        activeButton?.classList.add("active");
    }

    // =========================
    // DATABASE - FIXED
    // =========================
    async function initDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open("PhishingDefenderDB", 1);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => { 
                db = request.result; 
                console.log('[Popup] IndexedDB initialized');
                resolve(db); 
            };
            request.onupgradeneeded = (event) => {
                const database = event.target.result;
                if (!database.objectStoreNames.contains('threats')) {
                    const store = database.createObjectStore('threats', { keyPath: 'id', autoIncrement: true });
                    store.createIndex('timestamp', 'timestamp', { unique: false });
                    store.createIndex('url', 'url', { unique: false });
                }
            };
        });
    }

    // =========================
    // STATS PAGE - COMPLETELY FIXED
    // =========================
    function loadStats() {
        console.log('[Stats] Loading statistics...');
        
        // Load threat count from storage
        chrome.storage.local.get(["threatStats"], (result) => {
            const threats = result?.threatStats || 0;
            if (totalThreats) {
                totalThreats.textContent = threats;
                console.log('[Stats] Total threats:', threats);
            }
        });
        
        // Load and display the chart
        updateStatistics();
    }

    async function updateStatistics() {
        console.log('[Stats] Updating statistics...');
        
        try {
            // Get threat count
            const count = await getThreatsCount();
            if (totalThreats) {
                totalThreats.textContent = count;
                console.log('[Stats] Threats from IndexedDB:', count);
            }

            // Get weekly data and update chart
            const weeklyData = await getThreatsThisWeek();
            console.log('[Stats] Weekly data:', weeklyData.length, 'records');
            
            if (statsChart) {
                updateChart(weeklyData);
            } else {
                console.error('[Stats] Chart canvas not found');
            }

        } catch (error) {
            console.error('[Stats] Error updating statistics:', error);
        }
    }

    async function getThreatsCount() {
        if (!db) {
            console.log('[Stats] DB not available, returning 0');
            return 0;
        }
        
        return new Promise((resolve) => {
            const tx = db.transaction(['threats'], 'readonly');
            const store = tx.objectStore('threats');
            const req = store.count();
            
            req.onsuccess = () => {
                console.log('[Stats] Count result:', req.result);
                resolve(req.result);
            };
            
            req.onerror = () => {
                console.error('[Stats] Count error:', req.error);
                resolve(0);
            };
        });
    }

    async function getThreatsThisWeek() {
        if (!db) {
            console.log('[Stats] DB not available, returning empty array');
            return [];
        }
        
        return new Promise((resolve) => {
            const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
            const tx = db.transaction(['threats'], 'readonly');
            const store = tx.objectStore('threats');
            const index = store.index('timestamp');
            const range = IDBKeyRange.lowerBound(oneWeekAgo);
            const req = index.getAll(range);
            
            req.onsuccess = () => {
                console.log('[Stats] Weekly data count:', req.result?.length || 0);
                resolve(req.result || []);
            };
            
            req.onerror = () => {
                console.error('[Stats] Weekly data error:', req.error);
                resolve([]);
            };
        });
    }

    function updateChart(weeklyData) {
    if (!statsChart) {
        console.error('[Stats] Chart canvas not found');
        return;
    }

    const ctx = statsChart.getContext('2d');
    if (!ctx) {
        console.error('[Stats] Could not get chart context');
        return;
    }

    console.log('[Stats] Creating chart with data:', weeklyData);

    // Process data for chart
    const dailyCounts = {};
    weeklyData.forEach(threat => {
        const date = new Date(threat.timestamp).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
        dailyCounts[date] = (dailyCounts[date] || 0) + 1;
    });

    const labels = Object.keys(dailyCounts);
    const data = Object.values(dailyCounts);

    console.log('[Stats] Chart labels:', labels);
    console.log('[Stats] Chart data:', data);

    // Destroy existing chart if it exists
    if (statsChart.chart) {
        statsChart.chart.destroy();
    }

    // Create new chart with PROPER POPUP SIZING
    try {
        statsChart.chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Threats Detected',
                    data: data,
                    backgroundColor: '#ff4d4d',
                    borderColor: '#d93636',
                    borderWidth: 1,
                    borderRadius: 3,
                    barPercentage: 0.7, // Make bars thinner
                    categoryPercentage: 0.8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, // This is key for popup sizing
                layout: {
                    padding: {
                        top: 10,
                        bottom: 10,
                        left: 5,
                        right: 5
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        padding: 8,
                        cornerRadius: 4
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            color: '#666',
                            font: {
                                size: 10 // Smaller font
                            },
                            padding: 2
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)',
                            drawBorder: false
                        }
                    },
                    x: {
                        ticks: {
                            color: '#666',
                            font: {
                                size: 9, // Smaller font for dates
                                weight: 'bold'
                            },
                            maxRotation: 0, // Prevent label rotation
                            padding: 2
                        },
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
        
        console.log('[Stats] Chart created successfully with popup sizing');
    } catch (chartError) {
        console.error('[Stats] Chart creation failed:', chartError);
        
        // Fallback: Show simple text
        ctx.fillStyle = '#666';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('Chart data: ' + weeklyData.length + ' threats', statsChart.width / 2, statsChart.height / 2);
    }
}

    // =========================
    // STATUS DISPLAY - FIXED
    // =========================
    function setStatus(cssClass, text, bgColor) {
        if (!statusCircle) return;
        statusCircle.className = cssClass || "";
        statusCircle.textContent = text || "";
        if (bgColor) statusCircle.style.backgroundColor = bgColor;
        else statusCircle.style.removeProperty("background-color");
    }

    // =========================
    // URL HANDLING - FIXED
    // =========================
    function normalizeUrl(url) {
        try {
            const urlObj = new URL(url);
            let hostname = urlObj.hostname.replace(/^www\./i, '');
            const normalized = `${urlObj.protocol}//${hostname}${urlObj.pathname}`;
            return normalized.replace(/\/+$/, '');
        } catch (e) {
            return url.replace(/\/+$/, '').replace(/#.*$/, '').replace(/\?.*$/, '');
        }
    }

    async function getActiveTabUrl() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            console.log('[Popup] Current tab URL:', tab?.url);
            
            // Check if we're on the blocked page
            if (tab?.url && tab.url.startsWith('chrome-extension://') && tab.url.includes('blocked.html')) {
                console.log('[Popup] Detected blocked page');
                return 'BLOCKED_PAGE';
            }
            
            return tab?.url || tab?.pendingUrl || "";
        } catch (error) {
            console.error('[Popup] Error getting tab URL:', error);
            return "";
        }
    }

    // =========================
    // WHITELIST CHECK - FIXED
    // =========================
    async function checkWhitelistStatus(url) {
        try {
            const response = await chrome.runtime.sendMessage({ action: "isWhitelisted", url });
            return response?.whitelisted || false;
        } catch {
            return false;
        }
    }

    // =========================
    // BLOCKED URL CHECK - FIXED
    // =========================
    async function checkIfUrlIsBlocked(url) {
        return new Promise((resolve) => {
            chrome.storage.local.get(['lastBlocked'], (result) => {
                if (result.lastBlocked && result.lastBlocked.url === url) {
                    resolve(true);
                } else {
                    resolve(false);
                }
            });
        });
    }

    async function showBlockedStatus(url) {
        try {
            const storageData = await new Promise(resolve => {
                chrome.storage.local.get(['lastBlocked'], resolve);
            });
            
            if (storageData.lastBlocked) {
                setStatus("phishing", "Blocked", "#ff4d4d");
                classificationEl.textContent = storageData.lastBlocked.reasons?.[0] || "AI: Phishing pattern detected";
            } else {
                setStatus("phishing", "Blocked", "#ff4d4d");
                classificationEl.textContent = "This site was blocked for security reasons";
            }
        } catch (error) {
            console.error('[Popup] Blocked status error:', error);
            setStatus("phishing", "Blocked", "#ff4d4d");
            classificationEl.textContent = "Phishing site detected and blocked";
        }
    }

    // NEW: Handle when user is viewing the blocked page
    async function showBlockedPageStatus() {
        try {
            const storageData = await new Promise(resolve => {
                chrome.storage.local.get(['lastBlocked'], resolve);
            });
            
            if (storageData.lastBlocked) {
                const blockedInfo = storageData.lastBlocked;
                scannedUrl.textContent = new URL(blockedInfo.url).hostname || blockedInfo.url;
                setStatus("phishing", "Blocked", "#ff4d4d");
                classificationEl.textContent = blockedInfo.reasons?.[0] || "AI: Phishing pattern detected";
                console.log('[Popup] Showing blocked page info:', blockedInfo);
            } else {
                // Fallback if no storage data
                scannedUrl.textContent = "Blocked Site";
                setStatus("phishing", "Blocked", "#ff4d4d");
                classificationEl.textContent = "This site was blocked for security reasons";
            }
        } catch (error) {
            console.error('[Popup] Blocked page status error:', error);
            scannedUrl.textContent = "Blocked Site";
            setStatus("phishing", "Blocked", "#ff4d4d");
            classificationEl.textContent = "Phishing site detected and blocked";
        }
    }

    // =========================
    // SANDBOX BRIDGE - FIXED
    // =========================
    function initSandboxBridge() {
        if (!tfSandbox) return;

        const setSandboxWindowIfReady = () => {
            if (!sandboxWin && tfSandbox.contentWindow) {
                sandboxWin = tfSandbox.contentWindow;
            }
        };

        tfSandbox.addEventListener("load", () => {
            setSandboxWindowIfReady();
            setTimeout(() => {
                tryPostMessage({ type: "SANDBOX_HELLO" });
                postConfigToSandbox();
            }, 100);
        });

        window.addEventListener("message", (event) => {
            const msg = event.data;
            if (!msg || typeof msg !== "object") return;

            if (msg.type === "SANDBOX_HANDSHAKE") {
                sandboxReady = true;
                flushPendingJobs();
                return;
            }

            if (msg.type === "AI_PREDICTION_RESULT") {
                aiPending = false;
                aiResultLatest = msg.result;
                clearTimeout(aiFallbackTimer);
                if (lastPayload) {
                    lastPayload.aiResults = msg.result;
                }

                // Combine with API and update UI
                combineResultsAndUpdateUI(msg.result);
            }
        });

        setSandboxWindowIfReady();
        if (document.readyState === "complete" || document.readyState === "interactive") {
            setTimeout(() => tryPostMessage({ type: "SANDBOX_HELLO" }), 150);
        }
    }

    function buildSandboxConfig() {
        try {
            const MODEL_URL = chrome.runtime.getURL("tfjs_phishing_model_optimized/model.json");
            const META_URL = chrome.runtime.getURL("tfjs_phishing_model_optimized/metadata.json");
            return { modelUrl: MODEL_URL, metaUrl: META_URL };
        } catch (e) {
            console.warn("Could not build sandbox config:", e);
            return null;
        }
    }

    async function postConfigToSandbox(retries = 5, delayMs = 200) {
        if (!tfSandbox) return false;
        const cfg = buildSandboxConfig();
        if (!cfg) return false;

        for (let i = 0; i < retries; i++) {
            const win = tfSandbox.contentWindow;
            if (win) {
                try {
                    win.postMessage({ type: "SANDBOX_CONFIG", modelUrl: cfg.modelUrl, metaUrl: cfg.metaUrl }, "*");
                    win.postMessage({ type: "SANDBOX_HELLO" }, "*");
                    return true;
                } catch {}
            }
            await new Promise(r => setTimeout(r, delayMs));
        }
        return false;
    }

    function tryPostMessage(message) {
        if (!sandboxWin && tfSandbox?.contentWindow) sandboxWin = tfSandbox.contentWindow;
        if (sandboxWin) {
            try {
                sandboxWin.postMessage(message, "*");
                return true;
            } catch {}
        }
        return false;
    }

    function queueAIJob(url) {
        pendingJobs.push({ url });
    }

    function flushPendingJobs() {
        if (!sandboxReady || !sandboxWin) return;
        while (pendingJobs.length) {
            const job = pendingJobs.shift();
            sandboxWin.postMessage({ type: "RUN_AI_PREDICTION", url: job.url }, "*");
        }
    }

    // =========================
    // CORE CHECKING LOGIC - FIXED
    // =========================
    async function checkCurrentTab() {
        try {
            currentApiResults = null;

            const currentUrl = await getActiveTabUrl();
            console.log('[Popup] Processing URL:', currentUrl);
            
            // Handle blocked page scenario
            if (currentUrl === 'BLOCKED_PAGE') {
                console.log('[Popup] Showing blocked page status');
                await showBlockedPageStatus();
                return;
            }
            
            if (!currentUrl || !/^https?:\/\//i.test(currentUrl)) {
                scannedUrl.textContent = "";
                setStatus("unknown", "Unknown", "#ff9800");
                classificationEl.textContent = "Open a valid webpage (http/https) to scan.";
                return;
            }

            const normalizedUrl = normalizeUrl(currentUrl);
            try { 
                scannedUrl.textContent = new URL(normalizedUrl).hostname; 
            } catch { 
                scannedUrl.textContent = normalizedUrl; 
            }

            // Check if this URL is currently blocked
            const isBlocked = await checkIfUrlIsBlocked(normalizedUrl);
            if (isBlocked) {
                console.log('[Popup] URL is currently blocked, showing blocked status');
                await showBlockedStatus(normalizedUrl);
                return;
            }

            const isWhitelisted = await checkWhitelistStatus(normalizedUrl);
            if (isWhitelisted) {
                setStatus("safe", "Safe", "#4CAF50");
                classificationEl.textContent = "Trusted Domain.";
                return;
            }

            setStatus("loading", "AI Analyzing...");
            classificationEl.textContent = "Running AI detection...";
            lastPayload = { url: normalizedUrl, apiResults: {}, aiResults: null };

            // Start AI detection
            aiPending = true;
            aiResultLatest = null;
            clearTimeout(aiFallbackTimer);
            aiFallbackTimer = setTimeout(() => {
                if (aiPending) {
                    setStatus("unknown", "Unknown", "#ff9800");
                    classificationEl.textContent = "AI detection timeout - using fallback";
                }
            }, 5000);

            if (sandboxReady && sandboxWin) {
                sandboxWin.postMessage({
                    type: "RUN_AI_PREDICTION",
                    url: normalizedUrl,
                    originalUrl: currentUrl
                }, "*");
            } else {
                queueAIJob(normalizedUrl);
                tryPostMessage({ type: "SANDBOX_HELLO" });
            }

        } catch (e) {
            console.error('[Popup] Check error:', e);
            setStatus("error", "Error");
            classificationEl.textContent = "Failed to analyze";
        }
    }

    function updateUIFromAPIsOnly(apiResults) {
        const gsClass = apiResults?.google_safebrowsing?.classification || "Google: Unknown";
        const vtClass = apiResults?.virustotal?.classification || "VirusTotal: Unknown";

        if (apiResults?.google_safebrowsing?.status === 'phishing' || apiResults?.virustotal?.status === 'phishing') {
            setStatus("phishing", "Unsafe", "#ff4d4d");
            classificationEl.textContent = `Phishing detected by APIs | ${gsClass} | ${vtClass}`;
        } else if (apiResults?.google_safebrowsing?.status === 'safe' && apiResults?.virustotal?.status === 'safe') {
            setStatus("safe", "Safe", "#4CAF50");
            classificationEl.textContent = `Safe (API-only) | ${gsClass} | ${vtClass}`;
        } else {
            setStatus("unknown", "Unknown", "#ff9800");
            classificationEl.textContent = `Uncertain (API-only) | ${gsClass} | ${vtClass}`;
        }
    }

    function combineResultsAndUpdateUI(aiResult) {
        const apiResults = currentApiResults;
        if (!apiResults) {
            updateUIWithAIResult(aiResult);
            return;
        }
        
        if (aiResult.status === 'phishing' || aiResult.status === 'phishing_pattern') {
            setStatus("phishing", "Unsafe", "#ff4d4d");
            classificationEl.textContent = `🚨 PHISHING DETECTED | ${aiResult.classification}`;
        } else if (aiResult.status === 'safe') {
            setStatus("safe", "Safe", "#4CAF50");
            classificationEl.textContent = `✅ SAFE | ${aiResult.classification}`;
        } else {
            setStatus("unknown", "Unknown", "#ff9800");
            classificationEl.textContent = `⚠️ UNCERTAIN | ${aiResult.classification}`;
        }
    }

    function updateUIWithAIResult(aiResult) {
        const status = (aiResult.status || "").toLowerCase();
        const probability = aiResult.probability ? ` | Confidence: ${(aiResult.probability * 100).toFixed(1)}%` : "";

        if (status === 'phishing' || status === 'phishing_pattern') {
            setStatus("phishing", "Unsafe", "#ff4d4d");
            classificationEl.textContent = `AI: ${aiResult.classification}${probability}`;
        } else if (status === 'safe') {
            setStatus("safe", "Safe", "#4CAF50");
            classificationEl.textContent = `AI: ${aiResult.classification}${probability}`;
        } else {
            setStatus("unknown", "Unknown", "#ff9800");
            classificationEl.textContent = `AI: ${aiResult.classification}${probability}`;
        }
    }

    // =========================
    // EVENT LISTENERS - FIXED
    // =========================
    checkerBtn?.addEventListener("click", () => setActivePage(checkerPage, checkerBtn));
    statsBtn?.addEventListener("click", () => { 
        setActivePage(statsPage, statsBtn); 
        loadStats(); 
    });
    recommendationBtn?.addEventListener("click", () => setActivePage(recommendationPage, recommendationBtn));
    retryBtn?.addEventListener("click", checkCurrentTab);

    if (randomLinkBtn) {
        const links = [
            "https://www.occ.gov/topics/consumers-and-communities/consumer-protection/fraud-resources/phishing-attack-prevention.html",
            "https://www.kaspersky.com/resource-center/preemptive-safety/phishing-prevention-tips"
        ];
        randomLinkBtn.addEventListener("click", () => {
            chrome.tabs.create({ url: links[Math.floor(Math.random() * links.length)] });
        });
    }

    // =========================
    // INITIALIZATION - FIXED
    // =========================
    async function initializeExtension() {
        try {
            await initDatabase();
            initSandboxBridge();

            // Initial scan
            await checkCurrentTab();

            // Refresh on tab switch
            chrome.tabs.onActivated.addListener(() => {
                clearTimeout(tabSwitchTimeout);
                tabSwitchTimeout = setTimeout(async () => {
                    scannedUrl.textContent = "...";
                    classificationEl.textContent = "Loading...";
                    setStatus("loading", "AI Analyzing...");
                    await checkCurrentTab();
                }, 250);
            });

            // Refresh on tab update
            chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
                if (tab.active && changeInfo.status === "complete") {
                    scannedUrl.textContent = "...";
                    classificationEl.textContent = "Loading...";
                    setStatus("loading", "AI Analyzing...");
                    await checkCurrentTab();
                }
            });

            // Default active tab
            setActivePage(checkerPage, checkerBtn);

        } catch (error) {
            console.error('[Popup] Initialization error:', error);
            setStatus("error", "Error");
            classificationEl.textContent = "Extension initialization failed";
        }
    }

    // Start the extension
    initializeExtension();
});

// Theme switcher code (keep your existing theme code)
document.addEventListener('DOMContentLoaded', () => {
    const KEY   = 'ui-theme';
    const root  = document.documentElement;
    const cb    = document.getElementById('themeSwitch');
    const btn   = document.getElementById('themeToggle');
    const label = document.getElementById('themeToggleLabel');

    function applyTheme(mode){
        root.classList.toggle('theme-dark',  mode === 'dark');
        root.classList.toggle('theme-light', mode === 'light');
        if (cb) cb.checked = (mode === 'dark');
        if (label) label.textContent = (mode === 'dark' ? 'Dark' : 'Light');
        try { localStorage.setItem(KEY, mode); } catch(e) {}
    }

    let saved = null;
    try { saved = localStorage.getItem(KEY); } catch(e) {}
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(saved ?? (prefersDark ? 'dark' : 'light'));

    if (cb) {
        cb.addEventListener('change', () => applyTheme(cb.checked ? 'dark' : 'light'));
    }

    if (btn) {
        btn.addEventListener('click', () => {
            const next = root.classList.contains('theme-dark') ? 'light' : 'dark';
            applyTheme(next);
        });
    }
});