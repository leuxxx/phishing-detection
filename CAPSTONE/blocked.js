// blocked.js - IMPROVED REASON HANDLING
document.addEventListener('DOMContentLoaded', async function() {
    // Try to get the exact URL from storage first (more reliable)
    let blockedUrl = '';
    let blockedReasons = ["AI: Phishing pattern detected"]; // Default reason
    
    try {
        const storageData = await new Promise(resolve => {
            chrome.storage.local.get(['lastBlocked'], resolve);
        });
        
        if (storageData.lastBlocked) {
            blockedUrl = storageData.lastBlocked.url;
            blockedReasons = storageData.lastBlocked.reasons || blockedReasons;
            console.log('[Blocked] Got from storage:', { url: blockedUrl, reasons: blockedReasons });
        }
    } catch (e) {
        console.log('[Blocked] Failed to get from storage:', e);
    }
    
    // Fallback to URL parameters
    if (!blockedUrl) {
        const urlParams = new URLSearchParams(window.location.search);
        blockedUrl = decodeURIComponent(urlParams.get('url') || '');
        const reasonsParam = urlParams.get('reasons');
        
        if (reasonsParam) {
            try {
                const decoded = decodeURIComponent(reasonsParam);
                const parsed = JSON.parse(decoded);
                blockedReasons = Array.isArray(parsed) ? parsed : [parsed];
            } catch {
                blockedReasons = [reasonsParam];
            }
        }
        console.log('[Blocked] Got from params:', { url: blockedUrl, reasons: blockedReasons });
    }

    // ===== UPDATE UI =====
    document.getElementById('blocked-url').textContent = blockedUrl || 'Unknown URL';

    const reasonsList = document.getElementById('blocked-reasons');
    reasonsList.innerHTML = '';
    
    // Ensure reasons is always an array
    if (!Array.isArray(blockedReasons)) {
        blockedReasons = [blockedReasons];
    }
    
    // Add each reason
    blockedReasons.forEach(reason => {
        if (reason) {
            const li = document.createElement('li');
            li.textContent = typeof reason === 'string' ? reason : JSON.stringify(reason);
            reasonsList.appendChild(li);
        }
    });

    // If no reasons found, add default
    if (reasonsList.children.length === 0) {
        const li = document.createElement('li');
        li.textContent = "AI: Phishing pattern detected";
        reasonsList.appendChild(li);
    }

    // ===== DOMAIN LABEL =====
    try {
        const domain = new URL(blockedUrl).hostname;
        document.getElementById('domain-name').textContent = domain;
    } catch {
        document.getElementById('domain-name').textContent = blockedUrl;
    }

    // ===== LEAVE BUTTON =====
    const SAFE_PAGE = "https://www.google.com/";
    document.getElementById('leave-btn').addEventListener('click', function() {
        window.location.replace(SAFE_PAGE);
    });

    // ===== CONTINUE ANYWAY BUTTON - IMPROVED =====
    document.getElementById('continue-btn').addEventListener('click', function() {
        console.log('[Blocked] Continue Anyway clicked for:', blockedUrl);
        
        if (!blockedUrl) {
            console.error('[Blocked] No URL to continue to');
            return;
        }
        
        // Send bypass message with the exact URL
        chrome.runtime.sendMessage({ 
            type: "ALLOW_ONCE", 
            url: blockedUrl 
        }, (response) => {
            console.log('[Blocked] Bypass response:', response);
            // The background script will handle the navigation
        });
    });

    // ===== WHITELIST BUTTON =====
    document.getElementById('whitelist-btn').addEventListener('click', function() {
        if (!blockedUrl) return;
        
        try {
            const domain = new URL(blockedUrl).hostname;
            chrome.runtime.sendMessage({
                type: "ADD_TO_WHITELIST",
                domain: domain
            }, (response) => {
                if (response?.success) {
                    alert(`Added ${domain} to whitelist. You can now visit this site.`);
                    window.location.replace(SAFE_PAGE);
                }
            });
        } catch (error) {
            console.error('[Blocked] Whitelist error:', error);
        }
    });

    console.log('[Blocked] Blocked page shown:', { url: blockedUrl, reasons: blockedReasons });
});