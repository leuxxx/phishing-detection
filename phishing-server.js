// phishing-server.js - COMPLETELY FIXED THRESHOLD LOGIC
import express from 'express';
import cors from 'cors';
import tf from '@tensorflow/tfjs';
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

let model = null;
let metadata = null;

// Load model
async function loadModel() {
    try {
        const modelDir = join(__dirname, 'tfjs_phishing_model_optimized');
        
        // Load metadata
        const metadataPath = join(modelDir, 'metadata.json');
        const metadataFile = readFileSync(metadataPath, 'utf8');
        metadata = JSON.parse(metadataFile);
        console.log('✅ Metadata loaded');
        
        // Serve model files
        app.use('/model', express.static(modelDir));
        
        // Load model
        const modelUrl = `/model/model.json`;
        model = await tf.loadLayersModel(modelUrl);
        console.log('✅ Model loaded!');
        return true;
        
    } catch (error) {
        console.error('❌ Model failed:', error.message);
        return false;
    }
}

// Keep your existing extractFeatures function exactly as is
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

    const suspiciousKeywords = [
        "login", "verify", "secure", "update", "account", "bank", "payment",
        "signin", "password", "confirm", "authenticate", "validation", "wallet",
        "credential", "oauth", "authorize", "admin", "portal", "access", "security"
    ];
    const suspicious_words = suspiciousKeywords.filter((w) => url.toLowerCase().includes(w)).length;

    const has_https = url.toLowerCase().startsWith("https://") ? 1 : 0;
    const path_length = pathname.length;
    const query_length = search.length;
    const is_shortened = /(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bitly|shorte)/i.test(url) ? 1 : 0;
    const num_special_chars = (url.match(/[^a-zA-Z0-9\.\/:-]/g) || []).length;

    const tld = (domain.split(".").slice(-1)[0] || "").toLowerCase();
    const risky_tlds = ["ru", "tk", "cn", "ga", "cf", "ml", "gq", "xyz", "top", "club", "site", "online"];
    const tld_risk = risky_tlds.includes(tld) ? 1 : 0;

    const complexity_score = num_special_chars + num_subdirs + num_questionmarks + num_ampersands;
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

// FIXED: Use the EXACT SAME LOGIC as your extension
async function predictURL(url) {
    if (!model || !metadata) {
        return {
            status: "safe",
            classification: "AI: Model not ready",
            probability: 0.0,
            originalUrl: url,
        };
    }

    try {
        const threshold = metadata.optimal_threshold ?? 0.25;
        const feats = extractFeatures(url);
        const vec = makeInputVector(feats);

        const inputTensor = tf.tensor2d([vec], [1, vec.length]);
        let pred = model.predict(inputTensor);
        if (Array.isArray(pred)) pred = pred[0];
        const probArr = await pred.data();
        const probability = probArr[0];
        
        // Cleanup tensors
        inputTensor.dispose();
        if (pred.dispose) pred.dispose();

        console.log(`[Server] Raw probability: ${probability}, Threshold: ${threshold}`);

        // FIXED: USE EXACTLY THE SAME LOGIC AS EXTENSION
        // Higher probability = more phishing-like (same as your extension)
        let status, classification;
        if (probability >= threshold) {
            status = "phishing";
            // FIXED: Higher probability means more confidence it's phishing
            const confidence = probability * 100;
            classification = `AI: Phishing (${confidence.toFixed(1)}% match to known patterns)`;
        } else {
            status = "unknown";
            classification = `AI: Unknown (${(probability * 100).toFixed(1)}% match to known patterns)`;
        }

        return { 
            status, 
            classification, 
            probability, 
            threshold, 
            originalUrl: url 
        };

    } catch (err) {
        console.error("Prediction failed:", err);
        return {
            status: "safe",
            classification: "AI: Error - assuming safe",
            probability: 0.0,
            originalUrl: url,
        };
    }
}

// MAIN PREDICTION ENDPOINT
app.post('/predict', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });

        const result = await predictURL(url);
        console.log(`🤖 ${url} → ${result.status} (${result.probability})`);
        res.json(result);

    } catch (error) {
        console.error('Prediction error:', error);
        res.json({ 
            status: "safe",
            classification: "AI: Error",
            probability: 0.0
        });
    }
});

// TEST ENDPOINT
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        model_loaded: !!model, 
        metadata_loaded: !!metadata,
        timestamp: new Date().toISOString()
    });
});

// NEW: Debug endpoint to compare with extension logic
app.post('/debug-predict', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });

        const threshold = metadata.optimal_threshold ?? 0.25;
        const feats = extractFeatures(url);
        const vec = makeInputVector(feats);

        const inputTensor = tf.tensor2d([vec], [1, vec.length]);
        let pred = model.predict(inputTensor);
        if (Array.isArray(pred)) pred = pred[0];
        const probArr = await pred.data();
        const probability = probArr[0];
        
        inputTensor.dispose();
        if (pred.dispose) pred.dispose();

        // Show both interpretations
        const extensionLogic = probability >= threshold ? 'PHISHING' : 'SAFE/UNKNOWN';
        const wrongLogic = probability <= threshold ? 'PHISHING' : 'SAFE/UNKNOWN';

        res.json({
            url,
            raw_probability: probability,
            threshold: threshold,
            extension_logic: extensionLogic,
            wrong_logic: wrongLogic,
            features: feats,
            interpretation: `Probability ${probability} >= Threshold ${threshold} = ${extensionLogic}`
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`📊 Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`🐛 Debug: http://0.0.0.0:${PORT}/debug-predict`);
    await loadModel();
});
