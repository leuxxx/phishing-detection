// phishing-server.js - FIXED VERSION for Render
import express from 'express';
import cors from 'cors';
import tf from '@tensorflow/tfjs'; // Use regular tfjs, not tfjs-node
import { readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Enhanced CORS for production
app.use(cors({
  origin: '*', // Allow all origins for testing
  credentials: true
}));

app.use(express.json());

let model = null;
let metadata = null;

// Load model - FIXED for Render compatibility
async function loadModel() {
    try {
        const modelDir = join(__dirname, 'tfjs_phishing_model_optimized');
        
        // Check if model files exist
        if (!existsSync(join(modelDir, 'metadata.json'))) {
            console.error('❌ Model files not found in:', modelDir);
            console.log('📁 Available files:', await fs.promises.readdir(modelDir).catch(() => 'Cannot read directory'));
            return false;
        }
        
        // Load metadata
        const metadataPath = join(modelDir, 'metadata.json');
        const metadataFile = readFileSync(metadataPath, 'utf8');
        metadata = JSON.parse(metadataFile);
        console.log('✅ Metadata loaded');
        
        // Serve static files
        app.use('/model', express.static(modelDir));
        
        // FIXED: Use HTTP URL for model loading on Render
        const modelUrl = `http://localhost:${PORT}/model/model.json`;
        console.log('📥 Loading model from:', modelUrl);
        
        model = await tf.loadLayersModel(modelUrl);
        console.log('✅ Model loaded successfully!');
        console.log('📊 Model input shape:', model.inputs[0].shape);
        console.log('📊 Model output shape:', model.outputs[0].shape);
        return true;
        
    } catch (error) {
        console.error('❌ Model loading failed:', error.message);
        console.error('🔍 Error details:', error.stack);
        return false;
    }
}

// EXACT feature extraction from your sandbox.js
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

// FIXED: Use the SAME logic as sandbox.js
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

        console.log(`🔍 Features extracted:`, Object.keys(feats).length);
        console.log(`🔍 Vector length:`, vec.length);

        const inputTensor = tf.tensor2d([vec], [1, vec.length]);
        let pred = model.predict(inputTensor);
        if (Array.isArray(pred)) pred = pred[0];
        const probArr = await pred.data();
        const probability = probArr[0];
        
        // Cleanup tensors
        inputTensor.dispose();
        if (pred.dispose) pred.dispose();

        console.log(`[Server] Raw probability: ${probability}, Threshold: ${threshold}`);

        // FIXED: Use consistent logic with extension
        let status, classification;
        if (probability >= threshold) {
            status = "phishing";
            const confidence = probability * 100;
            classification = `AI: Phishing pattern detected (${confidence.toFixed(1)}% confidence)`;
        } else if (probability > 0.1 && probability < threshold) {
            status = "unknown";
            classification = `AI: Unfamiliar pattern (${(probability * 100).toFixed(1)}% match to phishing patterns)`;
        } else {
            status = "safe";
            classification = `AI: Likely safe (${((1 - probability) * 100).toFixed(1)}% confidence)`;
        }

        return { 
            status, 
            classification, 
            probability, 
            threshold, 
            originalUrl: url 
        };

    } catch (err) {
        console.error("❌ Prediction failed:", err);
        console.error("🔍 Error stack:", err.stack);
        return {
            status: "safe",
            classification: "AI: Error - assuming safe",
            probability: 0.0,
            originalUrl: url,
            error: err.message
        };
    }
}

// MAIN PREDICTION ENDPOINT
app.post('/predict', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL required' });

        console.log(`🔍 Predicting URL: ${url}`);
        
        if (!model || !metadata) {
            console.log('❌ Model not ready');
            return res.json({ 
                status: "safe",
                classification: "AI: Model not ready",
                probability: 0.0,
                originalUrl: url,
                error: "model_not_loaded"
            });
        }

        const result = await predictURL(url);
        console.log(`🤖 ${url} → ${result.status} (${result.probability})`);
        res.json(result);

    } catch (error) {
        console.error('❌ Prediction error:', error);
        console.error('🔍 Error stack:', error.stack);
        res.status(500).json({ 
            status: "safe",
            classification: "AI: Error in prediction",
            probability: 0.0,
            originalUrl: req.body?.url || 'unknown',
            error: error.message
        });
    }
});

// TEST ENDPOINT - to verify server is working
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        model_loaded: !!model, 
        metadata_loaded: !!metadata,
        timestamp: new Date().toISOString(),
        server: 'Render',
        port: PORT
    });
});

// NEW: Model info endpoint
app.get('/model-info', (req, res) => {
    if (!model) {
        return res.json({ error: 'Model not loaded' });
    }
    
    res.json({
        inputs: model.inputs.map(input => ({
            shape: input.shape,
            dtype: input.dtype
        })),
        outputs: model.outputs.map(output => ({
            shape: output.shape,
            dtype: output.dtype
        })),
        layers: model.layers.length,
        metadata: metadata ? {
            feature_names: metadata.feature_names,
            optimal_threshold: metadata.optimal_threshold
        } : null
    });
});

// FORCE UNSAFE DETECTION FOR TESTING
app.post('/predict-force-unsafe', async (req, res) => {
    const { url } = req.body;
    console.log(`🚨 FORCING UNSAFE DETECTION for: ${url}`);
    
    res.json({
        status: "phishing",
        classification: "AI: Phishing (95.0% confidence) - FORCED",
        probability: 0.95,
        forced: true
    });
});

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`📊 Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`🔧 Model info: http://0.0.0.0:${PORT}/model-info`);
    console.log(`🔄 Loading model...`);
    
    // Load model with retry logic
    let loaded = false;
    let attempts = 0;
    const maxAttempts = 3;
    
    while (!loaded && attempts < maxAttempts) {
        attempts++;
        console.log(`🔄 Model loading attempt ${attempts}/${maxAttempts}`);
        loaded = await loadModel();
        
        if (!loaded && attempts < maxAttempts) {
            console.log(`⏳ Retrying in 5 seconds...`);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
    
    if (loaded) {
        console.log('🎉 Server ready!');
    } else {
        console.log('❌ Server started but model failed to load');
    }
});
