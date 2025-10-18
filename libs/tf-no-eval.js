// TensorFlow.js compatibility layer for Chrome extensions
console.log('Loading TensorFlow.js compatibility layer');

// Check if we can use WebAssembly (preferred)
const canUseWASM = (() => {
    try {
        if (typeof WebAssembly === 'object' &&
            typeof WebAssembly.instantiate === 'function') {
            const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00));
            if (module instanceof WebAssembly.Module)
                return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
        }
    } catch (e) {}
    return false;
})();

console.log('WebAssembly available:', canUseWASM);

// Minimal TensorFlow implementation that loads the actual TFJS
async function loadTensorFlow() {
    try {
        // Try to load TensorFlow.js from CDN
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.15.0/dist/tf.min.js';
        script.type = 'text/javascript';
        
        return new Promise((resolve, reject) => {
            script.onload = () => {
                if (typeof tf !== 'undefined') {
                    console.log('TensorFlow.js loaded successfully from CDN');
                    resolve(tf);
                } else {
                    reject(new Error('TensorFlow not available after loading'));
                }
            };
            script.onerror = reject;
            document.head.appendChild(script);
        });
    } catch (error) {
        console.error('Failed to load TensorFlow.js:', error);
        throw error;
    }
}

// Initialize TensorFlow
let tfPromise = null;

function getTensorFlow() {
    if (!tfPromise) {
        tfPromise = loadTensorFlow();
    }
    return tfPromise;
}

// Make available globally
window.getTensorFlow = getTensorFlow;

console.log('TensorFlow.js compatibility layer ready');