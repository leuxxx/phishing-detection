// libs/tf-loader.js
console.log("Starting TensorFlow.js loader...");

// Global TensorFlow loading promise
window.tfReady = new Promise(async (resolve, reject) => {
    try {
        // Check if TensorFlow is already loaded
        if (typeof tf !== 'undefined') {
            console.log("TensorFlow.js already loaded");
            resolve(tf);
            return;
        }

        // Load TensorFlow.js
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('libs/tf-no-eval.js');
        script.onload = () => {
            console.log("TensorFlow.js script loaded, waiting for initialization...");
            
            // Wait for TensorFlow to be fully ready
            const checkTF = () => {
                if (typeof tf !== 'undefined' && tf.ready && tf.loadLayersModel) {
                    console.log("TensorFlow.js fully initialized");
                    tf.ready().then(() => {
                        console.log("TensorFlow.js ready promise resolved");
                        resolve(tf);
                    }).catch(reject);
                } else {
                    setTimeout(checkTF, 100);
                }
            };
            checkTF();
        };
        script.onerror = reject;
        document.head.appendChild(script);
        
    } catch (error) {
        reject(error);
    }
});

console.log("TensorFlow loader initialized");