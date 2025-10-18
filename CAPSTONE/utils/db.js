class PhishingDB {
    constructor() {
        this.dbName = 'PhishingDetectorDB';
        this.version = 1;
        this.db = null;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve(this.db);
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create threats store if it doesn't exist
                if (!db.objectStoreNames.contains('threats')) {
                    const threatsStore = db.createObjectStore('threats', { 
                        keyPath: 'id', 
                        autoIncrement: true 
                    });
                    threatsStore.createIndex('url', 'url', { unique: false });
                    threatsStore.createIndex('timestamp', 'timestamp', { unique: false });
                    threatsStore.createIndex('score', 'score', { unique: false });
                }

                // Create stats store for weekly data
                if (!db.objectStoreNames.contains('stats')) {
                    const statsStore = db.createObjectStore('stats', { 
                        keyPath: 'week' 
                    });
                }
            };
        });
    }

    async addThreat(threatData) {
        if (!this.db) await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['threats'], 'readwrite');
            const store = transaction.objectStore('threats');
            
            // Add timestamp if not provided
            if (!threatData.timestamp) {
                threatData.timestamp = Date.now();
            }
            
            const request = store.add(threatData);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async getThreatsCount() {
        if (!this.db) await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['threats'], 'readonly');
            const store = transaction.objectStore('threats');
            const request = store.count();
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async getWeeklyStats() {
        if (!this.db) await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['stats'], 'readonly');
            const store = transaction.objectStore('stats');
            const request = store.getAll();
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async updateWeeklyStats() {
        if (!this.db) await this.init();
        
        // Get current week identifier (year + week number)
        const now = new Date();
        const weekStart = new Date(now);
        weekStart.setDate(now.getDate() - now.getDay()); // Start of week (Sunday)
        const weekId = `${weekStart.getFullYear()}-${weekStart.getMonth() + 1}-${weekStart.getDate()}`;
        
        // Count threats from the past week
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['threats', 'stats'], 'readwrite');
            const threatsStore = transaction.objectStore('threats');
            const statsStore = transaction.objectStore('stats');
            
            // Create index on timestamp for efficient querying
            const index = threatsStore.index('timestamp');
            const range = IDBKeyRange.lowerBound(oneWeekAgo);
            
            const countRequest = index.count(range);
            
            countRequest.onerror = () => reject(countRequest.error);
            countRequest.onsuccess = () => {
                const weeklyCount = countRequest.result;
                
                // Update stats store
                const statsRequest = statsStore.put({
                    week: weekId,
                    count: weeklyCount,
                    updated: Date.now()
                });
                
                statsRequest.onerror = () => reject(statsRequest.error);
                statsRequest.onsuccess = () => resolve(weeklyCount);
            };
        });
    }

    async getThreatsThisWeek() {
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        
        if (!this.db) await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['threats'], 'readonly');
            const store = transaction.objectStore('threats');
            const index = store.index('timestamp');
            const range = IDBKeyRange.lowerBound(oneWeekAgo);
            
            const request = index.getAll(range);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }
}

// Create a global instance
const phishingDB = new PhishingDB();