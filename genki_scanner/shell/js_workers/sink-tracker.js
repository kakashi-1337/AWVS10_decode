/**
 * ANBU Sink Tracker
 * Monitors outgoing network requests to detect which variable mutations 
 * actually affect server-side behavior (the "does it have an effect?" question)
 * 
 * Tracks: fetch(), XHR, WebSocket messages, postMessage to workers
 */

class SinkTracker {
    constructor() {
        this.baselineRequests = []; // Requests before mutation
        this.mutatedRequests = [];  // Requests after mutation
        this.requestLog = [];
        this.isTracking = false;
    }

    /**
     * Attach to CDP session for network monitoring
     */
    async attach(cdpSession) {
        this.cdpSession = cdpSession;
        
        // Track all outgoing requests
        cdpSession.on('Network.requestWillBeSent', (params) => {
            const entry = {
                requestId: params.requestId,
                url: params.request.url,
                method: params.request.method,
                headers: params.request.headers,
                postData: params.request.postData,
                timestamp: params.timestamp,
                type: params.type,
                isMutated: this.isTracking
            };
            
            this.requestLog.push(entry);
            
            if (this.isTracking) {
                this.mutatedRequests.push(entry);
            }
        });

        // Track responses for status code changes
        cdpSession.on('Network.responseReceived', (params) => {
            const existingEntry = this.requestLog.find(r => r.requestId === params.requestId);
            if (existingEntry) {
                existingEntry.responseStatus = params.response.status;
                existingEntry.responseHeaders = params.response.headers;
            }
        });
    }

    /**
     * Start tracking (call before mutations)
     */
    startTracking() {
        this.isTracking = true;
        this.mutatedRequests = [];
    }

    /**
     * Stop tracking
     */
    stopTracking() {
        this.isTracking = false;
    }

    /**
     * Get requests that were modified by mutations
     * Compares mutated requests against baseline to find differences
     */
    getModifiedRequests() {
        return this.mutatedRequests.filter(req => {
            // Find if this request's POST data differs from baseline
            const baseline = this.baselineRequests.find(b => 
                b.url === req.url && b.method === req.method
            );
            
            if (!baseline) return true; // New endpoint = interesting
            if (baseline.postData !== req.postData) return true; // Body changed
            if (baseline.responseStatus !== req.responseStatus) return true; // Status changed
            
            return false;
        });
    }

    /**
     * Capture baseline (clean run without mutations)
     */
    captureBaseline() {
        this.baselineRequests = [...this.requestLog];
        this.requestLog = [];
    }

    /**
     * Compare a specific request before/after mutation
     */
    diffRequest(url) {
        const before = this.baselineRequests.filter(r => r.url.includes(url));
        const after = this.mutatedRequests.filter(r => r.url.includes(url));
        
        return {
            url,
            beforeCount: before.length,
            afterCount: after.length,
            bodyChanged: before.some((b, i) => 
                after[i] && b.postData !== after[i].postData
            ),
            statusChanged: before.some((b, i) => 
                after[i] && b.responseStatus !== after[i].responseStatus
            )
        };
    }
}

module.exports = { SinkTracker };
