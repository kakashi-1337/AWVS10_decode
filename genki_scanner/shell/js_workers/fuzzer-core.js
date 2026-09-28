/**
 * ANBU Runtime Fuzzer v1.0
 * CDP-based runtime variable manipulation for bug bounty hunting
 * 
 * Technique: Programmatic pause → inspect → mutate → resume
 * Uses Chrome DevTools Protocol (CDP) via Puppeteer
 * 
 * Supports: Main thread + Web Workers (critical for e-voting crypto workers)
 * 
 * Usage:
 *   const fuzzer = new ANBURuntimeFuzzer({ headless: false, chromePath: '/usr/bin/google-chrome' });
 *   await fuzzer.launch(targetUrl);
 *   await fuzzer.loadProfile(require('./profiles/swiss-post'));
 *   await fuzzer.startFuzzing();
 */

const puppeteer = require('puppeteer-core');
const { MutationEngine } = require('./mutation-engine');
const { SinkTracker } = require('./sink-tracker');
const fs = require('fs');

class ANBURuntimeFuzzer {
    constructor(options = {}) {
        this.options = {
            headless: options.headless ?? false,
            chromePath: options.chromePath || '/usr/bin/google-chrome',
            userDataDir: options.userDataDir || '/tmp/anbu-fuzzer-profile',
            logDir: options.logDir || './logs',
            verbose: options.verbose ?? true,
            ...options
        };
        
        this.browser = null;
        this.page = null;
        this.cdpSession = null;
        this.workerSessions = new Map(); // Worker target → CDP session
        this.profile = null;
        this.mutationEngine = new MutationEngine();
        this.sinkTracker = new SinkTracker();
        this.findings = [];
        this.breakpointHits = 0;
        this.mutationsApplied = 0;
        
        // Ensure log directory exists
        if (!fs.existsSync(this.options.logDir)) {
            fs.mkdirSync(this.options.logDir, { recursive: true });
        }
    }

    /**
     * Launch browser and navigate to target
     */
    async launch(targetUrl) {
        this.log('[*] Launching ANBU Runtime Fuzzer...');
        
        this.browser = await puppeteer.launch({
            headless: this.options.headless,
            executablePath: this.options.chromePath,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security', // For cross-origin debugging
                '--auto-open-devtools-for-tabs',
                `--user-data-dir=${this.options.userDataDir}`
            ]
        });

        this.page = await this.browser.newPage();
        
        // Get CDP session for main thread
        this.cdpSession = await this.page.target().createCDPSession();
        
        // Enable required CDP domains
        await this.cdpSession.send('Debugger.enable');
        await this.cdpSession.send('Runtime.enable');
        await this.cdpSession.send('Network.enable');
        
        // Track Web Workers (critical for crypto workers)
        await this.setupWorkerTracking();
        
        // Setup network interception for sink tracking
        await this.sinkTracker.attach(this.cdpSession);
        
        // Navigate to target
        this.log(`[*] Navigating to: ${targetUrl}`);
        await this.page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 30000 });
        
        this.log('[+] Browser launched and target loaded');
        return this;
    }

    /**
     * Connect to an EXISTING browser via CDP (Option A: pipeline-managed browser)
     * instead of launching our own. Used by the worker.js `keisechu` task so the whole
     * pipeline shares one browser. Mirrors launch() but uses puppeteer.connect.
     */
    async connect(cdpUrl, targetUrl) {
        this.log('[*] Connecting ANBU Runtime Fuzzer to CDP: ' + cdpUrl);
        this._external = true; // do not hard-close a browser we did not launch
        this.browser = await puppeteer.connect({
            browserWSEndpoint: cdpUrl,
            defaultViewport: null,
        });
        const pages = await this.browser.pages();
        this.page = pages.length ? pages[0] : await this.browser.newPage();
        this.cdpSession = await this.page.target().createCDPSession();
        await this.cdpSession.send('Debugger.enable');
        await this.cdpSession.send('Runtime.enable');
        await this.cdpSession.send('Network.enable');
        await this.setupWorkerTracking();
        await this.sinkTracker.attach(this.cdpSession);
        if (targetUrl) {
            this.log('[*] Navigating to: ' + targetUrl);
            try {
                await this.page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 30000 });
            } catch (e) {
                this.log('[!] Navigation warning: ' + e.message);
            }
        }
        this.log('[+] Connected to CDP; target ready');
        return this;
    }

    /**
     * Track Web Workers — attach CDP debugger to each worker
     * Critical for e-voting systems where crypto runs in Web Workers
     */
    async setupWorkerTracking() {
        this.browser.on('targetcreated', async (target) => {
            if (target.type() === 'worker' || target.type() === 'service_worker') {
                this.log(`[+] Worker detected: ${target.url()}`);
                try {
                    const workerSession = await target.createCDPSession();
                    await workerSession.send('Debugger.enable');
                    await workerSession.send('Runtime.enable');
                    
                    this.workerSessions.set(target.url(), workerSession);
                    
                    // Set breakpoints for this worker
                    if (this.profile) {
                        await this.setWorkerBreakpoints(workerSession, target.url());
                    }
                    
                    // Handle breakpoint hits in worker
                    workerSession.on('Debugger.paused', async (params) => {
                        await this.handleBreakpointHit(workerSession, params, target.url());
                    });
                    
                    this.log(`[+] CDP attached to worker: ${target.url()}`);
                } catch (e) {
                    this.log(`[!] Failed to attach to worker: ${e.message}`);
                }
            }
        });
    }

    /**
     * Load a target profile (breakpoints, mutation rules, variable filters)
     */
    async loadProfile(profile) {
        this.profile = profile;
        this.mutationEngine.loadRules(profile.mutationRules || []);
        
        this.log(`[*] Profile loaded: ${profile.name}`);
        this.log(`    Breakpoints: ${profile.breakpoints?.length || 0}`);
        this.log(`    Mutation rules: ${profile.mutationRules?.length || 0}`);
        this.log(`    Variable filters: ${JSON.stringify(profile.variableFilters || {})}`);
        
        // Set breakpoints on main thread
        await this.setMainBreakpoints();
        
        // Set breakpoints on any existing workers
        for (const [url, session] of this.workerSessions) {
            await this.setWorkerBreakpoints(session, url);
        }
        
        return this;
    }

    /**
     * Set breakpoints on main thread
     */
    async setMainBreakpoints() {
        if (!this.profile?.breakpoints) return;
        
        for (const bp of this.profile.breakpoints) {
            if (bp.target === 'main' || !bp.target) {
                try {
                    // Set breakpoint by URL pattern + line number
                    if (bp.urlPattern && bp.lineNumber) {
                        const result = await this.cdpSession.send('Debugger.setBreakpointByUrl', {
                            urlRegex: bp.urlPattern,
                            lineNumber: bp.lineNumber - 1, // CDP is 0-indexed
                            columnNumber: bp.columnNumber || 0,
                            condition: bp.condition || ''
                        });
                        this.log(`[+] Breakpoint set: ${bp.name} → ${result.breakpointId}`);
                    }
                    
                    // Set breakpoint by function name (via Runtime.evaluate)
                    if (bp.functionName) {
                        // Use Debugger.setBreakpointOnFunctionCall if available
                        // or set a conditional breakpoint
                        this.log(`[+] Function breakpoint queued: ${bp.functionName}`);
                    }
                } catch (e) {
                    this.log(`[!] Failed to set breakpoint ${bp.name}: ${e.message}`);
                }
            }
        }
        
        // Handle breakpoint hits on main thread
        this.cdpSession.on('Debugger.paused', async (params) => {
            await this.handleBreakpointHit(this.cdpSession, params, 'main');
        });
    }

    /**
     * Set breakpoints on a worker thread
     */
    async setWorkerBreakpoints(session, workerUrl) {
        if (!this.profile?.breakpoints) return;
        
        for (const bp of this.profile.breakpoints) {
            if (bp.target === 'worker' || bp.target === 'all') {
                try {
                    if (bp.urlPattern && bp.lineNumber) {
                        const result = await session.send('Debugger.setBreakpointByUrl', {
                            urlRegex: bp.urlPattern,
                            lineNumber: bp.lineNumber - 1,
                            columnNumber: bp.columnNumber || 0,
                            condition: bp.condition || ''
                        });
                        this.log(`[+] Worker breakpoint set: ${bp.name} → ${result.breakpointId}`);
                    }
                } catch (e) {
                    this.log(`[!] Worker breakpoint failed ${bp.name}: ${e.message}`);
                }
            }
        }
    }

    /**
     * CORE: Handle breakpoint hit — inspect, mutate, resume
     */
    async handleBreakpointHit(session, params, context) {
        this.breakpointHits++;
        const callFrames = params.callFrames;
        const topFrame = callFrames[0];
        const location = topFrame.location;
        
        this.log(`\n[BP HIT #${this.breakpointHits}] ${context} @ ${topFrame.functionName || 'anonymous'} (${location.scriptId}:${location.lineNumber})`);
        
        // Step 1: Inspect scope variables
        const scopeVars = await this.inspectScope(session, topFrame);
        
        // Step 2: Filter variables by profile rules
        const targetVars = this.filterVariables(scopeVars, topFrame.functionName);
        
        if (targetVars.length > 0) {
            this.log(`[*] Found ${targetVars.length} target variables to mutate`);
            
            // Step 3: Apply mutations
            for (const varInfo of targetVars) {
                const mutation = this.mutationEngine.getMutation(varInfo);
                if (mutation) {
                    await this.applyMutation(session, topFrame.callFrameId, varInfo, mutation);
                }
            }
        }
        
        // Step 4: Capture pre-resume state snapshot
        const snapshot = {
            hitNumber: this.breakpointHits,
            context,
            function: topFrame.functionName,
            location: `${location.scriptId}:${location.lineNumber}`,
            variables: targetVars,
            timestamp: new Date().toISOString()
        };
        
        // Step 5: Resume execution
        await session.send('Debugger.resume');
        this.log(`[>] Resumed execution`);
        
        return snapshot;
    }

    /**
     * Inspect all variables in the current scope chain
     */
    async inspectScope(session, callFrame) {
        const variables = [];
        
        for (const scope of callFrame.scopeChain) {
            if (scope.type === 'global') continue; // Skip global scope (too noisy)
            
            try {
                const props = await session.send('Runtime.getProperties', {
                    objectId: scope.object.objectId,
                    ownProperties: true,
                    generatePreview: true
                });
                
                for (const prop of props.result) {
                    if (prop.value) {
                        variables.push({
                            name: prop.name,
                            type: prop.value.type,
                            subtype: prop.value.subtype,
                            value: prop.value.value,
                            preview: prop.value.preview,
                            objectId: prop.value.objectId,
                            scopeType: scope.type,
                            description: prop.value.description
                        });
                    }
                }
            } catch (e) {
                // Scope may not be inspectable
            }
        }
        
        return variables;
    }

    /**
     * Filter variables based on profile rules (type, name pattern, sink relevance)
     */
    filterVariables(variables, functionName) {
        if (!this.profile?.variableFilters) return variables;
        
        const filters = this.profile.variableFilters;
        
        return variables.filter(v => {
            // Type filter
            if (filters.types && !filters.types.includes(v.type)) return false;
            
            // Name pattern filter (heuristic keywords)
            if (filters.namePatterns) {
                const nameMatch = filters.namePatterns.some(pattern => 
                    v.name.toLowerCase().includes(pattern.toLowerCase())
                );
                if (filters.nameMode === 'include' && !nameMatch) return false;
                if (filters.nameMode === 'exclude' && nameMatch) return false;
            }
            
            // Function-specific filter
            if (filters.functions && !filters.functions.includes(functionName)) return false;
            
            // Exclude known noise
            if (filters.excludeNames && filters.excludeNames.includes(v.name)) return false;
            
            return true;
        });
    }

    /**
     * Apply a mutation to a variable on the current call frame
     */
    async applyMutation(session, callFrameId, varInfo, mutation) {
        try {
            const expression = mutation.expression(varInfo);
            
            const result = await session.send('Debugger.evaluateOnCallFrame', {
                callFrameId: callFrameId,
                expression: expression,
                silent: false
            });
            
            this.mutationsApplied++;
            
            const finding = {
                variable: varInfo.name,
                originalValue: varInfo.value,
                mutationType: mutation.name,
                expression: expression,
                result: result.result?.value,
                error: result.exceptionDetails?.text,
                timestamp: new Date().toISOString()
            };
            
            this.log(`[M] Mutated: ${varInfo.name} (${mutation.name}) → ${expression}`);
            
            if (result.exceptionDetails) {
                this.log(`[!] Mutation error: ${result.exceptionDetails.text}`);
            }
            
            this.findings.push(finding);
            return finding;
            
        } catch (e) {
            this.log(`[!] Mutation failed for ${varInfo.name}: ${e.message}`);
        }
    }

    /**
     * Start the fuzzing loop — set breakpoints, wait for hits, mutate, track sinks
     */
    async startFuzzing(options = {}) {
        const timeout = options.timeout || 300000; // 5 min default
        
        this.log('\n' + '='.repeat(60));
        this.log('ANBU RUNTIME FUZZER — ACTIVE');
        this.log('='.repeat(60));
        this.log(`Profile: ${this.profile?.name || 'default'}`);
        this.log(`Timeout: ${timeout}ms`);
        this.log(`Workers tracked: ${this.workerSessions.size}`);
        this.log('='.repeat(60) + '\n');
        
        // Wait for user interaction or timeout
        return new Promise((resolve) => {
            const timer = setTimeout(async () => {
                this.log('\n[*] Fuzzing timeout reached');
                await this.generateReport();
                resolve(this.findings);
            }, timeout);
            
            // Allow manual stop
            this._stopResolve = () => {
                clearTimeout(timer);
                resolve(this.findings);
            };
        });
    }

    /**
     * Stop fuzzing and generate report
     */
    async stop() {
        this.log('\n[*] Stopping fuzzer...');
        await this.generateReport();
        if (this._stopResolve) this._stopResolve();
    }

    /**
     * Generate findings report
     */
    async generateReport() {
        const report = {
            profile: this.profile?.name,
            target: this.page?.url(),
            timestamp: new Date().toISOString(),
            stats: {
                breakpointHits: this.breakpointHits,
                mutationsApplied: this.mutationsApplied,
                findingsCount: this.findings.length,
                workersTracked: this.workerSessions.size
            },
            networkMutations: this.sinkTracker.getModifiedRequests(),
            findings: this.findings
        };
        
        const reportPath = `${this.options.logDir}/fuzzer-report-${Date.now()}.json`;
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        
        this.log('\n' + '='.repeat(60));
        this.log('ANBU RUNTIME FUZZER — REPORT');
        this.log('='.repeat(60));
        this.log(`Breakpoint hits: ${report.stats.breakpointHits}`);
        this.log(`Mutations applied: ${report.stats.mutationsApplied}`);
        this.log(`Findings: ${report.stats.findingsCount}`);
        this.log(`Modified network requests: ${report.networkMutations.length}`);
        this.log(`Report saved: ${reportPath}`);
        this.log('='.repeat(60));
        
        return report;
    }

    /**
     * Cleanup
     */
    async close() {
        if (this.browser) await this.browser.close();
    }

    log(msg) {
        if (this.options.verbose) console.log(msg);
        // Also append to log file
        const logPath = `${this.options.logDir}/fuzzer.log`;
        fs.appendFileSync(logPath, `${new Date().toISOString()} ${msg}\n`);
    }
}

module.exports = { ANBURuntimeFuzzer };
