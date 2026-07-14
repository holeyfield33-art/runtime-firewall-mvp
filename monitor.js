// monitor.js - Aletheia Research Monitor (Logging Only, No Blocking)
// Runs 24/7 scanning node_modules for threats and logs them.

const fs = require('fs');
const path = require('path');

// --------------------------------------------------------------
// 1. Load the Firewall's Detection Engine (without the blocking hook)
// --------------------------------------------------------------
let Detector;
try {
    Detector = require('./packages/fw-agent/src/detector').Detector;
} catch (e) {
    console.error('[Monitor] Error: Could not find detector module.');
    console.error('[Monitor] Make sure you are running this from the runtime-firewall-mvp folder.');
    process.exit(1);
}

const detector = new Detector();

// --------------------------------------------------------------
// 2. Configuration
// --------------------------------------------------------------
const TARGET_PROJECT = process.argv[2] || process.cwd();
const TARGET_DIR = path.join(TARGET_PROJECT, 'node_modules');
const LOG_FILE = path.join(__dirname, 'research.log');
const EXTENSIONS = ['.js', '.cjs', '.mjs', '.ts', '.jsx', '.tsx'];

// --------------------------------------------------------------
// 3. Helper: Recursively find all files
// --------------------------------------------------------------
function walkSync(dir, fileList = []) {
    if (!fs.existsSync(dir)) return fileList;
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
            if (file === 'bin' || file === 'dist' || file === 'build' || file === 'docs') continue;
            walkSync(fullPath, fileList);
        } else {
            if (EXTENSIONS.includes(path.extname(file))) {
                fileList.push(fullPath);
            }
        }
    }
    return fileList;
}

// --------------------------------------------------------------
// 4. Scan a single file
// --------------------------------------------------------------
function scanFile(filePath) {
    let content;
    try {
        content = fs.readFileSync(filePath, 'utf8');
        // only skip genuinely unreadable/binary files
    } catch (e) {
        return;
    }

    const result = detector.scanModuleSync(filePath, content, filePath);
    const threats = (result.detections || []).filter(
        d => d.severity === 'CRITICAL' || d.severity === 'HIGH'
    );

    if (threats.length) {
        const key = filePath + ':' + threats.map(t => t.type).join(',');
        if (scanFile._seen && scanFile._seen.has(key)) return; // dedupe repeat watch events
        (scanFile._seen = scanFile._seen || new Set()).add(key);

        const logEntry = {
            timestamp: new Date().toISOString(),
            file: filePath.replace(TARGET_PROJECT, ''),
            action: result.action,
            threats: threats.map(t => ({ type: t.type, severity: t.severity, matched: t.matched })),
        };
        fs.appendFileSync(LOG_FILE, JSON.stringify(logEntry) + '\n');
        console.log(`[MONITOR] Threat found: ${threats.map(t => t.type).join(', ')} in ${path.basename(filePath)}`);
    }
}

// --------------------------------------------------------------
// 5. Full system scan
// --------------------------------------------------------------
function runFullScan() {
    console.log(`[MONITOR] 🚀 Starting 24/7 Research Monitor...`);
    console.log(`[MONITOR] 📂 Watching: ${TARGET_DIR}`);
    console.log(`[MONITOR] 📄 Logging to: ${LOG_FILE}`);
    console.log(`[MONITOR] 🔍 Performing initial full scan...`);

    const files = walkSync(TARGET_DIR);
    console.log(`[MONITOR] Found ${files.length} files to scan.`);

    let count = 0;
    for (const file of files) {
        scanFile(file);
        count++;
        if (count % 100 === 0) {
            console.log(`[MONITOR] Scanned ${count}/${files.length} files...`);
        }
    }
    console.log(`[MONITOR] ✅ Initial scan complete. Now watching for changes...`);
}

// --------------------------------------------------------------
// 6. Watch for new files
// --------------------------------------------------------------
function startWatching() {
    if (!fs.existsSync(TARGET_DIR)) {
        console.log(`[MONITOR] ⚠️ ${TARGET_DIR} does not exist yet. Waiting...`);
        return;
    }
    fs.watch(TARGET_DIR, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        if (!EXTENSIONS.includes(path.extname(filename))) return;
        const fullPath = path.join(TARGET_DIR, filename);
        if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
            console.log(`[MONITOR] 🔄 Change detected: ${filename}`);
            scanFile(fullPath);
        }
    });
    console.log(`[MONITOR] 👀 Watching for new/changed files...`);
}

// --------------------------------------------------------------
// 7. Start
// --------------------------------------------------------------
try {
    runFullScan();
    startWatching();
    console.log(`[MONITOR] Press Ctrl+C to stop monitoring.`);
} catch (e) {
    console.error(`[MONITOR] Fatal error:`, e.message);
}
