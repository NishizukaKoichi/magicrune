const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const ext = os.platform() === 'win32' ? '.exe' : '';
const binaryPath = path.join(__dirname, 'bin', `magicrune${ext}`);

/**
 * Execute MagicRune command programmatically
 * @param {string} command - Command to execute
 * @param {Object} options - Execution options
 * @returns {Promise<{success: boolean, output: string, verdict: string}>}
 */
async function run(command, options = {}) {
  return new Promise((resolve, reject) => {
    const args = ['run', command];
    
    if (options.signature) {
      args.push('--signature', options.signature);
    }
    
    if (options.forceSandbox) {
      args.push('--force-sandbox');
    }
    
    const child = spawn(binaryPath, args, {
      env: process.env,
      cwd: options.cwd || process.cwd(),
    });
    
    let stdout = '';
    let stderr = '';
    
    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    child.on('error', (err) => {
      reject(err);
    });
    
    child.on('exit', (code) => {
      const output = stdout + stderr;
      
      // Parse verdict from output
      let verdict = 'Unknown';
      if (output.includes('(Green)')) verdict = 'Green';
      else if (output.includes('(Yellow)')) verdict = 'Yellow';
      else if (output.includes('(Red)')) verdict = 'Red';
      
      resolve({
        success: code === 0,
        output: output,
        verdict: verdict,
        exitCode: code,
      });
    });
  });
}

/**
 * Analyze command for external sources
 * @param {string} command - Command to analyze
 * @returns {Promise<{isExternal: boolean, detections: Array}>}
 */
async function analyze(command) {
  return new Promise((resolve, reject) => {
    const child = spawn(binaryPath, ['dryrun', command], {
      env: process.env,
    });
    
    let stdout = '';
    
    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    child.on('error', (err) => {
      reject(err);
    });
    
    child.on('exit', (code) => {
      const isExternal = stdout.includes('External source detected');
      
      // Parse detections from output
      const detections = [];
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.includes('- ')) {
          detections.push(line.trim().substring(2));
        }
      }
      
      resolve({
        isExternal,
        detections,
      });
    });
  });
}

module.exports = {
  run,
  analyze,
  binaryPath,
};