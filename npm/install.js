#!/usr/bin/env node

const os = require('os');
const path = require('path');
const fs = require('fs');
const https = require('https');
const tar = require('tar');
const ProgressBar = require('progress');

const REPO = 'NishizukaKoichi/magicrune';
const VERSION = require('./package.json').version;

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();
  
  const mapping = {
    'darwin-x64': 'x86_64-apple-darwin',
    'darwin-arm64': 'aarch64-apple-darwin',
    'linux-x64': 'x86_64-unknown-linux-gnu',
    'win32-x64': 'x86_64-pc-windows-msvc',
  };
  
  const key = `${platform}-${arch}`;
  if (!mapping[key]) {
    throw new Error(`Unsupported platform: ${key}`);
  }
  
  return mapping[key];
}

async function downloadBinary() {
  const platform = getPlatform();
  const ext = os.platform() === 'win32' ? '.exe' : '';
  const filename = `magicrune-${platform}${ext}.tar.gz`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${filename}`;
  
  console.log(`Downloading MagicRune ${VERSION} for ${platform}...`);
  
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Follow redirect
        https.get(response.headers.location, handleResponse);
      } else {
        handleResponse(response);
      }
      
      function handleResponse(res) {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed to download: ${res.statusCode}`));
          return;
        }
        
        const totalSize = parseInt(res.headers['content-length'], 10);
        const progressBar = new ProgressBar('[:bar] :percent :etas', {
          complete: '=',
          incomplete: ' ',
          width: 40,
          total: totalSize
        });
        
        const chunks = [];
        res.on('data', (chunk) => {
          chunks.push(chunk);
          progressBar.tick(chunk.length);
        });
        
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          resolve(buffer);
        });
        
        res.on('error', reject);
      }
    }).on('error', reject);
  });
}

async function extractBinary(buffer) {
  const binDir = path.join(__dirname, 'bin');
  
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }
  
  // Extract tar.gz
  await tar.extract({
    file: buffer,
    cwd: binDir,
    strip: 0,
  });
  
  // Make executable on Unix
  if (os.platform() !== 'win32') {
    const binaryPath = path.join(binDir, 'magicrune');
    fs.chmodSync(binaryPath, 0o755);
  }
  
  console.log('✓ MagicRune installed successfully!');
}

async function main() {
  try {
    const buffer = await downloadBinary();
    await extractBinary(buffer);
  } catch (error) {
    console.error('Installation failed:', error.message);
    process.exit(1);
  }
}

// Don't run during npm publish
if (!process.env.npm_config_dry_run) {
  main();
}