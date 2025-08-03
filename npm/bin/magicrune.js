#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const ext = os.platform() === 'win32' ? '.exe' : '';
const binaryPath = path.join(__dirname, `magicrune${ext}`);

// Pass through all arguments
const args = process.argv.slice(2);

const child = spawn(binaryPath, args, {
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (err) => {
  if (err.code === 'ENOENT') {
    console.error('MagicRune binary not found. Try reinstalling:');
    console.error('  npm install -g @magicrune/cli');
  } else {
    console.error('Failed to run MagicRune:', err.message);
  }
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});