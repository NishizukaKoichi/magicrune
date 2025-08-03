#!/bin/bash
set -euo pipefail

# MagicRune release script

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh 0.1.0"
    exit 1
fi

echo "Releasing MagicRune v$VERSION"

# Update version in Cargo.toml files
echo "Updating version numbers..."
find . -name "Cargo.toml" -exec sed -i.bak "s/version = \"0.1.0\"/version = \"$VERSION\"/g" {} \;
find . -name "*.bak" -delete

# Build for multiple targets
echo "Building release binaries..."
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-pc-windows-msvc"
)

mkdir -p dist

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    if cargo build --release --target "$target" 2>/dev/null; then
        cp "target/$target/release/magicrune" "dist/magicrune-$target" 2>/dev/null || \
        cp "target/$target/release/magicrune.exe" "dist/magicrune-$target.exe" 2>/dev/null || true
    else
        echo "Warning: Could not build for $target"
    fi
done

# Create release archives
echo "Creating release archives..."
cd dist
for file in magicrune-*; do
    if [ -f "$file" ]; then
        tar czf "$file.tar.gz" "$file"
        echo "Created $file.tar.gz"
    fi
done
cd ..

# Generate changelog
echo "Generating changelog..."
cat > CHANGELOG.md << EOF
# Changelog

## v$VERSION - $(date +%Y-%m-%d)

### Added
- Initial release of MagicRune Policy Runner
- Automatic external source detection
- Multi-platform sandbox support (Linux, macOS, Windows)
- Behavior analysis and risk scoring
- Signature verification system
- Audit logging
- CI/CD integration

### Security
- Enforced sandbox execution for external code
- Multi-layer defense with namespaces, chroot, and seccomp
- Protection against malware, information leakage, and privilege escalation

EOF

# Create git tag
echo "Creating git tag..."
git add -A
git commit -m "Release v$VERSION"
git tag -a "v$VERSION" -m "Release version $VERSION"

echo "Release preparation complete!"
echo ""
echo "Next steps:"
echo "1. Push to GitHub: git push origin main --tags"
echo "2. Create GitHub Release and upload dist/*.tar.gz files"
echo "3. Publish to crates.io: cargo publish -p magicrune-policy && ..."
echo "4. Update homebrew formula"