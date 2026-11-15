#!/bin/bash
set -euo pipefail

REPO_ROOT="${CI_PRIMARY_REPOSITORY_PATH:-$(git rev-parse --show-toplevel)}"
cd "$REPO_ROOT"

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required to install the pinned mobile toolchain." >&2
  exit 1
fi

if ! brew list --versions node@24 >/dev/null 2>&1; then
  brew install node@24
fi
export PATH="$(brew --prefix node@24)/bin:$PATH"

if ! command -v bun >/dev/null 2>&1 || [[ "$(bun --version)" != "1.4.2" ]]; then
  curl -fsSL https://bun.sh/install | bash -s bun-v1.4.2
fi
export PATH="$HOME/.bun/bin:$PATH"

if [[ "$(node --version)" != v24.* ]]; then
  echo "Expected Node 24; found $(node --version)." >&2
  exit 1
fi
if [[ "$(bun --version)" != "1.4.2" ]]; then
  echo "Expected Bun 1.4.2; found $(bun --version)." >&2
  exit 1
fi

COCOAPODS_VERSION="1.17.0"
if [[ "$(pod --version 2>/dev/null || true)" != "$COCOAPODS_VERSION" ]]; then
  gem install --user-install cocoapods -v "$COCOAPODS_VERSION" --no-document
fi
GEM_BIN="$(ruby -e 'print Gem.user_dir')/bin"
export PATH="$GEM_BIN:$PATH"
if [[ "$(pod --version)" != "$COCOAPODS_VERSION" ]]; then
  echo "Expected CocoaPods $COCOAPODS_VERSION; found $(pod --version)." >&2
  exit 1
fi
echo "Using CocoaPods $(pod --version)."

bun install --frozen-lockfile --filter @openbot/mobile
cd "$REPO_ROOT/apps/mobile/ios"
pod install --deployment
