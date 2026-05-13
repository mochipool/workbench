#!/usr/bin/env sh
set -eu

IOG_CACHE="https://cache.iog.io"
IOG_KEY="hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="

SYSTEM_CONF="/etc/nix/nix.custom.conf"
USER_CONF="$HOME/.config/nix/nix.conf"
TRUSTED_SETTINGS="$HOME/.local/share/nix/trusted-settings.json"

TARGET="${1:-.#mainnet}"

echo "==> Clearing remembered flake trust prompts"
rm -f "$TRUSTED_SETTINGS"

echo "==> Preparing Determinate Nix custom config"
sudo mkdir -p /etc/nix
sudo touch "$SYSTEM_CONF"

BACKUP="$SYSTEM_CONF.bak.$(date +%Y%m%d-%H%M%S)"
sudo cp "$SYSTEM_CONF" "$BACKUP"
echo "==> Backed up $SYSTEM_CONF to $BACKUP"

TMP="$(mktemp)"

sudo awk '
  /cache\.iog\.io:f\/Ea\+s\+dFdN\+3Y\/G\+FDgSq\+a5NEWhJGzdjvKNGv0\/EQ=/ { next }
  /hydra\.iohk\.io:f\/Ea\+s\+dFdN\+3Y\/G\+FDgSq\+a5NEWhJGzdjvKNGv0\/EQ=/ { next }
  /trusted-substituters[[:space:]]*=.*cache\.iog\.io/ { next }
  /extra-trusted-substituters[[:space:]]*=.*cache\.iog\.io/ { next }
  { print }
' "$SYSTEM_CONF" > "$TMP"

printf '%s\n' \
  "extra-trusted-substituters = $IOG_CACHE" \
  "extra-trusted-public-keys = $IOG_KEY" \
  >> "$TMP"

sudo cp "$TMP" "$SYSTEM_CONF"
rm -f "$TMP"

echo "==> Restarting nix-daemon"
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl restart nix-daemon
elif command -v launchctl >/dev/null 2>&1; then
  sudo launchctl kickstart -k system/org.nixos.nix-daemon
else
  echo "ERROR: could not find systemctl or launchctl to restart nix-daemon" >&2
  exit 1
fi

echo "==> Updating per-user Nix config"
mkdir -p "$HOME/.config/nix"
touch "$USER_CONF"

grep -q '^extra-substituters = .*cache\.iog\.io' "$USER_CONF" 2>/dev/null \
  || printf '%s\n' "extra-substituters = $IOG_CACHE" >> "$USER_CONF"

grep -q '^allow-import-from-derivation = true' "$USER_CONF" 2>/dev/null \
  || printf '%s\n' 'allow-import-from-derivation = true' >> "$USER_CONF"

echo "==> Verifying active config"
nix config show trusted-public-keys | grep -q 'hydra.iohk.io:' \
  || { echo "ERROR: hydra.iohk.io key is still missing from trusted-public-keys" >&2; exit 1; }

nix config show trusted-substituters | grep -q 'https://cache.iog.io' \
  || { echo "ERROR: cache.iog.io is still missing from trusted-substituters" >&2; exit 1; }
