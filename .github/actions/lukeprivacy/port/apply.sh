#!/usr/bin/env bash
# Apply the LukePrivacy kernel_port into a GKI android14-6.1 kernel source tree.
#
#   ./apply.sh /path/to/kernel-source-root      (the dir with drivers/ fs/ net/ …)
#
# Robust against the line-number shifts that the build's earlier patchers (SUSFS,
# misc, device-patches, NoMount) introduce before this step:
#   - call-site patches apply with patch(1) fuzz+offset, exactly like the build's
#     own patchers (strict `git apply` broke on those shifts);
#   - the Kconfig `source`, Makefile `obj-`, the `#include`, and the defconfig line
#     are injected programmatically (context-independent), never as fragile diffs.
# Fails loudly (non-zero) if any hunk rejects — a safe build-time stop.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KROOT="${1:-}"
[ -n "$KROOT" ] || { echo "usage: $0 <kernel-source-root>"; exit 2; }
[ -d "$KROOT/drivers" ] && [ -d "$KROOT/fs" ] || { echo "!! $KROOT is not a kernel source root"; exit 2; }

echo "==> LukePrivacy kernel_port -> $KROOT"

# 1) driver directory (12 files) + include contract header
mkdir -p "$KROOT/drivers/lukeprivacy" "$KROOT/include/linux"
cp -f "$HERE/drivers/lukeprivacy/"* "$KROOT/drivers/lukeprivacy/"
cp -f "$HERE/include/linux/lukeprivacy.h" "$KROOT/include/linux/lukeprivacy.h"
echo "   [ok] drivers/lukeprivacy/ ($(ls "$HERE/drivers/lukeprivacy" | wc -l) files) + include/linux/lukeprivacy.h"

# 2) call-site patches — tolerant apply (fuzz+offset), forward-only, no backups.
rc=0
for p in "$HERE"/patches/*.patch; do
  b="$(basename "$p")"
  if out=$(cd "$KROOT" && patch -p1 --fuzz=2 --forward --no-backup-if-mismatch < "$p" 2>&1); then
    echo "   [ok]   $b"
  else
    echo "   !! FAILED $b"; echo "$out" | sed 's/^/        /'; rc=1
  fi
done
if find "$KROOT" -name '*.rej' 2>/dev/null | grep -q .; then
  echo "   !! reject files produced:"; find "$KROOT" -name '*.rej' | sed 's/^/        /'; rc=1
fi
[ "$rc" = 0 ] || { echo "!! call-site patch application failed"; exit 1; }

# 2a) build glue — context-independent, idempotent (earlier patchers reshape these)
KC="$KROOT/drivers/Kconfig"; MK="$KROOT/drivers/Makefile"
if ! grep -q 'drivers/lukeprivacy/Kconfig' "$KC"; then
  awk 'BEGIN{last=0}{a[NR]=$0; if($0 ~ /^endmenu/) last=NR}
       END{for(i=1;i<=NR;i++){ if(i==last) print "source \"drivers/lukeprivacy/Kconfig\""; print a[i] }}' \
    "$KC" > "$KC.__lp" && mv "$KC.__lp" "$KC"
  echo "   [ok] drivers/Kconfig source line"
else echo "   [skip] drivers/Kconfig already sourced"; fi
if ! grep -q 'CONFIG_LUKEPRIVACY' "$MK"; then
  printf 'obj-$(CONFIG_LUKEPRIVACY)\t+= lukeprivacy/\n' >> "$MK"
  echo "   [ok] drivers/Makefile obj line"
else echo "   [skip] drivers/Makefile already has obj"; fi

# 2b) inject `#include <linux/lukeprivacy.h>` into the 9 hook-using core files
bash "$HERE/build_integration/inject_include.sh" "$KROOT"

# 3) defconfig: CONFIG_LUKEPRIVACY=y (gki_defconfig is what the GKI build uses)
DEF="$KROOT/arch/arm64/configs/gki_defconfig"
if [ -f "$DEF" ]; then
  if ! grep -q '^CONFIG_LUKEPRIVACY=y' "$DEF"; then
    echo 'CONFIG_LUKEPRIVACY=y' >> "$DEF"; echo "   [ok] CONFIG_LUKEPRIVACY=y -> arch/arm64/configs/gki_defconfig"
  else echo "   [skip] CONFIG_LUKEPRIVACY=y already in gki_defconfig"; fi
else
  echo "   !! arch/arm64/configs/gki_defconfig not found — add CONFIG_LUKEPRIVACY=y manually"
fi

echo "==> done. Confirm CONFIG_LUKEPRIVACY=y in the resulting .config; verify a CLEAN"
echo "    boot before relying on it (recovery: reflash known-good AnyKernel3 or boot luke.enable=0)."
