#!/usr/bin/env bash
# Inject `#include <linux/lukeprivacy.h>` into each core file that carries a
# lukeprivacy call-site — context-independently (after the last top-of-file
# #include, within the first 150 lines), idempotently. Kept OUT of the patches
# on purpose: SUSFS reshapes the include block of some fs/ files (stat.c,
# statfs.c), which conflicts a patch-based include. Run this AFTER all patches.
# fs/proc/generic.c is intentionally excluded — its patch declares what it needs
# inline (extern lp_proc_entry + local lp_skip_hidden) and calls no lp_*_hook.
set -euo pipefail
KROOT="${1:?usage: inject_include.sh <kernel-source-root>}"
INC='#include <linux/lukeprivacy.h>'
FILES="fs/read_write.c fs/open.c fs/stat.c fs/statfs.c kernel/sys.c net/socket.c \
drivers/input/input.c drivers/android/binder.c drivers/android/binder_alloc.c"
for f in $FILES; do
  file="$KROOT/$f"
  [ -f "$file" ] || { echo "  !! missing $f"; exit 1; }
  if grep -qF "$INC" "$file"; then echo "  [skip] include already in $f"; continue; fi
  awk -v inc="$INC" '
    { line[NR]=$0; if ($0 ~ /^#include / && NR<=150) last=NR }
    END { if (!last) { print "NO_INCLUDE_BLOCK" > "/dev/stderr"; exit 3 }
          for (i=1;i<=NR;i++){ print line[i]; if (i==last) print inc } }
  ' "$file" > "$file.__lp" && mv "$file.__lp" "$file"
  echo "  [ok] include -> $f"
done
