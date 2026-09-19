#!/usr/bin/env python3
"""
LukePrivacy kernel_port — patch generator.

Ports Luke's 6.1.99 call-site edits (extracted from reference_6.1.99/, which is
LukeKPMAPatch/staging_aosp/) onto PRISTINE GKI android14-6.1 (~6.1.145) source
in pristine/ (fetched from android.googlesource.com), and emits one unified
diff per core file into patches/.

Design: every edit is located by STRIPPED-CONTENT match (whitespace-robust) and
guarded by an exact-count assertion. A wrong/ambiguous anchor makes this script
FAIL LOUDLY naming the file+anchor — it never emits a mis-placed patch. A patch
that later fails to `git apply` (context drift vs the builder's exact sublevel)
is a SAFE, build-time failure, not a bootloop. Re-run after refreshing pristine/.
"""
import os, sys, difflib

ROOT = os.path.dirname(os.path.abspath(__file__))
PRISTINE = os.path.join(ROOT, "pristine")
EDITED   = os.path.join(ROOT, "edited")
PATCHES  = os.path.join(ROOT, "patches")

INCLUDE_LINE = "#include <linux/lukeprivacy.h>"

def die(msg):
    print(f"  !! FAIL: {msg}")
    sys.exit(1)

def add_include(lines):
    # The `#include <linux/lukeprivacy.h>` line is deliberately NOT emitted as a
    # patch hunk. SUSFS adds its own includes to the top of several fs/ files
    # (verified: fs/stat.c, fs/statfs.c), which shifts the include-block context
    # and makes a patch-based include insertion conflict. The lukeprivacy
    # composite action instead injects the include with a context-independent
    # script (after the last top-of-file #include), idempotently, AFTER every
    # other patcher (SUSFS/KSU/...) has run. So this is intentionally a no-op —
    # the patches carry only the hook CALL-SITES, which do not conflict.
    return

def func_span(lines, sig, f):
    starts = [i for i, l in enumerate(lines) if sig in l]
    if not starts:
        die(f"{f}: func sig not found: {sig!r}")
    for s in starts:                      # skip forward-decls (no brace before ';')
        b = None
        for i in range(s, min(s + 12, len(lines))):
            if lines[i].strip() == "{":
                b = i; break
            if lines[i].rstrip().endswith(";"):
                break
        if b is None:
            continue
        for i in range(b + 1, len(lines)):
            if lines[i] == "}":
                return s, i
    die(f"{f}: could not span func: {sig!r}")

def match_idxs(lines, stripped, lo, hi):
    return [i for i in range(lo, hi + 1) if lines[i].strip() == stripped]

def op_span(lines, f, sig, stripped, new, mode):
    s, e = func_span(lines, sig, f)
    idxs = match_idxs(lines, stripped, s, e)
    if len(idxs) != 1:
        die(f"{f}: {stripped!r} matched {len(idxs)}x in {sig!r} (need 1)")
    i = idxs[0]
    if mode == "before":   lines[i:i]   = new
    elif mode == "after":  lines[i+1:i+1] = new
    elif mode == "replace":lines[i:i+1] = new

def op_global(lines, f, stripped, new, mode, prev=None):
    idxs = [i for i in range(len(lines))
            if lines[i].strip() == stripped and (prev is None or lines[i-1].strip() == prev)]
    if len(idxs) != 1:
        die(f"{f}: global {stripped!r}(prev={prev!r}) matched {len(idxs)}x (need 1)")
    i = idxs[0]
    if mode == "before":   lines[i:i]   = new
    elif mode == "after":  lines[i+1:i+1] = new
    elif mode == "replace":lines[i:i+1] = new

def op_contains(lines, f, substr, new, mode):
    idxs = [i for i in range(len(lines)) if substr in lines[i]]
    if len(idxs) != 1:
        die(f"{f}: contains {substr!r} matched {len(idxs)}x (need 1)")
    i = idxs[0]
    if mode == "before":   lines[i:i]   = new
    elif mode == "after":  lines[i+1:i+1] = new
    elif mode == "replace":lines[i:i+1] = new

def insert_block_before(lines, f, sig_line_substr, block):
    idxs = [i for i, l in enumerate(lines) if sig_line_substr in l]
    if len(idxs) != 1:
        die(f"{f}: block anchor {sig_line_substr!r} matched {len(idxs)}x (need 1)")
    lines[idxs[0]:idxs[0]] = block

PROC_HELPER = [
    "#ifdef CONFIG_LUKEPRIVACY",
    "/* Hidden control node: keep it out of /proc readdir (still openable by exact",
    " * path, gated to the authorized UID set). Skipped at every traversal point so",
    " * pos accounting stays consistent — it is simply invisible in the listing. */",
    "extern struct proc_dir_entry *lp_proc_entry;",
    "static inline struct proc_dir_entry *lp_skip_hidden(struct proc_dir_entry *de)",
    "{",
    "\treturn (de && de == lp_proc_entry) ? pde_subdir_next(de) : de;",
    "}",
    "#else",
    "static inline struct proc_dir_entry *lp_skip_hidden(struct proc_dir_entry *de)",
    "{",
    "\treturn de;",
    "}",
    "#endif",
    "",
]

def port(f, fn):
    src = os.path.join(PRISTINE, f)
    if not os.path.isfile(src):
        die(f"pristine missing: {f}")
    with open(src, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    orig = text.splitlines()
    lines = list(orig)
    fn(lines)
    # write edited + diff
    dst = os.path.join(EDITED, f)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    diff = list(difflib.unified_diff(
        [l + "\n" for l in orig], [l + "\n" for l in lines],
        fromfile=f"a/{f}", tofile=f"b/{f}", n=3))
    flat = f.replace("/", "__") + ".patch"
    with open(os.path.join(PATCHES, flat), "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(diff)
    adds = sum(1 for d in diff if d.startswith("+") and not d.startswith("+++"))
    dels = sum(1 for d in diff if d.startswith("-") and not d.startswith("---"))
    print(f"  OK  {f:34s} -> patches/{flat}   (+{adds} -{dels})")

# ---- per-file edit programs -------------------------------------------------
def e_read_write(L):
    add_include(L)
    op_span(L, "fs/read_write.c", "ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)",
            "return ret;", ["\tif (ret > 0)", "\t\tret = lp_read_hook((int)fd, buf, ret);"], "before")
    op_span(L, "fs/read_write.c", "ssize_t ksys_pread64(unsigned int fd, char __user *buf, size_t count,",
            "return ret;", ["\tif (ret > 0)", "\t\tret = lp_read_hook((int)fd, buf, ret);"], "before")

def e_open(L):
    add_include(L)
    op_global(L, "fs/open.c", "putname(tmp);",
              ["\tif (fd >= 0)", "\t\tlp_openat_hook(dfd, filename, (int)how->flags, fd);"], "after")
    op_global(L, "fs/open.c", "int retval = close_fd(fd);",
              ["", "\tlp_close_hook((int)fd);"], "after")

def e_stat(L):
    add_include(L)
    op_span(L, "fs/stat.c", "SYSCALL_DEFINE4(newfstatat, int, dfd", "return cp_new_stat(&stat, statbuf);",
            ["\terror = cp_new_stat(&stat, statbuf);",
             "\tlp_stat_hook(LP_STAT_NEWFSTATAT, filename, statbuf, error);",
             "\treturn error;"], "replace")
    op_span(L, "fs/stat.c", "SYSCALL_DEFINE2(newfstat, unsigned int, fd", "return error;",
            ["\tlp_stat_hook(LP_STAT_FSTAT, NULL, statbuf, error);"], "before")
    op_span(L, "fs/stat.c", "SYSCALL_DEFINE5(statx,", "return ret;",
            ["\tlp_stat_hook(LP_STAT_STATX, filename, buffer, ret);"], "before")

def e_statfs(L):
    add_include(L)
    op_span(L, "fs/statfs.c", "SYSCALL_DEFINE2(statfs,", "return error;",
            ["\tlp_statfs_hook(buf, error);"], "before")
    op_span(L, "fs/statfs.c", "SYSCALL_DEFINE2(fstatfs,", "return error;",
            ["\tlp_statfs_hook(buf, error);"], "before")

def e_sys(L):
    add_include(L)
    op_span(L, "kernel/sys.c", "SYSCALL_DEFINE5(prctl,", "long error;",
            ["", "\tlp_prctl_hook();"], "after")

def e_socket(L):
    add_include(L)
    op_span(L, "net/socket.c", "int __sys_recvfrom(", "fput_light(sock->file, fput_needed);",
            ["\tlp_recv_hook(fd, ubuf, size, err, false);"], "after")

def e_input(L):
    add_include(L)
    op_span(L, "drivers/input/input.c", "void input_inject_event(",
            "if (is_event_supported(type, dev->evbit, EV_MAX)) {",
            ["\tlp_touch_capture_hook(handle, type, code, value);", ""], "before")

def e_binder(L):
    add_include(L)
    op_global(L, "drivers/android/binder.c", "trace_binder_ioctl_done(ret);",
              ["\tlp_ioctl_hook(cmd, arg, ret);"], "after")

def e_binder_alloc(L):
    add_include(L)
    op_global(L, "drivers/android/binder_alloc.c", "buffers = 0;",
              ["\tlp_binder_alloc_release_hook(alloc);", ""], "before")
    op_global(L, "drivers/android/binder_alloc.c", "INIT_LIST_HEAD(&alloc->buffers);",
              ["\tlp_binder_alloc_init_hook(alloc);"], "after")
    op_global(L, "drivers/android/binder_alloc.c", "if (!check_buffer(alloc, buffer, buffer_offset, bytes))",
              ["\tlp_binder_copy_to_buffer_hook(alloc, buffer, buffer_offset, from, bytes);", ""],
              "before", prev="{")
    op_global(L, "drivers/android/binder_alloc.c",
              "return binder_alloc_do_buffer_copy(alloc, true, buffer, buffer_offset,",
              ["\tlp_binder_copy_to_buffer_gnss_hook(src, bytes);"], "before")

def e_proc_generic(L):
    insert_block_before(L, "fs/proc/generic.c",
                        "int proc_readdir_de(struct file *file, struct dir_context *ctx,", PROC_HELPER)
    op_global(L, "fs/proc/generic.c", "de = pde_subdir_first(de);",
              ["\tde = lp_skip_hidden(pde_subdir_first(de));"], "replace")
    op_global(L, "fs/proc/generic.c", "de = pde_subdir_next(de);",
              ["\t\tde = lp_skip_hidden(pde_subdir_next(de));"], "replace")
    op_global(L, "fs/proc/generic.c", "next = pde_subdir_next(de);",
              ["\t\tnext = lp_skip_hidden(pde_subdir_next(de));"], "replace")

def e_drivers_kconfig(L):
    op_contains(L, "drivers/Kconfig", 'source "drivers/hte/Kconfig"',
                ["", 'source "drivers/lukeprivacy/Kconfig"'], "after")

def e_drivers_makefile(L):
    op_contains(L, "drivers/Makefile", "+= hte/",
                ["obj-$(CONFIG_LUKEPRIVACY)\t+= lukeprivacy/"], "after")

# NOTE: drivers/Kconfig and drivers/Makefile are NOT patched here. Their one-line
# additions (source "drivers/lukeprivacy/Kconfig" + obj-$(CONFIG_LUKEPRIVACY) +=
# lukeprivacy/) are injected programmatically by apply.sh — a context diff there is
# fragile because earlier build patchers (susfs/misc/etc.) shift those files.
FILES = [
    ("fs/read_write.c", e_read_write),
    ("fs/open.c", e_open),
    ("fs/stat.c", e_stat),
    ("fs/statfs.c", e_statfs),
    ("kernel/sys.c", e_sys),
    ("net/socket.c", e_socket),
    ("drivers/input/input.c", e_input),
    ("drivers/android/binder.c", e_binder),
    ("drivers/android/binder_alloc.c", e_binder_alloc),
    ("fs/proc/generic.c", e_proc_generic),
]

if __name__ == "__main__":
    os.makedirs(PATCHES, exist_ok=True)
    print("Porting Luke 6.1.99 call-sites -> pristine android14-6.1 (~6.1.145):")
    for f, fn in FILES:
        port(f, fn)
    print(f"\nDone. {len(FILES)} patches written to patches/.")
