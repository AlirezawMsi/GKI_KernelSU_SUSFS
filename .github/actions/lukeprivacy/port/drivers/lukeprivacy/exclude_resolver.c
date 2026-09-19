/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy (built-in kernel port) - Self-contained mandatory exclusions
 * resolver.
 *
 * Reads /data/system/packages.list (Android's package -> UID mapping) directly
 * from kernel space and adds the UIDs of MANDATORY_PACKAGES to g_excluded_uids.
 *
 * Why this lives in the kernel instead of the companion APK:
 *   The four Google services + the local KernelSU manager break very badly
 *   when our hooks tamper with their binder traffic — the system can become
 *   unresponsive or soft-brick before user-space code (BootReceiver, the
 *   APK itself) gets a chance to push UIDs via ctl0. Resolving them in-kernel
 *   the moment /data is mounted closes that window.
 *
 * The companion APK is still authoritative for user-added "extra" packages
 * (it can do live UID lookups via PackageManager); this resolver only
 * handles the always-required baseline.
 *
 * PORT NOTES (vs KernelPatch KPM):
 *   - filp_open()/kernel_read()/filp_close() are called DIRECTLY (built-in
 *     symbols), replacing the KPM kallsyms_lookup_name() resolution dance.
 *   - lp_resolve_excluded_packages() must run from a LATE worker (workqueue),
 *     NOT an initcall: /data (and thus packages.list) is not mounted at boot.
 *     The lazy-retry path (lp_resolver_tick) covers pre-/data hook fires.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/types.h>

#include "profile.h"
#include "lp_log.h"

/* Vendor/OEM/AOSP package prefixes that are unconditionally excluded from
 * all KPM hooks. Any package whose name starts with one of these strings
 * is treated as a system package and must not receive spoofed values. */
static const char *const SYSTEM_PREFIXES[] = {
    "com.android.",
    "com.google.android.",
    "com.qti.",
    "com.qualcomm.",
    "com.samsung.",
    "com.sec.",
    "com.lge.",
    "com.miui.",
    "com.xiaomi.",
    "com.huawei.",
    "com.honor.",
    "com.oppo.",
    "com.oneplus.",
    "com.motorola.",
    "com.sony.",
    "vendor.",
    "system.",
    NULL,
};

static bool pkg_matches_system_prefix(const char *pkg, size_t pkg_len)
{
    for (int i = 0; SYSTEM_PREFIXES[i]; i++) {
        const char *prefix = SYSTEM_PREFIXES[i];
        size_t plen = strlen(prefix);
        if (pkg_len >= plen && !memcmp(pkg, prefix, plen)) return true;
    }
    /* Exact "android" package (UID 1000 owner) */
    if (pkg_len == 7 && !memcmp(pkg, "android", 7)) return true;
    return false;
}

/* Keep this in sync with Exclusions.MANDATORY_PACKAGES in the companion APK
 * (com/luke/shield4/data/model/ProfileConfig.kt). The C list is the
 * authoritative one — it runs whether the APK is installed or not. */
static const char *const MANDATORY_PACKAGES[] = {
    /* --- Critical: actively destabilise the system when hooked --- */
    "com.google.android.as",
    "com.google.android.aicore",
    "com.google.android.as.oss",
    "com.google.android.ondevicepersonalization.services",
    /* Local KernelSU manager rename — hooking the manager itself
     * dead-locks its own UI on resume. Update if the package gets
     * renamed again. */
    "yagyzd.amjlhq.kkingw",

    /* --- Camera apps (GoogleCamera + sub-services). Hooking these
     * with country/imsi/wifi/cell spoofs makes the ML aesthetic scorer
     * and other native camera ML code crash on invalid metadata. */
    "com.google.android.GoogleCamera",
    "com.google.android.apps.camera.services",
    "com.android.cameraextensions",

    /* --- Telephony / RCS. Read SubscriptionInfo / ServiceState / TM
     * identifiers at startup and on every package-data-cleared broadcast;
     * without an explicit exclusion RcsProvisioningMonitor NPEs on a
     * missing ICCID → "RcsService keeps stopping" after any pm clear. */
    "com.google.android.ims",
    "com.google.android.apps.messaging",
    "com.android.phone",

    /* --- Precautionary: zero overlap with hook patterns. --- */
    "com.google.android.calculator",
    "com.google.android.deskclock",
    "com.google.android.tts",
    "com.google.android.markup",
    "com.google.android.apps.recorder",
    "com.google.android.apps.turbo",
    "com.google.android.apps.wallpaper",
    "com.google.android.apps.wallpaper.pixel",
    "com.android.wallpaper.livepicker",
    "com.google.android.printservice.recommendation",

    NULL,
};

#define PACKAGES_LIST_PATH "/data/system/packages.list"

/* Read in 4 KB slices and accumulate one logical line at a time so we never
 * need a multi-MB heap buffer. packages.list lines are comfortably under
 * 512 bytes (longest data_dir we've seen is ~200 chars). */
#define READ_CHUNK_BYTES 4096
#define MAX_LINE_BYTES   512

/* True once the resolver succeeded at least once. Hooks check this before
 * paying the open()/read()/parse cost on the slow path. */
static bool g_packages_resolved = false;

/* ── uid -> package-name map for per-package identifier derivation ────────
 * Populated in the SAME packages.list pass that resolves exclusions. Only
 * app UIDs (>= 10000, non-system) are stored. Deriving an identifier off the
 * stable package name instead of the UID means a reinstall (which reassigns
 * the UID) still yields the same value, so a backed-up identity restores
 * faithfully. */
#define LP_MAX_APP_PKGS 512
#define LP_PKG_NAME_MAX 128
struct lp_uid_pkg { __u32 uid; char pkg[LP_PKG_NAME_MAX]; };
static struct lp_uid_pkg g_uid_pkg[LP_MAX_APP_PKGS];
static int g_uid_pkg_count = 0;

const char *lp_pkg_for_uid(__u32 uid)
{
    for (int i = 0; i < g_uid_pkg_count; i++) {
        if (g_uid_pkg[i].uid == uid) return g_uid_pkg[i].pkg;
    }
    return NULL;
}

/* First-seen wins (a shared UID keeps its first package). No lock: writes
 * happen only in the resolver (late worker / ctl0), reads only in hooks; a
 * torn read during a rare concurrent refresh falls back to UID derivation,
 * which is benign. */
static void uid_pkg_store(__u32 uid, const char *pkg, size_t pkg_len)
{
    if (g_uid_pkg_count >= LP_MAX_APP_PKGS) return;
    for (int i = 0; i < g_uid_pkg_count; i++) {
        if (g_uid_pkg[i].uid == uid) return;
    }
    size_t n = (pkg_len < LP_PKG_NAME_MAX - 1) ? pkg_len : (LP_PKG_NAME_MAX - 1);
    struct lp_uid_pkg *e = &g_uid_pkg[g_uid_pkg_count++];
    e->uid = uid;
    memcpy(e->pkg, pkg, n);
    e->pkg[n] = '\0';
}

/* Throttle lazy retries from hook fast paths. The first ~thousand hook
 * invocations after boot will hit this; once /data is up the very next
 * one resolves and the flag flips, so we don't keep banging on the FS. */
static unsigned int g_resolve_throttle = 0;
#define RESOLVE_RETRY_EVERY 4096

/* Match a package list token against MANDATORY_PACKAGES entries. A trailing
 * `*` in an entry means prefix match; otherwise exact match. */
static bool is_mandatory_package(const char *tok, size_t tok_len)
{
    for (int i = 0; MANDATORY_PACKAGES[i]; i++) {
        const char *pat = MANDATORY_PACKAGES[i];
        size_t pat_len = strlen(pat);
        if (pat_len > 0 && pat[pat_len - 1] == '*') {
            size_t prefix_len = pat_len - 1;
            if (tok_len < prefix_len) continue;
            if (!memcmp(pat, tok, prefix_len)) return true;
            continue;
        }
        if (pat_len != tok_len) continue;
        if (!memcmp(pat, tok, tok_len)) return true;
    }
    return false;
}

/* Parse `<pkg> <uid> ...` from a line. Returns 0 on success. */
static int parse_line(const char *line, size_t len,
                      const char **pkg_out, size_t *pkg_len_out,
                      __u32 *uid_out)
{
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i >= len) return -1;

    size_t pkg_start = i;
    while (i < len && line[i] != ' ' && line[i] != '\t') i++;
    if (i >= len) return -1;
    size_t pkg_len = i - pkg_start;
    if (pkg_len == 0) return -1;

    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i >= len) return -1;
    if (line[i] < '0' || line[i] > '9') return -1;

    __u32 uid = 0;
    while (i < len && line[i] >= '0' && line[i] <= '9') {
        uid = uid * 10 + (line[i] - '0');
        i++;
    }

    *pkg_out = &line[pkg_start];
    *pkg_len_out = pkg_len;
    *uid_out = uid;
    return 0;
}

static bool already_excluded(__u32 uid)
{
    for (int j = 0; j < g_excluded_uids_count; j++) {
        if (g_excluded_uids[j] == uid) return true;
    }
    return false;
}

static void process_line(const char *line, size_t len)
{
    const char *pkg = NULL;
    size_t pkg_len = 0;
    __u32 uid = 0;
    if (parse_line(line, len, &pkg, &pkg_len, &uid) != 0) return;
    if (!is_mandatory_package(pkg, pkg_len) && !pkg_matches_system_prefix(pkg, pkg_len)) {
        /* Not excluded → it's a spoof-target app. Record uid->pkg so SSAID /
         * MediaDRM derive off the package name (reinstall-stable). */
        if (uid >= 10000) uid_pkg_store(uid, pkg, pkg_len);
        return;
    }
    if (already_excluded(uid)) return;
    if (g_excluded_uids_count >= LP_MAX_EXCLUDED_UIDS) return;
    g_excluded_uids[g_excluded_uids_count++] = uid;
    lp_dbg("lukeprivacy: auto-excluded uid=%u pkg=%.*s\n",
            uid, (int)pkg_len, pkg);
}

/* Read packages.list, resolve mandatory entries. Returns the number of
 * entries newly added (>= 0) or a negative errno-style code on failure.
 *
 * MUST be called from a late worker (workqueue) — /data is not mounted at
 * boot, so filp_open() before that returns -ENOENT and we lazy-retry. */
int lp_resolve_excluded_packages(void)
{
    struct file *fp;
    static char chunk[READ_CHUNK_BYTES];
    static char line[MAX_LINE_BYTES];
    size_t line_pos = 0;
    int added_before;
    loff_t pos = 0;

    if (g_packages_resolved) return 0;

    fp = filp_open(PACKAGES_LIST_PATH, O_RDONLY, 0);
    if (IS_ERR(fp) || !fp) {
        /* /data not up yet (or transient) — leave g_packages_resolved
         * false so lp_resolver_tick() retries later. */
        return -1;
    }

    /* Rebuild the uid->pkg map from scratch each full pass (a refresh after a
     * post-boot install must not accumulate stale UID rows). */
    g_uid_pkg_count = 0;

    line_pos = 0;
    added_before = g_excluded_uids_count;

    for (;;) {
        ssize_t n = kernel_read(fp, chunk, sizeof(chunk), &pos);
        if (n <= 0) break;

        for (ssize_t i = 0; i < n; i++) {
            char c = chunk[i];
            if (c == '\n') {
                if (line_pos > 0) process_line(line, line_pos);
                line_pos = 0;
            } else if (line_pos < sizeof(line) - 1) {
                line[line_pos++] = c;
            }
            /* If a line overflows MAX_LINE_BYTES we drop the rest of the
             * line — the package name is at the very start, so anything
             * we cared about has already been captured. */
        }
    }
    /* Tail line without trailing newline */
    if (line_pos > 0) process_line(line, line_pos);

    filp_close(fp, NULL);

    int added = g_excluded_uids_count - added_before;
    /* "Resolved" means we successfully read the file. Even an empty match
     * count counts — it just means none of MANDATORY_PACKAGES is installed
     * on this device, and we shouldn't keep retrying. */
    g_packages_resolved = true;
    return added;
}

void lp_force_resolve_retry(void)
{
    g_packages_resolved = false;
    g_resolve_throttle = 0;
}

/* Cheap fast-path probe for hooks. Most invocations are no-ops once the
 * resolver has succeeded; before that we throttle real attempts. */
void lp_resolver_tick(void)
{
    if (g_packages_resolved) return;
    if ((++g_resolve_throttle % RESOLVE_RETRY_EVERY) != 0) return;
    lp_resolve_excluded_packages();
}
