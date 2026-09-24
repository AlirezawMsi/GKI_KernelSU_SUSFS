/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy KPM - Pure kernel-level device spoofing
 * Copyright (C) 2026
 */

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/reboot.h>
#include <linux/random.h>
#include "profile.h"
#include "uaccess.h"

/* Port note: KernelPatch's runtime kallsyms resolve of _copy_{from,to}_user is
 * gone — built into the kernel, we call the real symbols directly. The wrapper
 * names are kept so every hook body that uses lp_copy_from_user()/
 * lp_copy_to_user_raw() compiles unchanged. */
int lp_init_uaccess(void)
{
    return 0;
}

unsigned long g_last_raw_not_copied = 9999;

long lp_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long not_copied = copy_from_user(to, from, n);
    g_last_raw_not_copied = not_copied;
    return (long)(n - not_copied);
}

long lp_copy_to_user_raw(void __user *to, const void *from, unsigned long n)
{
    unsigned long not_copied = copy_to_user(to, from, n);
    return (long)(n - not_copied);
}

/* Port: ctl0 replied into a __user buffer via KP's compat_copy_to_user. Now the
 * reply goes into a KERNEL buffer that the /proc read handler renders — this is
 * a bounded memcpy (callers pass a sufficiently large kernel buffer). */
static void compat_copy_to_user(char *dst, const void *src, unsigned long n)
{
    if (dst)
        memcpy(dst, src, n);
}

struct spoof_profile g_profile = {
    .gsf_id = "0000000000000000",
    .advertising_id = "00000000-0000-0000-0000-000000000000",
    /* Empty by default — passive until companion APK pushes a proper
     * 22-char base64url FID via set_firebase_id. The legacy UUID-format
     * placeholder here was the bug: read_hook tried to write a 36-char
     * UUID into a 22-char Fid slot, spoof_xml_value rejected (new_len >
     * value_len), spoof silently no-op'd. Companion APK's Firebase FID
     * toggle now controls activation. */
    .firebase_id = "",
    /* All identity fields default to empty so the per-hook bail-out
     * guards in binder_hook.c (`if (!g_profile.imsi[0]) return false;`
     * etc.) are effective on fresh load. The earlier defaults of "000…"
     * digit-strings and "00:00:…" MACs had [0] != 0, which made the
     * empty-field gate ineffective — every SIM/ID reply that matched
     * the structural anchors was rewritten with garbage zeros on a
     * fresh boot before companion APK Save had a chance to push real
     * (or cleared) values. Default empty = module fully passive until
     * Save. */
    .imei = "",
    .imsi = "",
    .iccid = "",
    .serial = "",
    .fingerprint = "",
    .model = "",
    .manufacturer = "",
    .brand = "",
    .device = "",
    .product = "",
    .board = "",
    .bluetooth_mac = "",
    .wifi_mac = "",
    .mcc = "",
    .mnc = "",
    .mccmnc = "",
    .country_iso = "",
    .operator_name = "",
    .phone_number = "",
    /* Empty string = hook deactivated. Hook in binder_hook.c gates on
     * mediadrm_id[0] != 0; if companion APK never pushes a real value
     * (toggle off, fresh boot before Save), TikTok / Widevine apps see the
     * REAL hardware HMAC instead of garbage zeros. Previous default
     * "0000..." had [0]='0'!=0 so hook fired and wrote 32 raw 0x00 bytes —
     * that's a stronger spoof tell than the real value. */
    .mediadrm_id = "",
    /* try_hide_dev_settings's adb-hide gate. Default off — module fully
     * passive on fresh load until companion APK Save pushes the toggle
     * state. (android_id_hide_enabled removed 2026-05-09 — see
     * try_hide_dev_settings comment for the reasoning.) */
    .adb_hide_enabled = false,
    .android_id_seed = "",
    .android_id_spoof_enabled = false,
    .ssaid_relaxed_enabled = false,
    .ssaid_relaxed_target_uid = 0,
    /* Sensor bias spoof. Both toggles default OFF on KPM init; companion
     * APK pushes the active state on Save. Reboot autoload reinitialises
     * the struct, resetting them to false — that's the "po reboocie
     * wyłączone" semantics. */
    .sensor_accel_spoof_enabled = false,
    .sensor_gyro_spoof_enabled = false,
    .sensor_mag_spoof_enabled = false,
    .sensor_held_enabled = false,

    /* Keva write hook (A3). Default OFF — opt-in. keva_seed empty = use
     * android_id_seed as fallback. */
    .keva_spoof_enabled = false,
    .keva_seed = "",

    /* GAID binder re-enable (A6). Default OFF — opt-in. */
    .gaid_binder_reenabled = false,

    /* HostProcessBridge IPC hook (A7). Default OFF — opt-in. */
    .hostprocess_bridge_enabled = false,

    /* /proc/version UID-redirect flag (A4). Default OFF. Existing
     * FD_TYPE_PROC_VERSION tracking in read_hook covers most cases;
     * this flag enables the counter and potential future extension. */
    .proc_version_uid_redirect_enabled = false,
    .boot_id_spoof_enabled = false,

    /* Timezone binder hook (A8). Companion handles via resetprop;
     * binder hook not implemented. Flag reserved for future use. */
    .timezone_binder_enabled = false,

    /* eventTime timeline offset — off until newIdentity sets a per-account value. */
    .eventtime_offset_enabled = false,
    .eventtime_offset_ns = 0,
    .eventtime_target_uid = 0,

    /* Block Store neutralization — all OFF until the companion pushes the key +
     * Snap uid and arms it at newIdentity. Resets to OFF on every boot autoload
     * (static init), so it never fires inertly against an unintended UID. */
    .blockstore_neutralize_enabled = false,
    .blockstore_target_uid = 0,
    .blockstore_key = "",
    .blockstore_fire_cap = 0,
    .blockstore_capture_enabled = false,
};

bool g_hooks_enabled = true;

/* Bootloop safety valve (kernel_port addition, 2026-09-19): boot with
 * `luke.enable=0` on the kernel command line to force every hook off AND skip
 * lp_init entirely (no /proc node, no *_hook_init) — a clean stock boot for
 * recovery without reflashing. The 7 hook entrypoints already early-return on
 * !g_hooks_enabled; this also short-circuits init-time work (incl. sensor_hook's
 * kallsyms resolves). Absent the param, behaviour is unchanged. */
static int __init lp_enable_setup(char *s)
{
    if (s && (*s == '0' || *s == 'n' || *s == 'N' || *s == 'f' || *s == 'F'))
        g_hooks_enabled = false;
    return 1;
}
__setup("luke.enable=", lp_enable_setup);

__u32 g_excluded_uids[LP_MAX_EXCLUDED_UIDS];
int g_excluded_uids_count = 0;

/* FORCE-SPOOF override — UIDs here are ALWAYS spoofed even though they are
 * system apps / in the exclude list / matched by the resolver's system-prefix.
 * Experimental: lets us spoof com.google.android.gms/gsf/vending so GMS sends
 * fake serial/MAC/IDs at checkin → Google issues a different GSF android_id →
 * breaks the device-identity anchor. Risk: GMS "action required" / DF-DFERH-01.
 * Pushed via ctl0 set_force_spoof_uids:CSV; cleared by clear_force_spoof_uids.
 * Default empty → no override. Resets on boot (static). */
#define LP_MAX_FORCE_SPOOF 64
__u32 g_force_spoof_uids[LP_MAX_FORCE_SPOOF];
int g_force_spoof_count = 0;

/* config.gz hide list — UIDs that get -ENOENT on open("/proc/config.gz") so
 * Play Integrity / DroidGuard (running in the GMS uid) can't read CONFIG_KSU/
 * SUSFS/LUKEPRIVACY out of the kernel config. TARGETED at the GMS uid ONLY
 * (pushed at runtime via /proc/luke set_configgz_uids:CSV) — never IG or other
 * apps, so signups are never disturbed. Default empty → hides from nobody. */
#define LP_MAX_CONFIGGZ 8
__u32 g_configgz_uids[LP_MAX_CONFIGGZ];
int g_configgz_count = 0;

bool lp_uid_hides_configgz(int uid)
{
    if (g_configgz_count <= 0) return false;
    __u32 b = (__u32)uid % 100000;
    for (int i = 0; i < g_configgz_count && i < LP_MAX_CONFIGGZ; i++) {
        __u32 f = g_configgz_uids[i];
        if (f == 0) continue;
        if (f == (__u32)uid || f == b || f % 100000 == b) return true;
    }
    return false;
}

/* U18 sensor-motion include list — identity-EXCLUDED uids (the GMS/DroidGuard uid)
 * that STILL receive the handheld sensor motion, so DroidGuard does not sample a
 * dead-flat device (audit S1). Motion only, zero static bias (see sensor_hook.c).
 * Pushed at runtime via /proc/luke set_sensor_include:CSV. Default empty. */
#define LP_MAX_SENSOR_INCL 8
__u32 g_sensor_incl_uids[LP_MAX_SENSOR_INCL];
int g_sensor_incl_count = 0;

bool lp_uid_sensor_included(__u32 uid)
{
    if (g_sensor_incl_count <= 0) return false;
    __u32 b = uid % 100000;
    for (int i = 0; i < g_sensor_incl_count && i < LP_MAX_SENSOR_INCL; i++) {
        __u32 f = g_sensor_incl_uids[i];
        if (f == 0) continue;
        if (f == uid || f == b || f % 100000 == b) return true;
    }
    return false;
}

bool lp_is_uid_excluded(__u32 uid)
{
    /* UID 0 is always excluded. Root daemons (init, ksud, magiskd, vold)
     * never originate the binder traffic we spoof, but they DO mediate
     * legitimate kernel/system operations whose binder parcels happen to
     * match our patterns (e.g. KernelSU Next's WebUI bind-mount setup
     * via ksud emits parcels that look like our IMEI/UUID targets and
     * gets corrupted, breaking module action buttons). */
    if (uid == 0) return true;

    /* FORCE-SPOOF override wins over everything below (list + resolver). */
    if (g_force_spoof_count > 0) {
        __u32 b = uid % 100000;
        for (int i = 0; i < g_force_spoof_count && i < LP_MAX_FORCE_SPOOF; i++) {
            __u32 f = g_force_spoof_uids[i];
            if (f == 0) continue;
            if (f == uid || f == b || f % 100000 == b) return false;
        }
    }

    int n = g_excluded_uids_count;
    if (n <= 0) return false;
    /* Match both base UID and per-user UID (uid % 100000) so secondary
     * Android users / work profiles of the same package are also excluded. */
    __u32 base = uid % 100000;
    for (int i = 0; i < n && i < LP_MAX_EXCLUDED_UIDS; i++) {
        __u32 e = g_excluded_uids[i];
        if (e == 0) continue;
        if (e == uid) return true;
        if (e == base) return true;
        if (e % 100000 == base) return true;
    }
    return false;
}

extern int openat_hook_init(void);
extern void openat_hook_exit(void);
extern int read_hook_init(void);
extern void read_hook_exit(void);
extern int ioctl_hook_init(void);
extern void ioctl_hook_exit(void);
extern int props_hook_init(void);
extern void props_hook_exit(void);
extern int binder_hook_init(void);
extern void binder_hook_exit(void);
extern int sensor_hook_init(void);
extern void sensor_hook_exit(void);
extern int statfs_hook_init(void);
extern void statfs_hook_exit(void);
extern int stat_hook_init(void);
extern void stat_hook_exit(void);
extern int touch_hook_init(void);
extern void touch_hook_exit(void);
extern int touch_inject_cmd(const char *args);

/* ─── FP-free IEEE-754 conversion (see binder_hook.c for the matching read
 * side). This unit also builds with -mgeneral-regs-only in-tree, so the
 * set_location parser must turn the shell-supplied scaled integers into the
 * `double`/`float` bit patterns g_profile stores WITHOUT any FP division.
 * Command format is UNCHANGED: set_location:lat_e6,lon_e6,alt_e2,acc_e1. */

/* Build IEEE-754 double bits for the rational num/den (den > 0), round to
 * nearest-even. Integer-only; bit-exact vs `(double)num/(double)den` for the
 * ranges we use (verified 1.4M random cases, 0 ULP). */
static __u64 lp_rat_to_f64_bits(__s64 num, __u64 den)
{
    int sign = 0, shift, e, hb;
    __u64 a, scaled, mant, rem, half, frac;

    if (num == 0)
        return 0;
    if (num < 0) { sign = 1; a = (__u64)(-(num)); }
    else         a = (__u64)num;

    /* value * 2^35 via a 64-bit division (kernel has no 128-bit __udivti3).
     * Inputs are e6/e2/e1-scaled coords: |a| < 2^28, so a<<35 < 2^63 fits u64,
     * and ~35 fractional bits far exceed the ~20 needed for e6 precision. */
    if (a >= ((__u64)1 << 28))
        a = ((__u64)1 << 28) - 1;         /* clamp; coords never reach this */
    scaled = div64_u64(a << 35, den);     /* = (a/den) << 35 */
    if (scaled == 0)
        return (__u64)sign << 63;

    hb = 63;
    while (!((scaled >> hb) & 1)) hb--;   /* index of highest set bit */
    e = hb - 35;                          /* value ~ 1.f * 2^e */
    shift = hb - 52;

    if (shift >= 0) {
        mant = scaled >> shift;
        if (shift >= 1) {
            rem  = scaled & (((__u64)1 << shift) - 1);
            half = (__u64)1 << (shift - 1);
            if (rem > half || (rem == half && (mant & 1)))
                mant++;                   /* round half to even */
        }
    } else {
        mant = scaled << (-shift);
    }
    if (mant >> 53) { mant >>= 1; e++; }  /* rounding carried out */

    frac = mant & 0xFFFFFFFFFFFFFULL;
    return ((__u64)sign << 63) | ((__u64)(e + 1023) << 52) | frac;
}

/* Narrow IEEE-754 double bits to float bits, round to nearest-even. */
static __u32 lp_f64_bits_to_f32(__u64 d)
{
    __u32 sign = (__u32)(d >> 63), fman;
    int ebits = (int)((d >> 52) & 0x7FF), fe;
    __u64 mant = d & 0xFFFFFFFFFFFFFULL, rem, half;

    if (ebits == 0)
        return sign << 31;                /* zero / subnormal-double -> 0 */
    fe = (ebits - 1023) + 127;
    if (fe <= 0)
        return sign << 31;                /* underflow -> +/-0 */
    if (fe >= 255)
        return (sign << 31) | 0x7F800000; /* overflow -> inf */
    fman = (__u32)(mant >> 29);
    rem  = mant & 0x1FFFFFFFULL;
    half = 0x10000000ULL;                 /* 2^28 */
    if (rem > half || (rem == half && (fman & 1))) {
        fman++;
        if (fman >> 23) { fman = 0; fe++; if (fe >= 255) return (sign << 31) | 0x7F800000; }
    }
    return (sign << 31) | ((__u32)fe << 23) | (fman & 0x7FFFFF);
}

/* (__s64)(double_at(p) * scale), truncating toward zero — for the status
 * report (mirrors binder_hook.c's lp_f64_to_scaled). */
static __s64 lp_dbl_to_scaled(const void *p, __u64 scale)
{
    __u64 bits, mag, mant, mant_full;
    __u32 exp;
    int e2;
    unsigned __int128 prod;
    __s64 out;

    memcpy(&bits, p, 8);
    mag = bits & 0x7FFFFFFFFFFFFFFFULL;
    if (mag == 0)
        return 0;
    exp  = (__u32)(mag >> 52);
    mant = mag & 0xFFFFFFFFFFFFFULL;
    mant_full = (exp == 0) ? mant : (mant | 0x10000000000000ULL);
    e2 = (int)exp - 1075;
    prod = (unsigned __int128)mant_full * scale;
    out  = (e2 >= 0) ? (__s64)(prod << e2) : (__s64)(prod >> (-e2));
    return (bits >> 63) ? -out : out;
}

/* ─── Persistence + identity rotation ──────────────────────────────────────
 * profile.bin = versioned binary dump of g_profile. Restored at boot by a fast
 * poll (lands before system_server caches SSAID/MediaDRM). Path is on /data
 * (parent dir always present) — relocate to a stealthier path before ship. */
#define LP_PROFILE_PATH  "/data/local/tmp/.lp_profile"
#define LP_PROFILE_MAGIC 0x4C554B45u          /* 'LUKE' */
#define LP_PROFILE_VER   1u

struct lp_persist_hdr { __u32 magic; __u32 version; __u32 size; };

static void lp_hexstr(char *out, const __u8 *in, int nbytes)
{
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 0; i < nbytes; i++) {
        out[2 * i]     = h[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = h[in[i] & 0xf];
    }
    out[2 * nbytes] = '\0';
}

/* Rotate to a fresh identity: new root seed (drives SSAID/MediaDRM/sensor
 * per-UID) + new GAID, and arm the seed-derived spoofs. Other fields (IMEI,
 * carrier, model) are set explicitly via set_* and left untouched. */
static void lp_new_identity(void)
{
    __u8 b[16];

    get_random_bytes(b, 8);
    lp_hexstr(g_profile.android_id_seed, b, 8);   /* 16 hex chars */
    g_profile.android_id_spoof_enabled   = true;
    g_profile.sensor_accel_spoof_enabled = true;
    g_profile.sensor_gyro_spoof_enabled  = true;
    g_profile.sensor_mag_spoof_enabled   = true;

    get_random_bytes(b, 16);
    b[6] = (b[6] & 0x0f) | 0x40;                  /* UUID v4 */
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(g_profile.advertising_id, sizeof(g_profile.advertising_id),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    g_profile.gaid_binder_reenabled = true;

    g_hooks_enabled = true;
    pr_info("lukeprivacy: newIdentity seed=%.16s\n", g_profile.android_id_seed);
}

static int lp_save_profile(void)
{
    struct file *f;
    struct lp_persist_hdr hdr = { LP_PROFILE_MAGIC, LP_PROFILE_VER,
                                  (__u32)sizeof(g_profile) };
    loff_t pos = 0;
    ssize_t n;

    f = filp_open(LP_PROFILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f)) {
        pr_warn("lukeprivacy: save open failed: %ld\n", PTR_ERR(f));
        return (int)PTR_ERR(f);
    }
    n = kernel_write(f, &hdr, sizeof(hdr), &pos);
    if (n == sizeof(hdr))
        kernel_write(f, &g_profile, sizeof(g_profile), &pos);
    filp_close(f, NULL);
    pr_info("lukeprivacy: profile saved\n");
    return 0;
}

/* 1 = loaded, 0 = /data-not-ready or file-absent (retry), <0 = present-but-bad. */
static int lp_load_profile(void)
{
    struct file *f;
    struct lp_persist_hdr hdr;
    loff_t pos = 0;
    ssize_t n;

    f = filp_open(LP_PROFILE_PATH, O_RDONLY, 0);
    if (IS_ERR(f))
        return 0;
    n = kernel_read(f, &hdr, sizeof(hdr), &pos);
    if (n == sizeof(hdr) && hdr.magic == LP_PROFILE_MAGIC &&
        hdr.size == sizeof(g_profile)) {
        n = kernel_read(f, &g_profile, sizeof(g_profile), &pos);
        if (n == sizeof(g_profile)) {
            g_hooks_enabled = true;
            filp_close(f, NULL);
            pr_info("lukeprivacy: profile restored\n");
            return 1;
        }
    }
    filp_close(f, NULL);
    return -1;
}

static int parse_profile_cmd(const char *args)
{
    /* Human touch-gesture injection (birthday-picker swipe). Replays a real-finger
     * swipe on the fts panel at ~5.4 ms cadence from kernel context — see
     * hooks/touch_hook.c. "swipe:sx,sy,ex,ey,flick,n". */
    if (!strncmp(args, "swipe:", 6)) {
        touch_inject_cmd(args + 6);
        return 0;
    }

    if (!strcmp(args, "newIdentity")) {
        lp_new_identity();
        return 0;
    }
    if (!strcmp(args, "save")) {
        return lp_save_profile();
    }
    if (!strcmp(args, "reboot")) {
        pr_info("lukeprivacy: reboot requested\n");
        kernel_restart(NULL);
        return 0;   /* not reached */
    }
    if (!strncmp(args, "set_controller_pkg:", 19)) {
        strncpy(g_profile.controller_pkg, args + 19,
                sizeof(g_profile.controller_pkg) - 1);
        g_profile.controller_pkg[sizeof(g_profile.controller_pkg) - 1] = '\0';
        pr_info("lukeprivacy: controller pkg = %s\n", g_profile.controller_pkg);
        return 0;
    }

    /* set_android_id ctl0 setter removed 2026-05-09 along with the
     * android_id field in g_profile. Companion APK no longer pushes
     * here — see profile.h comment for context. */
    if (!strncmp(args, "set_imei:", 9)) {
        strncpy(g_profile.imei, args + 9, 15);
        g_profile.imei[15] = '\0';
        pr_info("lukeprivacy: imei set to %s\n", g_profile.imei);
        return 0;
    }
    if (!strncmp(args, "set_serial:", 11)) {
        strncpy(g_profile.serial, args + 11, 16);
        g_profile.serial[16] = '\0';
        pr_info("lukeprivacy: serial set to %s\n", g_profile.serial);
        return 0;
    }
    if (!strncmp(args, "set_gaid:", 9)) {
        strncpy(g_profile.advertising_id, args + 9, 36);
        g_profile.advertising_id[36] = '\0';
        pr_info("lukeprivacy: gaid set to %s\n", g_profile.advertising_id);
        return 0;
    }
    if (!strncmp(args, "set_gsf_id:", 11)) {
        strncpy(g_profile.gsf_id, args + 11, 16);
        g_profile.gsf_id[16] = '\0';
        pr_info("lukeprivacy: gsf_id set to %s\n", g_profile.gsf_id);
        return 0;
    }
    if (!strncmp(args, "set_bt_mac:", 11)) {
        strncpy(g_profile.bluetooth_mac, args + 11, 17);
        g_profile.bluetooth_mac[17] = '\0';
        pr_info("lukeprivacy: bt_mac set to %s\n", g_profile.bluetooth_mac);
        return 0;
    }
    if (!strncmp(args, "set_bluetooth_mac:", 18)) {
        strncpy(g_profile.bluetooth_mac, args + 18, 17);
        g_profile.bluetooth_mac[17] = '\0';
        pr_info("lukeprivacy: bluetooth_mac set to %s\n", g_profile.bluetooth_mac);
        return 0;
    }
    if (!strncmp(args, "set_advertising_id:", 19)) {
        strncpy(g_profile.advertising_id, args + 19, 36);
        g_profile.advertising_id[36] = '\0';
        pr_info("lukeprivacy: advertising_id set to %s\n", g_profile.advertising_id);
        return 0;
    }
    if (!strncmp(args, "set_firebase_id:", 16)) {
        strncpy(g_profile.firebase_id, args + 16, 36);
        g_profile.firebase_id[36] = '\0';
        pr_info("lukeprivacy: firebase_id set to %s\n", g_profile.firebase_id);
        return 0;
    }
    if (!strncmp(args, "set_wifi_mac:", 13)) {
        strncpy(g_profile.wifi_mac, args + 13, 17);
        g_profile.wifi_mac[17] = '\0';
        pr_info("lukeprivacy: wifi_mac set to %s\n", g_profile.wifi_mac);
        return 0;
    }
    if (!strncmp(args, "set_mccmnc:", 11)) {
        const char *val = args + 11;
        int len = strlen(val);
        if (len == 0) {
            /* Toggle off path: clear the three buffers so the value-gated
             * checks (`if (g_profile.mcc[0])`) deactivate downstream hooks
             * and the carrier/MCC/MNC spoof becomes a no-op. */
            g_profile.mcc[0] = '\0';
            g_profile.mnc[0] = '\0';
            g_profile.mccmnc[0] = '\0';
            pr_info("lukeprivacy: mccmnc cleared\n");
        } else if (len >= 5) {
            strncpy(g_profile.mcc, val, 3);
            g_profile.mcc[3] = '\0';
            strncpy(g_profile.mnc, val + 3, 3);
            g_profile.mnc[3] = '\0';
            strncpy(g_profile.mccmnc, val, 7);
            g_profile.mccmnc[7] = '\0';
            pr_info("lukeprivacy: mccmnc set to %s (mcc=%s mnc=%s)\n", g_profile.mccmnc, g_profile.mcc, g_profile.mnc);
        }
        return 0;
    }
    if (!strncmp(args, "set_country:", 12)) {
        strncpy(g_profile.country_iso, args + 12, 3);
        g_profile.country_iso[3] = '\0';
        pr_info("lukeprivacy: country set to %s\n", g_profile.country_iso);
        return 0;
    }
    if (!strncmp(args, "set_operator:", 13)) {
        strncpy(g_profile.operator_name, args + 13, 31);
        g_profile.operator_name[31] = '\0';
        pr_info("lukeprivacy: operator set to %s\n", g_profile.operator_name);
        return 0;
    }
    if (!strncmp(args, "set_imsi:", 9)) {
        strncpy(g_profile.imsi, args + 9, 15);
        g_profile.imsi[15] = '\0';
        pr_info("lukeprivacy: imsi set to %s\n", g_profile.imsi);
        return 0;
    }
    if (!strncmp(args, "set_iccid:", 10)) {
        strncpy(g_profile.iccid, args + 10, 20);
        g_profile.iccid[20] = '\0';
        pr_info("lukeprivacy: iccid set to %s\n", g_profile.iccid);
        return 0;
    }
    if (!strncmp(args, "set_phone:", 10)) {
        strncpy(g_profile.phone_number, args + 10, 19);
        g_profile.phone_number[19] = '\0';
        pr_info("lukeprivacy: phone set to %s\n", g_profile.phone_number);
        return 0;
    }
    if (!strncmp(args, "set_carrier_id:", 15)) {
        const char *p = args + 15;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.carrier_id = v;
        pr_info("lukeprivacy: carrier_id set to %d\n", g_profile.carrier_id);
        return 0;
    }
    if (!strncmp(args, "set_real_mcc:", 13)) {
        strncpy(g_profile.real_mcc, args + 13, 3);
        g_profile.real_mcc[3] = '\0';
        pr_info("lukeprivacy: real_mcc set to %s\n", g_profile.real_mcc);
        return 0;
    }
    if (!strncmp(args, "set_real_mnc:", 13)) {
        strncpy(g_profile.real_mnc, args + 13, 3);
        g_profile.real_mnc[3] = '\0';
        pr_info("lukeprivacy: real_mnc set to %s\n", g_profile.real_mnc);
        return 0;
    }
    if (!strncmp(args, "set_real_country:", 17)) {
        strncpy(g_profile.real_country, args + 17, 3);
        g_profile.real_country[3] = '\0';
        pr_info("lukeprivacy: real_country set to %s\n", g_profile.real_country);
        return 0;
    }
    if (!strncmp(args, "set_real_carrier_id:", 20)) {
        const char *p = args + 20;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_carrier_id = v;
        pr_info("lukeprivacy: real_carrier_id set to %d\n", g_profile.real_carrier_id);
        return 0;
    }
    if (!strncmp(args, "set_carrier_name:", 17)) {
        strncpy(g_profile.carrier_name, args + 17, 63);
        g_profile.carrier_name[63] = '\0';
        pr_info("lukeprivacy: carrier_name set to %s\n", g_profile.carrier_name);
        return 0;
    }
    if (!strncmp(args, "set_real_carrier_name:", 22)) {
        strncpy(g_profile.real_carrier_name, args + 22, 63);
        g_profile.real_carrier_name[63] = '\0';
        pr_info("lukeprivacy: real_carrier_name set to %s\n", g_profile.real_carrier_name);
        return 0;
    }
    if (!strncmp(args, "set_real_operator_alpha_long:", 29)) {
        strncpy(g_profile.real_operator_alpha_long, args + 29, 63);
        g_profile.real_operator_alpha_long[63] = '\0';
        pr_info("lukeprivacy: real_operator_alpha_long set to %s\n", g_profile.real_operator_alpha_long);
        return 0;
    }
    if (!strncmp(args, "set_real_operator_alpha_short:", 30)) {
        strncpy(g_profile.real_operator_alpha_short, args + 30, 15);
        g_profile.real_operator_alpha_short[15] = '\0';
        pr_info("lukeprivacy: real_operator_alpha_short set to %s\n", g_profile.real_operator_alpha_short);
        return 0;
    }
    if (!strncmp(args, "set_real_phone_bare:", 20)) {
        strncpy(g_profile.real_phone_bare, args + 20, 15);
        g_profile.real_phone_bare[15] = '\0';
        /* Don't log the actual digits — user's real phone number, dmesg
         * is world-readable. Length only is enough to verify the push
         * landed. */
        int len = 0;
        while (g_profile.real_phone_bare[len] && len < 15) len++;
        pr_info("lukeprivacy: real_phone_bare set (len=%d)\n", len);
        return 0;
    }
    if (!strncmp(args, "set_real_channel_number:", 24)) {
        const char *p = args + 24;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_channel_number = v;
        pr_info("lukeprivacy: real_channel_number set to %d\n", g_profile.real_channel_number);
        return 0;
    }
    if (!strncmp(args, "set_real_cell_bandwidth:", 24)) {
        const char *p = args + 24;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_cell_bandwidth = v;
        pr_info("lukeprivacy: real_cell_bandwidth set to %d\n", g_profile.real_cell_bandwidth);
        return 0;
    }
    if (!strncmp(args, "set_real_ci:", 12)) {
        const char *p = args + 12;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_ci = v;
        pr_info("lukeprivacy: real_ci set to %d\n", g_profile.real_ci);
        return 0;
    }
    if (!strncmp(args, "set_real_pci:", 13)) {
        const char *p = args + 13;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_pci = v;
        pr_info("lukeprivacy: real_pci set to %d\n", g_profile.real_pci);
        return 0;
    }
    if (!strncmp(args, "set_real_tac:", 13)) {
        const char *p = args + 13;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_tac = v;
        pr_info("lukeprivacy: real_tac set to %d\n", g_profile.real_tac);
        return 0;
    }
    if (!strncmp(args, "set_real_earfcn:", 16)) {
        const char *p = args + 16;
        __s32 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.real_earfcn = v;
        pr_info("lukeprivacy: real_earfcn set to %d\n", g_profile.real_earfcn);
        return 0;
    }
    /* Spoof cell-identity ints. Companion APK picks per-MCC plausible
     * values (LTE band typical for the spoofed country, valid pci/tac/ci
     * range). Pushed after real_* capture so KPM has both halves of the
     * (real → spoof) rewrite pair. */
    if (!strncmp(args, "set_spoof_channel_number:", 25)) {
        const char *p = args + 25; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_channel_number = v;
        return 0;
    }
    if (!strncmp(args, "set_spoof_cell_bandwidth:", 25)) {
        const char *p = args + 25; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_cell_bandwidth = v;
        return 0;
    }
    if (!strncmp(args, "set_spoof_ci:", 13)) {
        const char *p = args + 13; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_ci = v;
        return 0;
    }
    if (!strncmp(args, "set_spoof_pci:", 14)) {
        const char *p = args + 14; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_pci = v;
        return 0;
    }
    if (!strncmp(args, "set_spoof_tac:", 14)) {
        const char *p = args + 14; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_tac = v;
        return 0;
    }
    if (!strncmp(args, "set_spoof_earfcn:", 17)) {
        const char *p = args + 17; __s32 v = 0; bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        g_profile.spoof_earfcn = v;
        return 0;
    }
    if (!strncmp(args, "set_mediadrm:", 13)) {
        const char *val = args + 13;
        if (!*val) {
            /* Empty value deactivates the hook — apps see real hardware
             * Widevine HMAC instead of any spoof. Used when companion APK
             * has the mediadrm_hook toggle OFF. */
            g_profile.mediadrm_id[0] = '\0';
            pr_info("lukeprivacy: mediadrm hook DEACTIVATED (empty value)\n");
        } else {
            strncpy(g_profile.mediadrm_id, val, 64);
            g_profile.mediadrm_id[64] = '\0';
            pr_info("lukeprivacy: mediadrm set to %.16s...\n", g_profile.mediadrm_id);
        }
        return 0;
    }
    /* Per-hook gate for try_hide_dev_settings's adb-hide path. Companion
     * APK pushes "1" when its UI toggle is on, "0" otherwise. Default
     * (set in the static initializer above) is off, so a freshly-loaded
     * module is fully passive. */
    if (!strncmp(args, "set_adb_hide:", 13)) {
        g_profile.adb_hide_enabled = (args[13] == '1');
        pr_info("lukeprivacy: adb_hide=%d\n", g_profile.adb_hide_enabled);
        return 0;
    }
    /* set_boot_id ctl0 removed 2026-07-24 — boot_id spoof retired (workflow
     * reboots between accounts → real boot_id rotates naturally). Enable path
     * gone; g_profile.boot_id_spoof_enabled stays false. */
    if (!strncmp(args, "set_eventtime_offset:", 21)) {
        const char *p = args + 21;
        __s64 v = 0;
        bool neg = false;
        if (*p == '-') { neg = true; p++; }
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        if (neg) v = -v;
        /* RE-ENABLED 2026-09-20: offsets verified vs BTF; the kCFI panic in lp_prctl_hook
           (indirect kallsyms calls) is fixed by marking that function __nocfi. Store + arm;
           hooks stay inert until eventtime_target_uid is set (per account, not persisted). */
        g_profile.eventtime_offset_ns = v;
        g_profile.eventtime_offset_enabled = (v != 0);
        pr_info("lukeprivacy: eventtime_offset=%lld ns enabled=%d\n",
                (long long)v, g_profile.eventtime_offset_enabled);
        return 0;
    }
    if (!strncmp(args, "set_eventtime_target_uid:", 25)) {
        const char *p = args + 25;
        __u32 v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        g_profile.eventtime_target_uid = v;
        pr_info("lukeprivacy: eventtime_target_uid=%u\n", g_profile.eventtime_target_uid);
        return 0;
    }
    if (!strncmp(args, "set_android_id_seed:", 20)) {
        const char *val = args + 20;
        size_t vlen = strlen(val);
        if (vlen == 16) {
            strncpy(g_profile.android_id_seed, val, 16);
            g_profile.android_id_seed[16] = 0;
            pr_info("[lukeprivacy] android_id_seed set (len=16)\n");
        } else {
            g_profile.android_id_seed[0] = 0;
            pr_info("[lukeprivacy] android_id_seed cleared\n");
        }
        return 0;
    }
    if (!strncmp(args, "set_android_id_spoof:", 21)) {
        const char *val = args + 21;
        g_profile.android_id_spoof_enabled = (val[0] == '1');
        pr_info("[lukeprivacy] android_id_spoof_enabled=%d\n",
                g_profile.android_id_spoof_enabled);
        return 0;
    }
    if (!strncmp(args, "set_ssaid_relaxed:", 18)) {
        const char *val = args + 18;
        bool was = g_profile.ssaid_relaxed_enabled;
        g_profile.ssaid_relaxed_enabled = (val[0] == '1');
        if (!was && g_profile.ssaid_relaxed_enabled) {
            extern unsigned int g_ssaid_relaxed_window_count;
            g_ssaid_relaxed_window_count = 0;
        }
        pr_info("[lukeprivacy] ssaid_relaxed_enabled=%d\n",
                g_profile.ssaid_relaxed_enabled);
        return 0;
    }
    if (!strncmp(args, "set_ssaid_relaxed_uid:", 22)) {
        const char *val = args + 22;
        unsigned int uid = 0;
        while (*val >= '0' && *val <= '9') {
            uid = uid * 10 + (*val - '0');
            val++;
        }
        g_profile.ssaid_relaxed_target_uid = uid;
        pr_info("[lukeprivacy] ssaid_relaxed_target_uid=%u\n", uid);
        return 0;
    }
    /* Sensor bias spoof toggles. Companion APK Dashboard "Spoof
     * Accelerometer" / "Spoof Gyroscope" switches push these on Save.
     * Defaults (set above) are false; reboot resets via KPM_INIT. */
    if (!strncmp(args, "set_sensor_accel:", 17)) {
        g_profile.sensor_accel_spoof_enabled = (args[17] == '1');
        pr_info("[lukeprivacy] sensor_accel_spoof_enabled=%d\n",
                g_profile.sensor_accel_spoof_enabled);
        return 0;
    }
    if (!strncmp(args, "set_sensor_gyro:", 16)) {
        g_profile.sensor_gyro_spoof_enabled = (args[16] == '1');
        pr_info("[lukeprivacy] sensor_gyro_spoof_enabled=%d\n",
                g_profile.sensor_gyro_spoof_enabled);
        return 0;
    }
    /* Magnetometer per-UID hard-iron bias spoof + slow micro-drift (types 2+14). */
    if (!strncmp(args, "set_sensor_mag:", 15)) {
        g_profile.sensor_mag_spoof_enabled = (args[15] == '1');
        pr_info("[lukeprivacy] sensor_mag_spoof_enabled=%d\n",
                g_profile.sensor_mag_spoof_enabled);
        return 0;
    }
    /* "Held" motion model — re-projects accel gravity onto a drifting
     * hand-held tilt + consistent gyro drift. Requires accel/gyro spoof ON. */
    if (!strncmp(args, "set_sensor_held:", 16)) {
        g_profile.sensor_held_enabled = (args[16] == '1');
        pr_info("[lukeprivacy] sensor_held_enabled=%d\n",
                g_profile.sensor_held_enabled);
        return 0;
    }
    /* sensor_tap / sensor_bump ctl0 handlers REMOVED (2026-07-08): tap↔gyro
     * correlation dropped, and the continuous baseline (tremor + held drift +
     * auto bump in sensor_hook.c) needs no manual trigger. Both also did float
     * arithmetic in the FPU-less ctl0 context (garbage). */
    if (!strncmp(args, "set_ssid:", 9)) {
        strncpy(g_profile.spoof_ssid, args + 9, 32);
        g_profile.spoof_ssid[32] = '\0';
        pr_info("lukeprivacy: ssid set to %s\n", g_profile.spoof_ssid);
        return 0;
    }
    if (!strncmp(args, "set_bssid:", 10)) {
        strncpy(g_profile.spoof_bssid, args + 10, 17);
        g_profile.spoof_bssid[17] = '\0';
        pr_info("lukeprivacy: bssid set to %s\n", g_profile.spoof_bssid);
        return 0;
    }
    /* A16 WifiInfo RE: wifi_debug:1 → log parcel layout (BSSID/SSID offsets +
     * header words) for every binder reply that carries a MAC/SSID string. */
    if (!strncmp(args, "wifi_debug:", 11)) {
        extern int g_wifi_debug;
        g_wifi_debug = (args[11] == '1');
        pr_info("lukeprivacy: wifi_debug=%d\n", g_wifi_debug);
        return 0;
    }
    /* WiFi SSID (network name) randomisation toggle — companion pushes this
     * from the wifi_ssid_hook toggle (default ON). BSSID spoof stays keyed on
     * spoof_bssid; this only gates the network-name rewrite. */
    if (!strncmp(args, "set_ssid_spoof:", 15)) {
        extern int g_wifi_ssid_spoof;
        g_wifi_ssid_spoof = (args[15] == '1');
        pr_info("lukeprivacy: wifi_ssid_spoof=%d\n", g_wifi_ssid_spoof);
        return 0;
    }
    /* Camera calibration spoof master toggle. Companion pushes from the
     * camera_calibration_hook toggle (default ON). Values must already be
     * loaded via set_camera_cal for the hook to fire. */
    if (!strncmp(args, "set_camera_spoof:", 17)) {
        g_profile.camera_spoof_enabled = (args[17] == '1');
        pr_info("lukeprivacy: camera_spoof=%d (pairs=%u)\n",
                g_profile.camera_spoof_enabled, g_profile.camera_cal_count);
        return 0;
    }
    /* Load (real,fake) float32 bit-pattern pairs for the camera-metadata
     * find/replace hook. Format: 8-hex,8-hex;8-hex,8-hex;... (each side is a
     * little-endian IEEE-754 float32 as an 8-char hex u32). Up to 64 pairs.
     * The companion recomputes the fake side on every identity reseed and
     * re-pushes, so this fully replaces the table each call. */
    if (!strncmp(args, "set_camera_cal:", 15)) {
        const char *p = args + 15;
        __u32 n = 0;
        while (*p && n < 64) {
            __u32 r = 0, f = 0;
            int i;
            /* real: 8 hex */
            for (i = 0; i < 8; i++) {
                char c = *p++;
                int d = (c >= '0' && c <= '9') ? c - '0' :
                        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                        (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (d < 0) goto cam_done;
                r = (r << 4) | (__u32)d;
            }
            if (*p++ != ',') goto cam_done;
            /* fake: 8 hex */
            for (i = 0; i < 8; i++) {
                char c = *p++;
                int d = (c >= '0' && c <= '9') ? c - '0' :
                        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                        (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (d < 0) goto cam_done;
                f = (f << 4) | (__u32)d;
            }
            g_profile.camera_cal_real[n] = r;
            g_profile.camera_cal_fake[n] = f;
            n++;
            if (*p == ';') p++;      /* pair separator */
            else break;
        }
    cam_done:
        g_profile.camera_cal_count = n;
        pr_info("lukeprivacy: camera_cal loaded %u pairs\n", n);
        return 0;
    }
    if (!strncmp(args, "clear_camera_cal", 16)) {
        g_profile.camera_cal_count = 0;
        g_profile.camera_spoof_enabled = false;
        pr_info("lukeprivacy: camera_cal cleared\n");
        return 0;
    }
    // Location: set_location:lat_i,lon_i,alt_i,acc_i (integers scaled by 1000000,1000000,100,10)
    // e.g. set_location:52229700,21012200,10000,50 = 52.2297, 21.0122, 100.0m, 5.0m
    if (!strncmp(args, "set_location:", 13)) {
        const char *p = args + 13;
        long lat_i = 0, lon_i = 0, alt_i = 0, acc_i = 100;
        int neg = 0;

        // Parse latitude
        if (*p == '-') { neg = 1; p++; }
        while (*p >= '0' && *p <= '9') { lat_i = lat_i * 10 + (*p - '0'); p++; }
        if (neg) lat_i = -lat_i;
        if (*p == ',') p++;

        // Parse longitude
        neg = 0;
        if (*p == '-') { neg = 1; p++; }
        while (*p >= '0' && *p <= '9') { lon_i = lon_i * 10 + (*p - '0'); p++; }
        if (neg) lon_i = -lon_i;
        if (*p == ',') p++;

        // Parse altitude (optional)
        neg = 0;
        if (*p == '-') { neg = 1; p++; }
        while (*p >= '0' && *p <= '9') { alt_i = alt_i * 10 + (*p - '0'); p++; }
        if (neg) alt_i = -alt_i;
        if (*p == ',') p++;

        // Parse accuracy (optional)
        if (*p >= '0' && *p <= '9') {
            acc_i = 0;
            while (*p >= '0' && *p <= '9') { acc_i = acc_i * 10 + (*p - '0'); p++; }
        }

        /* Build the IEEE-754 bit patterns from the scaled integers with pure
         * integer math (no FP division) and store them into the double/float
         * fields via memcpy. Field types in profile.h are unchanged. */
        {
            __u64 lat_b = lp_rat_to_f64_bits(lat_i, 1000000);
            __u64 lon_b = lp_rat_to_f64_bits(lon_i, 1000000);
            __u64 alt_b = lp_rat_to_f64_bits(alt_i, 100);
            __u32 acc_b = lp_f64_bits_to_f32(lp_rat_to_f64_bits(acc_i, 10));
            memcpy(&g_profile.latitude,  &lat_b, 8);
            memcpy(&g_profile.longitude, &lon_b, 8);
            memcpy(&g_profile.altitude,  &alt_b, 8);
            memcpy(&g_profile.accuracy,  &acc_b, 4);
        }
        g_profile.location_enabled = true;

        pr_info("lukeprivacy: location set lat_e6=%ld lon_e6=%ld alt_e2=%ld acc_e1=%ld\n",
                lat_i, lon_i, alt_i, acc_i);
        return 0;
    }
    if (!strcmp(args, "location_disable")) {
        g_profile.location_enabled = false;
        pr_info("lukeprivacy: location spoofing disabled\n");
        return 0;
    }
    if (!strcmp(args, "pretend_sim_enable")) {
        g_profile.pretend_sim_enabled = true;
        pr_info("lukeprivacy: pretend SIM internet enabled (5G NR)\n");
        return 0;
    }
    if (!strcmp(args, "pretend_sim_disable")) {
        g_profile.pretend_sim_enabled = false;
        pr_info("lukeprivacy: pretend SIM internet disabled\n");
        return 0;
    }
    if (!strncmp(args, "set_cell_info:", 14)) {
        g_profile.cell_info_enabled = (args[14] == '1');
        pr_info("lukeprivacy: cell_info_enabled=%d\n", g_profile.cell_info_enabled);
        return 0;
    }

    /* ── TikTok extended hooks (Phase A new ctl0 setters) ─────────────── */

    if (!strncmp(args, "set_ssaid_relaxed:", 18)) {
        /* Already handled above (set_ssaid_relaxed:). This path is
         * intentionally unreachable (the earlier block returns 0 first).
         * Kept for completeness in case parse order changes. */
        return 0;
    }
    if (!strncmp(args, "set_gaid_binder:", 16)) {
        g_profile.gaid_binder_reenabled = (args[16] == '1');
        pr_info("[lukeprivacy] gaid_binder_reenabled=%d\n", g_profile.gaid_binder_reenabled);
        return 0;
    }
    if (!strncmp(args, "set_hostbridge:", 15)) {
        g_profile.hostprocess_bridge_enabled = (args[15] == '1');
        pr_info("[lukeprivacy] hostprocess_bridge_enabled=%d\n", g_profile.hostprocess_bridge_enabled);
        return 0;
    }
    if (!strncmp(args, "set_proc_version_uid:", 21)) {
        g_profile.proc_version_uid_redirect_enabled = (args[21] == '1');
        pr_info("[lukeprivacy] proc_version_uid_redirect_enabled=%d\n",
                g_profile.proc_version_uid_redirect_enabled);
        return 0;
    }
    if (!strncmp(args, "set_timezone_hook:", 18)) {
        g_profile.timezone_binder_enabled = (args[18] == '1');
        /* Note: timezone spoofing is handled via companion resetprop
         * persist.sys.timezone. No kernel binder hook is implemented
         * (A8 deferred — companion path suffices). */
        pr_info("[lukeprivacy] timezone_binder_enabled=%d (companion handles via resetprop)\n",
                g_profile.timezone_binder_enabled);
        return 0;
    }

    /* ── Block Store neutralization (Snap SS03 device-cloud anchor) ─────── */

    /* Base64 Block Store entry key captured from schema.pb (constant per app).
     * Empty clears it (feature can't match without it). */
    if (!strncmp(args, "set_blockstore_key:", 19)) {
        const char *val = args + 19;
        size_t vlen = strlen(val);
        if (vlen > 0 && vlen < sizeof(g_profile.blockstore_key)) {
            strncpy(g_profile.blockstore_key, val, sizeof(g_profile.blockstore_key) - 1);
            g_profile.blockstore_key[sizeof(g_profile.blockstore_key) - 1] = '\0';
            pr_info("[lukeprivacy] blockstore_key set (len=%zu)\n", vlen);
        } else {
            g_profile.blockstore_key[0] = '\0';
            pr_info("[lukeprivacy] blockstore_key cleared\n");
        }
        return 0;
    }
    /* Snap's CURRENT uid — positive target (companion resolves pkg→uid and pushes
     * fresh at each newIdentity, since the uid changes on reinstall). 0 disables. */
    if (!strncmp(args, "set_blockstore_uid:", 19)) {
        const char *val = args + 19;
        unsigned int uid = 0;
        while (*val >= '0' && *val <= '9') { uid = uid * 10 + (*val - '0'); val++; }
        g_profile.blockstore_target_uid = uid;
        pr_info("[lukeprivacy] blockstore_target_uid=%u\n", uid);
        return 0;
    }
    if (!strncmp(args, "set_blockstore_neutralize:", 26)) {
        g_profile.blockstore_neutralize_enabled = (args[26] == '1');
        pr_info("[lukeprivacy] blockstore_neutralize_enabled=%d\n",
                g_profile.blockstore_neutralize_enabled);
        return 0;
    }
    if (!strncmp(args, "set_blockstore_capture:", 23)) {
        g_profile.blockstore_capture_enabled = (args[23] == '1');
        pr_info("[lukeprivacy] blockstore_capture_enabled=%d\n",
                g_profile.blockstore_capture_enabled);
        return 0;
    }
    /* ARM: set the fire cap AND reset the fire counter for a new cycle. Session-
     * bracket usage: companion sends `set_blockstore_arm:0` (cap 0 = UNLIMITED
     * while enabled) right before launching Snap, then set_blockstore_neutralize:1;
     * after Snap exits, set_blockstore_neutralize:0. cap > 0 = legacy first-N. */
    if (!strncmp(args, "set_blockstore_arm:", 19)) {
        const char *val = args + 19;
        unsigned int cap = 0;
        while (*val >= '0' && *val <= '9') { cap = cap * 10 + (*val - '0'); val++; }
        g_profile.blockstore_fire_cap = cap;
        lp_blockstore_arm();   /* reset fire counter for the new cycle */
        pr_info("[lukeprivacy] blockstore ARM cap=%u (fire counter reset)\n", cap);
        return 0;
    }

    return -1;
}

/* ─── Hidden control node (kanał A) ────────────────────────────────────────
 * NOT a mount — a proc entry in the already-mounted procfs (zero footprint in
 * /proc/self/mountinfo). Openable only by root/shell (uid 0 / 2000); any other
 * uid gets -ENOENT so an app cannot even confirm it exists. Also skipped in the
 * /proc readdir (see fs/proc/generic.c call-site keyed on lp_proc_entry), so it
 * never shows in `ls /proc`. Shell: `echo "set_imei:..." > /proc/<name>` to
 * mutate, `cat /proc/<name>` for status + counters. */
#define LP_PROC_NAME "luke"          /* stealth pass: genericize before ship */
struct proc_dir_entry *lp_proc_entry;
EXPORT_SYMBOL(lp_proc_entry);

static long lp_ctl(const char *args, char *out_msg, int outlen);

static int lp_uid_ok(void)
{
    kuid_t u = current_uid();
    unsigned int uid;
    const char *pkg;

    if (uid_eq(u, GLOBAL_ROOT_UID))
        return 1;
    uid = from_kuid(&init_user_ns, u);
    if (uid == 2000)                             /* adb shell */
        return 1;
    /* authorized controller app (e.g. SnapAuto), matched by package so it
     * survives reinstall (uid changes, package does not). */
    if (g_profile.controller_pkg[0]) {
        pkg = lp_pkg_for_uid(uid);
        if (pkg && !strcmp(pkg, g_profile.controller_pkg))
            return 1;
    }
    return 0;
}

static int lp_proc_open(struct inode *ino, struct file *f)
{
    return lp_uid_ok() ? 0 : -ENOENT;
}

static ssize_t lp_proc_write(struct file *f, const char __user *ubuf,
                             size_t len, loff_t *off)
{
    char kbuf[512];
    char resp[64];
    if (!lp_uid_ok())
        return -ENOENT;
    if (len == 0 || len >= sizeof(kbuf))
        return -EINVAL;
    if (copy_from_user(kbuf, ubuf, len))
        return -EFAULT;
    kbuf[len] = '\0';
    while (len && (kbuf[len - 1] == '\n' || kbuf[len - 1] == '\r'))
        kbuf[--len] = '\0';
    lp_ctl(kbuf, resp, sizeof(resp));
    return (ssize_t)(len ? len : 1);
}

static ssize_t lp_proc_read(struct file *f, char __user *ubuf,
                            size_t len, loff_t *off)
{
    static char buf[4096];
    int n;
    if (!lp_uid_ok())
        return -ENOENT;
    if (*off > 0)
        return 0;
    buf[0] = '\0';
    lp_ctl("status", buf, sizeof(buf));
    n = strlen(buf);
    lp_ctl("ioctl_stats", buf + n, sizeof(buf) - n);
    n = strlen(buf);
    if (len < (size_t)n)
        n = (int)len;
    if (copy_to_user(ubuf, buf, n))
        return -EFAULT;
    *off += n;
    return n;
}

static const struct proc_ops lp_proc_ops = {
    .proc_open  = lp_proc_open,
    .proc_read  = lp_proc_read,
    .proc_write = lp_proc_write,
    .proc_lseek = default_llseek,
};

/* /data (packages.list) is not mounted at late_initcall, so the mandatory-
 * exclusion uid resolve happens from a delayed worker that retries until it
 * lands. Hook fast paths also lazily retry via lp_resolver_tick(). */
static void lp_resolver_work_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(lp_resolver_work, lp_resolver_work_fn);
static int lp_resolver_tries;

static void lp_resolver_work_fn(struct work_struct *w)
{
    lp_resolve_excluded_packages();
    if (g_excluded_uids_count == 0 && ++lp_resolver_tries < 30)
        schedule_delayed_work(&lp_resolver_work, msecs_to_jiffies(2000));
    else
        pr_info("lukeprivacy: resolver settled excluded=%d tries=%d\n",
                g_excluded_uids_count, lp_resolver_tries);
}

/* Boot-restore: fast poll for the saved profile so the seed (SSAID/MediaDRM
 * driver) lands before system_server caches. /data mounts before zygote/
 * system_server; this catches profile.bin within ~100ms of that mount. */
static void lp_restore_work_fn(struct work_struct *w);
static DECLARE_DELAYED_WORK(lp_restore_work, lp_restore_work_fn);
static int lp_restore_tries;

static void lp_restore_work_fn(struct work_struct *w)
{
    int rc = lp_load_profile();
    if (rc == 0 && ++lp_restore_tries < 600)     /* ~60s of 100ms polls */
        schedule_delayed_work(&lp_restore_work, msecs_to_jiffies(100));
}

static int __init lp_init(void)
{
    int rc;
    pr_info("lukeprivacy: init\n");

    if (!g_hooks_enabled) {
        pr_info("lukeprivacy: disabled via cmdline (luke.enable=0) — skipping init\n");
        return 0;
    }

    rc = lp_init_uaccess();
    if (rc) {
        pr_err("lukeprivacy: failed to init uaccess: %d\n", rc);
        return rc;
    }
    pr_info("lukeprivacy: uaccess initialized\n");

    /* Resolve kmalloc/kfree for large-parcel scratch buffers used by the
     * SubscriptionInfo carrierName scan path. Non-fatal if missing — the
     * code falls back to skipping >4KB parcels rather than crashing. */
    extern void lp_init_kmalloc(void);
    lp_init_kmalloc();

    rc = openat_hook_init();
    if (rc) pr_warn("lukeprivacy: openat_hook_init failed: %d\n", rc);

    rc = read_hook_init();
    if (rc) pr_warn("lukeprivacy: read_hook_init failed: %d\n", rc);

    rc = ioctl_hook_init();
    if (rc) pr_warn("lukeprivacy: ioctl_hook_init failed: %d\n", rc);

    rc = props_hook_init();
    if (rc) pr_warn("lukeprivacy: props_hook_init failed: %d\n", rc);

    rc = binder_hook_init();
    if (rc) pr_warn("lukeprivacy: binder_hook_init failed: %d\n", rc);
    pr_info("[lukeprivacy] BUILD=bs-caid-uidindep-v4\n");  /* load marker: confirms this exact build is running */

    rc = sensor_hook_init();
    if (rc) pr_warn("lukeprivacy: sensor_hook_init failed: %d\n", rc);

    rc = touch_hook_init();
    if (rc) pr_warn("lukeprivacy: touch_hook_init failed: %d\n", rc);

    rc = statfs_hook_init();
    if (rc) pr_warn("lukeprivacy: statfs_hook_init failed: %d\n", rc);

    rc = stat_hook_init();
    if (rc) pr_warn("lukeprivacy: stat_hook_init failed: %d\n", rc);

    /* Best-effort early resolve of mandatory exclusions. /data is usually
     * not mounted yet at module load, so this almost always falls through
     * to the lazy retry inside hook fast paths. We try anyway in case
     * we're loaded post-boot via `kpatch kpm load`. */
    schedule_delayed_work(&lp_resolver_work, msecs_to_jiffies(5000));
    schedule_delayed_work(&lp_restore_work, msecs_to_jiffies(200));

    pr_info("lukeprivacy: initialized, hooks_enabled=%d\n", g_hooks_enabled);

    /* mode is permissive so shell(2000) and the controller app can reach the
     * ->open handler (no su in this design); lp_uid_ok() does the real gate and
     * returns -ENOENT to everyone else. The node is hidden from readdir. */
    lp_proc_entry = proc_create(LP_PROC_NAME, 0666, NULL, &lp_proc_ops);
    if (!lp_proc_entry)
        pr_warn("lukeprivacy: control node create failed\n");

    return 0;
}

static long lp_ctl(const char *args, char *out_msg, int outlen)
{

    if (!args || !*args) {
        const char *status = g_hooks_enabled ? "enabled" : "disabled";
        compat_copy_to_user(out_msg, status, strlen(status) + 1);
        return 0;
    }

    if (!strcmp(args, "enable")) {
        g_hooks_enabled = true;
        compat_copy_to_user(out_msg, "ok", 3);
        pr_info("lukeprivacy: hooks enabled\n");
        return 0;
    }

    if (!strcmp(args, "disable")) {
        g_hooks_enabled = false;
        compat_copy_to_user(out_msg, "ok", 3);
        pr_info("lukeprivacy: hooks disabled\n");
        return 0;
    }

    if (!strcmp(args, "status")) {
        char buf[512];
        __s64 lat_i = lp_dbl_to_scaled(&g_profile.latitude, 1000000);
        __s64 lon_i = lp_dbl_to_scaled(&g_profile.longitude, 1000000);
        snprintf(buf, sizeof(buf),
            "enabled=%d\n"
            "imei=%s\n"
            "serial=%s\n"
            "model=%s\n"
            "mcc=%s mnc=%s mccmnc=%s country=%s carrier_id=%d real_carrier_id=%d\n"
            "carrier_name=%s real_carrier_name=%s\n"
            "location_enabled=%d lat_i=%lld lon_i=%lld\n"
            "pretend_sim_enabled=%d cell_info_enabled=%d\n"
            "android_id_spoof=%d seed_set=%d\n"
            "sensor_accel_spoof=%d sensor_gyro_spoof=%d\n"
            "gaid_binder=%d hostbridge=%d proc_ver_uid=%d timezone_binder=%d\n",
            g_hooks_enabled,
            g_profile.imei,
            g_profile.serial,
            g_profile.model,
            g_profile.mcc, g_profile.mnc, g_profile.mccmnc, g_profile.country_iso,
            g_profile.carrier_id, g_profile.real_carrier_id,
            g_profile.carrier_name, g_profile.real_carrier_name,
            g_profile.location_enabled,
            lat_i, lon_i,
            g_profile.pretend_sim_enabled,
            g_profile.cell_info_enabled,
            g_profile.android_id_spoof_enabled,
            g_profile.android_id_seed[0] != 0 ? 1 : 0,
            g_profile.sensor_accel_spoof_enabled,
            g_profile.sensor_gyro_spoof_enabled,
            g_profile.gaid_binder_reenabled,
            g_profile.hostprocess_bridge_enabled,
            g_profile.proc_version_uid_redirect_enabled,
            g_profile.timezone_binder_enabled);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    if (!strcmp(args, "ioctl_stats")) {
        extern int g_binder_copy_calls, g_binder_imei_spoofed, g_binder_imsi_spoofed, g_binder_iccid_spoofed, g_binder_mcc_spoofed, g_binder_uuid_spoofed, g_binder_mediadrm_spoofed, g_binder_location_spoofed;
        extern int g_kernel_copy_calls, g_gnss_location_spoofed, g_cellinfo_spoofed, g_wifiinfo_spoofed, g_binder_country_spoofed, g_adb_hidden, g_dnt_spoofed, g_netinfo_spoofed, g_netcaps_spoofed;
        extern int g_carrier_name_spoofed;
        extern int g_phone_bare_seen, g_phone_bare_replaced;
        extern int g_gnss_status_spoofed;
        extern unsigned int g_ssaid_seen, g_ssaid_replaced, g_ssaid_relaxed_replaced;
        extern unsigned int g_sensor_events_seen, g_sensor_accel_spoofed, g_sensor_gravity_spoofed, g_sensor_gyro_spoofed;
        extern unsigned int g_uid_map_inserts, g_uid_map_evicts, g_uid_map_lookups_hit, g_uid_map_lookups_miss;
        extern unsigned int g_prop_writes_seen, g_prop_writes_blocked;
        extern unsigned int g_proc_version_spoofed, g_proc_cpuinfo_spoofed, g_proc_inet6_spoofed;
        extern unsigned int g_boot_id_spoofed;
        extern unsigned int g_battery_serial_spoofed, g_display_serial_spoofed, g_ufs_serial_spoofed;
        extern unsigned int g_soc0_spoofed;
        extern unsigned int g_mountinfo_filtered, g_mountinfo_seen;
        /* New counters from gap-plan A3/A5/A6/A7/A4 */
        extern unsigned int g_ssaid_anchor_fail[8];
        extern unsigned int g_ssaid_debug_enabled;
        extern unsigned int g_gaid_binder_repl, g_hostbridge_repl;
        extern unsigned int g_proc_version_uid_repl, g_timezone_repl;
        extern unsigned int g_statfs_overlay_seen, g_statfs_overlay_rewritten;
        extern unsigned int g_stat_seen, g_stat_overlay_seen, g_stat_rewritten;
        extern unsigned int g_blockstore_seen, g_blockstore_neutralized;
        char buf[1700];
        snprintf(buf, sizeof(buf),
            "user=%d kern=%d imei=%d imsi=%d iccid=%d mcc=%d country=%d uuid=%d drm=%d loc=%d gnss=%d gnss_st=%d cell=%d wifi=%d adb=%d dnt=%d netinfo=%d netcaps=%d cname=%d ph_seen=%d ph_repl=%d uidmap_ins=%u uidmap_evict=%u uidmap_hit=%u uidmap_miss=%u ssaid_seen=%u ssaid_repl=%u ssaid_rlx=%u sens_seen=%u sens_acc=%u sens_gyr=%u sens_grav=%u prop_seen=%u prop_blk=%u proc_ver=%u proc_cpu=%u proc_in6=%u bootid=%u bat_sn=%u disp_sn=%u ufs_sn=%u soc0=%u mnt_filt=%u"
            " ssaid_af0=%u ssaid_af1=%u ssaid_af2=%u ssaid_af3=%u ssaid_af4=%u ssaid_af5=%u ssaid_af6=%u ssaid_af7=%u"
            " gaid_repl=%u hpb_repl=%u pver_uid=%u tz_repl=%u statfs_seen=%u statfs_repl=%u mnt_seen=%u"
            " stat_seen=%u stat_ovl=%u stat_repl=%u bs_seen=%u bs_neut=%u cam_repl=%u cursor_aid=%u",
            g_binder_copy_calls, g_kernel_copy_calls, g_binder_imei_spoofed, g_binder_imsi_spoofed, g_binder_iccid_spoofed, g_binder_mcc_spoofed, g_binder_country_spoofed, g_binder_uuid_spoofed, g_binder_mediadrm_spoofed, g_binder_location_spoofed, g_gnss_location_spoofed, g_gnss_status_spoofed, g_cellinfo_spoofed, g_wifiinfo_spoofed, g_adb_hidden, g_dnt_spoofed, g_netinfo_spoofed, g_netcaps_spoofed, g_carrier_name_spoofed, g_phone_bare_seen, g_phone_bare_replaced, g_uid_map_inserts, g_uid_map_evicts, g_uid_map_lookups_hit, g_uid_map_lookups_miss, g_ssaid_seen, g_ssaid_replaced, g_ssaid_relaxed_replaced, g_sensor_events_seen, g_sensor_accel_spoofed, g_sensor_gyro_spoofed, g_sensor_gravity_spoofed, g_prop_writes_seen, g_prop_writes_blocked, g_proc_version_spoofed, g_proc_cpuinfo_spoofed, g_proc_inet6_spoofed, g_boot_id_spoofed, g_battery_serial_spoofed, g_display_serial_spoofed, g_ufs_serial_spoofed, g_soc0_spoofed, g_mountinfo_filtered,
            g_ssaid_anchor_fail[0], g_ssaid_anchor_fail[1], g_ssaid_anchor_fail[2], g_ssaid_anchor_fail[3],
            g_ssaid_anchor_fail[4], g_ssaid_anchor_fail[5], g_ssaid_anchor_fail[6], g_ssaid_anchor_fail[7],
            g_gaid_binder_repl, g_hostbridge_repl, g_proc_version_uid_repl, g_timezone_repl,
            g_statfs_overlay_seen, g_statfs_overlay_rewritten, g_mountinfo_seen,
            g_stat_seen, g_stat_overlay_seen, g_stat_rewritten,
            g_blockstore_seen, g_blockstore_neutralized, g_camera_cal_spoofed, g_cursor_aid_spoofed);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    if (!strncmp(args, "check_fd:", 9)) {
        extern enum fd_type { FD_TYPE_NONE=0, FD_TYPE_WIFI_MAC, FD_TYPE_BT_MAC, FD_TYPE_SHAREDPREFS } get_fd_type(int, int);
        int fd = 0;
        for (const char *p = args + 9; *p >= '0' && *p <= '9'; p++) fd = fd * 10 + (*p - '0');
        int type = get_fd_type(fd, 0);
        char buf[64];
        snprintf(buf, sizeof(buf), "fd=%d type=%d", fd, type);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }



    if (!strncmp(args, "add_excluded_uid:", 17)) {
        const char *p = args + 17;
        __u32 uid = 0;
        while (*p >= '0' && *p <= '9') { uid = uid * 10 + (*p - '0'); p++; }
        if (uid == 0) {
            compat_copy_to_user(out_msg, "bad uid", 8);
            return -1;
        }
        for (int i = 0; i < g_excluded_uids_count; i++) {
            if (g_excluded_uids[i] == uid) {
                compat_copy_to_user(out_msg, "dup", 4);
                return 0;
            }
        }
        if (g_excluded_uids_count >= LP_MAX_EXCLUDED_UIDS) {
            compat_copy_to_user(out_msg, "full", 5);
            return -1;
        }
        g_excluded_uids[g_excluded_uids_count++] = uid;
        pr_info("lukeprivacy: excluded uid added: %u (count=%d)\n", uid, g_excluded_uids_count);
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }

    /* Bulk variant — single ctl0 takes CSV of UIDs. APK enumerates ~280
     * (mandatory + extras + FLAG_SYSTEM apps) and would spawn 280 kpatch
     * subprocesses (~26 s wall) if pushed one-by-one. CSV collapses to
     * a single ctl0 call (~50 ms). */
    if (!strncmp(args, "add_excluded_uids:", 18)) {
        const char *p = args + 18;
        int added = 0, dup = 0;
        while (*p) {
            __u32 uid = 0;
            while (*p >= '0' && *p <= '9') { uid = uid * 10 + (*p - '0'); p++; }
            if (uid > 0) {
                bool already = false;
                for (int i = 0; i < g_excluded_uids_count; i++) {
                    if (g_excluded_uids[i] == uid) { already = true; break; }
                }
                if (already) { dup++; }
                else if (g_excluded_uids_count < LP_MAX_EXCLUDED_UIDS) {
                    g_excluded_uids[g_excluded_uids_count++] = uid;
                    added++;
                }
            }
            while (*p && (*p == ',' || *p == ' ')) p++;
        }
        pr_info("lukeprivacy: bulk add_excluded_uids: added=%d dup=%d total=%d\n",
                added, dup, g_excluded_uids_count);
        char buf[64];
        int n = snprintf(buf, sizeof(buf), "ok added=%d dup=%d", added, dup);
        compat_copy_to_user(out_msg, buf, n + 1);
        return 0;
    }

    if (!strcmp(args, "clear_excluded_uids")) {
        g_excluded_uids_count = 0;
        for (int i = 0; i < LP_MAX_EXCLUDED_UIDS; i++) g_excluded_uids[i] = 0;
        pr_info("lukeprivacy: excluded uids cleared\n");
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }

    if (!strcmp(args, "refresh_excluded")) {
        lp_force_resolve_retry();
        int added = lp_resolve_excluded_packages();
        char buf[64];
        snprintf(buf, sizeof(buf), "added=%d total=%d", added, g_excluded_uids_count);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    if (!strcmp(args, "list_excluded_uids")) {
        char buf[256];
        int off = 0;
        off += snprintf(buf + off, sizeof(buf) - off, "count=%d", g_excluded_uids_count);
        for (int i = 0; i < g_excluded_uids_count && off < (int)sizeof(buf) - 16; i++) {
            off += snprintf(buf + off, sizeof(buf) - off, " %u", g_excluded_uids[i]);
        }
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }

    /* FORCE-SPOOF override — CSV of UIDs that must ALWAYS be spoofed even if
     * system/excluded (experiment: spoof gms/gsf/vending). Replaces the whole
     * list each call. */
    if (!strncmp(args, "set_force_spoof_uids:", 21)) {
        const char *p = args + 21;
        int cnt = 0;
        for (int i = 0; i < LP_MAX_FORCE_SPOOF; i++) g_force_spoof_uids[i] = 0;
        while (*p && cnt < LP_MAX_FORCE_SPOOF) {
            __u32 u = 0; int got = 0;
            while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; got = 1; }
            if (got) g_force_spoof_uids[cnt++] = u;
            while (*p && (*p < '0' || *p > '9')) p++;   /* skip separators */
        }
        g_force_spoof_count = cnt;
        pr_info("lukeprivacy: force_spoof_uids set count=%d\n", cnt);
        char buf[32]; snprintf(buf, sizeof(buf), "ok count=%d", cnt);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (!strcmp(args, "clear_force_spoof_uids")) {
        g_force_spoof_count = 0;
        for (int i = 0; i < LP_MAX_FORCE_SPOOF; i++) g_force_spoof_uids[i] = 0;
        pr_info("lukeprivacy: force_spoof_uids cleared\n");
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }
    /* config.gz hide list — CSV of UIDs (the GMS/DroidGuard uid) that get -ENOENT
     * on open("/proc/config.gz"). Replaces the whole list each call. */
    if (!strncmp(args, "set_configgz_uids:", 18)) {
        const char *p = args + 18;
        int cnt = 0;
        for (int i = 0; i < LP_MAX_CONFIGGZ; i++) g_configgz_uids[i] = 0;
        while (*p && cnt < LP_MAX_CONFIGGZ) {
            __u32 u = 0; int got = 0;
            while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; got = 1; }
            if (got) g_configgz_uids[cnt++] = u;
            while (*p && (*p < '0' || *p > '9')) p++;   /* skip separators */
        }
        g_configgz_count = cnt;
        pr_info("lukeprivacy: configgz_uids set count=%d\n", cnt);
        char buf[32]; snprintf(buf, sizeof(buf), "ok count=%d", cnt);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (!strcmp(args, "clear_configgz_uids")) {
        g_configgz_count = 0;
        for (int i = 0; i < LP_MAX_CONFIGGZ; i++) g_configgz_uids[i] = 0;
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }

    /* U18 sensor-motion include list — CSV of uids (the GMS/DroidGuard uid) that
     * get the handheld motion despite being identity-excluded. Replaces the list. */
    if (!strncmp(args, "set_sensor_include:", 19)) {
        const char *p = args + 19;
        int cnt = 0;
        for (int i = 0; i < LP_MAX_SENSOR_INCL; i++) g_sensor_incl_uids[i] = 0;
        while (*p && cnt < LP_MAX_SENSOR_INCL) {
            __u32 u = 0; int got = 0;
            while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; got = 1; }
            if (got) g_sensor_incl_uids[cnt++] = u;
            while (*p && (*p < '0' || *p > '9')) p++;   /* skip separators */
        }
        g_sensor_incl_count = cnt;
        pr_info("lukeprivacy: sensor_include set count=%d\n", cnt);
        char buf[32]; snprintf(buf, sizeof(buf), "ok count=%d", cnt);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    if (!strcmp(args, "clear_sensor_include")) {
        g_sensor_incl_count = 0;
        for (int i = 0; i < LP_MAX_SENSOR_INCL; i++) g_sensor_incl_uids[i] = 0;
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }

    if (parse_profile_cmd(args) == 0) {
        compat_copy_to_user(out_msg, "ok", 3);
        return 0;
    }

    compat_copy_to_user(out_msg, "unknown command", 16);
    return -1;
}

/* Built-in: no unload path. Hooks are compiled-in call-sites, disabled at
 * runtime via `echo disable > /proc/<name>` (g_hooks_enabled). */
late_initcall(lp_init);
