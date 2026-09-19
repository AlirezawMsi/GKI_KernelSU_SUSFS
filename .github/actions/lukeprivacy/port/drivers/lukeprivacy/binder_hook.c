/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy - Binder parcel-rewrite logic (in-tree port)
 *
 * Ported from the KernelPatch module. The runtime inline hook on
 * binder_alloc_copy_user_to_buffer is replaced by a compiled-in call site:
 * drivers/android/binder_alloc.c invokes lp_binder_copy_to_buffer_hook()
 * with the same arguments and all parcel-rewriting logic below runs
 * unchanged. See the FLAGS in the port report for call-site placement.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>   /* init_user_ns */
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <uapi/linux/android/binder.h>   /* binder_size_t */

#include "profile.h"
#include "uaccess.h"
#include "lp_log.h"

/* Opaque forward decls — the hook only uses `alloc` as an identity key
 * (cast to unsigned long for the alloc->uid hash map); binder_buffer and
 * buffer_offset are never dereferenced, so incomplete types suffice and we
 * avoid pulling in the private drivers/android/binder_alloc.h. */
struct binder_alloc;
struct binder_buffer;

/* Exposed call-site entry points (declared here so -Wmissing-prototypes is
 * quiet; the shared lp_hooks.h in the driver dir re-declares them for the
 * call sites in drivers/android/binder_alloc.c). */
void lp_binder_copy_to_buffer_hook(struct binder_alloc *alloc,
                                   struct binder_buffer *buffer,
                                   binder_size_t buffer_offset,
                                   const void __user *from, size_t bytes);
void lp_binder_copy_to_buffer_gnss_hook(const void *src, size_t bytes);
void lp_binder_alloc_init_hook(struct binder_alloc *alloc);
void lp_binder_alloc_release_hook(struct binder_alloc *alloc);
void lp_init_kmalloc(void);
int  binder_hook_init(void);
void binder_hook_exit(void);


/* ─── FP-free IEEE-754 helpers ─────────────────────────────────────────────
 * arm64 in-tree kernel objects build with -mgeneral-regs-only: ANY float /
 * double operation is a hard compile error. All location / GNSS logic below
 * therefore treats coordinates as raw IEEE-754 bit patterns and uses pure
 * integer / bit arithmetic. g_profile.latitude/longitude/altitude stay
 * `double` and g_profile.accuracy stays `float` in profile.h (companion ABI
 * unchanged); we only ever read/write their BITS here, never do FP math. */

/* Bit patterns of the double constants the original FP code compared against
 * (verified with struct.pack round-trip). Magnitude compares use the abs-mask;
 * signed compares use the total-order key below. */
#define LP_F64_ABS_MASK  0x7FFFFFFFFFFFFFFFULL
#define LP_F64_ABS_90    0x4056800000000000ULL   /*  90.0  */
#define LP_F64_ABS_180   0x4066800000000000ULL   /* 180.0  */
#define LP_F64_ABS_1     0x3FF0000000000000ULL   /*   1.0  */
#define LP_F64_35        0x4041800000000000ULL   /*  35.0  */
#define LP_F64_72        0x4052000000000000ULL   /*  72.0  */
#define LP_F64_NEG10     0xC024000000000000ULL   /* -10.0  */
#define LP_F64_40        0x4044000000000000ULL   /*  40.0  */

/* Read/write raw 8-byte double bits (no FP register touched — memcpy of a
 * scalar lowers to an x-register load/store under -mgeneral-regs-only). */
static inline __u64 lp_f64_bits(const void *p) { __u64 b; memcpy(&b, p, 8); return b; }
static inline __u32 lp_f32_bits(const void *p) { __u32 b; memcpy(&b, p, 4); return b; }
static inline void  lp_put64(void *p, __u64 b) { memcpy(p, &b, 8); }

/* Total-order key: maps IEEE-754 double bits to a u64 whose unsigned ordering
 * equals the doubles' signed ordering. Lets us do signed range compares (the
 * Europe bounding box) purely on integers. */
static inline __u64 lp_f64_key(__u64 b)
{
    __u64 mask = (0ULL - (b >> 63)) | 0x8000000000000000ULL;
    return b ^ mask;
}
/* true iff double(a_bits) <= double(b_bits) */
static inline bool lp_f64_le(__u64 a, __u64 b)
{
    return lp_f64_key(a) <= lp_f64_key(b);
}

/* Exact integer equivalent of (__s64)(x * scale) with C truncation toward
 * zero, computed straight from the bit pattern (128-bit intermediate avoids
 * overflow of mantissa*scale). Used for the fractional-part and delta gates
 * that the original code did in double. */
static __s64 lp_f64_to_scaled(__u64 bits, __u64 scale)
{
    __u64 mag = bits & LP_F64_ABS_MASK;
    __u32 exp;
    __u64 mant, mant_full;
    int e2;
    unsigned __int128 prod;
    __s64 out;

    if (mag == 0)
        return 0;
    exp  = (__u32)(mag >> 52);
    mant = mag & 0xFFFFFFFFFFFFFULL;
    mant_full = (exp == 0) ? mant : (mant | 0x10000000000000ULL);
    e2 = (int)exp - 1075;                 /* value = mant_full * 2^e2 */
    prod = (unsigned __int128)mant_full * scale;
    out  = (e2 >= 0) ? (__s64)(prod << e2) : (__s64)(prod >> (-e2));
    return (bits >> 63) ? -out : out;
}

/* Widen IEEE-754 float bits to double bits (integer bit surgery — replaces the
 * `(double)g_profile.accuracy` cast). Exact for all finite/inf/nan/subnormal. */
static __u64 lp_f32_to_f64_bits(__u32 f)
{
    __u32 sign = f >> 31, exp = (f >> 23) & 0xFF, man = f & 0x7FFFFF;
    __u64 s = (__u64)sign << 63;

    if (exp == 0) {                       /* zero / subnormal */
        int e;
        if (man == 0)
            return s;
        e = -126;
        while (!(man & 0x800000)) { man <<= 1; e--; }
        man &= 0x7FFFFF;
        return s | ((__u64)(e + 1023) << 52) | ((__u64)man << 29);
    }
    if (exp == 0xFF)                      /* inf / nan */
        return s | 0x7FF0000000000000ULL | ((__u64)man << 29);
    return s | ((__u64)(exp - 127 + 1023) << 52) | ((__u64)man << 29);
}


int g_binder_copy_calls = 0;
int g_binder_imei_spoofed = 0;
int g_binder_imsi_spoofed = 0;
int g_binder_iccid_spoofed = 0;
int g_binder_mcc_spoofed = 0;
int g_binder_uuid_spoofed = 0;
int g_binder_mediadrm_spoofed = 0;
int g_binder_location_spoofed = 0;
int g_gnss_location_spoofed = 0;
int g_cellinfo_spoofed = 0;
int g_binder_country_spoofed = 0;
int g_adb_hidden = 0;
int g_dnt_spoofed = 0;       /* TelephonyManager.getDataNetworkType IWLAN→NR */
int g_netinfo_spoofed = 0;   /* ConnectivityManager.getActiveNetworkInfo WIFI→MOBILE/NR */
int g_netcaps_spoofed = 0;   /* NetworkCapabilities transport bitmask WIFI→CELLULAR */
int g_carrier_name_spoofed = 0; /* SubscriptionInfo.mCarrierName replaced */
int g_phone_bare_seen = 0;      /* parcels containing real_phone_bare ASCII / UTF-16 */
int g_phone_bare_replaced = 0;  /* parcels where bare-phone literal-match swap fired */

unsigned int g_ssaid_seen = 0;      /* parcels where SSAID rewrite matched */
unsigned int g_ssaid_replaced = 0;  /* SSAID UTF-16 strings actually rewritten */
unsigned int g_ssaid_relaxed_replaced = 0;  /* of which: matched relaxed tail anchor */
/* Cumulative fire counter for relaxed SSAID — capped at 10 per enable cycle.
 * Not static: lukeprivacy.c resets it on 0→1 toggle (set_ssaid_relaxed:1). */
unsigned int g_ssaid_relaxed_window_count = 0;

/* alloc_ptr → uid hash map. Populated by binder_alloc_init hook
 * (called when app opens /dev/binder; current = app, getuid() = app UID).
 * Cleared by binder_alloc_deferred_release hook (process death / fd close).
 *
 * Linear-probe open addressing, 2048 slots. alloc_ptr is kernel address
 * (16-byte aligned typically), so >>4 spreads bits well.
 */
#define LP_UIDMAP_SIZE 2048
struct lp_uid_entry {
    unsigned long alloc;  /* 0 = empty slot */
    unsigned int uid;
};
static struct lp_uid_entry g_uid_by_alloc[LP_UIDMAP_SIZE];
unsigned int g_uid_map_inserts = 0;
unsigned int g_uid_map_evicts = 0;
unsigned int g_uid_map_lookups_hit = 0;
unsigned int g_uid_map_lookups_miss = 0;

/* Lockless hash map. KernelPatch does not export
 * __raw_spin_lock_irqsave / __raw_spin_unlock_irqrestore symbols, so
 * proper kernel spinlocks are unavailable. Race conditions are
 * acceptable here:
 *   - Concurrent writes to different entries: linear probe finds
 *     different slots most of the time; collision worst case = one
 *     entry overwritten (we don't care which uid wins for the same
 *     alloc, since the alloc is single-receiver-process-owned).
 *   - Read-during-write: AArch64 may reorder the (alloc, uid) pair
 *     stores, so reader could observe alloc=X with stale uid=0
 *     briefly. Reader returns 0 → SSAID hook bails out → that ONE
 *     binder reply passes through unmodified. Next read sees the
 *     committed (alloc, uid) pair. JVM caches the first SSAID read
 *     per process, so the rare miss is invisible to the app in
 *     practice (one missed read in a sea of cache hits).
 *
 * To make the rare-miss window as small as possible: writer stores
 * uid FIRST, then alloc — so reader observing alloc==target also sees
 * the uid that was paired with it (compiler may still reorder, but
 * that's the intent and AArch64 release-acquire on subsequent loads
 * usually preserves it). For strict correctness `smp_wmb()` between
 * stores would help, but it's also typically unexported in KPM env.
 */

static void lp_uid_map_set(unsigned long alloc, unsigned int uid)
{
    unsigned int slot, i, idx;
    if (alloc == 0) return;
    slot = (unsigned int)((alloc >> 4) & (LP_UIDMAP_SIZE - 1));
    for (i = 0; i < LP_UIDMAP_SIZE; i++) {
        idx = (slot + i) & (LP_UIDMAP_SIZE - 1);
        if (g_uid_by_alloc[idx].alloc == 0 || g_uid_by_alloc[idx].alloc == alloc) {
            g_uid_by_alloc[idx].uid = uid;        /* publish uid first */
            g_uid_by_alloc[idx].alloc = alloc;    /* then alloc — reader sees pair */
            g_uid_map_inserts++;
            return;
        }
    }
    /* Map full — silently drop (should never happen with 2048 slots). */
}

static unsigned int lp_uid_map_get(unsigned long alloc)
{
    unsigned int slot, i, idx, result = 0;
    if (alloc == 0) return 0;
    slot = (unsigned int)((alloc >> 4) & (LP_UIDMAP_SIZE - 1));
    for (i = 0; i < LP_UIDMAP_SIZE; i++) {
        idx = (slot + i) & (LP_UIDMAP_SIZE - 1);
        if (g_uid_by_alloc[idx].alloc == alloc) {
            result = g_uid_by_alloc[idx].uid;
            g_uid_map_lookups_hit++;
            break;
        }
        if (g_uid_by_alloc[idx].alloc == 0) {
            g_uid_map_lookups_miss++;
            break;
        }
    }
    return result;
}

static void lp_uid_map_del(unsigned long alloc)
{
    unsigned int slot, i, idx;
    if (alloc == 0) return;
    slot = (unsigned int)((alloc >> 4) & (LP_UIDMAP_SIZE - 1));
    for (i = 0; i < LP_UIDMAP_SIZE; i++) {
        idx = (slot + i) & (LP_UIDMAP_SIZE - 1);
        if (g_uid_by_alloc[idx].alloc == alloc) {
            g_uid_by_alloc[idx].alloc = 0;
            g_uid_by_alloc[idx].uid = 0;
            g_uid_map_evicts++;
            break;
        }
        if (g_uid_by_alloc[idx].alloc == 0) break;
    }
}

/* Call-site entry for binder_alloc_init(struct binder_alloc *alloc).
 * Invoked from binder_alloc_init() when an app opens /dev/binder:
 * current = the opening app, so current_uid() = app UID. */
void lp_binder_alloc_init_hook(struct binder_alloc *alloc)
{
    unsigned int uid = from_kuid(&init_user_ns, current_uid());
    lp_uid_map_set((unsigned long)alloc, uid);
}

/* Call-site entry for binder_alloc_deferred_release(struct binder_alloc *alloc).
 * Invoked on binder fd close / process death. */
void lp_binder_alloc_release_hook(struct binder_alloc *alloc)
{
    lp_uid_map_del((unsigned long)alloc);
}

/* Parse first 16 hex chars of seed into u64. Returns 0 if invalid. */
static unsigned long long parse_seed_u64(const char *hex16)
{
    unsigned long long result = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex16[i];
        unsigned char nibble;
        if (c >= '0' && c <= '9') nibble = c - '0';
        else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else return 0;
        result = (result << 4) | nibble;
    }
    return result;
}

/* Splitmix64 — fast deterministic non-cryptographic mixer. Sufficient
 * for per-UID SSAID derivation — apps don't run cryptanalysis on
 * android_id. Avoids any dependency on kernel crypto API. */
static unsigned long long splitmix64(unsigned long long x)
{
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/* Derive per-UID 32-byte MediaDRM deviceUniqueId from the same seed that
 * drives SSAID. Real Android: Widevine TA derives device unique id from
 * device-bound key material that INCLUDES android_id, so apps reading
 * both expect a cryptographic pair, not two independent values. The
 * SSAID hook (try_spoof_ssaid_reply) already publishes per-UID values
 * descended from g_profile.android_id_seed; deriving mediadrm from the
 * same root closes the cross-correlation gap the static
 * g_profile.mediadrm_id couldn't address.
 *
 * 4× splitmix64 chains seeded with distinct per-quarter salts give
 * 256 bits of deterministic high-entropy output. Same UID + same seed =
 * same bytes across reads (the stable-read invariant Widevine needs).
 * Different UID = different bytes (matches our per-app fingerprint
 * model — even though real Android emits the same mediadrm to every
 * app, fraud SDKs hashing the pair (android_id, mediadrm) would also
 * see a different pair per app on real Android because android_id IS
 * per-app SSAID since Android 8; keeping the pair per-app keeps both
 * sides cryptographically consistent for any UID a fraud SDK observes).
 *
 * Pure u64 arithmetic + integer memcpy — no FPU, no allocation, no
 * yield points → safe to call from any binder hook context. */
/* FNV-1a 64-bit hash of a NUL-terminated string. Keys per-package
 * derivation off the stable package name instead of the UID. */
static unsigned long long hash_str_u64(const char *s)
{
    unsigned long long h = 0xcbf29ce484222325ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 0x100000001b3ULL; }
    return h;
}

/* Per-identity mixing key for a receiving app UID. PREFERS the package name
 * (stable across reinstall / UID reassignment) resolved from packages.list;
 * falls back to the UID when the package isn't mapped yet — e.g. an app
 * installed after the last resolver pass, until the companion fires the
 * `refresh_excluded` ctl0 to repopulate the map. The UID fallback reproduces
 * the pre-per-package behaviour, so an unmapped app is never worse off. */
static unsigned long long lp_ident_key(unsigned int uid)
{
    const char *pkg = lp_pkg_for_uid((__u32)uid);
    if (pkg && pkg[0]) return hash_str_u64(pkg);
    return (unsigned long long)uid * 0x9E3779B97F4A7C15ULL;
}

static void derive_per_uid_mediadrm(unsigned long long seed,
                                    unsigned int uid,
                                    unsigned char out[32])
{
    unsigned long long base =
        splitmix64(seed ^ lp_ident_key(uid));
    /* "MDRM" + quarter index. Distinct salts ensure each 8-byte chunk
     * has independent entropy. */
    unsigned long long w0 = splitmix64(base ^ 0x4d44524d00000001ULL);
    unsigned long long w1 = splitmix64(base ^ 0x4d44524d00000002ULL);
    unsigned long long w2 = splitmix64(base ^ 0x4d44524d00000003ULL);
    unsigned long long w3 = splitmix64(base ^ 0x4d44524d00000004ULL);
    for (int i = 0; i < 8; i++) {
        out[i]      = (unsigned char)(w0 >> (i * 8));
        out[i + 8]  = (unsigned char)(w1 >> (i * 8));
        out[i + 16] = (unsigned char)(w2 >> (i * 8));
        out[i + 24] = (unsigned char)(w3 >> (i * 8));
    }
}

/* Derive per-UID SSAID (16 lowercase hex chars) from profile seed.
 * No NUL terminator written — caller provides exactly 16-char buffer. */
static void derive_per_uid_ssaid(const char *seed_hex,
                                 unsigned int uid,
                                 char out_16hex[16])
{
    unsigned long long seed  = parse_seed_u64(seed_hex);
    unsigned long long mixed = splitmix64(seed ^ lp_ident_key(uid));
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        out_16hex[i] = hexchars[mixed & 0xf];
        mixed >>= 4;
    }
}

/* Spoof getSsaid reply parcel. Returns true if rewrite happened.
 *
 * STRUCTURED Bundle detection — SettingsProvider.call(GET_SSAID) returns a
 * Bundle wrapped in a binder reply. The wire layout (Android 14+):
 *
 *     offset 0x00: int status = 0  (binder reply success)
 *     offset 0x04: int dataSize    (Bundle data section size)
 *     offset 0x08: int BNDL magic  = 0x4C444E42 ("BNDL" little-endian)
 *     offset 0x0C: int entry_count = 1
 *     offset 0x10: int key_len     = 5  (length of "value")
 *     offset 0x14: UTF-16 "v\0a\0l\0u\0e\0" + 2-byte pad to 4-byte align
 *     offset 0x20: int val_type    = 0  (Parcel.VAL_STRING)
 *     offset 0x24: int value_len   = 16 (length of SSAID hex string)
 *     offset 0x28: UTF-16 16-hex chars (32 bytes) + 2-byte pad
 *
 * Total reply size: ~76 bytes. We accept 60..200 to absorb Android-version
 * variance.
 *
 * The Bundle structure is a STRONG signature — TikTok / app internal hex
 * tokens, MD5 fragments, session IDs, etc. are NOT wrapped in a Bundle
 * with BNDL magic + key="value" + VAL_STRING marker. False positives on
 * this pattern are practically zero.
 *
 * Pre-v26-rev6 we used a generic "16-char UTF-16 hex with int32=16
 * prefix" scan which over-matched any int_len-prefixed hex token. That
 * caused TikTok soft-rejection ("typing too fast") because TikTok's
 * internal session token / MD5 fragment binder traffic was getting
 * silently corrupted.
 */
/* Strict Bundle anchor (existing, unchanged). Returns true if rewrite done.
 * Caller has already validated preconditions (toggle+seed+UID gate). */
static bool try_strict_bundle_ssaid(char *buf, size_t size,
                                    unsigned int recv_uid)
{
    /* The SettingsProvider getString(android_id) reply carries the SSAID as a
     * Bundle entry keyed "value". Empirically (Pixel 6a, KernelSU Next) the
     * copied reply parcel starts DIRECTLY at that entry, with no outer BNDL
     * magic / entry-count header (the previous strict walk required BNDL and
     * always bailed → ssaid_seen stayed 0). So we anchor on the entry itself,
     * which is highly specific:
     *
     *   [int32 key_len=5]["value\0" UTF-16 = 76 00 61 00 6c 00 75 00 65 00 00 00]
     *   [int32 val_type=0 (VAL_STRING)] [int32 value_len=16]
     *   [16 lowercase-hex UTF-16 chars]  <- the SSAID
     *
     * key "value" + VAL_STRING + exactly-16-lowercase-hex is essentially unique
     * to android_id, so false positives are near zero. We scan the whole parcel
     * so framing variance across Android versions doesn't matter. */
    if (size < 32 || size > 512) return false;
    unsigned char *p = (unsigned char *)buf;

    static const unsigned char VKEY[16] = {
        5, 0, 0, 0,                              /* key_len = 5 */
        'v', 0, 'a', 0, 'l', 0, 'u', 0, 'e', 0, 0, 0  /* "value\0" UTF-16 */
    };

    for (size_t off = 0; off + 16 + 8 + 32 <= size; off += 4) {
        if (memcmp(p + off, VKEY, 16) != 0) continue;
        size_t cur = off + 16;
        unsigned int val_type = *(unsigned int *)(p + cur);
        unsigned int value_len = *(unsigned int *)(p + cur + 4);
        if (val_type != 0 || value_len != 16) continue;
        size_t vpos = cur + 8;

        /* verify 16 lowercase-hex UTF-16 chars */
        int ok = 1;
        for (int i = 0; i < 16; i++) {
            unsigned char c = p[vpos + i * 2];
            if (p[vpos + i * 2 + 1] != 0 ||
                !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = 0; break; }
        }
        if (!ok) continue;

        /* Derive per-receiver SSAID from the profile seed and rewrite.
         * Keyed per-package (stable across reinstall) via lp_ident_key. */
        unsigned long long seed_u64 = parse_seed_u64(g_profile.android_id_seed);
        unsigned long long mixed = splitmix64(seed_u64 ^ lp_ident_key(recv_uid));
        static const char hexchars[] = "0123456789abcdef";
        char derived[16];
        for (int i = 15; i >= 0; i--) { derived[i] = hexchars[mixed & 0xf]; mixed >>= 4; }
        for (int i = 0; i < 16; i++) {
            p[vpos + i * 2]     = (unsigned char)derived[i];
            p[vpos + i * 2 + 1] = 0;
        }
        g_ssaid_replaced++;
        g_ssaid_seen++;
        return true;
    }
    return false;
}

unsigned int g_cursor_aid_spoofed;

/* Cursor/query() android_id spoof. SettingsProvider.query() returns the
 * per-package SSAID inside a CursorWindow, bypassing the call()/Bundle SSAID
 * hook above (and every LSPosed/userspace hook that only wraps getString). A
 * security SDK doing `query(settings/secure, name='android_id')` therefore sees
 * the REAL SSAID while getString() is spoofed — an inconsistency + leak.
 *
 * Observed wire layout (CursorWindow, single-row query, in-parcel, ~144B):
 *   ... "android_id\0\0"  <16 lowercase-hex ASCII> "\0\0" ...
 * i.e. the value is a null-terminated ASCII/UTF-8 16-hex string stored right
 * after its column name. We rewrite it IN PLACE with the SAME per-UID value the
 * Bundle hook derives (derive_per_uid_ssaid, keyed by recv_uid) so both paths
 * agree. Same length (16 hex) → the window's field-slot size stays valid. */
static bool try_spoof_cursor_android_id(char *buf, size_t bytes, unsigned int recv_uid)
{
    if (!g_profile.android_id_spoof_enabled) return false;
    if (g_profile.android_id_seed[0] == 0) return false;
    if (bytes < 40) return false;

    /* Locate the ASCII column-name token "android_id". */
    static const char nm[] __maybe_unused = "android_id";
    long noff = -1;
    for (size_t o = 0; o + 10 <= bytes; o++) {
        if (buf[o] == 'a' && buf[o+1] == 'n' && buf[o+2] == 'd' && buf[o+3] == 'r' &&
            buf[o+4] == 'o' && buf[o+5] == 'i' && buf[o+6] == 'd' && buf[o+7] == '_' &&
            buf[o+8] == 'i' && buf[o+9] == 'd') { noff = (long)o; break; }
    }
    if (noff < 0) return false;

    /* Skip the null/padding between name and value (≤8 bytes) to the first
     * lowercase-hex digit of the value. */
    size_t vpos = (size_t)noff + 10;
    while (vpos < bytes) {
        unsigned char c = (unsigned char)buf[vpos];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) break;
        if (vpos > (size_t)noff + 18) return false;   /* too far — not the value */
        vpos++;
    }
    if (vpos + 16 > bytes) return false;

    /* Require EXACTLY 16 lowercase-hex chars, then a non-hex terminator. */
    for (int i = 0; i < 16; i++) {
        unsigned char c = (unsigned char)buf[vpos + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    if (vpos + 16 < bytes) {
        unsigned char c = (unsigned char)buf[vpos + 16];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) return false;  /* >16 → not SSAID */
    }

    /* Derive the SAME value the Bundle hook uses; skip if already applied. */
    char derived[16];
    derive_per_uid_ssaid(g_profile.android_id_seed, recv_uid, derived);
    int same = 1;
    for (int i = 0; i < 16; i++) if (buf[vpos + i] != derived[i]) { same = 0; break; }
    if (same) return false;

    for (int i = 0; i < 16; i++) buf[vpos + i] = derived[i];
    g_cursor_aid_spoofed++;
    return true;
}

/* Relaxed tail-anchor SSAID match — OPT-IN fallback (default OFF).
 *
 * Catches getSsaid reply variants that DON'T match the strict Bundle
 * envelope. Conservative pattern:
 *   - parcel size 40..400 bytes
 *   - 16-char UTF-16 lowercase-hex residing in last 40 bytes of parcel
 *   - preceded by int32 length prefix == 16 (Parcel.writeString convention)
 *   - recv_uid == g_profile.ssaid_relaxed_target_uid (single UID lock)
 *   - anti-recursion: skip if value already matches our derived spoof
 *
 * Safety guards (every condition AND-ed):
 *   1. Toggle `ssaid_relaxed_enabled` must be ON (default OFF, set via ctl0)
 *   2. Target UID must match `ssaid_relaxed_target_uid` (default 0 = off)
 *   3. Circuit breaker: > 5 rewrites within 60 jiffies-seconds → auto-disable
 *
 * Why so restrictive: pre-v26-rev6 a generic 16-hex scan caused TikTok
 * "typing too fast" because TikTok's OWN session tokens / MD5 fragments
 * got corrupted. UID gate alone wasn't enough — TikTok itself emits
 * 16-hex tokens through binder. Tail-position + single-target-UID +
 * circuit-breaker minimizes the over-match surface. */
static bool try_relaxed_tail_ssaid(char *buf, size_t size,
                                   unsigned int recv_uid)
{
    if (!g_profile.ssaid_relaxed_enabled) return false;
    if (g_profile.ssaid_relaxed_target_uid == 0) return false;
    if (recv_uid != g_profile.ssaid_relaxed_target_uid) return false;
    if (size < 40 || size > 400) return false;

    unsigned char *p = (unsigned char *)buf;

    /* Derive expected spoof value for anti-recursion check */
    char derived[16];
    derive_per_uid_ssaid(g_profile.android_id_seed, recv_uid, derived);

    /* Scan tail region for [int32=16][32-byte UTF-16 lowercase-hex].
     * Tail window = last 40 bytes; min slot = 36 (4+32). */
    size_t tail_start = (size > 40) ? (size - 40) : 0;
    for (size_t off = tail_start; off + 36 <= size; off += 4) {
        unsigned int len_prefix = *(unsigned int *)(p + off);
        if (len_prefix != 16) continue;

        unsigned char *hex = p + off + 4;
        bool valid = true;
        bool same_as_derived = true;
        for (int i = 0; i < 16; i++) {
            unsigned char c = hex[i * 2];
            if (hex[i * 2 + 1] != 0) { valid = false; break; }
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                valid = false; break;
            }
            if (c != (unsigned char)derived[i]) same_as_derived = false;
        }
        if (!valid) continue;
        if (same_as_derived) return false;  /* already spoofed, no-op */

        /* Circuit breaker: hard cap 10 fires cumulative per enable cycle.
         * User must explicitly re-toggle (set_ssaid_relaxed:1) after hitting
         * the cap. Resets when toggle goes 0→1. Conservative: TikTok signup
         * needs maybe 2-5 SSAID reads, 10 gives safety margin without
         * exposing system to runaway rewrite loop. */
        g_ssaid_relaxed_window_count++;
        if (g_ssaid_relaxed_window_count > 10) {
            g_profile.ssaid_relaxed_enabled = false;
            pr_warn("[lukeprivacy] ssaid_relaxed auto-disabled "
                    "(%u fires > 10 cap — safety circuit)\n",
                    g_ssaid_relaxed_window_count);
            return false;
        }

        /* Rewrite — same as strict path */
        for (int i = 0; i < 16; i++) {
            hex[i * 2]     = (unsigned char)derived[i];
            hex[i * 2 + 1] = 0;
        }
        g_ssaid_replaced++;
        g_ssaid_seen++;
        g_ssaid_relaxed_replaced++;
        return true;
    }
    return false;
}

/* Top-level SSAID spoof dispatcher: precondition check, then strict
 * Bundle anchor, then optional relaxed tail-anchor fallback. */
static bool try_spoof_ssaid_reply(char *buf, size_t size,
                                  unsigned long alloc_ptr)
{
    if (!g_profile.android_id_spoof_enabled) return false;
    if (g_profile.android_id_seed[0] == 0) return false;

    /* Per-UID gating via alloc→uid map. Skip if recv UID unknown or in
     * exclusion list (system apps, Google packages, user-added). */
    if (alloc_ptr == 0) return false;
    unsigned int recv_uid = lp_uid_map_get(alloc_ptr);
    if (recv_uid == 0) return false;
    if (recv_uid < 10000) return false;
    if (lp_is_uid_excluded((__u32)recv_uid)) return false;

    if (try_strict_bundle_ssaid(buf, size, recv_uid)) return true;
    return try_relaxed_tail_ssaid(buf, size, recv_uid);
}

/* ─── Google Block Store neutralization ────────────────────────────────────
 *
 * See the profile.h block-comment for the full mechanism + on-device proof.
 * Summary: Snap's IBlockstoreService.retrieveBytes reply (GMS → Snap) carries a
 * Block Store Map entry {key, value}. The KEY is a constant base64 string that
 * the companion captures from schema.pb once and pushes via set_blockstore_key.
 * When we see that key in a reply heading to the Snap UID, we GARBLE THE KEY in
 * place (same byte length → no parcel shift): Snap then looks up its requested
 * key in the returned Map, doesn't find it, and treats the entry as absent →
 * generates a FRESH cloud_account_id, exactly like a genuine new device.
 *
 * We garble the KEY rather than hunt the value offset because the key position
 * is exactly known (we just matched it), the edit is guaranteed same-size, and
 * it can't corrupt the parcel framing. Value-surgery would need the precise
 * wire layout, which we finalize via the capture path below.
 *
 * FLAPPING GUARD: Block Store is read-WRITE. If we garbled EVERY read, Snap
 * would read empty → generate → store → read empty → flap its Fidelius key
 * mid-session. So we only fire `blockstore_fire_cap` times per arm cycle. Snap
 * reads its identity ONCE early (the cloud-restored value we want to kill),
 * caches it in-process, then its own fresh writes read back untouched. The
 * companion re-arms (resets the fire counter) at each newIdentity. */

unsigned int g_blockstore_neutralized = 0;  /* cumulative garble count (stat) */
unsigned int g_blockstore_seen = 0;         /* replies to target UID carrying the key */
static unsigned int g_blockstore_fires = 0; /* fires THIS arm cycle; reset by set_blockstore_arm */

/* Reset the per-arm fire counter — called from lukeprivacy.c set_blockstore_arm. */
void lp_blockstore_arm(void) { g_blockstore_fires = 0; }

/* Plain substring search (no memmem in KPM env). Returns offset of first
 * occurrence of needle[0..nlen) in hay[0..hlen), or -1. */
static long lp_memfind(const char *hay, size_t hlen, const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen) return -1;
    for (size_t off = 0; off + nlen <= hlen; off++) {
        size_t i = 0;
        while (i < nlen && hay[off + i] == needle[i]) i++;
        if (i == nlen) return (long)off;
    }
    return -1;
}

/* UTF-16LE substring search: find ASCII `needle[0..nlen)` encoded as UTF-16LE
 * (each char followed by a 0x00 high byte) within hay[0..hlen). Returns the
 * byte offset of the first char, or -1. Java Parcel.writeString emits String16
 * (UTF-16LE), so a Map<String,...> key like "cloud_account_id" lands this way
 * in the retrieveBytes reply — NOT as base64 (that's GMS's on-disk schema.pb
 * form) and usually NOT as UTF-8. */
static long lp_find_utf16le(const char *hay, size_t hlen, const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen * 2) return -1;
    for (size_t off = 0; off + nlen * 2 <= hlen; off++) {
        size_t i = 0;
        while (i < nlen && hay[off + i * 2] == needle[i] && hay[off + i * 2 + 1] == 0) i++;
        if (i == nlen) return (long)off;
    }
    return -1;
}

/* The Block Store Map key Snap requests for its device-scoped cloud identity.
 * RE of 14.14 (AbstractC38695pg9.b): EnumC24333ft1.I → literal "cloud_account_id".
 * Value = a random UUID (KHk.a) stored with setShouldBackupToCloud(true), hence
 * it survives /data wipe AND factory reset via Google cloud restore. We match on
 * THIS constant string (self-contained, no companion key-push needed). */
static const char BS_CAID_KEY[] = "cloud_account_id";  /* 16 chars */

/* Scan a binder reply buffer for the "cloud_account_id" Map key (UTF-16LE first,
 * UTF-8 fallback). On a hit: bump bs_seen, log when capture is on. If neutralize
 * is on (and fire policy allows), GARBLE the key in place (same byte length → no
 * parcel shift): Snap's Map lookup for "cloud_account_id" then misses → treats the
 * entry as absent → generates a FRESH cloud_account_id (GENERATED_NEW), exactly
 * like a genuine new device. Only "cloud_account_id" is touched — "fidelius" and
 * other Block Store keys pass through untouched (no E2EE breakage).
 * Returns true iff the buffer was modified (caller copies it back). */
static bool try_bs_caid(char *buf, size_t size, unsigned int recv_uid,
                        const char *path_tag)
{
    const size_t klen = sizeof(BS_CAID_KEY) - 1;  /* 16 */
    int enc = 16;
    long off = lp_find_utf16le(buf, size, BS_CAID_KEY, klen);
    if (off < 0) { off = lp_memfind(buf, size, BS_CAID_KEY, klen); enc = 8; }
    if (off < 0) return false;

    /* This IS Snap's Block Store retrieve reply carrying cloud_account_id. */
    g_blockstore_seen++;
    if (g_profile.blockstore_capture_enabled) {
        pr_info("[lukeprivacy] BS-CAID hit uid=%u size=%zu off=%ld enc=utf%d path=%s\n",
                recv_uid, size, off, enc, path_tag);
        /* DIAG: full parcel hex (bounded 160B) to locate the VALUE relative to
         * the key — decides whether key-garble suffices or we must hit the value. */
        for (size_t d = 0; d < size && d < 160; d += 16)
            pr_info("[lukeprivacy] bs[%03zu] %02x %02x %02x %02x %02x %02x %02x %02x "
                    "%02x %02x %02x %02x %02x %02x %02x %02x\n", d,
                    (unsigned char)buf[d+0],(unsigned char)buf[d+1],(unsigned char)buf[d+2],
                    (unsigned char)buf[d+3],(unsigned char)buf[d+4],(unsigned char)buf[d+5],
                    (unsigned char)buf[d+6],(unsigned char)buf[d+7],(unsigned char)buf[d+8],
                    (unsigned char)buf[d+9],(unsigned char)buf[d+10],(unsigned char)buf[d+11],
                    (unsigned char)buf[d+12],(unsigned char)buf[d+13],(unsigned char)buf[d+14],
                    (unsigned char)buf[d+15]);
    }

    if (!g_profile.blockstore_neutralize_enabled) return false;

    /* Fire policy (see set_blockstore_arm). cap==0 → UNLIMITED while enabled
     * (session bracket: companion arms before launch, disarms after Snap exits).
     * cap>0 → first-N per arm cycle. */
    if (g_profile.blockstore_fire_cap != 0
        && g_blockstore_fires >= g_profile.blockstore_fire_cap) return false;

    /* PRIMARY neutralize: EMPTY THE VALUE.
     *
     * The reply is a SafeParcelable BlockstoreData:
     *   field1 (hdr 01 00 ff ff, size int) = value byte[]: `10 00 00 00` (len 16)
     *                                        + 16-byte UUID   ← what Snap actually uses
     *   field2 (02 00 04 00)               = flag (backupToCloud)
     *   field3 (03 00 ff ff, size int)     = key string "cloud_account_id"
     * Snap reads field1 by SafeParcel FIELD ID, not by the key string — so
     * garbling the key does nothing (proven: bs_neut fired, CAID unchanged).
     * We must zero the value byte[] LENGTH (0x00000010 → 0): Snap then reads an
     * EMPTY value → F2i UUID reconstruction throws → onErrorNext → GENERATED_NEW
     * (fresh random UUID per account). Same byte count (only a length int flips
     * to 0) → no parcel shift; the 16 stale value bytes become unread slack. */
    bool modified = false;
    for (size_t v = 0; v + 12 <= size; v++) {
        /* field1 header `01 00 ff ff`, then 4-byte field size, then byte[] len
         * `10 00 00 00` (16). Distinctive vs field2/field3 and the key-only
         * parcel (whose v+8 is `01 00 00 00`, not `10 00 00 00`). */
        if ((unsigned char)buf[v]   == 0x01 && (unsigned char)buf[v+1]  == 0x00 &&
            (unsigned char)buf[v+2] == 0xff && (unsigned char)buf[v+3]  == 0xff &&
            (unsigned char)buf[v+8] == 0x10 && (unsigned char)buf[v+9]  == 0x00 &&
            (unsigned char)buf[v+10]== 0x00 && (unsigned char)buf[v+11] == 0x00) {
            buf[v+8] = 0x00;   /* byte[] length 16 → 0 = empty value */
            modified = true;
            if (g_profile.blockstore_capture_enabled)
                pr_info("[lukeprivacy] BS-CAID VALUE-EMPTIED at off=%zu (was 16B UUID)\n", v + 12);
            break;
        }
    }

    /* Belt-and-suspenders: also garble the key string (harmless if Snap ignores
     * it; helps if any code path DOES key by the returned string). */
    for (int i = 0; i < 4; i++) {
        size_t p = (enc == 16) ? (size_t)off + i * 2 : (size_t)off + i;
        if (p < size) { buf[p] ^= 0x20; modified = true; }
    }

    if (!modified) return false;
    g_blockstore_fires++;
    g_blockstore_neutralized++;
    if (g_profile.blockstore_capture_enabled)
        pr_info("[lukeprivacy] BS-CAID NEUTRALIZED off=%ld enc=utf%d path=%s\n",
                off, enc, path_tag);
    return true;
}

/* Length-prefixed-string spoof helper. Scans `buf` for a String8 / String16
 * field (4-byte int length prefix + chars + null terminator + padding) whose
 * content matches `needle`, and overwrites with `replacement`. Three slot
 * size cases:
 *
 *   1. repl_len <= needle_len  → write repl, pad rest of payload with
 *      spaces (UTF-8) or U+0020 (UTF-16). Length prefix stays at needle_len.
 *      App sees a `needle_len`-char string with trailing spaces, which is
 *      always a coherent value (no parcel layout shift).
 *
 *   2. repl_len >  needle_len AND padded slot size unchanged
 *      → GROW path: update length prefix to repl_len, write the longer
 *      payload, zero remaining slot bytes. Padded slot capacity is
 *      `(len + 1 + 3) & ~3` for String8 and `(len*2 + 2 + 3) & ~3` for
 *      String16; growth that fits the same padded slot doesn't shift
 *      neighbour fields. Example fits: "Plus"(4)→"Cricket"(7) UTF-8
 *      both round to 8-byte payload.
 *
 *   3. repl_len >  needle_len AND padded slot would have to grow
 *      → SKIP. We can't extend the parcel (binder buffer is fixed-size
 *      per allocation), and overwriting only N chars while leaving the
 *      old length prefix produces visibly truncated values like "Veri"
 *      from "Verizon" — louder leak than letting the original pass.
 *
 * Both UTF-8 and UTF-16LE variants run because Parcel.writeString routes
 * to writeString16 in most cases, but writeString8 is used selectively in
 * ServiceState / SubscriptionInfo on modern AOSP. Try both encodings and
 * keep whichever matches; bounded to 8 swaps per parcel as a safety stop. */
/* PlanPrecision A6 (2026-05-11): `out_first_offset` lets the caller learn
 * where the first successful match landed, so subsequent passes (e.g.
 * scan_operator_alpha_leaks int-leak rewrite) can localise their scan
 * window around the hit instead of brute-forcing the whole parcel.
 * Callers that don't need the position pass NULL. SIZE_MAX is written on
 * "no match". */
static int spoof_lenprefixed_string(char *buf, size_t bytes,
                                    const char *needle, const char *replacement,
                                    size_t *out_first_offset)
{
    if (out_first_offset) *out_first_offset = (size_t)-1;
    if (!needle || !needle[0] || !replacement) return 0;
    int needle_len = 0;
    while (needle[needle_len] && needle_len < 63) needle_len++;
    int repl_len = 0;
    while (replacement[repl_len] && repl_len < 63) repl_len++;
    if (needle_len < 1) return 0;

    int swaps = 0;
    int needle_padded8  = (needle_len + 1 + 3) & ~3;
    int needle_padded16 = (needle_len * 2 + 2 + 3) & ~3;
    int repl_padded8    = (repl_len + 1 + 3) & ~3;
    int repl_padded16   = (repl_len * 2 + 2 + 3) & ~3;

    bool grow_ok_8  = (repl_padded8  <= needle_padded8);
    bool grow_ok_16 = (repl_padded16 <= needle_padded16);

    /* UTF-8 / String8 scan: int32(len)=needle_len, then needle bytes, then null. */
    for (size_t off = 0; off + 4 + needle_padded8 <= bytes && swaps < 8; off += 4) {
        if (*(__s32 *)(buf + off) != needle_len) continue;
        unsigned char *data = (unsigned char *)(buf + off + 4);
        bool match = true;
        for (int i = 0; i < needle_len; i++) {
            if (data[i] != (unsigned char)needle[i]) { match = false; break; }
        }
        if (!match) continue;
        if (data[needle_len] != 0) continue;
        if (out_first_offset && *out_first_offset == (size_t)-1) *out_first_offset = off;

        if (repl_len <= needle_len) {
            /* Zero-pad past replacement payload. Length prefix stays
             * needle_len; parser reads up to NUL at position repl_len.
             * Real getCarrierName never returns trailing-space, so do
             * NOT space-pad — would be a structural tell. */
            for (int i = 0; i < repl_len; i++) data[i] = (unsigned char)replacement[i];
            for (int i = repl_len; i < needle_padded8; i++) data[i] = 0;
        } else if (grow_ok_8) {
            /* Grow within padded slot: bump length prefix, write payload,
             * zero remaining slot bytes (NUL terminator + padding). */
            *(__s32 *)(buf + off) = repl_len;
            for (int i = 0; i < repl_len; i++) data[i] = (unsigned char)replacement[i];
            for (int i = repl_len; i < needle_padded8; i++) data[i] = 0;
        } else {
            /* Truncate fallback: replacement doesn't fit padded slot. Write
             * first needle_len chars of replacement, keep length prefix
             * unchanged so subsequent parcel fields don't shift. Zero
             * NUL terminator and any residual slot bytes. */
            for (int i = 0; i < needle_len; i++) data[i] = (unsigned char)replacement[i];
            for (int i = needle_len; i < needle_padded8; i++) data[i] = 0;
        }
        swaps++;
    }

    /* UTF-16LE / String16 scan: int32(len)=needle_len, then UTF-16 chars, then 0x0000. */
    for (size_t off = 0; off + 4 + needle_padded16 <= bytes && swaps < 8; off += 4) {
        if (*(__s32 *)(buf + off) != needle_len) continue;
        __u16 *data = (__u16 *)(buf + off + 4);
        bool match = true;
        for (int i = 0; i < needle_len; i++) {
            if (data[i] != (__u16)(unsigned char)needle[i]) { match = false; break; }
        }
        if (!match) continue;
        if (data[needle_len] != 0) continue;
        if (out_first_offset && *out_first_offset == (size_t)-1) *out_first_offset = off;

        if (repl_len <= needle_len) {
            for (int i = 0; i < repl_len; i++) data[i] = (__u16)(unsigned char)replacement[i];
            for (int i = repl_len; i < needle_len; i++) data[i] = (__u16)' ';
        } else if (grow_ok_16) {
            *(__s32 *)(buf + off) = repl_len;
            for (int i = 0; i < repl_len; i++) data[i] = (__u16)(unsigned char)replacement[i];
            /* Zero out remaining slot bytes (past the new payload + null). */
            char *p   = (char *)(data + repl_len + 1);
            char *end = (char *)data + needle_padded16;
            while (p < end) *p++ = 0;
        } else {
            /* Truncate fallback (UTF-16): same as String8 path above. */
            for (int i = 0; i < needle_len; i++) data[i] = (__u16)(unsigned char)replacement[i];
            data[needle_len] = 0;
        }
        swaps++;
    }

    return swaps;
}

/* ServiceState / NetworkRegistrationInfo / cellIdentity operatorAlpha leak.
 * tm.getServiceState() and getActiveSubscriptionInfoList() return parcels
 * containing operatorAlphaLong / operatorAlphaShort strings that expose the
 * REAL network-side carrier identity (e.g. "Plus" leaks even when displayName
 * has been spoofed to "Verizon"). Same fields appear nested inside
 * NetworkRegistrationInfo's cellIdentity. Companion APK captures both alpha
 * variants once and pushes them via set_real_operator_alpha_long/short ctl0;
 * here we scan every parcel for those exact strings and rewrite them with
 * carrier_name.
 *
 * When an operatorAlpha hit lands, we know this is a ServiceState (or NRI)
 * parcel — that gives us the gate we need to also zero the int leaks
 * (mChannelNumber, mCellBandwidths[]) without false-flipping unrelated
 * 4-byte ints in the same buffer. The int swap is bounded to a short
 * window after the alpha match (~256 bytes either side covers
 * ServiceState's adjacent fields without touching neighbour parcels) and
 * literal-matched against the captured real values, both of which combine
 * to keep false-positive risk negligible. */
static bool scan_operator_alpha_leaks(char *buf, size_t bytes)
{
    if (!g_profile.carrier_name[0]) return false;
    int total = 0;
    size_t hit_long = (size_t)-1, hit_short = (size_t)-1;
    if (g_profile.real_operator_alpha_long[0])
        total += spoof_lenprefixed_string(buf, bytes,
            g_profile.real_operator_alpha_long, g_profile.carrier_name, &hit_long);
    if (g_profile.real_operator_alpha_short[0])
        total += spoof_lenprefixed_string(buf, bytes,
            g_profile.real_operator_alpha_short, g_profile.carrier_name, &hit_short);
    if (total > 0) {
        g_carrier_name_spoofed += total;

        /* PlanPrecision A6: int leaks scan is now LOCALISED to a ±256 B
         * window around the earliest operatorAlpha hit instead of the full
         * parcel. ServiceState / NetworkRegistrationInfo fields
         * (mChannelNumber, mCellBandwidths[], cellIdentity.ci/pci/tac/earfcn)
         * sit directly adjacent to operatorAlpha in the AOSP serialisation
         * order — within tens of bytes for the same NRI, up to a couple
         * hundred for the neighbouring NRI in the same ServiceState. Going
         * unbounded across 4-16 KB SubscriptionInfo big-parcels meant a
         * single match on pci ∈ [0..503] (a tiny range, statistically dense
         * with native SDK loop counters / enum values / colour values
         * embedded in unrelated nested parcels) could rewrite int4s far
         * outside the cell-identity region.
         *
         * Cap at 6 swaps per int (NRI parcel typically has 2-3 NRIs:
         * IWLAN+WWAN+CS). If spoof is 0 (not configured), skip the field
         * entirely — leaving real intact is less detectable than zeroing
         * to a physically impossible value (earfcn=0, pci=0, etc.) */
        size_t hit = (hit_long  != (size_t)-1) ? hit_long  : hit_short;
        if (hit_long != (size_t)-1 && hit_short != (size_t)-1 && hit_short < hit_long)
            hit = hit_short;
        size_t lo = (hit > 256) ? hit - 256 : 0;
        size_t hi = (hit + 256 < bytes) ? hit + 256 : bytes;

        const __s32 ints_real[] = {
            g_profile.real_channel_number, g_profile.real_cell_bandwidth,
            g_profile.real_ci, g_profile.real_pci,
            g_profile.real_tac, g_profile.real_earfcn,
        };
        const __s32 ints_spoof[] = {
            g_profile.spoof_channel_number, g_profile.spoof_cell_bandwidth,
            g_profile.spoof_ci, g_profile.spoof_pci,
            g_profile.spoof_tac, g_profile.spoof_earfcn,
        };
        for (int k = 0; k < 6; k++) {
            __s32 needle = ints_real[k];
            __s32 repl   = ints_spoof[k];
            if (!needle || !repl) continue;
            int swaps = 0;
            for (size_t i = lo; i + 4 <= hi && swaps < 6; i += 4) {
                if (*(__s32 *)(buf + i) == needle) {
                    *(__s32 *)(buf + i) = repl;
                    swaps++;
                }
            }
        }
    }
    return total > 0;
}

/* Verify a region looks like printable ASCII / UTF-8 of given length —
 * used to disambiguate carrierName slot from random ints that happen to
 * fall in 1..63 range. Allows printable ASCII, common Unicode UTF-8 (high
 * bit set), and space. */
static bool looks_like_string(const unsigned char *p, int len)
{
    if (len < 1) return false;
    int printable = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = p[i];
        if (c >= 0x20 && c <= 0x7e) printable++;
        else if (c >= 0x80) printable++;  /* UTF-8 continuation/lead */
        else return false;  /* control char in middle of string */
    }
    /* Require null terminator at len (writeString8 always writes one) */
    return p[len] == 0;
}

static bool scan_subinfo_anchor(char *buf, size_t bytes)
{
    if (!g_profile.carrier_name[0]) return false;
    bool changed = false;
    int dn_len = 0;
    while (g_profile.carrier_name[dn_len] && dn_len < 63) dn_len++;
    if (dn_len < 1) return false;
    int dn_padded = (dn_len + 1 + 3) & ~3;

    /* AOSP writeCharSequence layout:
     *   [type_marker int(4)] [len int(4)] [utf8 bytes][null][padding to 4B]
     *
     * For SubscriptionInfo (mDisplayName, mCarrierName) sequence the parcel
     * holds two such CharSequence blobs back-to-back, so after displayName's
     * payload+padding we get: carrierName's [type=0] then [len].
     *
     * Anchor scan: find displayName length+content, then check that the
     * next int is a 0 type-marker, then read carrierName length, then verify
     * the carrierName payload looks like a string (printable + null term).
     * That triple anchor is essentially impossible to false-match. */
    static int dbg_match = 0;
    static int dbg_type __maybe_unused = 0;
    for (size_t off = 0; off + 4 + dn_padded + 4 + 4 + 4 <= bytes; off += 4) {
        if (*(__s32 *)(buf + off) != dn_len) continue;
        unsigned char *dn_data = (unsigned char *)(buf + off + 4);
        bool ok = true;
        for (int i = 0; i < dn_len; i++) {
            if (dn_data[i] != (unsigned char)g_profile.carrier_name[i]) { ok = false; break; }
        }
        if (!ok) continue;
        if (dn_data[dn_len] != 0) continue;
        if (dbg_match < 3) { dbg_match++; lp_dbg("lukeprivacy: dn match off=%zu bytes=%zu type@%zu=%d\n", off, bytes, off+4+dn_padded, *(__s32 *)(buf + off + 4 + dn_padded)); }

        /* After displayName slot: TextUtils.writeToParcel CharSequence type
         * marker. AOSP convention: 1 = plain String (not Spanned), 0 = Spanned.
         * For SubscriptionInfo.mCarrierName the value is always a plain String,
         * so we accept type=1 only — type=0 would indicate a different parcel
         * structure and likely a false-positive displayName match. */
        size_t type_off = off + 4 + dn_padded;
        if (*(__s32 *)(buf + type_off) != 1) continue;

        /* Then carrierName length */
        size_t cn_prefix_off = type_off + 4;
        if (cn_prefix_off + 4 > bytes) continue;
        __s32 cn_len = *(__s32 *)(buf + cn_prefix_off);
        if (cn_len < 1 || cn_len > 63) continue;
        int cn_padded = (cn_len + 1 + 3) & ~3;
        if (cn_prefix_off + 4 + cn_padded > bytes) continue;

        /* Verify carrierName payload looks like a string (printable + null term) */
        unsigned char *cn_data = (unsigned char *)(buf + cn_prefix_off + 4);
        if (!looks_like_string(cn_data, cn_len)) continue;

        /* All anchors confirmed — this IS a SubscriptionInfo parcel.
         * Three carrierName slot cases (mirrors spoof_lenprefixed_string):
         *
         *  - dn_len <= cn_len: write displayName, pad rest with spaces.
         *    Length prefix stays at cn_len (slot byte count unchanged).
         *
         *  - dn_len  > cn_len AND padded slot still fits: GROW. Bump the
         *    length prefix to dn_len, write payload + null, zero remaining
         *    slot bytes. Doesn't shift neighbouring fields because
         *    String8 padded slot is `(len + 1 + 3) & ~3`, which is the
         *    same for cn_len in [1..3] and dn_len in [1..3], in [4..7],
         *    in [8..11], etc. Real "Plus"(4)→spoof "Cricket"(7) hits
         *    this path: both round to an 8-byte payload.
         *
         *  - dn_len  > cn_len AND padded slot would have to grow:
         *    TRUNCATE the displayName to cn_len chars and write into slot.
         *    Length prefix stays at cn_len. Yes a 4-char prefix of "T-Mobile"
         *    ("T-Mo") is recognisable, but it's strictly less of a leak than
         *    letting the real carrierName ("Plus") pass through verbatim.
         *    Skipping was the previous behaviour and produced exactly that
         *    leak in the SubscriptionInfo panel — trade-off explicitly
         *    overruled by user 2026-05-07.
         */
        int dn_padded_in_cn_slot = (dn_len + 1 + 3) & ~3;
        if (dn_len <= cn_len) {
            for (int i = 0; i < dn_len; i++) cn_data[i] = (unsigned char)g_profile.carrier_name[i];
            for (int i = dn_len; i < cn_len; i++) cn_data[i] = ' ';
            g_carrier_name_spoofed++;
            changed = true;
        } else if (dn_padded_in_cn_slot <= cn_padded) {
            *(__s32 *)(buf + cn_prefix_off) = dn_len;
            for (int i = 0; i < dn_len; i++) cn_data[i] = (unsigned char)g_profile.carrier_name[i];
            for (int i = dn_len; i < cn_padded - 1; i++) cn_data[i] = 0;
            g_carrier_name_spoofed++;
            changed = true;
        } else {
            /* Truncation fallback: dn doesn't fit padded slot. Write first
             * cn_len chars of displayName, keep the original length prefix
             * (so subsequent fields don't shift), and re-null-terminate. */
            for (int i = 0; i < cn_len; i++) cn_data[i] = (unsigned char)g_profile.carrier_name[i];
            cn_data[cn_len] = 0;
            g_carrier_name_spoofed++;
            changed = true;
        }

        /* Knowing this is SubscriptionInfo, also swap mCarrierId int. The
         * field lies further into the parcel (after mNameSource, mIconTint,
         * mNumber, mMcc, mMnc, mCountryIso, mCardString, ...) so we don't
         * have a fixed offset — but we can scan from end of cn_padded
         * onward for the exact real_carrier_id int. Keeping the search
         * scoped to AFTER the cn slot (within 1KB) avoids false matches
         * elsewhere in the parcel. Only swap once per SubscriptionInfo to
         * avoid corrupting iconTint or other ints that coincidentally
         * equal real_carrier_id (rare for 4-digit IDs, but bounded). */
        if (g_profile.real_carrier_id && g_profile.carrier_id &&
            g_profile.real_carrier_id != g_profile.carrier_id) {
            size_t scan_start = cn_prefix_off + 4 + cn_padded;
            size_t scan_end = scan_start + 1024;
            if (scan_end > bytes) scan_end = bytes;
            for (size_t i = scan_start; i + 4 <= scan_end; i += 4) {
                if (*(__s32 *)(buf + i) == g_profile.real_carrier_id) {
                    *(__s32 *)(buf + i) = g_profile.carrier_id;
                    break;
                }
            }
        }
    }
    return changed;
}

/* Heap allocator looked up at module init (kpmalloc/tlsf isn't exported by
 * KPatch-Next on this kernel). Used to allocate per-call scratch buffers
 * for SubscriptionInfo parcels >4KB. NULL if lookup failed → fallback path
 * skips large parcels rather than crashing. */
typedef void *(*kmalloc_fn_t)(unsigned long, unsigned int);
typedef void  (*kfree_fn_t)(const void *);
static kmalloc_fn_t lp_kmalloc = NULL;
static kfree_fn_t   lp_kfree   = NULL;
#define LP_GFP_ATOMIC GFP_ATOMIC  /* binder copy runs in atomic-safe context */

/* In-tree: resolve the allocator directly instead of kallsyms. __kmalloc and
 * kfree are exported kernel symbols. Cast to the local fn typedefs (size_t vs
 * unsigned long and gfp_t vs unsigned int are ABI-identical on arm64). */
void lp_init_kmalloc(void)
{
    lp_kmalloc = (kmalloc_fn_t)__kmalloc;
    lp_kfree   = (kfree_fn_t)kfree;
}

// Forward declarations for GNSS functions
static int try_detect_gnss_location(char *buf, size_t bytes);
static void spoof_gnss_location(char *buf);

static bool is_imei_format_u16(const __u16 *data, size_t len)
{
    if (len < 30) return false;
    int digits = 0;
    for (size_t i = 0; i < 15 && i * 2 + 1 < len; i++) {
        __u16 c = data[i];
        if (c >= '0' && c <= '9') digits++;
        else return false;
    }
    return digits == 15;
}

static bool is_imsi_format_u16(const __u16 *data, __s32 len)
{
    if (len != 15) return false;
    for (int i = 0; i < 15; i++) {
        if (data[i] < '0' || data[i] > '9') return false;
    }
    /* Per ITU-T E.212, MCCs always start with 2 (Europe), 3 (NA), 4 (Asia),
     * 5 (Oceania), 6 (Africa), 7 (South America), or 9 (Worldwide/special).
     * Restricting to those buckets keeps IMSI distinguishable from generic
     * 15-digit values (timestamps, randoms) while covering every real
     * subscriber. The previous narrow "260/234/310/311 only" check missed
     * IMSIs from every other carrier and silently let them through to the
     * IMEI replacement path. */
    __u16 mcc1 = data[0];
    return (mcc1 == '2' || mcc1 == '3' || mcc1 == '4' ||
            mcc1 == '5' || mcc1 == '6' || mcc1 == '7' || mcc1 == '9');
}

/* ICCID validation. ITU-T E.118 mandates that every telecom SIM ICCID
 * starts with the industry identifier "89" (Major Industry Identifier =
 * telecommunications). Without this prefix anchor the format check
 * (19-22 ASCII digits) also matches arbitrary 19-22 digit values found
 * in native SDK replies — database row IDs, sequence counters,
 * high-resolution timestamps. The "89" prefix narrows the match to
 * actual telecom payloads. (PlanPrecision A3, 2026-05-11.) */
static bool is_iccid_format_u16(const __u16 *data, size_t len)
{
    if (len < 38) return false;
    if (data[0] != '8' || data[1] != '9') return false;
    int digits = 0;
    for (size_t i = 0; i < 22 && i * 2 + 1 < len; i++) {
        __u16 c = data[i];
        if (c >= '0' && c <= '9') digits++;
        else break;
    }
    return digits >= 19 && digits <= 22;
}

static void replace_utf16_inline(char *data, const char *new_val, size_t max_chars)
{
    __u16 *utf16 = (__u16 *)data;
    size_t i;
    for (i = 0; new_val[i] && i < max_chars; i++) {
        utf16[i] = (__u16)new_val[i];
    }
    utf16[i] = 0;
}

/* Resize-aware UTF-16 replacement that updates the 4-byte length prefix.
 * Parcel.writeString16 pads the chars+null payload to a 4-byte boundary,
 * so 2-char and 3-char strings both occupy 8 bytes after the prefix
 * (2 chars + null + 2 padding = 8; 3 chars + null = 8). That means we
 * can swap a 2-char field with a 3-char value (and vice versa) without
 * shifting any subsequent parcel content — exactly what's needed to
 * spoof MNC across 2↔3-char carriers (PL "06" ↔ US "260"). For larger
 * size jumps (e.g. 5→6) the slot would grow and we'd corrupt the
 * neighbour, so we refuse and let the caller fall back. */
static bool replace_utf16_resize(char *prefix_ptr, const char *new_val, int new_chars, int old_chars)
{
    int old_data = ((old_chars + 1) * 2 + 3) & ~3;
    int new_data = ((new_chars + 1) * 2 + 3) & ~3;
    if (new_data > old_data) return false;

    *(__s32 *)prefix_ptr = (__s32)new_chars;
    __u16 *utf16 = (__u16 *)(prefix_ptr + 4);
    int i;
    for (i = 0; i < new_chars && new_val[i]; i++) {
        utf16[i] = (__u16)new_val[i];
    }
    utf16[i] = 0;
    /* Zero remaining bytes within the (old) slot so stale chars can't
     * leak when the new string is shorter than the slot. */
    char *p = (char *)utf16 + (i + 1) * 2;
    char *end = (char *)utf16 + old_data;
    while (p < end) *p++ = 0;
    return true;
}

static bool __maybe_unused is_mccmnc_format_u16(const __u16 *data, __s32 len)
{
    if (len < 5 || len > 6) return false;
    for (int i = 0; i < len; i++) {
        if (data[i] < '0' || data[i] > '9') return false;
    }
    __u16 mcc1 = data[0];
    if (mcc1 != '2' && mcc1 != '3' && mcc1 != '4' && mcc1 != '5') return false;
    return true;
}

static bool is_country_format_u16(const __u16 *data, __s32 len)
{
    if (len != 2) return false;
    for (int i = 0; i < 2; i++) {
        if (data[i] < 'a' || data[i] > 'z') return false;
    }
    return true;
}

/* SubscriptionInfo.mMcc is a 3-char digit string. AOSP only stores MCC
 * here, so we accept any 3-digit string with first digit in 2-7 (the
 * valid first-digit range for ITU-T E.212 region codes). */
static bool is_mcc3_format_u16(const __u16 *data, __s32 len)
{
    if (len != 3) return false;
    if (data[0] < '2' || data[0] > '7') return false;
    if (data[1] < '0' || data[1] > '9') return false;
    if (data[2] < '0' || data[2] > '9') return false;
    return true;
}

/* SubscriptionInfo.mMnc can be 2 or 3 chars, all digits. Only used in
 * the marker-guarded path so the only 2-digit fields nearby are real
 * MNC values, not arbitrary integers from elsewhere. */
static bool is_mnc_format_u16(const __u16 *data, __s32 len)
{
    if (len != 2 && len != 3) return false;
    for (int i = 0; i < len; i++) {
        if (data[i] < '0' || data[i] > '9') return false;
    }
    return true;
}

static bool is_phone_format_u16(const __u16 *data, __s32 len)
{
    if (len < 10 || len > 16) return false;
    if (data[0] != '+') return false;
    for (int i = 1; i < len; i++) {
        if (data[i] < '0' || data[i] > '9') return false;
    }
    return true;
}

static bool __maybe_unused is_uuid_format_u16(const __u16 *data, __s32 len)
{
    if (len != 36) return false;
    for (int i = 0; i < 36; i++) {
        __u16 c = data[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
    }
    return true;
}

static bool is_mediadrm_reply(const char *buf, size_t bytes)
{
    if (bytes != 40) return false;
    __s32 status = *(__s32 *)(buf);
    __s32 arr_len = *(__s32 *)(buf + 4);
    if (status != 0) return false;
    if (arr_len != 32) return false;
    return true;
}

// Location parcel field masks (from AOSP Location.java)
#define LOC_HAS_ALTITUDE                    (1 << 0)
#define LOC_HAS_SPEED                       (1 << 1)
#define LOC_HAS_BEARING                     (1 << 2)
#define LOC_HAS_HORIZONTAL_ACCURACY         (1 << 3)
#define LOC_HAS_MOCK_PROVIDER               (1 << 4)
#define LOC_HAS_ALTITUDE_ACCURACY           (1 << 5)
#define LOC_HAS_SPEED_ACCURACY              (1 << 6)
#define LOC_HAS_BEARING_ACCURACY            (1 << 7)
#define LOC_HAS_ELAPSED_REALTIME_UNCERTAINTY (1 << 8)
#define LOC_HAS_MSL_ALTITUDE                (1 << 9)
#define LOC_HAS_MSL_ALTITUDE_ACCURACY       (1 << 10)
#define LOC_VALID_MASK                      0x7FF

static bool is_valid_provider(const char *str, int len)
{
    if (len == 3 && str[0] == 'g' && str[1] == 'p' && str[2] == 's') return true;
    if (len == 5 && str[0] == 'f' && str[1] == 'u' && str[2] == 's' && str[3] == 'e' && str[4] == 'd') return true;
    if (len == 7 && str[0] == 'n' && str[1] == 'e' && str[2] == 't' && str[3] == 'w' && str[4] == 'o' && str[5] == 'r' && str[6] == 'k') return true;
    if (len == 7 && str[0] == 'p' && str[1] == 'a' && str[2] == 's' && str[3] == 's' && str[4] == 'i' && str[5] == 'v' && str[6] == 'e') return true;
    return false;
}

static int try_detect_location_parcel_at(const char *buf, size_t bytes, size_t start, size_t *out_lat_offset)
{
    if (start + 48 > bytes) return 0;

    const char *p = buf + start;
    size_t remaining = bytes - start;

    // Read provider string length (string8 format: int32 len + chars + null + pad)
    __s32 provider_len = *(__s32 *)p;
    if (provider_len < 3 || provider_len > 7) return 0;

    // Validate provider name
    const char *provider = p + 4;
    if (!is_valid_provider(provider, provider_len)) return 0;

    // Calculate padded string size (len + null, aligned to 4 bytes)
    size_t str_size = (provider_len + 1 + 3) & ~3;
    size_t offset = 4 + str_size;

    if (offset + 40 > remaining) return 0;

    // Read fieldsMask
    __s32 fields_mask = *(__s32 *)(p + offset);
    if (fields_mask < 0 || (fields_mask & ~LOC_VALID_MASK) != 0) return 0;

    offset += 4;  // fieldsMask
    offset += 8;  // timeMs (int64)
    offset += 8;  // elapsedRealtimeNs (int64)

    // Optional elapsedRealtimeUncertaintyNs
    if (fields_mask & LOC_HAS_ELAPSED_REALTIME_UNCERTAINTY) {
        offset += 8;
    }

    if (offset + 16 > remaining) return 0;

    // Now we should be at latitude (8B IEEE-754) and longitude (8B IEEE-754)
    __u64 lat_bits = lp_f64_bits(p + offset);
    __u64 lon_bits = lp_f64_bits(p + offset + 8);
    __u64 lat_mag  = lat_bits & LP_F64_ABS_MASK;
    __u64 lon_mag  = lon_bits & LP_F64_ABS_MASK;

    // Validate coordinates are in valid range: |lat|<=90, |lon|<=180
    if (lat_mag > LP_F64_ABS_90)  return 0;
    if (lon_mag > LP_F64_ABS_180) return 0;

    // Additional sanity: reject 0,0 (both exactly +/-0 = uninitialized)
    if (lat_mag == 0 && lon_mag == 0) return 0;

    *out_lat_offset = start + offset;
    return 1;
}

static int try_detect_location_parcel(const char *buf, size_t bytes, size_t *out_lat_offset, size_t *out_start)
{
    // Try at offset 0 (direct Location parcel)
    if (try_detect_location_parcel_at(buf, bytes, 0, out_lat_offset)) { *out_start = 0; return 1; }

    // Try at offset 4 (after writeTypedObject's int32(1) prefix)
    if (bytes > 4) {
        __s32 prefix = *(__s32 *)buf;
        if (prefix == 1 && try_detect_location_parcel_at(buf, bytes, 4, out_lat_offset)) { *out_start = 4; return 1; }
    }

    // Try at offset 8 (status + typed object prefix)
    if (bytes > 8) {
        __s32 status = *(__s32 *)buf;
        __s32 prefix = *(__s32 *)(buf + 4);
        if (status == 0 && prefix == 1 && try_detect_location_parcel_at(buf, bytes, 8, out_lat_offset)) { *out_start = 8; return 1; }
    }

    return 0;
}

static void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    for (size_t i = 0; i < out_len && hex[i*2] && hex[i*2+1]; i++) {
        char h = hex[i*2];
        char l = hex[i*2+1];
        unsigned char hv = (h >= 'a') ? (h - 'a' + 10) : ((h >= 'A') ? (h - 'A' + 10) : (h - '0'));
        unsigned char lv = (l >= 'a') ? (l - 'a' + 10) : ((l >= 'A') ? (l - 'A' + 10) : (l - '0'));
        out[i] = (hv << 4) | lv;
    }
}

/* Parse "AA:BB:CC:DD:EE:FF" → out[0..5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}.
 * Returns false on malformed input. */
static bool parse_mac_str(const char *str, unsigned char *out)
{
    if (!str || !str[0]) return false;
    for (int i = 0; i < 6; i++) {
        const char *p = str + i * 3;
        char h = p[0], l = p[1];
        unsigned char hv = (h >= 'a') ? (h - 'a' + 10) : ((h >= 'A') ? (h - 'A' + 10) : (h - '0'));
        unsigned char lv = (l >= 'a') ? (l - 'a' + 10) : ((l >= 'A') ? (l - 'A' + 10) : (l - '0'));
        if (hv > 15 || lv > 15) return false;
        out[i] = (hv << 4) | lv;
        if (i < 5 && p[2] != ':') return false;
    }
    return true;
}

int g_wifiinfo_spoofed = 0;
int g_binder_btmac_spoofed = 0;
int g_wifi_debug = 0;   /* ctl0 wifi_debug:1 → log WifiInfo parcel layout (A16 RE) */
int g_wifi_ssid_spoof = 1;  /* ctl0 set_ssid_spoof:0/1 → randomise network name (default ON) */

static bool is_mac_utf16(const __u16 *u)
{
    return u[2] == ':' && u[5] == ':' && u[8] == ':' && u[11] == ':' && u[14] == ':';
}

static void replace_mac_utf16(__u16 *u, const char *mac)
{
    for (int i = 0; i < 17 && mac[i]; i++)
        u[i] = (__u16)mac[i];
}

/* HCI Command Complete event for Read_BD_ADDR (OGF=0x04, OCF=0x009, opcode 0x1009).
 * Layout (12 bytes, no HCI packet-type prefix — Android BluetoothHci HAL strips it):
 *
 *   [0]=0x0E       event code: Command Complete
 *   [1]=0x0A       parameter total length (10)
 *   [2]=NN         num HCI command packets allowed (host flow control)
 *   [3]=0x09       opcode low byte (Read_BD_ADDR LE)
 *   [4]=0x10       opcode high byte
 *   [5]=0x00       status: success
 *   [6..11]        BD_ADDR (LITTLE-ENDIAN — buf[6] is byte that prints last in MAC)
 *
 * The vendor BT HAL service (e.g. /vendor/bin/hw/android.hardware.bluetooth-service.bcmbtlinux)
 * delivers HCI events to com.google.android.bluetooth via AIDL hciEventReceived(byte[]).
 * The byte[] travels through binder as length-prefixed inline data; we scan the binder
 * buffer for the 6-byte event signature and rewrite the BD_ADDR before the daemon parses
 * it. Daemon then writes the spoofed MAC into bt_config.conf [Adapter] Address line and
 * settings.secure.bluetooth_address — every leak vector we couldn't reach from userspace.
 *
 * Userspace sed on bt_config.conf is futile: daemon overwrites it from this very HCI
 * response on every BT enable.
 */
static bool try_spoof_hci_bdaddr(char *buf, size_t bytes)
{
    if (bytes < 12) return false;
    if (!g_profile.bluetooth_mac[0]) return false;

    unsigned char mac[6];
    if (!parse_mac_str(g_profile.bluetooth_mac, mac)) return false;

    /* Reject 00:00:00:00:00:00 (uninitialized profile) so we don't poison the
     * daemon with an invalid MAC if the user hasn't configured one yet. */
    bool all_zero = true;
    for (int i = 0; i < 6; i++) if (mac[i]) { all_zero = false; break; }
    if (all_zero) return false;

    for (size_t i = 0; i + 12 <= bytes; i++) {
        unsigned char *p = (unsigned char *)(buf + i);
        if (p[0] != 0x0E) continue;
        if (p[1] != 0x0A) continue;
        /* p[2] num_cmd_packets — varies, accept any */
        if (p[3] != 0x09) continue;
        if (p[4] != 0x10) continue;
        if (p[5] != 0x00) continue;

        /* Skip if BD_ADDR is all-zero (firmware not ready) */
        bool addr_zero = true;
        for (int k = 0; k < 6; k++) if (p[6 + k]) { addr_zero = false; break; }
        if (addr_zero) continue;

        /* HCI is little-endian: buf[6] = MAC[5] (last printed octet), buf[11] = MAC[0] */
        for (int k = 0; k < 6; k++) {
            p[6 + k] = mac[5 - k];
        }
        return true;
    }
    return false;
}

static bool try_spoof_wifiinfo(char *buf, size_t bytes)
{
    /* A16 RE instrumentation: when wifi_debug on, locate BSSID (MAC UTF-16)
     * and SSID ("Net.." UTF-16) in ANY reply + dump header words, so we can
     * rewrite the stale detection gate below to the real A16 parcel layout. */
    if (g_wifi_debug && bytes >= 40 && bytes <= 16384) {
        /* Only length-prefixed UTF-16 strings (Parcel.writeString16: int charcount,
         * then chars). BSSID = 17-char MAC; SSID = "Net"+digit (Net1-16). Kills the
         * offset-0 binder-header false positives from the first pass. */
        size_t bssid_off = 0, bssid2_off = 0, ssid_off = 0;
        __s32 ssid_len = 0;
        for (size_t off = 4; off + 40 <= bytes; off += 4) {
            __s32 slen = *(__s32 *)(buf + off - 4);
            __u16 *u = (__u16 *)(buf + off);
            if (slen == 17 && is_mac_utf16(u)) {
                if (!bssid_off) bssid_off = off; else if (!bssid2_off) bssid2_off = off;
            }
            /* SSID stored quoted: "Net5" → first char is a double-quote. */
            if (!ssid_off && slen >= 1 && slen <= 34 && u[0] == '"') {
                ssid_off = off; ssid_len = slen;
            }
        }
        /* A16 SSID is a raw ASCII byte-array (WifiSsid), not UTF-16. Scan for
         * "Net"+digit as single bytes, log offset + the 4-byte length prefix. */
        size_t assid_off = 0; __s32 assid_len = 0;
        for (size_t off = 4; off + 5 <= bytes; off++) {
            unsigned char *b = (unsigned char *)(buf + off);
            if ((b[0] == 'N' || b[0] == 'n') && b[1] == 'e' && b[2] == 't' &&
                b[3] >= '0' && b[3] <= '9') {
                assid_off = off; assid_len = *(__s32 *)(buf + off - 4); break;
            }
        }
        if (bssid_off || ssid_off || assid_off) {
            __s32 *h = (__s32 *)buf;
            pr_info("lukeprivacy wifi_dbg: bytes=%zu bssid@%zu mac2@%zu qssid@%zu(len=%d) assid@%zu(len=%d) hdr=%d,%d,%d,%d\n",
                    bytes, bssid_off, bssid2_off, ssid_off, ssid_len, assid_off, assid_len,
                    h[0], h[1], h[2], h[3]);
        }
    }
    /* A16 fix: the old h[0]==0/h[1]==1 header gate rejected every modern
     * WifiInfo parcel (measured: 872B, h[0]=-127) before reaching the MAC
     * scan below. And the old offset-32 SSID parse assumed a stale layout.
     * New approach: a light size gate (WifiInfo ~872B; the 2048 cap still
     * excludes the ~2484B getScanResults parcel we must NOT touch), then
     * the self-validating MAC scan finds BSSID+macAddress wherever they are.
     * SSID (A16 = raw byte-array WifiSsid, not a UTF-16 string) is handled
     * separately in a follow-up pass. */
    if (bytes < 60 || bytes > 2048) return false;
    if (!g_profile.spoof_bssid[0]) return false;

    bool modified = false;

    // BSSID: replace ONLY the first length-17 UTF-16 MAC string (the AP MAC =
    // getBSSID(), the field Snap reads). The 2nd MAC is getMacAddress() (the
    // phone's OWN wlan0 MAC) — Android already redacts it to 02:00:00:00:00:00
    // for apps, and a real device returns exactly that, so we LEAVE it intact.
    // Overwriting it with a real-looking MAC would be an anomaly/tell (real
    // apps never see a genuine MAC there). The hardware MAC for privileged
    // /sys/class/net/wlan0/address reads is handled by the read hook, not here.
    size_t bssid_prefix_off = 0;
    for (size_t off = 8; off + 40 <= bytes; off += 4) {
        __s32 slen = *(__s32 *)(buf + off);
        if (slen != 17 || off + 4 + 36 > bytes) continue;
        __u16 *u = (__u16 *)(buf + off + 4);
        if (!is_mac_utf16(u)) continue;

        replace_mac_utf16(u, g_profile.spoof_bssid);   // 1st MAC = BSSID
        bssid_prefix_off = off;
        modified = true;
        break;                                          // leave macAddress (2nd MAC) = 02:00..
    }

    /* SSID (A16 = raw ASCII byte-array WifiSsid, e.g. "Net5") sits immediately
     * before the BSSID length-prefix: [ssid_len][ssid+pad][17][bssid...].
     * Anchor on the just-found BSSID prefix, walk back over 4-byte-aligned
     * padded content to the ssid_len field, then overwrite the name in place
     * with a deterministic random string (seeded from spoof_bssid → stable
     * per-account, rotates when the identity rotates). Style: mixed-case
     * alnum like "Z21s". Only fires when the WiFi identity spoof is on. */
    if (bssid_prefix_off >= 12 && g_profile.spoof_bssid[0] && g_wifi_ssid_spoof) {
        for (__s32 L = 1; L <= 32; L++) {
            size_t padded = (L + 3) & ~3;
            if (padded + 4 > bssid_prefix_off) break;
            size_t len_off = bssid_prefix_off - padded - 4;
            size_t content = len_off + 4;
            if (*(__s32 *)(buf + len_off) != L) continue;
            /* content must be printable ASCII, no colon (else it's the MAC) */
            bool printable = true;
            for (__s32 i = 0; i < L; i++) {
                unsigned char c = (unsigned char)buf[content + i];
                if (c < 0x20 || c > 0x7e || c == ':') { printable = false; break; }
            }
            if (!printable) continue;
            static const char cs[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
            unsigned long long s = 0xcbf29ce484222325ULL;
            for (const char *p = g_profile.spoof_bssid; *p; p++) {
                s ^= (unsigned char)*p; s *= 0x100000001b3ULL;
            }
            for (__s32 i = 0; i < L; i++) {
                s ^= (unsigned long long)(i + 1) * 0x9E3779B97F4A7C15ULL;
                s *= 0x100000001b3ULL;
                buf[content + i] = cs[(s >> 33) % (sizeof(cs) - 1)];
            }
            modified = true;
            break;
        }
    }

    if (modified) g_wifiinfo_spoofed++;
    return modified;
}

/* getScanResults spoof — SCOPED to the Net1..Net16 farm SSIDs.
 *
 * The getScanResults parcel (List<ScanResult>, ~2484B — the one try_spoof_wifiinfo
 * deliberately excludes via its 2048 cap) leaks the REAL BSSIDs of the farm's
 * routers, a location/cluster fingerprint, even though WifiInfo's connected
 * BSSID is already spoofed. For each ScanResult whose SSID is "Net"+1..16
 * (raw ASCII WifiSsid byte-array on A16), we overwrite the following 17-char
 * UTF-16 BSSID string IN PLACE with a deterministic fake MAC derived from
 * spoof_bssid + the network number: stable per identity, DISTINCT per net (no
 * "all APs share one BSSID" anomaly). Same length (17 UTF-16 chars) → no
 * re-marshalling, parcel size unchanged. Real neighbour APs (non-Net) are left
 * untouched. Only fires when the WiFi identity spoof is armed. */
static bool try_spoof_scanresults(char *buf, size_t bytes)
{
    if (bytes < 200 || bytes > 16384) return false;
    if (!g_profile.spoof_bssid[0] || !g_wifi_ssid_spoof) return false;

    bool modified = false;
    for (size_t off = 4; off + 5 <= bytes; off++) {
        unsigned char *b = (unsigned char *)(buf + off);
        if (!((b[0] == 'N' || b[0] == 'n') && b[1] == 'e' && b[2] == 't' &&
              b[3] >= '0' && b[3] <= '9'))
            continue;
        /* Net number: 1 or 2 digits (Net1..Net16). */
        int netnum = b[3] - '0';
        size_t namelen = 4;
        if (off + 4 < bytes && b[4] >= '0' && b[4] <= '9') {
            netnum = netnum * 10 + (b[4] - '0');
            namelen = 5;
        }
        if (netnum < 1 || netnum > 16) continue;

        /* BSSID = next length-17 UTF-16 MAC after the SSID, in a bounded window. */
        for (size_t o = off + namelen; o + 4 + 34 <= bytes && o < off + namelen + 96; o += 2) {
            __s32 slen = *(__s32 *)(buf + o);
            if (slen != 17) continue;
            __u16 *u = (__u16 *)(buf + o + 4);
            if (!is_mac_utf16(u)) continue;

            /* Deterministic fake MAC from spoof_bssid seed XOR netnum. */
            unsigned long long s = 0xcbf29ce484222325ULL;
            for (const char *p = g_profile.spoof_bssid; *p; p++) {
                s ^= (unsigned char)*p; s *= 0x100000001b3ULL;
            }
            s ^= (unsigned long long)netnum * 0x9E3779B97F4A7C15ULL;
            s = splitmix64(s);
            static const char hx[] = "0123456789abcdef";
            unsigned char mb[6];
            char fake[18];
            for (int i = 0; i < 6; i++) mb[i] = (unsigned char)((s >> (i * 8)) & 0xff);
            mb[0] = (mb[0] & 0xfe) | 0x02;   /* locally-administered, unicast */
            for (int i = 0; i < 6; i++) {
                fake[i * 3]     = hx[mb[i] >> 4];
                fake[i * 3 + 1] = hx[mb[i] & 0xf];
                if (i < 5) fake[i * 3 + 2] = ':';
            }
            fake[17] = '\0';
            replace_mac_utf16(u, fake);
            modified = true;
            break;
        }
    }
    if (modified) g_wifiinfo_spoofed++;
    return modified;
}

/* Camera calibration metadata spoof (see profile.h camera_cal_* rationale).
 * getCameraCharacteristics() returns a ~12KB camera_metadata blob IN the binder
 * parcel (< the 40KB writeBlob ashmem threshold) carrying per-unit lens
 * intrinsics/distortion/pose + sensor colour matrices as IEEE-754 float32
 * words. The companion read the REAL words via Camera2 and pushed (real,fake)
 * 32-bit pairs (fake = seed-perturbed ±0.3% from android_id_seed). We do a
 * width-preserving in-place replace of each real word with its fake — no
 * camera_metadata_t parsing, parcel size unchanged.
 *
 * Guard against clobbering a non-camera parcel that merely contains a matching
 * 32-bit word: require a camera-metadata marker first (any LENS/SENSOR
 * calibration tag present). USER apps only (gated by caller). */
unsigned int g_camera_cal_spoofed;

static bool parcel_has_camera_tag(const char *buf, size_t bytes)
{
    /* LENS_INTRINSIC_CALIBRATION/DISTORTION/POSE_*, SENSOR_CALIBRATION_TRANSFORM1/2 */
    static const __u32 tags[] = {
        0x0008000aU, 0x0008000dU, 0x00080006U, 0x00080007U,
        0x000e0005U, 0x000e0006U,
    };
    for (size_t off = 0; off + 4 <= bytes; off++) {
        __u32 w = *(__u32 *)(buf + off);
        for (int i = 0; i < 6; i++)
            if (w == tags[i]) return true;
    }
    return false;
}

static bool try_spoof_camera_calibration(char *buf, size_t bytes)
{
    if (!g_profile.camera_spoof_enabled || g_profile.camera_cal_count == 0) return false;
    if (bytes < 64 || bytes > 65536) return false;
    if (!parcel_has_camera_tag(buf, bytes)) return false;

    bool modified = false;
    /* Byte-granular scan: the metadata data section is 4-aligned within the
     * parcel in practice, but scanning every offset is bulletproof against any
     * blob-start alignment and costs little (parcel ≤64KB, few dozen pairs,
     * only on the rare camera-characteristics reply). Replacing every match of
     * a repeated real value (e.g. fx==fy) with the same fake keeps the intrinsic
     * model self-consistent. */
    for (__u32 pi = 0; pi < g_profile.camera_cal_count; pi++) {
        __u32 real = g_profile.camera_cal_real[pi];
        __u32 fake = g_profile.camera_cal_fake[pi];
        if (real == fake) continue;
        for (size_t off = 0; off + 4 <= bytes; off++) {
            if (*(__u32 *)(buf + off) == real) {
                *(__u32 *)(buf + off) = fake;
                modified = true;
            }
        }
    }
    if (modified) g_camera_cal_spoofed++;
    return modified;
}

static bool try_spoof_cellinfo(char *buf, size_t bytes)
{
    /* User-toggle gate: dormant unless the operator explicitly enabled
     * cell info spoofing. Without this the hook fires whenever a binder
     * reply structurally looks like a CellInfo list — irrespective of
     * sim_hook/cell_info_hook toggles in the UI — and apps with a real
     * working SIM see getAllCellInfo() = empty. That cascades into
     * carrier-service crashes (RcsService NPE on missing cell context,
     * "RcsService keeps stopping") for users who only want identity
     * spoofing turned off. */
    if (!g_profile.cell_info_enabled) return false;

    if (bytes < 40 || bytes > 2048) return false;

    __s32 status = *(__s32 *)(buf);
    if (status != 0) return false;

    __s32 count = *(__s32 *)(buf + 4);
    /* Cell tower count cap. Originally 10, which silently let dense urban
     * cell lists (we saw 11 WCDMA neighbours in real Polish 3G coverage)
     * fall through unspoofed — apps then read getAllCellInfo() and got
     * the actual environment, contradicting the spoofed SIM operator
     * country. Modems can legitimately surface 32+ neighbours; raise the
     * cap so all of them get zeroed out. */
    if (count < 1 || count > 64) return false;

    __s32 non_null = *(__s32 *)(buf + 8);
    if (non_null != 1) return false;

    // CellInfo.type: 1=GSM, 2=CDMA, 3=LTE, 4=WCDMA, 5=TDSCDMA, 6=NR
    __s32 cell_type = *(__s32 *)(buf + 12);
    if (cell_type < 1 || cell_type > 6) return false;

    __s32 registered = *(__s32 *)(buf + 16);
    if (registered != 0 && registered != 1) return false;

    // timestamp: nanoseconds, must be positive and reasonable
    __s64 timestamp = *(__s64 *)(buf + 20);
    if (timestamp < 1000000000LL) return false;

    // connectionStatus: 0=NONE, 1=PRIMARY, 2=SECONDARY
    __s32 conn_status = *(__s32 *)(buf + 28);
    if (conn_status < 0 || conn_status > 2) return false;

    /* Zero count — AOSP readTypedList stops here, trailing bytes ignored.
     * Also zero the first-element marker (non_null) as defense-in-depth
     * for any consumer doing raw parcel inspection field-by-field; with
     * count=0 marker is structurally unread but a non-zero stale marker
     * looks inconsistent in raw dumps. */
    *(__s32 *)(buf + 4) = 0;
    *(__s32 *)(buf + 8) = 0;
    g_cellinfo_spoofed++;
    return true;
}

/* GnssStatus parcel zero-out (IGnssStatusListener.onGnssStatusChanged
 * one-way transaction). Layout after enforceInterface header:
 *   int32 svCount
 *   int32 arr_len = svCount; int32[svCount]   svidWithFlags
 *   int32 arr_len = svCount; float[svCount]   cn0DbHz
 *   int32 arr_len = svCount; float[svCount]   elevations
 *   int32 arr_len = svCount; float[svCount]   azimuths
 *   int32 arr_len = svCount; float[svCount]   carrierFrequencies   (Android 8+)
 *   int32 arr_len = svCount; float[svCount]   basebandCn0DbHz      (Android 11+)
 * Total content: 28 + 24*N bytes.
 *
 * The header (interface descriptor token, strict-mode policy, work-source uid)
 * varies in size between Android versions, so we brute-scan for the
 * structural anchor: 6 sequential `arr_len == svCount` int32s at the
 * expected fixed strides, with svCount in [4..50] (real Pixel sees ~10-30
 * GPS+GLONASS+Galileo+BeiDou+QZSS satellites at any given moment).
 *
 * Defeats TLE-based comparison: an anti-fraud SDK with ACCESS_FINE_LOCATION
 * registers GnssStatus.Callback (public API since Android 7) and compares
 * visible PRNs+constellations against a TLE for the spoofed coordinates.
 * Server-side check is ~10 lines of skyfield. Zero-out yields "no satellites
 * visible" — same baseline as indoor / GPS-off, harder to flag than
 * "satellites visible but wrong constellation for claimed location". */
int g_gnss_status_spoofed = 0;
static bool try_spoof_gnss_status(char *buf, size_t bytes)
{
    if (bytes < 28 + 24) return false;        /* min: svCount + 6*(arr+1*4) for N=1 */
    if (bytes > 28 + 24 * 200) return false;  /* sanity cap */

    for (size_t off = 0; off + 28 <= bytes; off += 4) {
        __s32 svCount = *(__s32 *)(buf + off);
        if (svCount < 4 || svCount > 50) continue;
        size_t expected = 28 + 24 * (size_t)svCount;
        if (off + expected > bytes) continue;

        /* All 6 arr_len fields must equal svCount, at fixed strides. */
        bool ok = true;
        size_t inner = off + 4;
        for (int i = 0; i < 6; i++) {
            if (inner + 4 > bytes) { ok = false; break; }
            if (*(__s32 *)(buf + inner) != svCount) { ok = false; break; }
            inner += 4 + 4 * (size_t)svCount;
        }
        if (!ok) continue;

        /* Anchor confirmed — zero svCount and every arr_len.
         * Android Parcel readers stop iterating at arr_len=0 and
         * ignore the trailing payload bytes. */
        *(__s32 *)(buf + off) = 0;
        inner = off + 4;
        for (int i = 0; i < 6; i++) {
            *(__s32 *)(buf + inner) = 0;
            inner += 4 + 4 * (size_t)svCount;
        }
        g_gnss_status_spoofed++;
        return true;
    }
    return false;
}

/* PlanPrecision #3 (2026-05-11): standalone IPhoneSubInfo IMSI/IMEI reply
 * spoof, locked on the exact parcel shape produced by
 * `IPhoneSubInfo.getSubscriberId(int)` / `.getDeviceId()`:
 *
 *   [status:int=0][len:int=15][utf16: 30 B + 2 B null] = 40 B exact
 *
 * Previous gate `bytes >= 40 && bytes <= 48` accepted padded variants that
 * the AOSP path never emits — and any analytics SDK shipping a 15-char
 * UTF-16 string as a first-field reply (timestamps, internal IDs) would
 * fall through the same check. Tightening to `bytes == 40` keeps the swap
 * scoped to the canonical reply shape; in-SubscriptionInfo IMSI handling
 * stays inside scan_and_spoof_parcel, gated by the ICCID anchor marker. */
static bool try_spoof_imsi_standalone(char *buf, size_t bytes)
{
    if (bytes != 40) return false;
    if (*(__s32 *)buf != 0) return false;        /* status = 0 */
    if (*(__s32 *)(buf + 4) != 15) return false; /* utf16 length = 15 */

    __u16 *utf16 = (__u16 *)(buf + 8);
    /* IMSI first (MCC-prefix validated). Without this order any 15-digit
     * reply collapsed onto IMEI; IMSI replies ended up as a copy of the
     * configured IMEI string.
     *
     * Empty-profile bail-out: when companion APK clears the relevant
     * profile field (imsi_hook / imei_hook off → `set_imsi:` /
     * `set_imei:` empty pushed), replace_utf16_inline with new_val=""
     * would write utf16[0]=0 and erase the real 15-digit reply. Apps
     * with imsi_hook off would see empty getSubscriberId() instead of
     * the real IMSI. Guard each branch on the matching field. */
    if (is_imsi_format_u16(utf16, 15)) {
        if (!g_profile.imsi[0]) return false;
        replace_utf16_inline(buf + 8, g_profile.imsi, 15);
        g_binder_imsi_spoofed++;
        return true;
    }
    if (is_imei_format_u16(utf16, 32)) {
        if (!g_profile.imei[0]) return false;
        replace_utf16_inline(buf + 8, g_profile.imei, 15);
        g_binder_imei_spoofed++;
        return true;
    }
    return false;
}

static bool scan_and_spoof_parcel(char *buf, size_t bytes)
{
    bool modified = false;
    size_t offset = 0;
    /* Marker: ICCID (19-22 char digit string starting with '8') is the
     * unambiguous SubscriptionInfo signature. Once we see one in this
     * parcel, we know subsequent 3-char/2-char fields in the same buffer
     * are SubscriptionInfo.mMcc / mMnc / mCountryIso and not random
     * 3-digit / 2-letter strings from unrelated parcels (locale codes,
     * port numbers, etc.). Keeps the more aggressive replacements free
     * of false positives in non-telephony parcels. */
    bool subinfo_marker_seen = false;

    while (offset + 8 < bytes) {
        __s32 str_len = *(__s32 *)(buf + offset);

        if (str_len >= 19 && str_len <= 22 && offset + 4 + (str_len + 1) * 2 <= bytes) {
            __u16 *utf16 = (__u16 *)(buf + offset + 4);
            if (is_iccid_format_u16(utf16, bytes - offset - 4)) {
                /* Set the SubInfo marker regardless of iccid_hook state:
                 * the IMSI-match branch below uses it as a structural
                 * "this parcel is SubscriptionInfo" gate, and we want
                 * IMSI spoofing to remain possible even when iccid_hook
                 * is off but imsi_hook is on. */
                subinfo_marker_seen = true;
                if (g_profile.iccid[0]) {
                    replace_utf16_inline(buf + offset + 4, g_profile.iccid, str_len);
                    g_binder_iccid_spoofed++;
                    modified = true;
                }
            }
        }
        /* PlanPrecision #3: IMSI match inside scan_and_spoof_parcel only
         * fires after the ICCID anchor has been seen in the same parcel
         * (subinfo_marker_seen=true). Without that gate any 15-digit
         * UTF-16 string at any 4-byte-aligned offset — analytics SDK
         * timestamps, internal IDs, hash truncations — was treated as
         * SubscriptionInfo.mImsi and rewritten. Standalone IMSI replies
         * (40 B exact) are handled by try_spoof_imsi_standalone instead. */
        else if (subinfo_marker_seen && str_len == 15 &&
                 offset + 4 + 32 <= bytes && g_profile.imsi[0]) {
            __u16 *utf16 = (__u16 *)(buf + offset + 4);
            if (is_imsi_format_u16(utf16, 15)) {
                replace_utf16_inline(buf + offset + 4, g_profile.imsi, 15);
                g_binder_imsi_spoofed++;
                modified = true;
            }
        }
        /* MCCMNC concatenation (operatorNumeric / network operator string).
         * Literal-match against real_mcc + real_mnc concatenated. Replace
         * with target g_profile.mccmnc using resize-aware swap so a 5→6
         * char grow refuses (UTF-16 padded slot 12→16 doesn't fit) instead
         * of producing the truncated "31041" garbage that `replace_utf16_inline`
         * used to emit. UTF-8 path handles writeString8 case where padded
         * slot is `(len+1+3)&~3` (5 and 6 both round to 8 → grow fits).
         *
         * The previous heuristic (`is_mccmnc_format_u16`: any 5-6 digit
         * string starting with 2-5) false-matched dates / area codes / etc.
         * inside larger parcels. Literal real-value match keeps swaps
         * scoped to the specific carrier we know the SIM has. */
        else if ((str_len == 5 || str_len == 6) && offset + 4 + (str_len + 1) * 2 <= bytes
                 && g_profile.mccmnc[0]
                 && g_profile.real_mcc[0] && g_profile.real_mnc[0]) {
            int rmcc_len = 0; while (g_profile.real_mcc[rmcc_len] && rmcc_len < 3) rmcc_len++;
            int rmnc_len = 0; while (g_profile.real_mnc[rmnc_len] && rmnc_len < 3) rmnc_len++;
            int rmccmnc_len = rmcc_len + rmnc_len;
            if (rmccmnc_len == str_len && rmccmnc_len <= 6) {
                /* Build real_mccmnc on stack to compare slot bytes against. */
                char rmccmnc[7];
                int i = 0;
                for (int j = 0; j < rmcc_len && i < 6; j++) rmccmnc[i++] = g_profile.real_mcc[j];
                for (int j = 0; j < rmnc_len && i < 6; j++) rmccmnc[i++] = g_profile.real_mnc[j];
                rmccmnc[i] = '\0';

                int spoof_len = 0;
                while (g_profile.mccmnc[spoof_len] && spoof_len < 6) spoof_len++;

                /* UTF-16 path */
                __u16 *utf16 = (__u16 *)(buf + offset + 4);
                bool m16 = true;
                for (int j = 0; j < str_len; j++) {
                    if (utf16[j] != (__u16)(unsigned char)rmccmnc[j]) { m16 = false; break; }
                }
                if (m16 && utf16[str_len] == 0) {
                    if (replace_utf16_resize(buf + offset, g_profile.mccmnc, spoof_len, str_len)) {
                        g_binder_mcc_spoofed++;
                        modified = true;
                    }
                } else if (offset + 4 + ((str_len + 1 + 3) & ~3) <= bytes) {
                    /* UTF-8 path */
                    unsigned char *u8 = (unsigned char *)(buf + offset + 4);
                    bool m8 = true;
                    for (int j = 0; j < str_len; j++) {
                        if (u8[j] != (unsigned char)rmccmnc[j]) { m8 = false; break; }
                    }
                    if (m8 && u8[str_len] == 0) {
                        int old_padded = (str_len + 1 + 3) & ~3;
                        int new_padded = (spoof_len + 1 + 3) & ~3;
                        if (new_padded <= old_padded) {
                            *(__s32 *)(buf + offset) = spoof_len;
                            for (int j = 0; j < spoof_len; j++) u8[j] = (unsigned char)g_profile.mccmnc[j];
                            for (int j = spoof_len; j < old_padded - 1; j++) u8[j] = 0;
                            g_binder_mcc_spoofed++;
                            modified = true;
                        }
                    }
                }
            }
        }
        /* SubscriptionInfo.mMcc — 3-char digit string. Literal-match against
         * real_mcc. Both UTF-16 and UTF-8 (writeString8) layouts handled.
         * Note mcc is fixed 3 chars worldwide so no resize needed; spoof
         * mcc must also be 3 chars (validated by companion APK). */
        else if (str_len == 3 && offset + 4 + 8 <= bytes && g_profile.mcc[0] && g_profile.real_mcc[0]) {
            __u16 *utf16 = (__u16 *)(buf + offset + 4);
            unsigned char *u8 = (unsigned char *)(buf + offset + 4);
            if (is_mcc3_format_u16(utf16, 3)
                && (__u16)g_profile.real_mcc[0] == utf16[0]
                && (__u16)g_profile.real_mcc[1] == utf16[1]
                && (__u16)g_profile.real_mcc[2] == utf16[2]) {
                replace_utf16_inline(buf + offset + 4, g_profile.mcc, 3);
                g_binder_mcc_spoofed++;
                modified = true;
            } else if (u8[0] == (unsigned char)g_profile.real_mcc[0]
                    && u8[1] == (unsigned char)g_profile.real_mcc[1]
                    && u8[2] == (unsigned char)g_profile.real_mcc[2]
                    && u8[3] == 0) {
                /* UTF-8 String8 path — payload is exactly 3 bytes + null
                 * in a 4-byte slot. Length stays 3, just rewrite chars. */
                u8[0] = (unsigned char)g_profile.mcc[0];
                u8[1] = (unsigned char)g_profile.mcc[1];
                u8[2] = (unsigned char)g_profile.mcc[2];
                g_binder_mcc_spoofed++;
                modified = true;
            } else if (g_profile.mnc[0] && g_profile.real_mnc[0]
                    && is_mnc_format_u16(utf16, 3)
                    && (__u16)g_profile.real_mnc[0] == utf16[0]
                    && (__u16)g_profile.real_mnc[1] == utf16[1]
                    && (__u16)g_profile.real_mnc[2] == utf16[2]) {
                /* 3-char MNC literal match (UTF-16). */
                int mnc_len = 0;
                while (g_profile.mnc[mnc_len] && mnc_len < 3) mnc_len++;
                if (replace_utf16_resize(buf + offset, g_profile.mnc, mnc_len, 3)) {
                    g_binder_mcc_spoofed++;
                    modified = true;
                }
            } else if (g_profile.mnc[0] && g_profile.real_mnc[0]
                    && g_profile.real_mnc[0] == u8[0]
                    && g_profile.real_mnc[1] == u8[1]
                    && g_profile.real_mnc[2] == u8[2]
                    && u8[3] == 0
                    && g_profile.real_mnc[3] == '\0') {
                /* 3-char MNC literal match (UTF-8). Spoof mnc must also
                 * be 3 chars to fit (no growth needed). */
                int mnc_len = 0;
                while (g_profile.mnc[mnc_len] && mnc_len < 3) mnc_len++;
                if (mnc_len == 3) {
                    u8[0] = (unsigned char)g_profile.mnc[0];
                    u8[1] = (unsigned char)g_profile.mnc[1];
                    u8[2] = (unsigned char)g_profile.mnc[2];
                    g_binder_mcc_spoofed++;
                    modified = true;
                }
            }
        }
        /* 2-char field: MNC (digits, may grow to 3) or country code
         * (letters, fixed 2 chars). UTF-16 path uses replace_utf16_resize
         * which handles 2→3 growth (both round to 8-byte padded payload).
         * UTF-8 path handles writeString8: payload is exactly 2 bytes +
         * null + 1 padding byte = 4 bytes; growing to 3 chars + null
         * still fits the same 4-byte payload. */
        else if (str_len == 2 && offset + 4 + 6 <= bytes) {
            __u16 *utf16 = (__u16 *)(buf + offset + 4);
            unsigned char *u8 = (unsigned char *)(buf + offset + 4);
            if (g_profile.mnc[0] && g_profile.real_mnc[0]
                && is_mnc_format_u16(utf16, 2)
                && (__u16)g_profile.real_mnc[0] == utf16[0]
                && (__u16)g_profile.real_mnc[1] == utf16[1]
                && g_profile.real_mnc[2] == '\0') {
                int mnc_len = 0;
                while (g_profile.mnc[mnc_len] && mnc_len < 3) mnc_len++;
                if (replace_utf16_resize(buf + offset, g_profile.mnc, mnc_len, 2)) {
                    g_binder_mcc_spoofed++;
                    modified = true;
                }
            } else if (g_profile.country_iso[0] && g_profile.real_country[0]
                && is_country_format_u16(utf16, 2)
                && (__u16)g_profile.real_country[0] == utf16[0]
                && (__u16)g_profile.real_country[1] == utf16[1]) {
                replace_utf16_inline(buf + offset + 4, g_profile.country_iso, 2);
                g_binder_country_spoofed++;
                modified = true;
            } else if (g_profile.mnc[0] && g_profile.real_mnc[0]
                    && u8[0] == (unsigned char)g_profile.real_mnc[0]
                    && u8[1] == (unsigned char)g_profile.real_mnc[1]
                    && u8[2] == 0
                    && g_profile.real_mnc[2] == '\0') {
                /* UTF-8 String8 MNC: payload [r0][r1][\0][pad] in 4-byte
                 * slot. Spoof up to 3 chars fits. Length prefix grows to
                 * spoof_len. */
                int mnc_len = 0;
                while (g_profile.mnc[mnc_len] && mnc_len < 3) mnc_len++;
                if (mnc_len >= 1 && mnc_len <= 3) {
                    *(__s32 *)(buf + offset) = mnc_len;
                    for (int i = 0; i < mnc_len; i++) u8[i] = (unsigned char)g_profile.mnc[i];
                    for (int i = mnc_len; i < 3; i++) u8[i] = 0;
                    u8[3] = 0;
                    g_binder_mcc_spoofed++;
                    modified = true;
                }
            } else if (g_profile.country_iso[0] && g_profile.real_country[0]
                    && u8[0] == (unsigned char)g_profile.real_country[0]
                    && u8[1] == (unsigned char)g_profile.real_country[1]
                    && u8[2] == 0) {
                /* UTF-8 String8 country: payload [r0][r1][\0][pad].
                 * Spoof country must also be exactly 2 chars (ISO-3166-1
                 * alpha-2; companion APK validates). */
                u8[0] = (unsigned char)g_profile.country_iso[0];
                u8[1] = (unsigned char)g_profile.country_iso[1];
                g_binder_country_spoofed++;
                modified = true;
            }
        }
        else if (str_len >= 10 && str_len <= 16 && offset + 4 + (str_len + 1) * 2 <= bytes
                 && g_profile.phone_number[0]) {
            __u16 *utf16 = (__u16 *)(buf + offset + 4);
            if (is_phone_format_u16(utf16, str_len)) {
                replace_utf16_inline(buf + offset + 4, g_profile.phone_number, str_len);
                modified = true;
            }
        }
        /* Bare-digit phone is handled in a separate pass below via
         * spoof_lenprefixed_string — the previous inline-here UTF-16-only
         * branch missed tm.line1Number replies that come over the wire as
         * String8 (writeString8) on this AOSP build. Punting to the
         * shared helper below covers both encodings and applies the same
         * grow-within-padded-slot logic the carrierName / operatorAlpha
         * passes already use. */
        /* UUID branch intentionally absent: matching any 36-char UUID
         * embedded inside a larger parcel produced false positives on
         * session tokens / cookies / file IDs that GMS and other system
         * components emit (Android uses UUIDs everywhere internally).
         * Replacing those corrupted manager-state and broke unrelated
         * things like KSU Next's WebUI launch. GAID is no longer
         * spoofed at the binder layer at all — the companion APK
         * rotates `adid_settings.xml` and bounces GMS persistent
         * instead, which is the same path the system Reset UI uses. */
        offset += 4;
    }

    /* Second pass: SubscriptionInfo.mCarrierId is a 4-byte int. Companion
     * APK reads the original carrier_id via getCarrierId() before our hook
     * runs and pushes it as `real_carrier_id`. Here we scan for that exact
     * int and rewrite it to the spoofed `carrier_id`. Restricted to
     * marker-seen parcels so we don't flip carrier_id-shaped ints in
     * unrelated binder traffic, and capped at 1 swap so a coincident
     * match on iconTint / displayNameSource / etc. (very unlikely with
     * a 4-digit carrier_id) only burns one slot. */
    if (subinfo_marker_seen && g_profile.real_carrier_id && g_profile.carrier_id
        && g_profile.real_carrier_id != g_profile.carrier_id) {
        for (size_t i = 0; i + 4 <= bytes; i += 4) {
            __s32 v = *(__s32 *)(buf + i);
            if (v == g_profile.real_carrier_id) {
                *(__s32 *)(buf + i) = g_profile.carrier_id;
                modified = true;
                break;
            }
        }
    }

    /* Small-reply carrier_id: TelephonyManager.getSimCarrierId() /
     * getSimSpecificCarrierId() / getCarrierIdFromSimMccMnc() return an
     * 8-byte parcel [status int][carrier_id int] — no ICCID marker, so
     * the marker-gated scan above misses them and the real value (e.g.
     * 1658 = Plus PL) leaks straight through. We literal-match against
     * `real_carrier_id` which is specific enough (4-digit AOSP carrier_list
     * IDs like 1658, 1815) that the chance of any other 8-byte int reply
     * coincidentally containing the same value is negligible — every
     * other binder reply in this size has a tiny constrained range
     * (NETWORK_TYPE 0..22, DATA_STATE 0..4, RIL_CDMA_SUBSCRIPTION 0..3
     * etc.) that doesn't overlap with carrier_list IDs. */
    if (bytes == 8 && g_profile.real_carrier_id && g_profile.carrier_id
        && g_profile.real_carrier_id != g_profile.carrier_id) {
        __s32 status_word = *(__s32 *)buf;
        __s32 value_word = *(__s32 *)(buf + 4);
        /* Diagnostic: which 8-byte replies arrive, and which match the
         * carrier_id swap criteria. Rate-limited via static counter so dmesg
         * doesn't drown. Remove after the leak is confirmed fixed. */
        static int dbg_8b = 0;
        if (dbg_8b < 30) {
            dbg_8b++;
            lp_dbg("lukeprivacy: 8b reply status=%d value=%d real_cid=%d spoof_cid=%d\n",
                status_word, value_word, g_profile.real_carrier_id, g_profile.carrier_id);
        }
        if (status_word == 0 && value_word == g_profile.real_carrier_id) {
            *(__s32 *)(buf + 4) = g_profile.carrier_id;
            modified = true;
        }
    }

    /* Third pass: SubscriptionInfo.mCarrierName — structural anchor on
     * (displayName, carrierName, nameSource) tuple. See scan_subinfo_anchor
     * comment for details. Replaces the byte-pattern UTF-8/UTF-16 match
     * approach which got fooled by previously-spoofed values stored in real_*. */
    if (scan_subinfo_anchor(buf, bytes)) {
        modified = true;
    }

    /* Fourth pass: ServiceState / NRI / cellIdentity operatorAlpha leak.
     * Scans for `real_operator_alpha_long` and `real_operator_alpha_short`
     * (captured by companion APK from ss.getOperatorAlphaLong/Short) and
     * rewrites them in-place with `carrier_name`. Catches the real network
     * identity that bypasses SubscriptionInfo's carrierName slot. */
    if (scan_operator_alpha_leaks(buf, bytes)) {
        modified = true;
    }

    /* Fifth pass: NetworkRegistrationInfo.rplmn — registered PLMN string,
     * concatenation of real_mcc + real_mnc (e.g. "26006" for Plus PL or
     * "31148" appearing in screenshots). Different from the standalone
     * MCC / MNC string fields handled in the main pass — rplmn is one
     * combined string. Build the concat from real_* / target values and
     * delegate to the same length-prefixed string spoofer. */
    if (g_profile.real_mcc[0] && g_profile.real_mnc[0] &&
        g_profile.mcc[0] && g_profile.mnc[0]) {
        char real_rplmn[8] = {0};
        char spoof_rplmn[8] = {0};
        int p = 0;
        for (int i = 0; g_profile.real_mcc[i] && i < 3 && p < 7; i++) real_rplmn[p++] = g_profile.real_mcc[i];
        for (int i = 0; g_profile.real_mnc[i] && i < 3 && p < 7; i++) real_rplmn[p++] = g_profile.real_mnc[i];
        real_rplmn[p] = '\0';
        p = 0;
        for (int i = 0; g_profile.mcc[i] && i < 3 && p < 7; i++) spoof_rplmn[p++] = g_profile.mcc[i];
        for (int i = 0; g_profile.mnc[i] && i < 3 && p < 7; i++) spoof_rplmn[p++] = g_profile.mnc[i];
        spoof_rplmn[p] = '\0';
        if (spoof_lenprefixed_string(buf, bytes, real_rplmn, spoof_rplmn, NULL) > 0) {
            modified = true;
        }
    }

    /* Sixth pass: bare-digit phone (tm.line1Number-style replies). Diagnostic
     * counters expose how many parcels contain the real bare phone digits
     * vs. how many actually got swapped — visible in ctl0 status as
     * `phone_seen=N phone_repl=M`. If seen > 0 and repl == 0 the literal
     * match is failing (bytes layout differs from a length-prefixed string
     * — wrap, padding, or wrong encoding). If seen == 0 the reply doesn't
     * route through this hook at all (different binder transfer path). */
    if (g_profile.real_phone_bare[0] && g_profile.phone_number[0]) {
        int rpb_len = 0;
        while (g_profile.real_phone_bare[rpb_len] && rpb_len < 15) rpb_len++;

        /* Substring scan (ASCII + UTF-16) — independent of length prefix /
         * null terminator / padding. Finds the digits anywhere in the
         * parcel even if surrounding metadata doesn't match what
         * spoof_lenprefixed_string expects. */
        if (rpb_len >= 7) {
            bool seen_here = false;
            /* ASCII */
            for (size_t i = 0; i + rpb_len <= bytes && !seen_here; i++) {
                bool m = true;
                for (int j = 0; j < rpb_len; j++) {
                    if (buf[i + j] != g_profile.real_phone_bare[j]) { m = false; break; }
                }
                if (m) seen_here = true;
            }
            /* UTF-16LE */
            if (!seen_here) {
                for (size_t i = 0; i + rpb_len * 2 <= bytes && !seen_here; i += 2) {
                    bool m = true;
                    for (int j = 0; j < rpb_len; j++) {
                        if ((unsigned char)buf[i + j * 2]     != (unsigned char)g_profile.real_phone_bare[j]) { m = false; break; }
                        if ((unsigned char)buf[i + j * 2 + 1] != 0) { m = false; break; }
                    }
                    if (m) seen_here = true;
                }
            }
            if (seen_here) {
                g_phone_bare_seen++;
                /* Counter only — never log the actual bare digits to dmesg
                 * (they're the user's real phone number, dmesg is readable
                 * by anyone with logcat / `dmesg` access). */
                lp_dbg("lukeprivacy: PHONE_DBG real_phone_bare(len=%d) seen in parcel bytes=%zu seen=%d repl=%d\n",
                    rpb_len, bytes, g_phone_bare_seen, g_phone_bare_replaced);
            }
        }

        const char *spoof = g_profile.phone_number;
        if (spoof[0] == '+') spoof++;
        if (spoof[0] != '\0') {
            int n = spoof_lenprefixed_string(buf, bytes,
                                             g_profile.real_phone_bare, spoof, NULL);
            if (n > 0) {
                g_phone_bare_replaced += n;
                modified = true;
            }
        }
    }

    return modified;
}

static int inline_gnss_debug __maybe_unused = 0;
static int loc_scan_debug;  // Reset at module load

// Scan buffer for any double pair that looks like real coordinates and spoof them
static int __maybe_unused scan_and_spoof_coordinates(char *buf, size_t bytes)
{
    if (bytes < 24) return 0;
    int spoofed = 0;

    for (size_t i = 0; i + 16 <= bytes; i += 8) {
        __u64 lat_bits = lp_f64_bits(buf + i);
        __u64 lon_bits = lp_f64_bits(buf + i + 8);
        __u64 lat_mag  = lat_bits & LP_F64_ABS_MASK;
        __u64 lon_mag  = lon_bits & LP_F64_ABS_MASK;
        __s64 lat_e4, lon_e4, lat_frac, lon_frac, dlat, dlon;

        if (lat_mag > LP_F64_ABS_90  || lat_mag == 0) continue;
        if (lon_mag > LP_F64_ABS_180 || lon_mag == 0) continue;
        if (lat_mag < LP_F64_ABS_1) continue;   /* |lat| < 1.0 */

        // Must have meaningful fractional part (not near-integer = random data)
        lat_e4   = lp_f64_to_scaled(lat_bits, 10000);
        lon_e4   = lp_f64_to_scaled(lon_bits, 10000);
        lat_frac = lat_e4 % 10000;
        lon_frac = lon_e4 % 10000;
        if (lat_frac < 0) lat_frac = -lat_frac;
        if (lon_frac < 0) lon_frac = -lon_frac;
        if (lat_frac < 100 && lon_frac < 100) continue;

        // Skip if already spoofed (matches our target within 0.001 deg)
        dlat = lat_e4 - lp_f64_to_scaled(lp_f64_bits(&g_profile.latitude), 10000);
        dlon = lon_e4 - lp_f64_to_scaled(lp_f64_bits(&g_profile.longitude), 10000);
        if (dlat < 0) dlat = -dlat;
        if (dlon < 0) dlon = -dlon;
        if (dlat < 10 && dlon < 10) continue;

        lp_put64(buf + i,     lp_f64_bits(&g_profile.latitude));
        lp_put64(buf + i + 8, lp_f64_bits(&g_profile.longitude));
        spoofed++;
    }
    return spoofed;
}

/* Corrupt last char of every UTF-16 occurrence of `needle` inside `u`
 * (length `len` chars). Used by try_hide_dev_settings to catch raw-SQL
 * queries like cr.query(URI, null, "name='adb_enabled'", null, null) where
 * "adb_enabled" appears as a substring of a longer where-clause string,
 * not as a standalone selectionArgs element. */
static int corrupt_utf16_substring(__u16 *u, int len, const char *needle)
{
    int nlen = 0;
    while (needle[nlen] && nlen < 32) nlen++;
    if (nlen < 2 || len < nlen) return 0;
    int hits = 0;
    for (int i = 0; i + nlen <= len && hits < 4; i++) {
        bool m = true;
        for (int j = 0; j < nlen; j++) {
            if (u[i + j] != (__u16)(unsigned char)needle[j]) { m = false; break; }
        }
        if (m) {
            u[i + nlen - 1] = (__u16)'x';
            hits++;
            i += nlen - 1;
        }
    }
    return hits;
}

// Redirect SettingsProvider lookups by corrupting the last char of the
// setting name in IContentProvider.call() request parcels.
//
// Two flavours, same trick:
//   1. HIDE (adb_enabled, adb_wifi_enabled, development_settings_enabled):
//      flip last char to 'x' so the lookup misses; companion APK pre-creates
//      the fake "*_enablex" settings with value "0" so apps still get a
//      sensible answer instead of null.
//   2. REDIRECT (android_id): flip last 'd' to 'x' so the lookup hits a
//      different key ("android_ix"); companion APK pre-creates that key
//      with the spoofed android_id. The REAL `secure.android_id` row stays
//      intact, so Google services that bind account state to it (Play,
//      GMS) don't see the device "change identity" and don't log the user
//      out.
//
// In all cases UID < 10000 (system) is bypassed: ADB stays functional, the
// Settings app still shows real values, system services keep working.
/* SettingsProvider call structural anchor.
 *
 * The substring-scan branch below (PlanPrecision #2, 2026-05-11) used to fire
 * on any UTF-16 string 12-128 chars containing "adb_enabled" /
 * "adb_wifi_enabled" / "development_settings_enabled". That hit raw-SQL
 * where-clauses (the real target) but also any analytics SDK / logger
 * payload that mentioned those tokens. Real SettingsProvider binder calls
 * always carry the UTF-16 URI token `content://settings/global/` (or
 * `content://settings/secure/`, `/system/`) in the parcel header before
 * the where-clause field. Gate the substring scan on that URI prefix to
 * keep the false-positive surface scoped to actual SettingsProvider
 * traffic. Standalone exact-shape matches (str_len==11/16/28 with
 * byte-by-byte literal compare) remain anchored on str_len alone — they
 * are already strict enough that the URI gate is unnecessary. */
static bool parcel_has_settings_uri(const char *buf, size_t bytes)
{
    /* UTF-16 LE "content://settings/" — 19 chars × 2 = 38 B. SettingsProvider
     * URI prefix lives in the parcel header (descriptor / authority field).
     * Cap search at first 80 B; deeper than that and we are inside the
     * SQL fragment, not the URI. */
    static const unsigned char prefix[38] = {
        'c',0,'o',0,'n',0,'t',0,'e',0,'n',0,'t',0,':',0,
        '/',0,'/',0,'s',0,'e',0,'t',0,'t',0,'i',0,'n',0,
        'g',0,'s',0,'/',0
    };
    size_t limit = bytes < 80 ? bytes : 80;
    if (limit < sizeof(prefix)) return false;
    const unsigned char *p = (const unsigned char *)buf;
    for (size_t i = 0; i + sizeof(prefix) <= limit; i += 2) {
        if (p[i] == 'c' && p[i+1] == 0 &&
            memcmp(p + i, prefix, sizeof(prefix)) == 0)
            return true;
    }
    return false;
}

static bool try_hide_dev_settings(char *buf, size_t bytes)
{
    __u32 uid = from_kuid(&init_user_ns, current_uid());
    if (uid < 10000) return false;

    /* Only the adb_hide path is still wired in (android_id corruption
     * removed 2026-05-09 — see comment in the inner branch). If the
     * adb-hide gate is off there's nothing for this function to do
     * regardless of android_id_hide_enabled. */
    if (!g_profile.adb_hide_enabled)
        return false;

    /* PlanPrecision #2 gate: substring branch is only safe when the parcel
     * carries a SettingsProvider URI. Standalone exact-shape matches below
     * stay reachable regardless (they have their own str_len anchor). */
    bool has_settings_uri = parcel_has_settings_uri(buf, bytes);

    bool modified = false;
    for (size_t off = 0; off + 28 < bytes; off += 4) {
        __s32 str_len = *(__s32 *)(buf + off);
        __u16 *u = (__u16 *)(buf + off + 4);

        // "adb_enabled" (11 chars)
        if (g_profile.adb_hide_enabled && str_len == 11 && off + 28 <= bytes &&
            u[0]=='a' && u[1]=='d' && u[2]=='b' && u[3]=='_' &&
            u[4]=='e' && u[5]=='n' && u[6]=='a' && u[7]=='b' &&
            u[8]=='l' && u[9]=='e' && u[10]=='d') {
            u[10] = 'x';
            modified = true;
        }
        // "adb_wifi_enabled" (16 chars)
        else if (g_profile.adb_hide_enabled && str_len == 16 && off + 36 <= bytes &&
            u[0]=='a' && u[1]=='d' && u[2]=='b' && u[3]=='_' &&
            u[4]=='w' && u[5]=='i' && u[6]=='f' && u[7]=='i' &&
            u[8]=='_' && u[9]=='e' && u[10]=='n' && u[11]=='a' &&
            u[12]=='b' && u[13]=='l' && u[14]=='e' && u[15]=='d') {
            u[15] = 'x';
            modified = true;
        }
        // "development_settings_enabled" (28 chars)
        else if (g_profile.adb_hide_enabled && str_len == 28 && off + 60 <= bytes &&
            u[0]=='d' && u[1]=='e' && u[2]=='v' && u[3]=='e' &&
            u[4]=='l' && u[5]=='o' && u[6]=='p' && u[7]=='m' &&
            u[8]=='e' && u[9]=='n' && u[10]=='t' && u[11]=='_' &&
            u[12]=='s' && u[13]=='e' && u[14]=='t' && u[15]=='t' &&
            u[16]=='i' && u[17]=='n' && u[18]=='g' && u[19]=='s' &&
            u[20]=='_' && u[21]=='e' && u[22]=='n' && u[23]=='a' &&
            u[24]=='b' && u[25]=='l' && u[26]=='e' && u[27]=='d') {
            u[27] = 'x';
            modified = true;
        }
        // "enabled_accessibility_services" (30 chars) — hide the automation a11y
        // service from Snap's setting read. Corrupt → lookup misses → app gets null
        // ("no a11y services", the common state). Belt-and-suspenders: the service is
        // already renamed to a benign package. System (uid<10000) reads it UNMODIFIED
        // so the framework still binds the service — only the target app is blinded.
        else if (g_profile.adb_hide_enabled && str_len == 30 && off + 64 <= bytes &&
            u[0]=='e' && u[1]=='n' && u[2]=='a' && u[3]=='b' &&
            u[4]=='l' && u[5]=='e' && u[6]=='d' && u[7]=='_' &&
            u[8]=='a' && u[9]=='c' && u[10]=='c' && u[11]=='e' &&
            u[12]=='s' && u[13]=='s' && u[14]=='i' && u[15]=='b' &&
            u[16]=='i' && u[17]=='l' && u[18]=='i' && u[19]=='t' &&
            u[20]=='y' && u[21]=='_' && u[22]=='s' && u[23]=='e' &&
            u[24]=='r' && u[25]=='v' && u[26]=='i' && u[27]=='c' &&
            u[28]=='e' && u[29]=='s') {
            u[29] = 'x';
            modified = true;
        }
        /* android_id corruption REMOVED 2026-05-09.
         *
         * The previous approach flipped "android_id" → "android_ix" in
         * the binder request name and relied on the companion APK to
         * pre-create `secure.android_ix` as a redirect target. That left
         * a non-stock key in `/data/system/users/0/settings_secure.xml`
         * (visible via Settings enumeration APIs) and the corrupted
         * lookup name itself was an unusual binder pattern.
         *
         * Modern Android (8+) hands apps a per-package SSAID generated
         * by SettingsProvider and persisted in
         * `/data/system/users/0/settings_ssaid.xml` — one row per
         * package, regenerated on first read after a `pm clear`.
         * That's stock behaviour, indistinguishable from any other
         * device, and `pm clear` gives a fresh android_id on every
         * reinstall flow naturally. No KPM corruption needed.
         *
         * `android_id_hide_enabled` flag remains for ctl0 wire compat
         * (companion APK still pushes `set_android_id_hide:0/1`) but
         * the gate has no effect — there's no rewrite branch left.
         */
        /* Substring catch for raw-SQL where-clause queries like
         *   cr.query(URI, null, "name='adb_enabled'", null, null)
         * Apps that build the where-clause as one big string put
         * "adb_enabled" inside e.g. a 20-char selection — standalone
         * 11-char match above misses it. Skip very short strings (the
         * standalone match handles them) and very long ones (log
         * messages, JSON payloads — false-positive risk).
         *
         * Only runs the substring scan when adb_hide_enabled is on.
         * The android_id raw-SQL form is not currently substring-scanned
         * (10-char "android_id" overlaps too many tokens for low-FP
         * scanning); when android_id_hide_enabled is off, we just rely
         * on the standalone 10-char match path being skipped above. */
        else if (has_settings_uri &&
                 g_profile.adb_hide_enabled && str_len >= 12 && str_len <= 128 &&
                 off + 4 + (size_t)((str_len + 1) * 2) <= bytes) {
            int hits = corrupt_utf16_substring(u, str_len, "adb_enabled");
            hits   += corrupt_utf16_substring(u, str_len, "adb_wifi_enabled");
            hits   += corrupt_utf16_substring(u, str_len, "development_settings_enabled");
            if (hits > 0) modified = true;
        }
    }
    return modified;
}

// Static buffer for location spoofing - will replace userspace pointer
static char g_loc_spoof_buf[4096] __attribute__((aligned(4096))) __maybe_unused;
static int g_loc_spoof_log = 0;
static bool g_spoof_buf_in_use __maybe_unused = false;

/* ── SSAID per-step fail logging ─────────────────────────────────────────── *
 * Counters for each structural step of try_strict_bundle_ssaid. When
 * g_ssaid_debug_enabled is ON, every bail point also emits a pr_info line.
 * Exposed in ioctl_stats as ssaid_af0..af7 (anchor fail).
 * [0]=step1(BNDL magic) [1]=step2(entry_count) [2]=step3(key_len)
 * [3]=step4(UTF-16 "value") [4]=step5(val_type) [5]=step6(value_len)
 * [6]=step7(hex chars) [7]=total any-step fail */
unsigned int g_ssaid_anchor_fail[8] = {0};
unsigned int g_ssaid_debug_enabled = 0;

/* ── GAID binder re-enable ───────────────────────────────────────────────── *
 * Opt-in UID-gated hook on the IAdvertisingIdService.getAdvertisingId
 * binder reply. Was removed due to false positives (comment at :1639).
 * Re-enabled here as gaid_binder_reenabled=true (default OFF).
 *
 * Anchor: bytes==48 (status:int=0 + arr_len:int=36 + 36-char UTF-8 UUID +
 *   4B padding) — the exact layout emitted by the GAID Binder RPC.
 *   Also catches bytes==8 (status=0 + empty arr_len=0) for empty reply.
 *
 * UID filter: recv_uid >= 10000 AND not excluded. GMS/vending/gsf stay in
 * exclude list so they never see a spoofed GAID (avoids token corruption). */
unsigned int g_gaid_binder_repl = 0;

/* UUID4 format check: 36-char string with dashes at [8,13,18,23]. */
static bool is_uuid4_ascii(const char *s)
{
    if (!s) return false;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return false;
        } else {
            char c = s[i];
            bool hex = (c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
    }
    return true;
}

static bool try_spoof_gaid_binder(char *buf, size_t bytes, unsigned int recv_uid)
{
    if (!g_profile.gaid_binder_reenabled) return false;
    if (!g_profile.advertising_id[0]) return false;
    if (recv_uid < 10000 || lp_is_uid_excluded((__u32)recv_uid)) return false;

    /* bytes==8: status=0 + arr_len=0 → empty reply → inject our UUID */
    if (bytes == 8) {
        __s32 status = *(__s32 *)(buf + 0);
        __s32 arr_len = *(__s32 *)(buf + 4);
        if (status != 0 || arr_len != 0) return false;
        /* Can't grow a fixed-size binder buffer — passthrough */
        return false;
    }

    /* bytes==48: status(4)=0 + arr_len(4)=36 + 36 UTF-8 UUID chars + 4 pad */
    if (bytes == 48) {
        __s32 status = *(__s32 *)(buf + 0);
        __s32 arr_len = *(__s32 *)(buf + 4);
        if (status != 0 || arr_len != 36) return false;
        char *uuid_field = buf + 8;
        if (!is_uuid4_ascii(uuid_field)) return false;
        /* Overwrite with spoofed GAID */
        for (int i = 0; i < 36; i++) uuid_field[i] = g_profile.advertising_id[i];
        g_gaid_binder_repl++;
        return true;
    }

    return false;
}

/* ── HostProcessBridge IPC (TikTok mini-app device_id) ──────────────────── *
 * TikTok's mini-app sandbox (com.zhiliaoapp.musically:miniapp0) reads
 * device_id from the host process via Binder. The reply is a Bundle with:
 *   BNDL magic, entry_count=1, key_len=9, UTF-16 "device_id",
 *   val_type=0 (VAL_STRING), value_len=19, 19 ASCII digit chars.
 * We substitute with a per-UID deterministic 19-digit snowflake string. */
unsigned int g_hostbridge_repl = 0;

static bool try_spoof_hostprocess_bridge(char *buf, size_t bytes,
                                          unsigned int recv_uid)
{
    if (!g_profile.hostprocess_bridge_enabled) return false;
    if (!g_profile.android_id_seed[0]) return false;
    if (recv_uid < 10000 || lp_is_uid_excluded((__u32)recv_uid)) return false;

    /* Size: BNDL(4)+entry_count(4)+key_len(4)+UTF-16"device_id"(20)+pad(0)+
     *        val_type(4)+value_len(4)+19*2+2pad = ~76-90 bytes range */
    if (bytes < 60 || bytes > 120) return false;

    unsigned char *p = (unsigned char *)buf;

    /* Find BNDL magic in first 32 bytes */
    int bndl_off = -1;
    for (size_t s = 0; s + 4 <= 32 && s + 4 <= bytes; s += 4) {
        if (*(unsigned int *)(p + s) == 0x4C444E42u) { bndl_off = (int)s; break; }
    }
    if (bndl_off < 0) return false;

    size_t cur = (size_t)bndl_off + 4;
    if (cur + 4 > bytes) return false;
    if (*(unsigned int *)(p + cur) != 1) return false;  /* entry_count */
    cur += 4;

    if (cur + 4 > bytes) return false;
    if (*(unsigned int *)(p + cur) != 9) return false;  /* key_len == "device_id" */
    cur += 4;

    /* UTF-16 "device_id" (9 chars → 18 bytes + 2 NUL = 20 bytes) */
    if (cur + 20 > bytes) return false;
    static const unsigned char DID_KEY[20] = {
        'd',0,'e',0,'v',0,'i',0,'c',0,'e',0,'_',0,'i',0,'d',0,0,0
    };
    if (memcmp(p + cur, DID_KEY, 20) != 0) return false;
    cur += 20;
    cur = (cur + 3) & ~(size_t)3;

    if (cur + 4 > bytes) return false;
    if (*(unsigned int *)(p + cur) != 0) return false;  /* val_type VAL_STRING */
    cur += 4;

    if (cur + 4 > bytes) return false;
    unsigned int vlen = *(unsigned int *)(p + cur);
    if (vlen != 19) return false;  /* Snowflake device_id = 19 decimal digits */
    cur += 4;

    if (cur + 19 * 2 > bytes) return false;
    /* Verify 19 ASCII digit chars in UTF-16LE */
    for (int i = 0; i < 19; i++) {
        unsigned char c = p[cur + i * 2];
        if (p[cur + i * 2 + 1] != 0) return false;
        if (c < '0' || c > '9') return false;
    }

    /* Derive per-UID 19-digit Snowflake.
     * Use two splitmix64 rounds to get ~128 bits, then take mod 10^19. */
    unsigned long long seed = parse_seed_u64(g_profile.android_id_seed);
    unsigned long long base =
        splitmix64(seed ^ ((unsigned long long)recv_uid * 0x9E3779B97F4A7C15ULL));
    unsigned long long mixed = splitmix64(base ^ 0x4445564943454944ULL /* "DEVICEID" */);

    /* Compute 19-digit decimal in char buf. 2^64 < 19 digits so we use
     * the high and low parts to build a full 19-digit number. */
    static const char DIGITS[] = "0123456789";
    char dec[20]; /* 19 digits + NUL */
    /* Use modular reduction: force first digit ≥ 1 (no leading zero). */
    unsigned long long mod = 1000000000000000000ULL; /* 10^18 */
    unsigned long long hi19 = mixed % (9ULL * mod) + mod;  /* range 10^18..10^19-1 */
    for (int i = 18; i >= 0; i--) {
        dec[i] = DIGITS[hi19 % 10];
        hi19 /= 10;
    }
    dec[19] = '\0';

    /* Write UTF-16LE digits */
    for (int i = 0; i < 19; i++) {
        p[cur + i * 2]     = (unsigned char)dec[i];
        p[cur + i * 2 + 1] = 0;
    }
    g_hostbridge_repl++;
    return true;
}

/* ── Timezone binder hook counter ───────────────────────────────────────── *
 * Companion handles timezone via resetprop persist.sys.timezone — no kernel
 * binder hook needed. Counter defined here to satisfy extern in profile.h. */
unsigned int g_timezone_repl = 0;

void lp_binder_copy_to_buffer_hook(struct binder_alloc *alloc,
                                   struct binder_buffer *buffer,
                                   binder_size_t buffer_offset,
                                   const void __user *from, size_t bytes)
{
    (void)buffer;
    (void)buffer_offset;

    if (!g_hooks_enabled) return;

    /* Lazy retry of the mandatory-package resolver. Cheap when already
     * resolved (single bool check); throttled when not (so we don't pound
     * /data/system/packages.list on every binder copy during early boot). */
    lp_resolver_tick();

    const void __user *from_early = from;
    size_t bytes_early = bytes;

    /* SSAID reply spoof — RUNS BEFORE the writer-UID exclude filter below,
     * because in binder reply direction the writer is system_server (uid
     * 1000), which IS in the exclude list, and the filter would short-
     * circuit this hook before it could rewrite the SettingsProvider
     * getSsaid response heading to the calling app.
     *
     * Parcel size range: 36 (minimum) to 256 bytes (Bundle overhead).
     * Strict pattern detection in try_spoof_ssaid_reply (int32 prefix=16
     * + 16 lowercase-hex UTF-16 chars) keeps false positives near-zero. */
    if (g_profile.android_id_spoof_enabled && bytes_early >= 36 && bytes_early <= 512 && from_early) {
        char ssaid_buf[512];
        if (lp_copy_from_user(ssaid_buf, from_early, bytes_early) > 0) {
            /* Pass binder_alloc pointer (args->arg0) as receiver-process
             * identity proxy — see per-process derivation comment in
             * try_spoof_ssaid_reply. */
            unsigned long alloc_ptr = (unsigned long)alloc;
            if (try_spoof_ssaid_reply(ssaid_buf, bytes_early, alloc_ptr)) {
                lp_copy_to_user((void __user *)from_early, ssaid_buf, bytes_early);
                return;
            }
        }
    }

    /* Cursor/query() android_id spoof — mirrors the Bundle hook above (same
     * point in the pipeline, same recv_uid, same derivation) so getString() and
     * query() agree. Handles the SettingsProvider CursorWindow reply (~144B,
     * single-row query). Structural anchor ("android_id" + 16-hex value) — no
     * device-specific constants, so it works on any same-build Pixel 6a. */
    if (g_profile.android_id_spoof_enabled && bytes_early >= 40 && bytes_early <= 2048 && from_early) {
        char cur_buf[2048];
        if (lp_copy_from_user(cur_buf, from_early, bytes_early) > 0) {
            unsigned int cur_uid = lp_uid_map_get((unsigned long)alloc);
            if (try_spoof_cursor_android_id(cur_buf, bytes_early, cur_uid)) {
                lp_copy_to_user((void __user *)from_early, cur_buf, bytes_early);
                return;
            }
        }
    }

    /* ── Block Store cloud_account_id — UID-INDEPENDENT (runs here, BEFORE the
     * writer/recv filters, exactly like the SSAID/cursor blocks above). The
     * "cloud_account_id" Map key is Snap-specific, so the string match alone IS
     * the specificity — we deliberately do NOT gate on recv_uid, because the
     * alloc→uid map misses ~90% of the time (uidmap_miss ≫ hit) for apps that
     * opened /dev/binder before the KPM loaded, and that miss (recv_uid==0) was
     * silently skipping Snap's retrieveBytes reply. Hardcoded key (UTF-16LE first,
     * UTF-8 fallback), full size range via kmalloc. Self-contained (no companion
     * key-push). Fires only when capture OR neutralize is armed. */
    if ((g_profile.blockstore_capture_enabled || g_profile.blockstore_neutralize_enabled)
        && from_early && bytes_early >= 34 && bytes_early <= 16384) {
        unsigned int bsu = lp_uid_map_get((unsigned long)alloc);  /* logging only */
        if (bytes_early <= 2048) {
            char bs_buf[2048];
            if (lp_copy_from_user(bs_buf, from_early, bytes_early) > 0
                && try_bs_caid(bs_buf, bytes_early, bsu, "small")) {
                lp_copy_to_user((void __user *)from_early, bs_buf, bytes_early);
                return;
            }
        } else if (lp_kmalloc && lp_kfree) {
            char *bs_big = (char *)lp_kmalloc(bytes_early, LP_GFP_ATOMIC);
            if (bs_big) {
                if (lp_copy_from_user(bs_big, from_early, bytes_early) > 0
                    && try_bs_caid(bs_big, bytes_early, bsu, "big"))
                    lp_copy_to_user((void __user *)from_early, bs_big, bytes_early);
                lp_kfree(bs_big);
            }
        }
    }

    /* Writer-side filter — skip ONLY root daemons (uid 0: init, ksud,
     * magiskd, vold). System services like com.android.phone (uid 1001)
     * and system_server (uid 1000) MUST pass through here because they
     * are the senders of TelephonyManager / SettingsProvider /
     * SubscriptionManager replies that we want to spoof.
     *
     * Receiver-side gating (lp_is_uid_excluded on recv UID looked up
     * via uid-by-alloc map) happens IMMEDIATELY below — that's where
     * Google packages, system apps, and user-added exclusions are
     * honoured to avoid sending them spoofed identifiers (which causes
     * Google "Action Required" challenges, system instability, etc.). */
    {
        __u32 uid = from_kuid(&init_user_ns, current_uid());
        if (uid == 0) return;
    }

    /* Receiver-side exclusion — single gate for all pattern matchers
     * below (IMEI / MCC / cname / country / etc.). If we know the
     * receiving app's UID (it's in our alloc→uid map) and that UID is
     * excluded, drop the entire pattern-match phase rather than risk
     * sending spoofed values to apps that need real ones (Google
     * packages, system apps, user-added).
     *
     * Apps that opened /dev/binder BEFORE this KPM loaded won't be in
     * the map (lookup returns 0). Those fall through — pattern matchers
     * fire for them. Risk window: during this run, any Google process
     * still on its pre-KPM-load binder fd may see spoofed replies.
     * Reboot mitigates: KPM loads from autoload before any app opens
     * binder, so every alloc→uid mapping is captured from clean slate. */
    unsigned int recv_uid_main;
    {
        unsigned long alloc_ptr_filter = (unsigned long)alloc;
        recv_uid_main = lp_uid_map_get(alloc_ptr_filter);
        if (recv_uid_main != 0 && lp_is_uid_excluded((__u32)recv_uid_main)) return;
    }

    /* GAID binder re-enable — opt-in UID-gated GAID UUID reply hook.
     * Must run BEFORE the large parcel copy below (which mallocs scratch)
     * and uses from_early / bytes_early directly. */
    if (g_profile.gaid_binder_reenabled && bytes_early >= 8 && bytes_early <= 48
        && recv_uid_main >= 10000 && from_early) {
        char gaid_buf[48];
        long gaid_copied = lp_copy_from_user(gaid_buf, from_early, bytes_early);
        if (gaid_copied > 0) {
            if (try_spoof_gaid_binder(gaid_buf, bytes_early, recv_uid_main)) {
                lp_copy_to_user((void __user *)from_early, gaid_buf, bytes_early);
                return;
            }
        }
    }

    /* HostProcessBridge IPC — TikTok mini-app device_id Bundle reply. */
    if (g_profile.hostprocess_bridge_enabled && bytes_early >= 60 && bytes_early <= 120
        && recv_uid_main >= 10000 && from_early) {
        char hpb_buf[120];
        long hpb_copied = lp_copy_from_user(hpb_buf, from_early, bytes_early);
        if (hpb_copied > 0) {
            if (try_spoof_hostprocess_bridge(hpb_buf, bytes_early, recv_uid_main)) {
                lp_copy_to_user((void __user *)from_early, hpb_buf, bytes_early);
                return;
            }
        }
    }

    g_binder_copy_calls++;

    /* `from` / `bytes` are the hook parameters and already equal
     * from_early / bytes_early (never reassigned above), so the rest of the
     * function uses them directly — the KP-era local shadows are dropped. */

    /* Pretend SIM Internet — spoof TelephonyManager.getDataNetworkType reply.
     *
     * On a WiFi-routed device (no active mobile data), the system returns
     * NETWORK_TYPE_IWLAN (18) — the "Voice/Internet over WLAN" radio access
     * tech. That value is itself a tell: an app that asks "what RAT am I on?"
     * and gets IWLAN learns the data path is over WiFi.
     *
     * We rewrite IWLAN→NR (20) in 8-byte int replies. Risk is false positives
     * on other 8-byte int replies coincidentally returning 18, but value 18
     * is a rare hit outside of telephony RAT enumeration (CallState 0-2,
     * SimCount 0-2, etc. don't reach 18). The pattern is gated by
     * `pretend_sim_enabled` so it lies dormant unless the user opted in.
     *
     * UID filter is already applied above (lp_is_uid_excluded). System
     * services (UID < 10000) are not excluded by default — but they don't
     * call getDataNetworkType in 8-byte form either; the privileged path
     * uses the larger ServiceState API. */
    /* Pretend SIM Internet — NetworkCapabilities parcel from
     * IConnectivityManager.getNetworkCapabilities(Network).
     *
     * Layout per AOSP NetworkCapabilities.writeToParcel (mainline Connectivity,
     * Android 14/15 — mainline so identical across Pixel 6/6a/7/8):
     *   buf[0..3]:   status = 0
     *   buf[4..7]:   non_null marker = 1
     *   buf[8..15]:  mNetworkCapabilities (long, bitmask of NET_CAPABILITY_*)
     *   buf[16..23]: mForbiddenNetworkCapabilities (long)
     *   buf[24..31]: mTransportTypes (long, bitmask of TRANSPORT_*)
     *   buf[32..35]: mLinkUpBandwidthKbps
     *   buf[36..39]: mLinkDownBandwidthKbps
     *   ... mNetworkSpecifier, mTransportInfo (WifiInfo embedded for WIFI),
     *   ... mSignalStrength, mUids, mSSID, mPrivateDnsBroken, mAdminUids,
     *   ... mOwnerUid, mRequestorUid, mRequestorPackageName, ...
     *
     * MVP: flip mTransportTypes lo from 0x02 (TRANSPORT_WIFI bit) to 0x01
     * (TRANSPORT_CELLULAR bit). Apps using nc.hasTransport(TRANSPORT_CELLULAR)
     * see TRUE. Embedded mTransportInfo (WifiInfo with SSID/BSSID) stays
     * intact — apps calling nc.getTransportInfo() instanceof WifiInfo still
     * detect WiFi metadata; full TransportInfo nullification needs variable-
     * length parcel rewrite (deferred).
     *
     * Anchor: status==0, non_null==1, capabilities has NET_CAPABILITY_INTERNET
     * (bit 12, value 0x1000), transport bitmask exactly 0x02 (WIFI alone).
     * That triple narrows false positives — most other parcels of similar
     * size won't simultaneously satisfy bit12-set + transport==WIFI alone. */
    if (g_profile.pretend_sim_enabled && bytes >= 100 && bytes <= 1024 && from) {
        char ncbuf[1024];
        if (lp_copy_from_user(ncbuf, from, bytes) > 0) {
            __s32 status   = *(__s32 *)(ncbuf + 0);
            __s32 non_null = *(__s32 *)(ncbuf + 4);
            __u32 caps_lo  = *(__u32 *)(ncbuf + 8);
            __u32 caps_hi  = *(__u32 *)(ncbuf + 12);
            __u32 tx_lo    = *(__u32 *)(ncbuf + 24);
            __u32 tx_hi    = *(__u32 *)(ncbuf + 28);
            (void)caps_hi;
            /* NET_CAPABILITY_INTERNET = bit 12 → 0x1000 in low dword */
            if (status == 0 && non_null == 1 &&
                (caps_lo & 0x1000) != 0 &&
                tx_lo == 0x02 && tx_hi == 0x00) {
                *(__u32 *)(ncbuf + 24) = 0x01;  /* TRANSPORT_WIFI → TRANSPORT_CELLULAR */
                lp_copy_to_user((void __user *)from, ncbuf, bytes);
                g_netcaps_spoofed++;
                return;
            }
        }
    }

    /* Pretend SIM Internet — NetworkInfo parcel from
     * IConnectivityManager.getActiveNetworkInfo / .getNetworkInfo(int).
     *
     * Layout after binder reply header (verified by `service call connectivity 3`
     * dump on Pixel 6 / Android 15, mainline Connectivity module):
     *   buf[0]:  status(4) = 0
     *   buf[4]:  non_null marker(4) = 1
     *   buf[8]:  mNetworkType(4)  TYPE_MOBILE=0 / TYPE_WIFI=1 / ...
     *   buf[12]: mSubtype(4)      NETWORK_TYPE_NR=20 / LTE=13 / IWLAN=18
     *   buf[16]: mTypeName.len(4) e.g. 4 for "WIFI"
     *   buf[20]: mTypeName UTF-16 + null + pad
     *   ... mSubtypeName, mState, mDetailedState, flags, mReason, mExtraInfo
     *
     * Strategy: flip TYPE_WIFI(1)→TYPE_MOBILE(0), force mSubtype to NR(20),
     * and rewrite mTypeName 'WIFI' → 'MOBI' in place. tn_len=4 stays so
     * the slot byte count is preserved (4 UTF-16 chars + null + pad = 12)
     * — no parcel shift, downstream fields stay at their offsets. Apps
     * comparing getTypeName().equals("WIFI") see false. 'MOBI' is not in
     * the AOSP TypeName whitelist ('MOBILE'/'WIFI'/'BLUETOOTH'/...),
     * so an app comparing against the full list could still flag it —
     * but that's a less common check than the simple equals("WIFI")
     * test, and the slot is too short to hold the canonical 'MOBILE'
     * (6 chars → 16-byte slot, would shift downstream). Net gain.
     *
     * Pattern is content-anchored (status, non_null, type, exact "WIFI" string)
     * so it's safe across Pixel 6 / 6a / 7 / 8 — NetworkInfo is mainline since
     * Android 12, identical binary layout per Android version. */
    if (g_profile.pretend_sim_enabled && bytes >= 80 && bytes <= 256 && from) {
        char netbuf[256];
        if (lp_copy_from_user(netbuf, from, bytes) > 0) {
            __s32 status   = *(__s32 *)(netbuf + 0);
            __s32 non_null = *(__s32 *)(netbuf + 4);
            __s32 type     = *(__s32 *)(netbuf + 8);
            __s32 tn_len   = *(__s32 *)(netbuf + 16);
            if (status == 0 && non_null == 1 && type == 1 && tn_len == 4) {
                __u16 *tn = (__u16 *)(netbuf + 20);
                if (tn[0] == 'W' && tn[1] == 'I' && tn[2] == 'F' && tn[3] == 'I') {
                    *(__s32 *)(netbuf + 8) = 0;   /* TYPE_WIFI → TYPE_MOBILE */
                    *(__s32 *)(netbuf + 12) = 20; /* mSubtype → NR (5G) */
                    /* In-place mTypeName rewrite — tn_len unchanged. */
                    tn[0] = (__u16)'M';
                    tn[1] = (__u16)'O';
                    tn[2] = (__u16)'B';
                    tn[3] = (__u16)'I';
                    lp_copy_to_user((void __user *)from, netbuf, bytes);
                    g_netinfo_spoofed++;
                    return;
                }
            }
        }
    }

    if (g_profile.pretend_sim_enabled && bytes == 8 && from) {
        /* No UID filter here: binder REPLY copies happen in the SERVER's
         * thread context (system_server UID 1000 / radio UID 1001), not the
         * calling app's. Filtering on `getuid() >= 10000` would block every
         * reply because the hook never sees the app's UID on the reply path.
         *
         * The pattern is narrow on its own — 8-byte parcel, status==0, exact
         * value 18 (NETWORK_TYPE_IWLAN). Other binder int replies don't
         * coincide with that constant in normal traffic. */
        char tmp[8];
        if (lp_copy_from_user(tmp, from, 8) > 0) {
            __s32 status = *(__s32 *)(tmp + 0);
            __s32 value  = *(__s32 *)(tmp + 4);
            if (status == 0 && value == 18) {  /* NETWORK_TYPE_IWLAN → NR */
                __s32 nr = 20;
                *(__s32 *)(tmp + 4) = nr;
                lp_copy_to_user((void __user *)from, tmp, 8);
                g_dnt_spoofed++;
                return;
            }
        }
    }

    /* Large-parcel SubscriptionInfo carrier-name spoof — runs BEFORE the
     * small-parcel main path so parcels >4KB get a chance at carrier_name
     * rewrite without going through the main scan loop (which would race
     * on a shared static buffer with multi-threaded binder).
     *
     * Per-call kp_malloc (TLSF, thread-safe), narrowly scoped: only the
     * carrier_name pattern is scanned and rewritten. carrier_id swap is
     * cheap enough to inline here too. Other identifier swaps (IMSI/ICCID/
     * MCC) only matter for small reply parcels and stay in the main path. */
    /* SubscriptionInfo.mCarrierName spoof — structural anchor on mDisplayName.
     * Runs for parcels >4KB only (kp_malloc'd scratch). Small parcels (≤4KB)
     * are handled in scan_and_spoof_parcel via the same anchor logic, so all
     * parcel sizes get covered without race-prone shared buffers.
     *
     * AOSP SubscriptionInfo.writeToParcel emits fields in this order:
     *   ... writeString8(mIccId)
     *       writeInt(mSimSlotIndex)
     *       writeString8(mDisplayName)    ← we KNOW this value (= operator_name
     *                                       set via privileged setDisplayName API
     *                                       by companion APK)
     *       writeString8(mCarrierName)    ← unknown content (locale-dependent,
     *                                       carrier-dependent: "Emergency calls
     *                                       only", "Play", "비상 통화만 가능", ...)
     *       writeInt(mNameSource)         ← 4 bytes of int (0..4 small value)
     *   ...
     *
     * Triple anchor (displayName + adjacent String8 + small int) makes false
     * positives essentially impossible. */
    if (from && bytes > 4096 && bytes <= 16384 && lp_kmalloc && lp_kfree &&
        g_profile.carrier_name[0]) {
        char *big_buf = (char *)lp_kmalloc(bytes, LP_GFP_ATOMIC);
        if (big_buf) {
            if (lp_copy_from_user(big_buf, from, bytes) > 0) {
                /* scan_subinfo_anchor handles BOTH carrierName and carrier_id
                 * swap (carrier_id scoped to the field range AFTER the
                 * carrierName slot — so we don't accidentally rewrite some
                 * other int that happens to equal real_carrier_id). */
                bool changed = scan_subinfo_anchor(big_buf, bytes);
                /* operatorAlphaLong/Short leak — same scan as small-parcel
                 * fourth pass. Big parcels (>4KB SubscriptionInfo with carrier
                 * configs) often contain operatorAlpha embedded in nested
                 * NRI / cellIdentity structures. */
                if (scan_operator_alpha_leaks(big_buf, bytes)) changed = true;
                if (changed) lp_copy_to_user((void __user *)from, big_buf, bytes);
            }
            lp_kfree(big_buf);
        }
    }

    /* Large-parcel path for CameraCharacteristics metadata. The camera_metadata
     * blob is ~8-13KB (rear ~10.6KB, front ~12KB) — it exceeds the 4096 stack
     * buffer below, so the small path drops it (bytes > 4096 return). It is
     * delivered INLINE in the binder transaction (writeBlob stays in-place under
     * ~40KB), so it lands in this 4096..16384 window. Copy to a heap scratch,
     * find/replace the per-unit calibration floats, write back. USER apps only.
     * Independent of the carrier block above (that one is gated on carrier_name). */
    if (from && bytes > 4096 && bytes <= 16384 && lp_kmalloc && lp_kfree &&
        g_profile.camera_spoof_enabled && g_profile.camera_cal_count > 0 &&
        recv_uid_main >= 10000 && !lp_is_uid_excluded((__u32)recv_uid_main)) {
        char *cam_buf = (char *)lp_kmalloc(bytes, LP_GFP_ATOMIC);
        if (cam_buf) {
            if (lp_copy_from_user(cam_buf, from, bytes) > 0) {
                if (try_spoof_camera_calibration(cam_buf, bytes))
                    lp_copy_to_user((void __user *)from, cam_buf, bytes);
            }
            lp_kfree(cam_buf);
        }
    }

    /* Original main path: small parcels only, stack buffer, no race.
     * Lower-bound 8 (was 12) so the bytes==8 carrier_id swap path inside
     * scan_and_spoof_parcel actually receives its target replies — `tm
     * .getSimCarrierId()` and friends return exactly 8 bytes (status int
     * + carrier_id int) and were silently dropped at this top-level gate
     * in earlier revisions, even after the inner `bytes >= 8` was added.
     * Diagnostic added 2026-05-08 confirmed zero 8-byte parcels reaching
     * the hook until this change. */
    if (!from || bytes < 8 || bytes > 4096) return;

    char buf[4096];
    if (lp_copy_from_user(buf, from, bytes) <= 0) return;

    // Hide dev settings from non-system apps (request-side, corrupts setting name)
    if (bytes >= 100 && bytes <= 1500 && try_hide_dev_settings(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
        g_adb_hidden++;
        return;
    }

    /* HCI Command Complete: Read_BD_ADDR — fires once during BT init when the
     * vendor HAL delivers the chip's factory MAC to the daemon. Spoof here so
     * daemon writes our MAC into bt_config.conf, settings.secure, dumpsys cache. */
    if (bytes >= 12 && bytes <= 256 && try_spoof_hci_bdaddr(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
        g_binder_btmac_spoofed++;
        lp_dbg("lukeprivacy: HCI Read_BD_ADDR spoofed to %s\n", g_profile.bluetooth_mac);
        return;
    }

    /* Removed: brute-force 8-byte-offset location scan (PlanPrecision #1,
     * 2026-05-11). Range-check on doubles + fractional-precision heuristic
     * had zero structural anchor — any parcel carrying two doubles in
     * (-90,+90)/(-180,+180) with 4-digit precision was rewritten, hitting
     * Mapbox/Yandex geometry parcels, ML float arrays, sensor-fusion native
     * payloads. All known location parcel sizes (128/136/176/192/204/212/
     * 220/228/292/300) carry a provider string and are covered by the
     * structural detector `try_detect_location_parcel` (:2235) plus the
     * embedded scan below — both anchored on provider literal +
     * fieldsMask. */

    // GNSS Location spoofing with strict timestamp validation
    // Real GNSS has valid timestampMillis at offset 80 (Unix time in ms)
    // Settings parcels have garbage there
    if (g_profile.location_enabled && bytes == 112) {
        if (try_detect_gnss_location(buf, 112)) {
            spoof_gnss_location(buf);
            lp_copy_to_user((void __user *)from, buf, 112);
            g_gnss_location_spoofed++;
            return;
        }
    }

    __s32 status = *(__s32 *)buf;
    __s32 str_len = *(__s32 *)(buf + 4);

    /* IPhoneSubInfo standalone IMSI/IMEI reply (40 B exact, see helper). */
    if (try_spoof_imsi_standalone(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
        return;
    }

    /* GAID standalone reply hook removed (handled in companion APK).
     *
     * Previously we matched 36-char UUID replies from
     * `AdvertisingIdClient.getAdvertisingIdInfo()` and rewrote the value to
     * `g_profile.advertising_id`. That was racey because (a) GMS persists
     * the GAID on disk and serves it from memory, so individual binder
     * replies aren't the only path, and (b) clients cache the first
     * GAID they ever read, so each per-Save change in g_profile only
     * propagates if the client process is also restarted.
     *
     * The companion APK now performs a *native-grade* GAID rotation —
     * it overwrites `/data/data/com.google.android.gms/shared_prefs/
     * adid_settings.xml` with the new UUID, bumps `adid_reset_count`
     * exactly the way the system "Reset advertising ID" UI does, and
     * force-stops `com.google.android.gms.persistent`/`.unstable` so
     * the in-memory cache rebuilds from the new disk value. That is
     * what fraud SDKs treat as an authoritative reset, and it doesn't
     * touch account auth state.
     *
     * `g_profile.advertising_id` and `set_gaid:` ctl0 remain live for
     * forward-compat with older companion APKs and so the field can be
     * re-enabled here if a future gap reopens.
     */

    /* Network/SIM country ISO - standalone reply.
     *
     * Minimal layout (e.g. getSimCountryIso): status(4) + len=2(4) +
     * UTF-16 chars(4) + null+pad(4) = 16 bytes.
     *
     * Wider replies (observed for getNetworkCountryIso on Android 14+):
     * the same UTF-16 country string is followed by extras — subId,
     * caller-package marker, exception trail — pushing the parcel up
     * to ~48-56 bytes. Our previous `bytes <= 24` cap silently dropped
     * those, leaving real registered-network country (e.g. "pl" when
     * the SIM is roaming on a Polish tower) leaking past the spoof
     * even though SIM-side ISO was already being rewritten.
     *
     * The matcher is anchored on the parcel header (status=0, str_len=2)
     * AND `is_country_format_u16` (two lowercase letters) — that's a
     * very narrow pattern; widening the size cap to 64 is safe because
     * no other 2-char-lowercase string reply is dense in binder traffic. */
    /* v37 (2026-05-17): blind country ISO spoof - rewrite ANY 2-char
     * lowercase country reply to configured country_iso, without
     * literal-match anchor on real_country. Reason: when SIM tray is
     * empty, tm.networkCountryIso returns cached last-known ("pl" from
     * prior registration) but companion has no way to capture it as
     * real_country (no Phase 1 getprop -> empty without radio, no
     * Phase 2 reflection without priv-app, fresh prefs empty). With
     * anchor required, the rewrite stays dormant.
     *
     * False-positive mitigation: recv-UID gate in before_binder_copy
     * already excludes system_server/GMS/Google packages where IETF
     * language tags and error mnemonics ("en", "no", "ok") legitimately
     * appear. App-context recv-UIDs (>= 10000, non-excluded) get the
     * rewrite. Plus skip if current == target (no inflation when SIM
     * present and country already matches). */
    if (status == 0 && str_len == 2 && bytes >= 12 && bytes <= 64
        && g_profile.country_iso[0]) {
        __u16 *utf16 = (__u16 *)(buf + 8);
        if (is_country_format_u16(utf16, 2)
            && !((__u16)g_profile.country_iso[0] == utf16[0]
                 && (__u16)g_profile.country_iso[1] == utf16[1])) {
            replace_utf16_inline(buf + 8, g_profile.country_iso, 2);
            lp_copy_to_user((void __user *)from, buf, bytes);
            g_binder_country_spoofed++;
            return;
        }
    }

    /* PlanPrecision A2 (2026-05-11): MediaDRM `deviceUniqueId` spoof.
     *
     * Shape anchor (is_mediadrm_reply): 40 B parcel, status==0, len==32 — that
     * matches ANY length-prefixed 32-byte byte-array reply, not just MediaDRM.
     * SHA-256 hashes, AES-256 keys, HMAC-SHA256 outputs, ECDSA P-256 r/s
     * components, random nonces returned through binder by native crypto SDKs
     * (rootbeer, Datadog SDK, GuardSquare DexGuard runtime, AppSealing, etc.)
     * all share this shape. Reply parcels do NOT carry the interface
     * descriptor (that lives in the request side via writeInterfaceToken),
     * so we can't gate by IMediaDrm descriptor directly without
     * request/reply correlation state tracking.
     *
     * Mitigation: require the recipient UID to be a known app (in the
     * alloc→uid map, UID >= 10000). System processes that route crypto
     * blobs between mediaserver and other services don't match (they're
     * UID < 10000 or unmapped). Apps reading MediaDRM.getPropertyByteArray
     * naturally have their alloc tracked by the binder driver hook.
     *
     * Per-UID derivation (preferred): when android_id_seed is set,
     * derive_per_uid_mediadrm() produces a 32-byte deviceUniqueId by
     * chaining splitmix64 from the same seed SSAID uses. That keeps
     * mediadrm cryptographically correlated with the per-UID SSAID a
     * fraud SDK reads alongside — real Android's Widevine TA derives
     * both from device-bound key material, so independent values
     * (which the legacy static path produced) would be a cross-check
     * fingerprint vector by themselves.
     *
     * Static fallback: when android_id_seed isn't set yet (companion
     * APK hasn't pushed it, or older companion version), fall back to
     * the hex-encoded g_profile.mediadrm_id. Backward compat — the
     * deviceUniqueId still gets spoofed, just not correlated.
     *
     * Stability: derivation is pure u64 arithmetic, deterministic, no
     * yield. Same UID across reads → same bytes (Widevine's stable-read
     * invariant — apps reading deviceUniqueId twice in a session
     * expect the same value). Different UID → different bytes
     * (per-app fingerprint surface; matches the SSAID per-UID model). */
    /* Toggle gate: companion APK signals "mediadrm hook OFF" by pushing
     * empty `set_mediadrm:` (clears g_profile.mediadrm_id[0]). When off,
     * real hardware Widevine HMAC must pass through — DO NOT use the
     * seed path here, because android_id_seed is set for SSAID/sensor
     * even when mediadrm is intentionally disabled. Toggling mediadrm
     * via the static-id presence preserves the legacy disable path. */
    if (is_mediadrm_reply(buf, bytes) && g_profile.mediadrm_id[0]) {
        unsigned long mdrm_alloc = (unsigned long)alloc;
        unsigned int mdrm_recv_uid = lp_uid_map_get(mdrm_alloc);
        if (mdrm_recv_uid >= 10000) {
            unsigned char new_id[32];
            bool have_id = false;
            /* Preferred path: per-UID derivation from android_id_seed.
             * Cryptographically correlates with SSAID (same seed root). */
            if (g_profile.android_id_seed[0] != 0) {
                unsigned long long seed = parse_seed_u64(g_profile.android_id_seed);
                if (seed != 0) {
                    derive_per_uid_mediadrm(seed, mdrm_recv_uid, new_id);
                    have_id = true;
                }
            }
            /* Fallback: companion-pushed static hex (legacy / no-seed). */
            if (!have_id) {
                hex_to_bytes(g_profile.mediadrm_id, new_id, 32);
                have_id = true;
            }
            if (have_id) {
                memcpy(buf + 8, new_id, 32);
                lp_copy_to_user((void __user *)from, buf, bytes);
                g_binder_mediadrm_spoofed++;
                return;
            }
        }
    }

    // WiFi spoof (WifiInfo + getScanResults) — USER apps only, NEVER system.
    // System apps (uid < 10000), excluded UIDs, and unresolved (0) UIDs are
    // skipped so connectivity/WiFi-settings surfaces see the real WiFi state
    // and we never break a system component with a spoofed BSSID/SSID.
    if (recv_uid_main >= 10000 && !lp_is_uid_excluded((__u32)recv_uid_main)) {
        // WifiInfo → redact BSSID + spoof MAC
        if (try_spoof_wifiinfo(buf, bytes)) {
            lp_copy_to_user((void __user *)from, buf, bytes);
            return;
        }

        // getScanResults → spoof BSSID of farm SSIDs (Net1-16), scoped
        if (try_spoof_scanresults(buf, bytes)) {
            lp_copy_to_user((void __user *)from, buf, bytes);
            return;
        }

        // CameraCharacteristics → replace per-unit lens/sensor calibration
        // floats (intrinsics/distortion/pose/colour) with seed-perturbed fakes
        if (try_spoof_camera_calibration(buf, bytes)) {
            lp_copy_to_user((void __user *)from, buf, bytes);
            return;
        }
    }

    // CellInfo response → empty list
    if (try_spoof_cellinfo(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
        return;
    }


    // GnssStatus parcel (IGnssStatusListener.onGnssStatusChanged)
    // zero-out — only when location spoof is enabled (otherwise no
    // motivation to lie about visible satellites). Defeats TLE
    // cross-check that anti-fraud SDKs use to verify the claimed
    // location matches the satellites actually overhead.
    if (g_profile.location_enabled && try_spoof_gnss_status(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
        return;
    }

    // Location parcel detection and spoofing
    if (g_profile.location_enabled && bytes >= 48 && bytes <= 512) {
        size_t lat_offset = 0;
        size_t parcel_start = 0;
        if (try_detect_location_parcel(buf, bytes, &lat_offset, &parcel_start)) {
            lp_put64(buf + lat_offset,     lp_f64_bits(&g_profile.latitude));
            lp_put64(buf + lat_offset + 8, lp_f64_bits(&g_profile.longitude));

            __s32 provider_len = *(__s32 *)(buf + parcel_start);
            size_t str_size = (provider_len + 1 + 3) & ~3;
            size_t mask_offset = parcel_start + 4 + str_size;
            __s32 fields_mask = *(__s32 *)(buf + mask_offset);

            // Clear mock provider flag so apps don't see isMock()=true
            if (fields_mask & LOC_HAS_MOCK_PROVIDER) {
                *(__s32 *)(buf + mask_offset) = fields_mask & ~LOC_HAS_MOCK_PROVIDER;
                fields_mask &= ~LOC_HAS_MOCK_PROVIDER;
            }

            if ((fields_mask & LOC_HAS_ALTITUDE) &&
                (lp_f64_bits(&g_profile.altitude) & LP_F64_ABS_MASK) != 0) {
                size_t alt_offset = lat_offset + 16;
                if (alt_offset + 8 <= bytes)
                    lp_put64(buf + alt_offset, lp_f64_bits(&g_profile.altitude));
            }

            lp_copy_to_user((void __user *)from, buf, bytes);
            g_binder_location_spoofed++;
            return;
        }
    }

    /* Lowered from 32 → 12 (bare phone) → 8 (carrier_id 8-byte swap).
     * The exact-8-byte path inside scan_and_spoof_parcel handles small
     * replies from `tm.getSimCarrierId()` / `tm.getSimSpecificCarrierId()`
     * (parcel layout = [status int=0][carrier_id int]). With the gate at
     * 12 those replies never reached the function and the real carrier_id
     * (1658 = Plus PL) leaked straight through, which user reproduced
     * 2026-05-08 with `tm.simCarrierId = 1658` despite an AT&T spoof
     * profile. Internal passes have their own length checks and fail
     * fast on a 8-byte buffer (only the `bytes == 8` carrier_id swap
     * actually does anything at this size). */
    if (bytes >= 8 && scan_and_spoof_parcel(buf, bytes)) {
        lp_copy_to_user((void __user *)from, buf, bytes);
    }

    // Scan for embedded Location parcels in larger buffers (FusedLocation LocationResult)
    // GMS embeds Location parcels at deep offsets (172, 260, 480+) inside LocationResult
    if (g_profile.location_enabled && bytes >= 48) {
        bool loc_modified = false;
        for (size_t i = 4; i + 40 <= bytes; i += 4) {
            size_t lat_offset = 0;
            if (try_detect_location_parcel_at(buf, bytes, i, &lat_offset)) {
                __u64 cur_lat = lp_f64_bits(buf + lat_offset);
                __s64 dlat = lp_f64_to_scaled(cur_lat, 10000)
                           - lp_f64_to_scaled(lp_f64_bits(&g_profile.latitude), 10000);
                if (dlat < 0) dlat = -dlat;
                if (dlat < 10) continue;
                lp_put64(buf + lat_offset,     lp_f64_bits(&g_profile.latitude));
                lp_put64(buf + lat_offset + 8, lp_f64_bits(&g_profile.longitude));
                if ((lp_f64_bits(&g_profile.altitude) & LP_F64_ABS_MASK) != 0 &&
                    lat_offset + 24 <= bytes)
                    lp_put64(buf + lat_offset + 16, lp_f64_bits(&g_profile.altitude));
                __s32 provider_len = *(__s32 *)(buf + i);
                size_t str_size = (provider_len + 1 + 3) & ~3;
                size_t mask_off = i + 4 + str_size;
                if (mask_off + 4 <= bytes) {
                    __s32 mask = *(__s32 *)(buf + mask_off);
                    if (mask & LOC_HAS_MOCK_PROVIDER)
                        *(__s32 *)(buf + mask_off) = mask & ~LOC_HAS_MOCK_PROVIDER;
                }
                g_binder_location_spoofed++;
                loc_modified = true;
            }
        }
        if (loc_modified) {
            lp_copy_to_user((void __user *)from, buf, bytes);
            return;
        }
    }
}

/* Dropped in the in-tree port: the KP-era direct-kernel-buffer-modification
 * path (binder_alloc_get_page + kmap_local_page) and the empty after_binder_copy
 * handler. They were disabled in the KPM ("copy_to_user writes to wrong address
 * space") and unused. */

// GNSS HAL GnssLocation struct (112 bytes) - from AOSP hardware/interfaces/gnss/aidl
// Offset 0:   int32  gnssLocationFlags (bitmask: 0x01=LAT_LONG, 0x02=ALT, 0x04=SPEED, etc)
// Offset 4:   padding
// Offset 8:   double latitudeDegrees
// Offset 16:  double longitudeDegrees
// Offset 24:  double altitudeMeters
// Offset 32:  double speedMetersPerSec
// Offset 40:  double bearingDegrees
// Offset 48:  double horizontalAccuracyMeters
// Offset 56:  double verticalAccuracyMeters
// ...
// Total: 112 bytes
#define GNSS_LOC_HAS_LAT_LONG   0x0001
#define GNSS_LOC_HAS_ALTITUDE   0x0002
#define GNSS_LOC_HAS_SPEED      0x0004
#define GNSS_LOC_HAS_BEARING    0x0008
#define GNSS_LOC_HAS_H_ACC      0x0010
#define GNSS_LOC_HAS_V_ACC      0x0020
#define GNSS_LOC_VALID_MASK     0x00FF

static int gnss_detect_log;  // Reset at module load

static int gnss_debug_112;  // Reset at module load

static int try_detect_gnss_location(char *buf, size_t bytes)
{
    // GnssLocation AIDL struct is exactly 112 bytes
    if (bytes != 112) return 0;

    __s32 flags = *(__s32 *)buf;
    __u64 lat_bits = lp_f64_bits(buf + 8);
    __u64 lon_bits = lp_f64_bits(buf + 16);
    __u64 lat_mag  = lat_bits & LP_F64_ABS_MASK;
    __u64 lon_mag  = lon_bits & LP_F64_ABS_MASK;
    __s64 timestamp_ms = *(__s64 *)(buf + 80);
    /* lat in micro-degrees, integer — for FP-free debug prints only. */
    __s64 lat_e6 __maybe_unused = lp_f64_to_scaled(lat_bits, 1000000);
    bool in_europe;

    // Debug: log ALL 112-byte buffers with their timestamps
    if (gnss_debug_112 < 30) {
        gnss_debug_112++;
        lp_dbg("lukeprivacy: 112b: flags=0x%x lat_e6=%lld ts=%lld\n", flags, lat_e6, timestamp_ms);
    }

    // Flags must be in GNSS range (0x01-0xFF)
    if (flags <= 0 || flags > 0xFF) return 0;

    // Must have LAT_LONG flag
    if (!(flags & GNSS_LOC_HAS_LAT_LONG)) return 0;

    // Validate lat/lon: |lat|<=90, |lon|<=180, not exactly 0,0
    if (lat_mag > LP_F64_ABS_90)  return 0;
    if (lon_mag > LP_F64_ABS_180) return 0;
    if (lat_mag == 0 && lon_mag == 0) return 0;

    // Check if coordinates look like Europe (real location)
    // If yes, spoof regardless of timestamp
    in_europe = (lp_f64_le(LP_F64_35, lat_bits) && lp_f64_le(lat_bits, LP_F64_72) &&
                 lp_f64_le(LP_F64_NEG10, lon_bits) && lp_f64_le(lon_bits, LP_F64_40));

    if (!in_europe) {
        // Not in Europe - check timestamp as fallback
        if (timestamp_ms < 1577836800000LL || timestamp_ms > 2208988800000LL) {
            if (gnss_detect_log < 20) {
                gnss_detect_log++;
                lp_dbg("lukeprivacy: REJECTED not_eu ts=%lld flags=0x%x lat_e6=%lld\n", timestamp_ms, flags, lat_e6);
            }
            return 0;
        }
    }

    if (gnss_detect_log < 20) {
        gnss_detect_log++;
        lp_dbg("lukeprivacy: GNSS MATCH flags=0x%x ts=%lld lat_e6=%lld\n", flags, timestamp_ms, lat_e6);
    }

    return 1;
}

static void spoof_gnss_location(char *buf)
{
    // Spoof lat/lon (copy raw IEEE-754 bits)
    lp_put64(buf + 8,  lp_f64_bits(&g_profile.latitude));
    lp_put64(buf + 16, lp_f64_bits(&g_profile.longitude));

    // Spoof altitude if we have it (altitude != 0.0 -> magnitude nonzero)
    if ((lp_f64_bits(&g_profile.altitude) & LP_F64_ABS_MASK) != 0)
        lp_put64(buf + 24, lp_f64_bits(&g_profile.altitude));

    // Spoof horizontal accuracy: accuracy > 0.0f == positive, nonzero float.
    // Widen the float bits to double bits (offset 48 is a double field).
    {
        __u32 acc = lp_f32_bits(&g_profile.accuracy);
        if ((acc & 0x80000000u) == 0 && (acc & 0x7FFFFFFFu) != 0)
            lp_put64(buf + 48, lp_f32_to_f64_bits(acc));
    }
}

// Tracepoint counters (retained: extern-referenced by lukeprivacy.c ioctl_stats)
int g_kernel_copy_calls = 0;

/* GNSS spoof on the kernel-source copy path.
 *
 * binder_alloc_copy_to_buffer() copies driver/kernel-owned data (not the
 * sender's userspace parcel) into the receiver's binder buffer. The GNSS AIDL
 * GnssLocation struct (exactly 112 B) arrives this way. Call this hook BEFORE
 * the memcpy in binder_alloc_copy_to_buffer(): `src` is a kernel pointer, so we
 * detect + rewrite the 112-byte struct in place and the (now spoofed) bytes get
 * copied into the buffer. Optional — the primary Location spoofing already runs
 * in lp_binder_copy_to_buffer_hook (userspace-parcel path). */
void lp_binder_copy_to_buffer_gnss_hook(const void *src, size_t bytes)
{
    if (!g_hooks_enabled) return;
    if (!g_profile.location_enabled) return;
    if (!src) return;

    if (bytes == 112) {
        char *p = (char *)src;   /* modifies the caller's kernel source buffer */
        if (try_detect_gnss_location(p, 112)) {
            spoof_gnss_location(p);
            g_gnss_location_spoofed++;
        }
    }
}

/* Dropped in the in-tree port: the android_vh_binder_transaction_received
 * tracepoint probe (binder_txn_received_hook) and its struct-offset scanning.
 * It was receiver-context and explicitly could-not-modify ("TODO: need
 * sender-side hook") in the KPM, and its location-scan is redundant with the
 * embedded-Location pass in lp_binder_copy_to_buffer_hook. */

int binder_hook_init(void)
{
    /* In-tree port: hook installation is compile-time (direct call sites in
     * drivers/android/binder_alloc.c), so there is nothing to register here.
     * This is setup-only: reset the GNSS/location diagnostic counters. The
     * allocator pointers are resolved separately by lp_init_kmalloc(), which
     * the driver init calls before this. */
    gnss_debug_112 = 0;
    gnss_detect_log = 0;
    loc_scan_debug = 0;
    g_loc_spoof_log = 0;
    return 0;
}

void binder_hook_exit(void)
{
    /* Nothing to unregister — hooks are compile-time call sites. */
}
