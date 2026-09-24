#ifndef _LUKEPRIVACY_PROFILE_H
#define _LUKEPRIVACY_PROFILE_H

/* requires <linux/types.h> to be included by the translation unit */

#define MAX_ID_LEN 64
#define MAX_PROP_LEN 128

struct spoof_profile {
    /* android_id field removed 2026-05-09 — KPM no longer takes part in
     * android_id spoofing (Android 8+ serves apps a per-package SSAID
     * from settings_ssaid.xml that any binder-side spoof can't reach
     * cleanly). The companion APK still keeps an android_id value in
     * profile.json as the seed for MediaDRM HMAC derivation, but it
     * never reaches the kernel. */
    char gsf_id[17];
    char advertising_id[37];
    char firebase_id[37];

    char imei[16];
    char imsi[16];
    char iccid[21];
    char serial[17];

    char fingerprint[MAX_PROP_LEN];
    char model[MAX_PROP_LEN];
    char manufacturer[MAX_PROP_LEN];
    char brand[MAX_PROP_LEN];
    char device[MAX_PROP_LEN];
    char product[MAX_PROP_LEN];
    char board[MAX_PROP_LEN];

    char bluetooth_mac[18];
    char wifi_mac[18];

    char mcc[4];
    char mnc[4];
    char mccmnc[8];
    char country_iso[4];

    /* "Real" SIM values captured by the companion APK before any spoof
     * landed (or persisted in prefs across saves). The KPM binder hook
     * uses these to do literal-value matching when no SubscriptionInfo
     * marker is present in the parcel — needed because unprivileged
     * apps (no READ_PRIVILEGED_PHONE_STATE) get a filtered SubscriptionInfo
     * where iccId/number/hplmns are masked out. Without ICCID we can't
     * use the marker-guard scan, so we fall back to "rewrite this exact
     * string anywhere it appears" — safe because the string we match
     * is the user's specific real-SIM value, not a generic format. */
    char real_mcc[4];
    char real_mnc[4];
    char real_country[4];
    char operator_name[32];
    char phone_number[20];
    char mediadrm_id[65];

    /* SubscriptionInfo.mCarrierId is an int. Real value comes from
     * the AOSP carrier_id list (e.g. 1662 = Plus PL). Companion APK
     * reads it via subInfo.getCarrierId() before our hook can mask
     * it, then pushes both `real` (what's currently in the parcel)
     * and `target` (what we want to spoof to) here. KPM scans the
     * SubscriptionInfo parcel for the 4-byte LE pattern matching
     * `real_carrier_id` and rewrites it to `carrier_id`. */
    __s32 carrier_id;
    __s32 real_carrier_id;

    /* SubscriptionInfo.mCarrierName — literal match like MCC/MNC. Companion
     * APK reads real value via getCarrierName() (e.g. "Emergency calls only",
     * "Play", "No service") and displayName via getDisplayName() (e.g. "AT&T").
     * KPM scans for real_carrier_name UTF-16 and overwrites with carrier_name,
     * padded/truncated to same byte length. */
    char carrier_name[64];
    char real_carrier_name[64];

    /* ServiceState / NetworkRegistrationInfo / CellIdentity operatorAlpha
     * (real carrier alpha label as advertised by the network, e.g. "Plus",
     * "Verizon Wireless", "T-Mobile"). Different from displayName/carrierName
     * — ServiceState exposes mOperatorAlphaLong and mOperatorAlphaShort which
     * leak the network-side identity even when SubscriptionInfo carrierName
     * is spoofed. Companion APK captures these from ss.getOperatorAlphaLong()/
     * Short() and pushes both — KPM scans every binder parcel for the exact
     * real strings (UTF-8 + UTF-16) and overwrites them with carrier_name
     * (= operator_name = displayName). One target replacement, both alpha
     * variants, since apps treat them as carrier identity strings. */
    char real_operator_alpha_long[64];
    char real_operator_alpha_short[16];

    /* Real bare-digit phone number (e.g. "781988711" — Plus PL line1Number).
     * AOSP tm.line1Number on some carriers returns the local number without
     * country code or '+' prefix, so the existing is_phone_format_u16
     * check (which mandates '+' for low FP risk) lets it pass through.
     * Companion APK captures it via reflection on first save and pushes
     * here; KPM does literal-match in scan_and_spoof_parcel and rewrites
     * with phone_number (truncated/padded to same length so no parcel
     * shift, like other UTF-16 fields). */
    char real_phone_bare[16];

    /* ServiceState integer leaks: channelNumber (current EARFCN/ARFCN, e.g.
     * 3526 for LTE B7) and the first cellBandwidth value (e.g. 5000 / 20000
     * kHz). These uniquely identify the user's tower / cell config. KPM
     * literal-matches the captured int (gated by operatorAlpha presence in
     * the same parcel to avoid flipping unrelated ints) and rewrites to 0. */
    __s32 real_channel_number;
    __s32 real_cell_bandwidth;

    /* CellIdentity LTE/NR integer leaks per NRI:
     *  - ci: 28-bit cell identity (eNB ID + sector). Globally unique per
     *    tower, identifies the user's exact cell.
     *  - pci: physical cell ID (0..503 LTE, 0..1007 NR). Tower-local but
     *    distinguishes adjacent cells.
     *  - tac: tracking area code (16-bit LTE, 24-bit NR). Identifies the
     *    paging area, reveals approximate region.
     *  - earfcn: E-UTRA absolute radio-frequency channel number. Reveals
     *    the carrier band the user is camped on.
     * All four are zeroed via the same operatorAlpha-gated literal-match
     * pass that handles channelNumber / cellBandwidth. */
    __s32 real_ci;
    __s32 real_pci;
    __s32 real_tac;
    __s32 real_earfcn;

    /* Spoofed cell identity ints. Companion APK picks consistent
     * values per spoofed MCC (typical LTE band + plausible cell IDs)
     * and pushes here. KPM rewrites real_* to spoof_* instead of
     * zeroing — earfcn=0/pci=0/tac=0 are physically impossible /
     * extremely rare on real LTE/NR networks and would themselves
     * be a structural tell. If a spoof_* value is 0 (not set),
     * the corresponding real_* is left untouched. */
    __s32 spoof_ci;
    __s32 spoof_pci;
    __s32 spoof_tac;
    __s32 spoof_earfcn;
    __s32 spoof_channel_number;
    __s32 spoof_cell_bandwidth;

    char spoof_ssid[33];
    char spoof_bssid[18];

    // Location spoofing
    double latitude;
    double longitude;
    double altitude;
    float accuracy;
    bool location_enabled;

    /* Pretend SIM Internet — make apps think the data path is on cellular
     * (5G NR) while the device is actually carrying traffic over WiFi.
     * Pure API-level spoof: NetworkInfo / NetworkCapabilities / TelephonyManager
     * binder replies are rewritten. We do NOT touch routing — the user's
     * proxy on the WiFi router handles ASN/IP. Default off because flipping
     * the transport breaks apps that gate features on WiFi (e.g. large
     * downloads "WiFi only"). */
    bool pretend_sim_enabled;

    /* Gate for try_spoof_cellinfo (getAllCellInfo() reply count-zeroing).
     * Without this gate the hook fires on every CellInfo-shaped binder
     * reply regardless of UI toggles — apps with a real working SIM see
     * empty getAllCellInfo() and carrier services (com.google.android.ims
     * RcsProvisioningMonitor) NPE on missing cell context. Default off →
     * cellinfo passthrough until companion APK pushes set_cell_info:1. */
    bool cell_info_enabled;

    /* Per-hook gating flag for try_hide_dev_settings's adb-hide path.
     * The android_id-corruption sibling was removed 2026-05-09 — Android
     * 8+ serves apps a per-package SSAID from settings_ssaid.xml that
     * the old "android_id"→"android_ix" name flip never reached anyway,
     * so the corresponding `secure.android_ix` was a non-stock-key
     * detection tell with zero functional benefit on modern targets.
     *
     * adb_hide_enabled gates the adb_enabled / adb_wifi_enabled /
     * development_settings_enabled name corruption inside
     * try_hide_dev_settings. Default false → fully passive on fresh
     * KPM init until companion APK Save pushes the toggle state.
     */
    bool adb_hide_enabled;

    /* Per-app SSAID spoof — KPM hook on SettingsProvider getSsaid binder reply.
     * Seed is the same as Ids.android_id pushed by companion APK; per-UID
     * values are derived deterministically (splitmix64) from this seed at
     * hook time, so MediaDRM HMAC and SSAID share one root seed but every
     * app sees a different SSAID (mimics stock per-(pkg,cert) isolation).
     */
    char android_id_seed[17];           /* 16 hex chars + NUL */
    bool android_id_spoof_enabled;

    /* SSAID relaxed-anchor fallback. Default OFF — strict 7-step Bundle
     * anchor (BNDL magic + entry_count=1 + key="value" + VAL_STRING + 16
     * hex) is the only path that fires. With this toggle ON, after strict
     * fails the hook tries a SECOND precise pattern: int32 length-prefix
     * == 16 followed by 32 bytes of UTF-16 lowercase-hex residing in the
     * last 40 bytes of a parcel sized 40..400. This catches Cursor-data
     * shaped SSAID replies (ContentResolver.query path) without the BNDL
     * envelope. Per-UID gate identical to strict path (recv_uid >= 10000,
     * non-excluded). Circuit breaker auto-disables this toggle if it
     * fires > 50× per minute (sanity — protects against catastrophic
     * over-match if a different binder reply happens to embed 16 hex
     * chars in the last 40 bytes).
     */
    bool ssaid_relaxed_enabled;
    /* Single-UID lock for relaxed SSAID. 0 = disabled (relaxed never fires
     * even if ssaid_relaxed_enabled is true). Pushed via ctl0
     * set_ssaid_relaxed_uid:<uid>. */
    unsigned int ssaid_relaxed_target_uid;

    /* Per-UID accel / gyro bias spoof. KPM hook on __NR_recvfrom intercepts
     * SensorEventListener stream (BitTube socketpair). For each event
     * matching a strict 7-step sensors_event_t anchor (version + sensor
     * handle + type ∈ {1, 4} + timestamp range + finite-data + UID gate
     * ≥ 10000 + matching toggle), data[0..2] gets a per-UID seeded
     * Gaussian-equivalent offset ADDED in place — preserves gravity (Z
     * stays ~9.8) and motion deltas while shifting the per-chip stationary
     * bias every app reads.
     *
     * Seed reuses android_id_seed (companion APK pushes one seed; SSAID,
     * MediaDRM, and sensor offsets share the root for cryptographic
     * correlation — matches the way Widevine TA derives mediadrm from
     * android_id). Defaults to false; toggled on Save in the companion
     * APK; resets to false on every KPM init (boot autoload). */
    bool sensor_accel_spoof_enabled;
    bool sensor_gyro_spoof_enabled;

    /* Magnetometer (TYPE_MAGNETIC_FIELD 2 + UNCALIBRATED 14) per-UID hard-iron
     * bias spoof + slow micro-drift. Closes a per-UNIT fingerprint gap: the
     * uncalibrated bias fields are the cleanest device-stable signal and Snap
     * samples both types. Default OFF on KPM init; companion pushes it (Snap
     * default ON). */
    bool sensor_mag_spoof_enabled;

    /* "Held" motion model layer (opt-in, requires accel/gyro spoof ON).
     * When set, the accel gravity vector is re-projected onto a slowly
     * drifting hand-held tilt (pitch ~35-65°, roll ±12°) instead of being
     * left on the real orientation, and the gyro carries the angular
     * velocity of that drift — so a phone lying flat on a desk reads as if
     * held in a hand. Default OFF; reboot autoload resets it to false. */
    bool sensor_held_enabled;

    /* Keva write hook — intercepts libmetasec_ov writes to TikTok's binary
     * key-value store (keva). Substitutes sdi / ecneuq / openudid / semithc
     * / msmodel values with per-UID splitmix64-derived 16-hex strings at
     * write time, before bytes hit the disk. Default OFF (opt-in only).
     * keva_seed: if non-empty (16 hex), used instead of android_id_seed for
     * keva derivation so keva values can be rotated independently. When
     * empty, falls back to android_id_seed. */
    bool keva_spoof_enabled;
    char keva_seed[17];                 /* 16 hex + null, default empty = use android_id_seed */

    /* SSAID relaxed-anchor per-step fail counters. Packed in ssaid_anchor_fail[]:
     *   [0] = step 1 (BNDL magic), [1] = step 2 (entry_count),
     *   [2] = step 3 (key_len),     [3] = step 4 (UTF-16 "value"),
     *   [4] = step 5 (val_type),    [5] = step 6 (value_len),
     *   [6] = step 7 (hex chars),   [7] = total fails (any step)
     * Exposed in ioctl_stats for debug; gated by g_ssaid_debug_enabled. */

    /* GAID binder hook re-enable (UID-gated). Was intentionally absent after
     * over-match investigation 2026-05-08. Re-enabled as opt-in: gates on
     * recv_uid >= 10000 + not excluded. Anchor: bytes==48 (status+arr_len+36B
     * UUID+pad) OR bytes==8 (status+empty). */
    bool gaid_binder_reenabled;

    /* HostProcessBridge IPC — TikTok mini-app sandbox reads device_id from
     * host process via Binder. Hook rewrites Bundle reply key="device_id",
     * val=19-digit Snowflake with per-UID derived value. */
    bool hostprocess_bridge_enabled;

    /* /proc/version UID-gated redirect. read_hook already rewrites for all
     * tracked fds; this flag gates an ADDITIONAL pass targeting uid>=10000
     * processes that managed to get the real /proc/version (e.g. via a path
     * not caught by openat). Reuses FAKE_PROC_VERSION from read_hook.c via
     * extern. Counter: proc_version_uid_repl. Currently handled via existing
     * openat fd tracking; flag reserved for future extension. */
    bool proc_version_uid_redirect_enabled;

    /* boot_id spoof: read_hook rewrites /proc/sys/kernel/random/boot_id with a
     * per-SEED UUID (same across all apps, rotates on re-seed). Default off.
     * Without it, boot_id is the real per-boot UUID — stable across accounts
     * within one boot session (a linking signal), only changing on reboot. */
    bool boot_id_spoof_enabled;

    /* Timezone binder hook. Companion already handles persist.sys.timezone
     * via resetprop. If this flag is false (default), no binder hook fires.
     * Kept in profile for future extension. See A8 in gap plan. */
    bool timezone_binder_enabled;

    /* eventTime timeline offset. When enabled, the input recvfrom hook adds
     * eventtime_offset_ns to the MotionEvent eventTime (buffer off 16) AND
     * downTime (off 96) — same offset on both, so dwell (= et - dt) is preserved
     * while getEventTime() shifts. Per-account value (rand 2-3 days ns) set in
     * newIdentity: breaks the shared per-boot uptime timeline Snap leaks via
     * getEventTime() without a reboot, and makes each account look like a device
     * booted 2-3 days ago (not freshly-rebooted). Default off (offset 0). */
    bool eventtime_offset_enabled;
    __s64 eventtime_offset_ns;
    /* eventTime offset applies ONLY to this UID (Snap's CURRENT uid, captured fresh
     * by the companion at newIdentity; changes on reinstall). 0 = disabled. This is
     * a POSITIVE target, not an exclusion — a broad "all apps but excluded" gate
     * mutated the launcher and ANR'd the system. NOT persisted in profile.json, so a
     * boot re-apply of the offset stays inert (target 0) until newIdentity sets it. */
    __u32 eventtime_target_uid;

    /* ─── Google Block Store neutralization (Snap SS03 anchor) ──────────────
     * PROVEN on-device (2026-07-20): Snap backs its device identity
     * (cloud_account_id / Fidelius device key) to Google Block Store with
     * shouldBackupToCloud=true. Google restores it DEVICE-scoped — the SAME
     * token survives a full /data wipe, an OS re-flash (A16→A17), a different
     * Google account, AND a spoofed serial (anchored to Titan-M hardware
     * attestation in GMS checkin, which is unspoofable in SW). So no amount of
     * companion-side `rm schema.pb` helps: Snap's retrieveBytes triggers a
     * fresh cloud restore. The ONLY place to sever it is the read path — here,
     * in the binder reply from GMS to Snap.
     *
     * The reply (IBlockstoreService.retrieveBytes → Snap) carries the Block
     * Store entry as {key, value}. The KEY is a constant base64 string the
     * companion captures once from schema.pb and pushes via
     * `set_blockstore_key:<b64>`. When a reply heading to `blockstore_target_uid`
     * contains that key, we NEUTRALIZE the value in place (zero the value bytes +
     * its length prefix → Snap reads an empty entry → generates a FRESH
     * cloud_account_id, exactly like a genuine new device; empty is the natural
     * new-device state so it is NOT itself a tell).
     *
     * Fire policy — SESSION BRACKET (Snap "open once, register, exit"): Snap
     * reads Block Store MULTIPLE times per signup, and the old value persists in
     * schema.pb until Snap overwrites it, so a small count cap would leak the old
     * token on later reads. Instead the companion brackets the whole session:
     * enable neutralize BEFORE launch, disable AFTER Snap exits. `fire_cap == 0`
     * means UNLIMITED-while-enabled (kill every read in the window); `> 0` keeps
     * the legacy first-N mode. Safe for FRESH SIGNUP — a new account has no E2EE
     * identity to restore, so empty is the expected state throughout (no "shake to
     * e2ee" prompt) and Snap registers a fresh, unlinked Fidelius identity.
     * Companion arms via `set_blockstore_arm:0` (cap 0 + reset) then toggles
     * `set_blockstore_neutralize:1|0` around the session. Default disabled. */
    bool  blockstore_neutralize_enabled;
    __u32 blockstore_target_uid;        /* Snap's CURRENT uid; 0 = disabled */
    char  blockstore_key[48];           /* base64 Block Store entry key (constant) */
    __u32 blockstore_fire_cap;          /* 0 = unlimited while enabled (session bracket); >0 = first-N */
    /* capture/diagnostic mode: log candidate reply hex to dmesg so we can nail
     * the exact retrieveBytes wire layout on the first live test, then refine the
     * neutralization surgery. Independent of neutralize. */
    bool  blockstore_capture_enabled;

    /* Camera calibration spoof (per-unit hardware fingerprint) — factory-burned
     * lens intrinsics/distortion/pose + sensor colour matrices live in
     * /mnt/vendor/persist/camera/ (root-only) but surface to any CAMERA-perm
     * app via CameraCharacteristics binder metadata (LENS_INTRINSIC_CALIBRATION
     * 0x0008000a, LENS_DISTORTION 0x0008000d, LENS_POSE_ROTATION/TRANSLATION
     * 0x00080006/7, SENSOR_CALIBRATION_TRANSFORM1/2 0x000e0005/6). These are
     * unique per physical unit at 15-digit precision → a device ID that
     * survives factory reset + reinstall. The metadata blob is ~12KB (< the
     * 40KB in-place Parcel::writeBlob limit) so it stays IN the binder parcel,
     * not ashmem → we can rewrite it in place.
     *
     * The companion reads the REAL float values via Camera2 once (they're
     * static per device), computes seed-perturbed replacements (±0.3%, keyed by
     * android_id_seed so they rotate with every identity change and stay
     * coherent with serial/SSAID/GAID), and pushes (real,fake) 4-byte float
     * pairs here. The binder hook does a plain width-preserving find/replace of
     * each real bit-pattern → parcel size unchanged, no camera_metadata_t
     * parsing. USER apps only. */
    bool  camera_spoof_enabled;
    __u32 camera_cal_count;             /* number of (real,fake) pairs in use, 0 = off */
    __u32 camera_cal_real[64];          /* real IEEE-754 float32 bit patterns (from CameraCharacteristics) */
    __u32 camera_cal_fake[64];          /* seed-perturbed replacements, same order */

    /* Authorized controller package (e.g. SnapAuto). /proc/luke is writable by
     * root, shell(uid 2000), AND the process whose package == controller_pkg
     * (resolved via lp_pkg_for_uid). Empty = only root+shell. Set via
     * `set_controller_pkg:<pkg>`; persisted in profile.bin, restored at boot. */
    char controller_pkg[128];
};

extern struct spoof_profile g_profile;
extern bool g_hooks_enabled;

/* eventTime offset apply counter — verify via LukeTester delta jump. Defined in sensor_hook.c. */
extern unsigned int g_eventtime_offset_applied;

/* keva hook counters — exposed in ioctl_stats. Defined in keva_hook.c. */
extern unsigned int g_keva_sdi_w;
extern unsigned int g_keva_ecneuq_w;
extern unsigned int g_keva_openudid_w;
extern unsigned int g_keva_semithc_w;
extern unsigned int g_keva_msmodel_w;

/* SSAID anchor per-step fail counters (8 slots). Defined in binder_hook.c. */
extern unsigned int g_ssaid_anchor_fail[8];
/* SSAID debug mode flag — enables pr_info per anchor bail step. */
extern unsigned int g_ssaid_debug_enabled;

/* GAID binder re-enable counter. Defined in binder_hook.c. */
extern unsigned int g_gaid_binder_repl;

/* HostProcessBridge IPC rewrite counter. Defined in binder_hook.c. */
extern unsigned int g_hostbridge_repl;

/* /proc/version UID-gated redirect counter. Defined in read_hook.c. */
extern unsigned int g_proc_version_uid_repl;

/* Timezone binder hook counter. Defined in binder_hook.c. */
extern unsigned int g_timezone_repl;

/* Camera calibration find/replace counter. Defined in binder_hook.c. */
extern unsigned int g_camera_cal_spoofed;
extern unsigned int g_cursor_aid_spoofed;  /* Cursor/query android_id rewrites */

/* Block Store neutralization counters + arm reset. Defined in binder_hook.c. */
extern unsigned int g_blockstore_neutralized;  /* cumulative key garbles */
extern unsigned int g_blockstore_seen;         /* target-UID replies carrying the key */
void lp_blockstore_arm(void);                  /* reset per-arm fire counter */

#define LP_MAX_EXCLUDED_UIDS 1024
extern __u32 g_excluded_uids[LP_MAX_EXCLUDED_UIDS];
extern int g_excluded_uids_count;

bool lp_is_uid_excluded(__u32 uid);
/* config.gz hide list (GMS/DroidGuard uid only) — set via /proc/luke set_configgz_uids:CSV */
bool lp_uid_hides_configgz(int uid);
extern int g_configgz_count;
/* U18 sensor-motion include list (GMS/DroidGuard uid) — set via /proc/luke set_sensor_include:CSV */
bool lp_uid_sensor_included(__u32 uid);
extern int g_sensor_incl_count;

/* exclude_resolver.c — kernel-side mandatory-package resolver. */
int  lp_resolve_excluded_packages(void);
void lp_force_resolve_retry(void);
void lp_resolver_tick(void);

/* uid -> package-name lookup, populated by the resolver from packages.list
 * (app UIDs only, >= 10000, non-system). Returns NULL when the uid is not a
 * known app package. Used for PER-PACKAGE identifier derivation (SSAID /
 * MediaDRM) so a reinstall — which changes the UID — still yields the same
 * value, making a backed-up identity faithfully restorable. */
const char *lp_pkg_for_uid(__u32 uid);

#endif
