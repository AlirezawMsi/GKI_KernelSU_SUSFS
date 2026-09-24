/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy KPM — sensor bias spoof hook.
 *
 * Targets: per-chip stationary bias on accelerometer and gyroscope.
 * Per Pixel 6 research (Documents/eng/TIKTOK_DEVICE_IDS_REPORT.md:72-77)
 * fraud SDKs like TikTok's libmetasec_ov sample stationary sensor readings
 * during signup, compute the mean over a short window, and hash the
 * resulting bias vector as a device fingerprint that SURVIVES factory
 * reset (the bias is fused into the LSM6DSR chip's EEPROM at factory
 * calibration time). The chip's factory CSV in
 * /mnt/vendor/persist/sensors/imu6_*_static.csv is unreachable to
 * untrusted_app (SELinux persist_file context), so the only attack
 * surface available to apps is the SensorEventListener stream itself.
 *
 * Stream architecture (frameworks/native/libs/sensor/BitTube.cpp):
 *   sensorservice ──[sensors_event_t]──> BitTube (socketpair)
 *                                          │
 *                          recv(receiveFd) │  (== recvfrom syscall)
 *                                          ▼
 *                                  App SensorEventQueue
 *
 * We hook __NR_recvfrom in app processes. When the returned buffer
 * matches a strict 7-step structural anchor for a sensors_event_t
 * stream — version field, sensor handle, type ∈ {accel/gyro
 * calibrated+uncalibrated}, timestamp range, finite floats, UID gate,
 * matching toggle — we add a per-UID-seeded offset to data[0..2]. The
 * offset is a static shift (NOT noise dither) so the SDK's sample mean
 * lands on a UID-specific bias rather than the chip's real one.
 *
 * PRECISION CONTRACT (matches user requirement "precyzja hooków musi
 * być perfekcyjna"). 7 anchor checks per event, all must pass:
 *
 *   1) recv bytes is multiple of sizeof(sensors_event_t)
 *   2) sensors_event_t.version in known AOSP range [88..128]
 *   3) bytes / version == integer count of events
 *   4) event.type ∈ {1 ACCEL, 4 GYRO, 16 GYRO_UNCAL, 35 ACCEL_UNCAL}
 *   5) event.sensor handle > 0  (real handle)
 *   6) event.timestamp > 1 ns AND < 2^58 ns (~9 years, sane upper bound)
 *   7) event.data[0..2] all finite floats (rejects HAL transient NaN)
 *
 * Plus per-event UID gate: current_uid() ≥ 10000 AND not in exclude
 * list. System sensors (auto-rotate, step counter, screen-off proximity)
 * read with UID < 10000 → bypass → unaffected.
 *
 * False-positive surface: random recvfrom returning bytes % 104 == 0 with
 * the first u32 in [88..128] AND second u32 valid handle AND third u32
 * being one of 4 specific small ints AND timestamp-shaped 8 bytes AND
 * three finite floats. Joint probability negligible.
 *
 * Add semantics (vs replace): event.data[0..2] += offset preserves
 * gravity component on accel-Z (~9.8 stays ~9.8 + offset_z) and motion
 * deltas (rotation reflected through real gyro values + constant bias
 * shift). Replacement would make the device "feel weightless" to the
 * spoofed app — detection vector. ADD keeps all kinematic relationships
 * intact, only the static bias differs from real.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/nsproxy.h>
#include <linux/time_namespace.h>
#include <linux/kallsyms.h>
#include <asm/current.h>
#include <asm/neon.h>
#include <asm/simd.h>

#include "profile.h"
#include "uaccess.h"
#include "lp_log.h"

/* Calling-process UID. The recvfrom / prctl choke-points run in the caller's
 * task context, so `current` is the app. Replaces KP raw_syscall0(__NR_getuid). */
static inline __u32 lp_current_uid(void)
{
    return from_kuid(&init_user_ns, current_uid());
}

#ifdef LP_EVENTTIME_DIAG
/* fwd-decl: recvmsg diagnostic parser, defined below (diag builds only). */
static void lp_recvmsg_diag(void __user *umsg, long ret);
#endif

/* AOSP sensors.h: sensors_event_t total = 104 B on aarch64 since
 * Android 8 (24 B header + 64 B data union + 4 B flags + 12 B reserved).
 * Some pre-release / OEM-extended builds shift the union slot, so we
 * accept any version in [88..128] — the field still self-identifies the
 * struct size, which we cross-check against (bytes / count) == version. */
#define SENS_EVT_MIN_SIZE 88
#define SENS_EVT_MAX_SIZE 128
#define SENS_EVT_TYPICAL  104

/* Sensor type constants from android/sensor.h. We target the four IMU
 * types where the per-chip stationary bias is the fingerprint signal. */
#define SENS_TYPE_ACCELEROMETER              1
#define SENS_TYPE_MAGNETIC_FIELD             2
#define SENS_TYPE_ORIENTATION                3
#define SENS_TYPE_GYROSCOPE                  4
#define SENS_TYPE_GRAVITY                    9
#define SENS_TYPE_LINEAR_ACCELERATION        10
#define SENS_TYPE_ROTATION_VECTOR            11
#define SENS_TYPE_MAGNETIC_FIELD_UNCALIBRATED 14
#define SENS_TYPE_GAME_ROTATION_VECTOR       15
#define SENS_TYPE_GYROSCOPE_UNCALIBRATED     16
#define SENS_TYPE_ACCELEROMETER_UNCALIBRATED 35

/* Per-UID derivation magic: distinct salts per axis. Reuses the same
 * splitmix64 chain pattern that try_spoof_ssaid_reply uses for SSAID
 * derivation, so the sensor bias and SSAID are cryptographically
 * correlated through android_id_seed (matches the user requirement that
 * "MediaDRM zawsze powstaje z android_id w sposób kryptograficzny" — same
 * principle: all per-device identifiers descend from one root seed). */
#define MAGIC_ACCEL_X 0x53454e5341434358ULL  /* "SENSACCX" */
#define MAGIC_ACCEL_Y 0x53454e5341434359ULL  /* "SENSACCY" */
#define MAGIC_ACCEL_Z 0x53454e534143435aULL  /* "SENSACCZ" */
#define MAGIC_GYRO_X  0x53454e5347595258ULL  /* "SENSGYRX" */
#define MAGIC_GYRO_Y  0x53454e5347595259ULL  /* "SENSGYRY" */
#define MAGIC_GYRO_Z  0x53454e534759525aULL  /* "SENSGYRZ" */
#define MAGIC_MAG_X   0x53454e534d414758ULL  /* "SENSMAGX" */
#define MAGIC_MAG_Y   0x53454e534d414759ULL  /* "SENSMAGY" */
#define MAGIC_MAG_Z   0x53454e534d41475aULL  /* "SENSMAGZ" */

/* Diagnostic counters (visible in ctl0 ioctl_stats). */
unsigned int g_sensor_events_seen = 0;
unsigned int g_sensor_accel_spoofed = 0;
unsigned int g_sensor_gravity_spoofed = 0;
unsigned int g_sensor_gyro_spoofed = 0;
unsigned int g_sensor_mag_spoofed = 0;

/* ── Per-event jitter + simulated desk movement ──────────────────────
 *
 * Jitter: small noise on every event, simulates real sensor noise floor.
 * Desk bump: every ~800-2000 events, a larger perturbation lasting
 * ~15-40 events with smooth ramp-up/sustain/ramp-down envelope,
 * simulating someone bumping the desk or phone vibrating.
 *
 * Uses xorshift64 PRNG seeded from event counter — no kernel RNG
 * needed in the hot path (~3 cycles per call). */

static unsigned long long jitter_rng_state = 0x1234567890ABCDEFULL;

static unsigned long long xorshift64(void)
{
    unsigned long long x = jitter_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    jitter_rng_state = x;
    return x;
}

/* Map xorshift output to float in [-range, +range). */
static float rng_float(float range)
{
    unsigned long long r = xorshift64();
    int signed_val = (int)(r & 0x7FFFu) - 0x4000;  /* [-16384, +16383] */
    float result = (float)signed_val * (range / 16384.0f);
    /* Hard clamp — defense against any FPU edge case. */
    if (result > range) result = range;
    if (result < -range) result = -range;
    return result;
}

/* Hand-tremor magnitudes — CALIBRATED to a real 40s hand-held capture
 * (GyroCap, spoof off): gyro std ≈ X0.75 Y0.50 Z0.20, |max| ≈ X4.7 Y3.6 Z1.8;
 * accel std ≈ X1.3 Y2.2 Z2.4. Uniform half-range R → std ≈ R/1.73; the big
 * peaks come from the bump layer, the gravity-swing (held model) supplies most
 * of the accel Y/Z variance. Tune these against GyroCap, don't guess. */
/* Sensor NOISE FLOOR only — a tiny white component so the smooth coherent
 * motion (OSC_* oscillators below) still shows the small high-freq jaggedness a
 * real MEMS sensor has (real gyro jaggedness std(diff)/std ≈ 0.034, NOT 0). The
 * BULK of the motion is the smooth oscillator, never white noise. */
#define NOISE_FLOOR_GYRO  0.009f  /* rad/s (jaggedness ~0.05, matches real) */
#define NOISE_FLOOR_ACCEL 0.030f  /* m/s² */

/* Bump window state. A bump is a RARE window during which the oscillator drive
 * is boosted (see held_update → gain), producing a SMOOTH larger swing — the
 * fat tail that lifts gyro |max| to ~4.7. It only gates timing; no magnitudes
 * here (the smoothness/coherence comes from forcing the same oscillator). */
unsigned int bump_cooldown = 0;
unsigned int bump_remaining = 0;
unsigned int bump_total = 0;

static void maybe_start_bump(void)
{
    if (bump_remaining > 0) return;
    if (bump_cooldown > 0) { bump_cooldown--; return; }
    /* Avg every ~3000 events (~7s), lasts ~0.1-0.4s, long cooldown. */
    if ((xorshift64() % 3000) != 0) return;
    bump_total = 40 + (unsigned int)(xorshift64() % 120);      /* 40-160 events */
    bump_remaining = bump_total;
    bump_cooldown = 1500 + (unsigned int)(xorshift64() % 2500); /* 1500-4000 (~3-9s) */
}

/* Smooth envelope: ramp up 20%, sustain 40%, ramp down 40%. */
static float bump_envelope(void)
{
    if (bump_remaining == 0 || bump_total == 0) return 0.0f;
    float progress = 1.0f - ((float)bump_remaining / (float)bump_total);
    if (progress < 0.2f)
        return progress / 0.2f;           /* ramp up */
    else if (progress < 0.6f)
        return 1.0f;                       /* sustain */
    else
        return (1.0f - progress) / 0.4f;   /* ramp down */
}

/* Tap↔gyro correlation REMOVED (2026-07-08): in a realistic continuous hand-
 * held motion stream (see tremor + held model below) a per-tap spike is
 * invisible to the server anyway, and a clean repeating spike would itself be
 * an artifact. Detection reduces to "is there realistic continuous motion at
 * all" — which the baseline now provides. So no write-hook, no tap envelope. */

/* Magnitude budget for the per-UID seeded offset. Chosen to:
 *   - sit comfortably above natural inter-chip variance on Pixel 6
 *     (~0.05 m/s² accel between LSM6DSR units) so the spoof actually
 *     produces a bias hash different from the real one,
 *   - stay well below the gravity / motion signal scale so the spoofed
 *     stream still passes kinematic consistency checks (gravity on Z
 *     remains 9.8 ± 0.1, integration of gyro stays within ε of accel),
 *   - keep the resulting bias in the realistic range a fraud SDK would
 *     accept (real-device biases are typically ±0.10 m/s² accel /
 *     ±0.01 rad/s gyro). */
#define ACCEL_OFFSET_RANGE 0.10f   /* m/s²: offset ∈ [-0.10, +0.10) */
#define GYRO_OFFSET_RANGE  0.010f  /* rad/s: offset ∈ [-0.010, +0.010) */
/* Magnetometer per-UID static hard-iron offset + slow micro-drift. The
 * per-chip bias is the cleanest per-UNIT fingerprint (stable, orientation-
 * independent — see the uncalibrated bias fields). We shift it per-UID and let
 * it wander slowly (thermal-like) so it isn't a frozen constant. Range chosen
 * to stay within realistic hard-iron magnitudes (tens of µT). */
#define MAG_OFFSET_RANGE   40.0f   /* µT: per-UID static offset ∈ [-40, +40) */
#define MAG_DRIFT_STEP     0.05f   /* µT per event: micro random-walk step */
#define MAG_DRIFT_MAX      4.0f    /* µT: bound on the slow drift wander */

/* SplitMix64 — same generator used by try_spoof_ssaid_reply. Identical
 * implementation kept here to avoid binder_hook.c → sensor_hook.c
 * coupling. Cheap (~10 cycles), deterministic, well-distributed. */
static unsigned long long splitmix64(unsigned long long x)
{
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    x = x ^ (x >> 31);
    return x;
}

/* Parse the 16-hex-char android_id_seed string into u64. Mirrors
 * parse_seed_u64 from binder_hook.c. Returns 0 if seed is empty or
 * malformed (which short-circuits all derivation downstream — caller
 * should already have gated on g_profile.android_id_seed[0] != 0). */
static unsigned long long sensor_parse_seed_u64(const char *seed)
{
    unsigned long long v = 0;
    for (int i = 0; i < 16 && seed[i]; i++) {
        char c = seed[i];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') digit = 10 + (c - 'A');
        else return 0;
        v = (v << 4) | digit;
    }
    return v;
}

/* Map a u64 hash to a float offset in [-range, +range). 17 bits of the
 * hash drive resolution ≈ range / 65536 ≈ 1.5 µ-unit precision, which
 * is far below the chip noise floor — so consecutive UIDs get visibly
 * distinct biases without aliasing. */
static float u64_to_offset(unsigned long long h, float range)
{
    /* Take 17 bits, treat as signed in [-65536, +65535]. */
    int signed_val = (int)((h >> 16) & 0x1FFFFu) - 0x10000;
    float scale = range / 65536.0f;
    return (float)signed_val * scale;
}

/* Compute the 6-axis per-UID seeded offset table. Called once per
 * recvfrom invocation where the toggle is on AND the buffer matches the
 * structural anchor. Cheap (12 splitmix64 calls = ~120 cycles). */
static void derive_offsets(unsigned int uid,
                           float *off_ax, float *off_ay, float *off_az,
                           float *off_gx, float *off_gy, float *off_gz,
                           float *off_mx, float *off_my, float *off_mz)
{
    unsigned long long seed = sensor_parse_seed_u64(g_profile.android_id_seed);
    if (seed == 0) {
        *off_ax = *off_ay = *off_az = 0.0f;
        *off_gx = *off_gy = *off_gz = 0.0f;
        *off_mx = *off_my = *off_mz = 0.0f;
        return;
    }
    /* Mix seed and UID into a base derivation key (same pattern as
     * SSAID). golden-ratio multiplier from splitmix64 source paper. */
    unsigned long long base =
        splitmix64(seed ^ ((unsigned long long)uid * 0x9E3779B97F4A7C15ULL));
    *off_ax = u64_to_offset(splitmix64(base ^ MAGIC_ACCEL_X), ACCEL_OFFSET_RANGE);
    *off_ay = u64_to_offset(splitmix64(base ^ MAGIC_ACCEL_Y), ACCEL_OFFSET_RANGE);
    *off_az = u64_to_offset(splitmix64(base ^ MAGIC_ACCEL_Z), ACCEL_OFFSET_RANGE);
    *off_gx = u64_to_offset(splitmix64(base ^ MAGIC_GYRO_X),  GYRO_OFFSET_RANGE);
    *off_gy = u64_to_offset(splitmix64(base ^ MAGIC_GYRO_Y),  GYRO_OFFSET_RANGE);
    *off_gz = u64_to_offset(splitmix64(base ^ MAGIC_GYRO_Z),  GYRO_OFFSET_RANGE);
    *off_mx = u64_to_offset(splitmix64(base ^ MAGIC_MAG_X),   MAG_OFFSET_RANGE);
    *off_my = u64_to_offset(splitmix64(base ^ MAGIC_MAG_Y),   MAG_OFFSET_RANGE);
    *off_mz = u64_to_offset(splitmix64(base ^ MAGIC_MAG_Z),   MAG_OFFSET_RANGE);
}

/* Magnetometer slow micro-drift — a bounded random walk so the spoofed
 * hard-iron bias wanders slowly (thermal-like) instead of sitting as a frozen
 * constant. Tiny per-event steps → the tester's short-window Δ stays ~0 (looks
 * stable) while it drifts a few µT over a long session (realistic). */
static float mag_drift_x = 0.0f, mag_drift_y = 0.0f, mag_drift_z = 0.0f;

static void mag_drift_update(void)
{
    mag_drift_x += rng_float(MAG_DRIFT_STEP);
    mag_drift_y += rng_float(MAG_DRIFT_STEP);
    mag_drift_z += rng_float(MAG_DRIFT_STEP);
    if (mag_drift_x >  MAG_DRIFT_MAX) mag_drift_x =  MAG_DRIFT_MAX;
    if (mag_drift_x < -MAG_DRIFT_MAX) mag_drift_x = -MAG_DRIFT_MAX;
    if (mag_drift_y >  MAG_DRIFT_MAX) mag_drift_y =  MAG_DRIFT_MAX;
    if (mag_drift_y < -MAG_DRIFT_MAX) mag_drift_y = -MAG_DRIFT_MAX;
    if (mag_drift_z >  MAG_DRIFT_MAX) mag_drift_z =  MAG_DRIFT_MAX;
    if (mag_drift_z < -MAG_DRIFT_MAX) mag_drift_z = -MAG_DRIFT_MAX;
}

static inline bool is_finite_f(float f)
{
    /* IEEE 754: NaN and ±Inf both have exponent == 0xFF. Mantissa is
     * irrelevant for the check. Reinterpret as u32 to avoid FPU
     * comparison (would need to be inside kernel_neon_begin). */
    union { float f; unsigned int u; } v;
    v.f = f;
    return ((v.u >> 23) & 0xFF) != 0xFF;
}

static inline bool is_target_type(int type)
{
    return type == SENS_TYPE_ACCELEROMETER ||
           type == SENS_TYPE_GYROSCOPE ||
           type == SENS_TYPE_GYROSCOPE_UNCALIBRATED ||
           type == SENS_TYPE_ACCELEROMETER_UNCALIBRATED ||
           type == SENS_TYPE_MAGNETIC_FIELD_UNCALIBRATED;
    /* EXPERIMENT (KPM3, 2026-07-20): TYPE_GRAVITY REMOVED from targeting — gravity
       now passes through UNMODIFIED (was added 2026-07-19). Testing whether the
       gravity spoof path is what trips SS03 / detection. */
    /* NOTE: calibrated TYPE_MAGNETIC_FIELD (2) is deliberately NOT targeted —
     * it carries no stable per-unit signal (bias already subtracted by the
     * framework) and offsetting it would break the invariant calibrated =
     * uncal_field - bias that real hardware always holds. Only the
     * uncalibrated stream (14) is spoofed; its bias IS the fingerprint.
     *
     * TYPE_GRAVITY (9) IS targeted: it is the fused DC gravity vector = the
     * low-passed accelerometer, so it must carry the SAME static per-UID bias
     * as accel. If accel is offset but gravity is not, |gravity| != |accel|@rest
     * and a consumer computing linear = accel - gravity sees a phantom constant
     * (a stationary phone "accelerating" — impossible physics). Snap's q5d reads
     * accel(1)+gyro(4)+gravity(9) together, so this pairing is directly checkable.
     *
     * DELIBERATELY NOT targeted (motion/orientation channels — the bias must be
     * ABSENT here, exactly as on real biased hardware):
     *   - TYPE_LINEAR_ACCELERATION (10): = accel - gravity, physically zero-mean.
     *     Adding the DC bias here would mean sustained net acceleration at rest =
     *     an instant impossible-physics flag. It stays real (motion-only).
     *   - TYPE_ROTATION_VECTOR (11) / GAME_ROTATION_VECTOR (15) / ORIENTATION (3):
     *     orientation quaternions. A biased accel tilts these by ~bias/g (~0.6°),
     *     which real biased hardware also exhibits, so leaving them real is
     *     physically plausible. Applying the tilt correctly needs quaternion math
     *     validated against real captures (GyroCap) — measured follow-up, NOT a
     *     blind kernel-side quaternion rotation (a wrong quaternion is a worse
     *     tell than the tiny residual). */
}

/* ── "Held" motion model ─────────────────────────────────────────────
 *
 * The per-UID bias + jitter + bump layer above uses ADD semantics, which
 * preserves the REAL gravity orientation: a phone lying flat on a desk
 * keeps gravity on +Z and reads "flat & stationary" no matter how much
 * jitter we add. That is a bot tell (every account created on a perfectly
 * flat device). This layer, gated by sensor_held_enabled, re-projects the
 * gravity vector onto a slowly drifting hand-held tilt and drives the gyro
 * with the angular velocity of that drift, so the flat device reads as if
 * held in a hand — and accel-derived orientation change stays consistent
 * with the gyro integral (kinematic cross-check that fraud SDKs run).
 *
 * No libm in the kernel hot path: sin/cos via Horner-form Taylor (accurate
 * to <2e-3 for |x| ≤ 1.2 rad, which covers our bounded tilt), sqrt via a
 * bit-trick seed + 2 Newton steps. FPU is already used throughout this
 * hook, so float math here is consistent with the existing code. */

static inline float approx_sin(float x)
{
    float x2 = x * x;
    return x * (1.0f - x2 * (1.0f/6.0f - x2 * (1.0f/120.0f - x2 * (1.0f/5040.0f))));
}

static inline float approx_cos(float x)
{
    float x2 = x * x;
    return 1.0f - x2 * (0.5f - x2 * (1.0f/24.0f - x2 * (1.0f/720.0f)));
}

static inline float approx_sqrt(float x)
{
    if (x <= 0.0f) return 0.0f;
    union { float f; unsigned int i; } u;
    u.f = x;
    u.i = (u.i >> 1) + 0x1FC00000u;   /* rough seed */
    float y = u.f;
    y = 0.5f * (y + x / y);           /* Newton ×2 */
    y = 0.5f * (y + x / y);
    return y;
}

/* Tilt drift model: an over-damped random walk with a restoring pull to a
 * comfortable "holding" centre, so pitch/roll wander realistically without
 * running away. Velocities double as the gyro drift output (rad/s). */
/* Tilt center matches the real gravity split (accel |mean| Z>Y → pitch <45°).
 * Bigger velocity noise + wider range → the gravity vector swings enough to
 * reproduce the real accel Y/Z std ≈ 2.2 (was ~1.1, half of real). */
/* ── Coherent motion: 3 damped harmonic oscillators + 1 linear bob ────
 * Real hand motion (GyroCap 40s): gyro lag-1 autocorr 0.999 (SMOOTH), std
 * X0.747 Y0.498 Z0.197, angle excursion only ~0.28 rad → a lightly-damped
 * ~0.4Hz oscillation, NOT white noise. Each oscillator is a damped-harmonic SDE:
 *     v += (-w0²(θ-c) - 2ζw0·v)·dt + σ·√dt·N;   θ += v·dt
 *   σ_v = σ/(2√(ζw0)) = target gyro std;  σ_θ = σ_v/w0;  autocorr ≈ exp(-ζw0·dt).
 * Gyro output = the oscillator angular velocities. Accel output = gravity
 * projected on the INTEGRATED angles → accel IS the integral of gyro, so the two
 * are kinematically consistent (no teleport, correct accel↔gyro correlation and
 * low-freq spectrum). pitch→gyroX+accelY/Z, roll→gyroY+accelX, yaw→gyroZ. A
 * separate smooth vertical "bob" adds accel-Z variance (hand translation, which
 * a real hand does WITHOUT rotation, so it touches accel only — coherent). */
#define OSC_ZETA         0.08f    /* damping ratio: light → autocorr~0.999, jaggedness~0.04 */
#define OSC_PITCH_W0     2.65f    /* rad/s: σ_v0.747/σ_θ0.282 → gyroX + accelY/Z */
#define OSC_PITCH_DRIVE  0.79f    /* σ = σ_v·2√(ζw0); tuned → gyroX std 0.747 & accelY std 2.15 */
#define OSC_PITCH_CENTER 0.68f    /* rad ~39° — real gravity split (Z>Y) */
#define OSC_ROLL_W0      3.83f    /* σ_v0.498/σ_θ0.130 → gyroY + accelX */
#define OSC_ROLL_DRIVE   0.55f
#define OSC_YAW_W0       1.97f    /* σ_v0.197/σ_θ0.100 → gyroZ (no gravity) */
#define OSC_YAW_DRIVE    0.156f
#define OSC_BOB_W0       2.50f    /* smooth vertical accel (translation) → accel Z std */
#define OSC_BOB_DRIVE    1.43f    /* accel-std target ~1.6 (fills Z to real 2.37) */
#define OSC_BUMP_GAIN    4.5f     /* drive ×(1+gain) during a bump → smooth fat tail (gyro |max|~4.7) */

static float osc_pitch = OSC_PITCH_CENTER, osc_roll = 0.0f, osc_yaw = 0.0f, osc_bob = 0.0f;
static float osc_pitch_v = 0.0f, osc_roll_v = 0.0f, osc_yaw_v = 0.0f, osc_bob_v = 0.0f;
static __s64 held_last_ts = 0;

/* One damped-harmonic SDE step (semi-implicit Euler with real dt). */
static void osc_step(float *ang, float *vel, float center, float w0,
                     float drive, float dt, float sqrt_dt, float gain)
{
    float force = -(w0 * w0) * (*ang - center) - 2.0f * OSC_ZETA * w0 * (*vel);
    /* rng_float(1.732) ≈ unit-std uniform; √dt scaling makes it rate-independent. */
    float noise = drive * gain * sqrt_dt * rng_float(1.732f);
    *vel += force * dt + noise;
    *ang += (*vel) * dt;
}

/* Advance all oscillators once per sensor event using the real inter-event dt. */
static void held_update(__s64 ts)
{
    float dt = 0.0023f;   /* ~443 Hz fallback (Pixel 6a IMU rate) */
    if (held_last_ts != 0 && ts > held_last_ts) {
        dt = (float)(ts - held_last_ts) * 1e-9f;
        if (dt < 0.0005f) dt = 0.0005f;
        if (dt > 0.05f)   dt = 0.05f;
    }
    held_last_ts = ts;
    float sqrt_dt = approx_sqrt(dt);

    /* Bump window smoothly boosts the drive (fat tail); env ramps 0→1→0. */
    float env = bump_envelope();
    if (bump_remaining > 0) bump_remaining--;
    float gain = 1.0f + OSC_BUMP_GAIN * env;

    osc_step(&osc_pitch, &osc_pitch_v, OSC_PITCH_CENTER, OSC_PITCH_W0, OSC_PITCH_DRIVE, dt, sqrt_dt, gain);
    osc_step(&osc_roll,  &osc_roll_v,  0.0f,             OSC_ROLL_W0,  OSC_ROLL_DRIVE,  dt, sqrt_dt, gain);
    osc_step(&osc_yaw,   &osc_yaw_v,   0.0f,             OSC_YAW_W0,   OSC_YAW_DRIVE,   dt, sqrt_dt, gain);
    osc_step(&osc_bob,   &osc_bob_v,   0.0f,             OSC_BOB_W0,   OSC_BOB_DRIVE,   dt, sqrt_dt, gain);

    /* Soft bounds (velocity reflection). Spring normally keeps well inside. */
    if (osc_pitch >  1.40f) { osc_pitch =  1.40f; osc_pitch_v = -osc_pitch_v * 0.5f; }
    if (osc_pitch <  0.10f) { osc_pitch =  0.10f; osc_pitch_v = -osc_pitch_v * 0.5f; }
    if (osc_roll  >  0.50f) { osc_roll  =  0.50f; osc_roll_v  = -osc_roll_v  * 0.5f; }
    if (osc_roll  < -0.50f) { osc_roll  = -0.50f; osc_roll_v  = -osc_roll_v  * 0.5f; }
    if (osc_yaw   >  0.60f) { osc_yaw   =  0.60f; osc_yaw_v   = -osc_yaw_v   * 0.5f; }
    if (osc_yaw   < -0.60f) { osc_yaw   = -0.60f; osc_yaw_v   = -osc_yaw_v   * 0.5f; }
}

/* ── InputMessage eventTime layout discovery (Pixel 6a / Android 16) ──────────
 * Uncomment LP_EVENTTIME_DIAG to build a READ-ONLY probe: for the LukeTester UID
 * it logs every timestamp-magnitude int64 in the input-channel recvfrom buffer to
 * dmesg. Correlate those with LukeTester's logged getEventTime() (logcat
 * LukeTimeline) to pin the exact eventTime/downTime byte offsets — no struct
 * guessing, no Frida on Snap. Leave COMMENTED for any production/normal build. */
// #define LP_EVENTTIME_DIAG 1
#define LP_EVENTTIME_DIAG_UID 10308   /* com.lp4.test (LukeTester) */

/* Byte offsets of the int64 eventTime/downTime inside the input-channel recvfrom
 * buffer (an InputMessage MOTION), per device/Android version. Measured live on
 * Pixel 6a / A16 (2026-07-10): eventTime@16, downTime@96, buffer size ~312. */
struct input_ts_layout { int off_eventtime; int off_downtime; int off_action; };
/* Pixel 6a / A16 measured 2026-07-10: eventTime@16, downTime@96, action@68 (UP=1). */
static const struct input_ts_layout LAYOUT_A16_6A = { 16, 96, 68 };
/* Pixel 6 / Android 15 — DEAD stub (offsets differ; measure when that device
 * is back). off_eventtime < 0 makes the mutation a no-op on this layout. */
static const struct input_ts_layout LAYOUT_A15_6 __attribute__((unused)) = { -1, -1, -1 };
#define LP_ACTION_UP 1   /* MotionEvent.ACTION_UP */

/* Verify hook: increments each time an eventTime/downTime pair is offset. */
unsigned int g_eventtime_offset_applied = 0;

/* Choke-point handler — called from net/socket.c AFTER a successful
 * __sys_recvfrom (is_msg=false) or ___sys_recvmsg (is_msg=true), with the
 * copy already delivered to userspace:
 *     __sys_recvfrom():  lp_recv_hook(fd, ubuf, size, ret, false);
 *     ___sys_recvmsg():  lp_recv_hook(fd, user_msg, 0, ret, true);   // diag only
 * For recvfrom, `ubuf` is the user data buffer; for recvmsg, `ubuf` is the
 * user `struct msghdr *` (consumed only by the diag path). The sensor +
 * eventTime logic operates on the direct recvfrom buffer. */
void lp_recv_hook(int fd, void __user *ubuf, size_t len, long ret, bool is_msg)
{
    (void)fd; (void)len;

    /* CHEAPEST checks FIRST. Fires on EVERY recvfrom in EVERY process
     * system-wide (RIL packet routers, network daemons, IPC sockets — the
     * vast majority NOT sensor BitTube), so bail fast on non-matches. */
    if (unlikely(!g_hooks_enabled)) return;

#ifdef LP_EVENTTIME_DIAG
    if (is_msg) { lp_recvmsg_diag(ubuf, ret); return; }
#endif
    /* recvmsg carries no sensor/eventTime payload (sensor stream = recvfrom). */
    if (is_msg) return;
    if (unlikely(!ubuf)) return;

#ifdef LP_EVENTTIME_DIAG
    /* Read-only InputMessage layout probe. Input-channel recvfroms are NOT sensor
     * sized (never 104-multiples), so this never collides with the sensor path
     * below. Scans int64 fields; logs only those in a plausible ns-since-boot
     * magnitude (~1 s … ~11.5 days) so eventTime/downTime stand out. */
    {
        long iret = ret;
        if (iret >= 24 && iret <= 1664) {
            __u32 diag_uid = lp_current_uid();
            if (diag_uid == LP_EVENTTIME_DIAG_UID) {
                void __user *ib = ubuf;
                if (ib) {
                    static char dbuf[256];
                    long dn = iret < 256 ? iret : 256;
                    if (lp_copy_from_user(dbuf, ib, dn) > 0) {
                        __u32 mtype = *(__u32 *)dbuf;   /* InputMessage::header.type */
                        pr_info("lukeprivacy: [ETDIAG] size=%ld type=%u\n", iret, mtype);
                        for (long o = 0; o + 8 <= dn; o += 4) {
                            __s64 v;
                            __builtin_memcpy(&v, dbuf + o, 8);   /* alignment-safe */
                            if (v > 1000000000LL && v < 1000000000000000LL)
                                pr_info("lukeprivacy: [ETDIAG]   off=%ld i64=%lld\n", o, v);
                        }
                        /* int32 window around the expected action field (after the
                         * 32-byte hmac). DOWN=0 vs UP=1 reveals the action offset. */
                        if (dn >= 80) {
                            __s32 a[6];
                            for (int k = 0; k < 6; k++)
                                __builtin_memcpy(&a[k], dbuf + 56 + k * 4, 4);
                            pr_info("lukeprivacy: [ETDIAG]   i32@56-76: %d %d %d %d %d %d\n",
                                    a[0], a[1], a[2], a[3], a[4], a[5]);
                        }
                    }
                }
            }
        }
    }
#endif

    /* ── eventTime timeline offset (input MotionEvent via recvfrom) ──────────────
     * Shift the leaked getEventTime() off the shared per-boot uptime timeline by a
     * per-account offset, applied to BOTH eventTime (off 16) and downTime (off 96)
     * so dwell (= et - dt) is preserved. Structurally anchored: both must be
     * coherent MONOTONIC ns with downTime <= eventTime and a gesture-length span —
     * which no sensor (BOOTTIME ts at off 16, garbage at off 96) or vsync (rising
     * ts) buffer satisfies. The sensor path below re-rejects this buffer on its
     * version anchor (off0 = type 1, not 104). Independent of the sensor toggles. */
    if (unlikely(g_profile.eventtime_offset_enabled) &&
        g_profile.eventtime_offset_ns != 0 && g_profile.eventtime_target_uid != 0) {
        const struct input_ts_layout *L = &LAYOUT_A16_6A;   /* TODO: pick by Android ver for A15/6 */
        long iret = ret;
        if (L->off_eventtime >= 0 && iret >= L->off_downtime + 8 && iret <= 4096) {
            __u32 uid = lp_current_uid();
            /* TARGET UID ONLY (captured fresh per newIdentity; 0 = off). NOT a
             * broad "all apps but excluded" gate — that mutated the launcher's
             * scroll events and ANR'd the system. */
            if (uid == g_profile.eventtime_target_uid) {
                void __user *ib = ubuf;
                if (ib) {
                    /* ACTION_UP ONLY: the event Snap serialises (AY.b). Leaving
                     * DOWN/MOVE real keeps the framework's within-gesture
                     * resampling/velocity consistent — no scroll/fling breakage. */
                    __s32 action = -1;
                    lp_copy_from_user(&action, (void __user *)((char *)ib + L->off_action), 4);
                    if (action == LP_ACTION_UP) {
                        void __user *et_p = (void __user *)((char *)ib + L->off_eventtime);
                        void __user *dt_p = (void __user *)((char *)ib + L->off_downtime);
                        __s64 et = 0, dt = 0;
                        if (lp_copy_from_user(&et, et_p, 8) > 0 &&
                            lp_copy_from_user(&dt, dt_p, 8) > 0) {
                            if (et >= 1000000000LL && dt >= 1000000000LL &&
                                et >= dt && (et - dt) < 60000000000LL) {
                                __s64 off = g_profile.eventtime_offset_ns;
                                et += off; dt += off;
                                lp_copy_to_user(et_p, &et, 8);
                                lp_copy_to_user(dt_p, &dt, 8);
                                g_eventtime_offset_applied++;
                            }
                        }
                    }
                }
            }
        }
    }

    /* Toggle pre-gate — single bool. */
    if (likely(!g_profile.sensor_accel_spoof_enabled &&
               !g_profile.sensor_gyro_spoof_enabled &&
               !g_profile.sensor_mag_spoof_enabled)) return;

    /* recvfrom return: bytes read (the `ret` param). ~90% of recvfroms
     * return sizes that don't match sensors_event_t multiples and bail
     * out below. */
    if (ret < SENS_EVT_MIN_SIZE) return;
    if (ret > 65536) return;  /* sanity bound: sensorservice batches max
                                * ~256 events × 104 B = 26.6 KB; 64 KB
                                * is well above any legit batch. */

    /* UID gate — after cheap rejects. UID < 10000 = system; excluded =
     * Google/system pkgs. */
    __u32 uid = lp_current_uid();
    if (uid < 10000) return;
    /* U18 (2026-09-24 genuine-device audit S1): identity-excluded uids
     * (GMS/DroidGuard) normally bypass ALL spoofing — correct for identity, but a
     * real phone's GMS reads the SAME handheld motion every other process sees.
     * Excluding it here is exactly why DroidGuard sampled a dead-flat/frozen device.
     * Let sensor-INCLUDED uids (the GMS uid, pushed via set_sensor_include) through
     * for MOTION ONLY; binder_hook/ioctl_hook identity spoofing keeps excluding them. */
    if (lp_is_uid_excluded(uid) && !lp_uid_sensor_included(uid)) return;

    /* Try the most common size first to short-circuit on the typical case. */
    size_t evt_size = SENS_EVT_TYPICAL;
    if ((size_t)ret % evt_size != 0) {
        /* Buffer size isn't a clean multiple of 104. Try other sizes in
         * the accepted range, picking the largest that divides cleanly. */
        bool found = false;
        for (size_t cand = SENS_EVT_MAX_SIZE; cand >= SENS_EVT_MIN_SIZE; cand -= 4) {
            if ((size_t)ret % cand == 0) { evt_size = cand; found = true; break; }
        }
        if (!found) return;  /* Not a sensors_event_t stream — skip. */
    }
    size_t count = (size_t)ret / evt_size;
    if (count == 0 || count > 256) return;  /* Sanity bound on batched events. */

    /* Copy entire buffer into kernel scratch. Bounded above by 65 536. */
    static char scratch[65536];
    if (lp_copy_from_user(scratch, ubuf, (long)ret) <= 0) return;

    /* Cross-check: first event's version field must match evt_size. The
     * version field is the FIRST self-describing structural anchor and
     * confirms we guessed the per-version layout correctly. */
    __s32 first_version = *(__s32 *)scratch;
    if (first_version != (__s32)evt_size) return;

    /* FP/NEON is used from here on (bias math, oscillators, sin/cos/sqrt).
     * On arm64 the kernel is built -mgeneral-regs-only and FP/SIMD registers
     * belong to userspace unless claimed via kernel_neon_begin(). We are in
     * process (syscall) context after a successful copy, so SIMD is available;
     * bail defensively if not. copy_to_user() below stays OUTSIDE the NEON
     * region (it may fault/sleep; NEON section is preempt-disabled). */
    if (unlikely(!may_use_simd())) return;

    /* Derive per-UID offset table once for this batch. */
    float off_ax, off_ay, off_az, off_gx, off_gy, off_gz, off_mx, off_my, off_mz;
    bool modified = false;

    kernel_neon_begin();
    if (lp_is_uid_excluded(uid)) {
        /* U18: sensor-included-but-identity-excluded (GMS/DroidGuard) — MOTION
         * ONLY, zero static bias. derive_offsets seeds from the per-CONTAINER
         * android_id, so a per-uid bias here would make GMS's chip bias change per
         * IG account — but a real IMU's bias is device-stable. Zero bias → clean
         * gravity magnitude + the global time-based held motion + noise floor:
         * coherent with IG's pose and stable across containers. */
        off_ax = off_ay = off_az = 0.0f;
        off_gx = off_gy = off_gz = 0.0f;
        off_mx = off_my = off_mz = 0.0f;
    } else {
        derive_offsets(uid, &off_ax, &off_ay, &off_az,
                       &off_gx, &off_gy, &off_gz,
                       &off_mx, &off_my, &off_mz);
    }

    for (size_t i = 0; i < count; i++) {
        char *e = scratch + i * evt_size;

        /* Re-verify per-event anchor — same evt_size in entire batch is
         * the AOSP contract but defense in depth catches HAL bugs. */
        __s32 ver  = *(__s32 *)(e + 0);
        if (ver != first_version) continue;

        __s32 hndl = *(__s32 *)(e + 4);
        if (hndl <= 0) continue;

        __s32 type = *(__s32 *)(e + 8);
        if (!is_target_type(type)) continue;

        __s64 ts = *(__s64 *)(e + 16);
        if (ts < 1) continue;
        if (ts > (1LL << 58)) continue;  /* ~9 years of ns since boot */

        /* Sensor data union starts at offset 24. data[0..2] = x, y, z
         * for accel/gyro (calibrated AND uncalibrated forms — the union
         * layout puts the 3-axis vector first in all variants). */
        float *data = (float *)(e + 24);
        if (!is_finite_f(data[0]) ||
            !is_finite_f(data[1]) ||
            !is_finite_f(data[2])) continue;

        bool is_accel = (type == SENS_TYPE_ACCELEROMETER ||
                         type == SENS_TYPE_ACCELEROMETER_UNCALIBRATED);
        bool is_gyro  = (type == SENS_TYPE_GYROSCOPE ||
                         type == SENS_TYPE_GYROSCOPE_UNCALIBRATED);
        bool is_mag   = (type == SENS_TYPE_MAGNETIC_FIELD_UNCALIBRATED);
        bool is_gravity = (type == SENS_TYPE_GRAVITY);

        g_sensor_events_seen++;

        /* Advance the coherent motion oscillators once per event (bump window +
         * smooth pitch/roll/yaw/bob). Cheap; accel and gyro both read the state. */
        maybe_start_bump();
        held_update(ts);

        /* Clamp helper: keep spoofed value within physical sensor range. */
        #define CLAMP(v, lo, hi) ((v) < (lo) ? (lo) : ((v) > (hi) ? (hi) : (v)))
        #define ACCEL_MAX 20.0f   /* m/s² — 2g, max for phone in hand */
        #define GYRO_MAX  10.0f   /* rad/s — max realistic rotation */

        if (is_accel && g_profile.sensor_accel_spoof_enabled) {
            /* Tiny white noise floor → real-MEMS jaggedness (~0.03-0.05), not a
             * suspiciously perfect analytic curve. */
            float nfx = rng_float(NOISE_FLOOR_ACCEL);
            float nfy = rng_float(NOISE_FLOOR_ACCEL);
            float nfz = rng_float(NOISE_FLOOR_ACCEL);
            if (g_profile.sensor_held_enabled) {
                /* Gravity projected on the INTEGRATED oscillator tilt (osc_pitch/
                 * osc_roll) → accel IS the integral of the gyro output, so the two
                 * are kinematically consistent (no teleport, correct cross-corr).
                 * Real magnitude preserved. osc_bob_v = smooth vertical translation
                 * (accel-only, no rotation — a hand bobs without rotating). */
                float g_mag = approx_sqrt(data[0]*data[0] + data[1]*data[1] + data[2]*data[2]);
                if (g_mag < 7.0f || g_mag > 12.0f) g_mag = 9.81f;
                float sp = approx_sin(osc_pitch), cp = approx_cos(osc_pitch);
                float sr = approx_sin(osc_roll),  cr = approx_cos(osc_roll);
                float gx = g_mag * sr;              /* roll  → accel X */
                float gy = g_mag * sp * cr;         /* pitch → accel Y */
                float gz = g_mag * cp * cr;         /* pitch → accel Z */
                data[0] = CLAMP(gx + off_ax + nfx, -ACCEL_MAX, ACCEL_MAX);
                data[1] = CLAMP(gy + off_ay + nfy, -ACCEL_MAX, ACCEL_MAX);
                data[2] = CLAMP(gz + off_az + osc_bob_v + nfz, -ACCEL_MAX, ACCEL_MAX);
            } else {
                data[0] = CLAMP(data[0] + off_ax + nfx, -ACCEL_MAX, ACCEL_MAX);
                data[1] = CLAMP(data[1] + off_ay + nfy, -ACCEL_MAX, ACCEL_MAX);
                data[2] = CLAMP(data[2] + off_az + nfz, -ACCEL_MAX, ACCEL_MAX);
            }
            g_sensor_accel_spoofed++;
            modified = true;
        } else if (is_gyro && g_profile.sensor_gyro_spoof_enabled) {
            /* Gyro = the SMOOTH oscillator angular velocities (autocorr ~0.999,
             * like a real hand) + per-UID static bias + tiny noise floor. The old
             * per-event white tremor is GONE — white angular velocity means
             * infinite angular acceleration (physically impossible, autocorr ~0). */
            float nfx = rng_float(NOISE_FLOOR_GYRO);
            float nfy = rng_float(NOISE_FLOOR_GYRO);
            float nfz = rng_float(NOISE_FLOOR_GYRO);
            float b0 = data[0], b1 = data[1], b2 = data[2];
            if (g_profile.sensor_held_enabled) { b0 = osc_pitch_v; b1 = osc_roll_v; b2 = osc_yaw_v; }
            float ny0 = b0 + off_gx + nfx;
            float ny1 = b1 + off_gy + nfy;
            float ny2 = b2 + off_gz + nfz;
            /* Guard: CLAMP does NOT catch NaN (all comparisons false). */
            if (is_finite_f(ny0)) data[0] = CLAMP(ny0, -GYRO_MAX, GYRO_MAX);
            if (is_finite_f(ny1)) data[1] = CLAMP(ny1, -GYRO_MAX, GYRO_MAX);
            if (is_finite_f(ny2)) data[2] = CLAMP(ny2, -GYRO_MAX, GYRO_MAX);
            g_sensor_gyro_spoofed++;
            modified = true;
        } else if (is_mag && g_profile.sensor_mag_spoof_enabled) {
            /* UNCALIBRATED magnetometer (type 14) ONLY. Its bias estimate
             * (data[3..5]) is the cleanest per-UNIT fingerprint (device-stable
             * hard-iron offset). Shift the uncal field (data[0..2]) AND bias by
             * the SAME per-UID amount + slow drift → the bias rotates while
             * calibrated = uncal_field - bias stays EXACTLY consistent (an
             * invariant real hardware always holds; calibrated type 2 is left
             * real). No jitter/bump — real bias is stable, so only the static
             * offset + slow drift apply. */
            #define MAG_MAX 4900.0f  /* µT — above Earth (~50) + strong-magnet slack */
            mag_drift_update();
            float mx = off_mx + mag_drift_x;
            float my = off_my + mag_drift_y;
            float mz = off_mz + mag_drift_z;
            data[0] = CLAMP(data[0] + mx, -MAG_MAX, MAG_MAX);
            data[1] = CLAMP(data[1] + my, -MAG_MAX, MAG_MAX);
            data[2] = CLAMP(data[2] + mz, -MAG_MAX, MAG_MAX);
            if (is_finite_f(data[3]) && is_finite_f(data[4]) && is_finite_f(data[5])) {
                data[3] = CLAMP(data[3] + mx, -MAG_MAX, MAG_MAX);
                data[4] = CLAMP(data[4] + my, -MAG_MAX, MAG_MAX);
                data[5] = CLAMP(data[5] + mz, -MAG_MAX, MAG_MAX);
            }
            g_sensor_mag_spoofed++;
            modified = true;
        } else if (is_gravity && g_profile.sensor_accel_spoof_enabled) {
            /* TYPE_GRAVITY (9): the fused DC gravity vector. Carry the SAME
             * static per-UID bias (off_a*) as accel so |gravity| == |accel|@rest
             * and linear = accel - gravity shows NO phantom constant. In held
             * mode use the SAME oscillator tilt (osc_pitch/osc_roll) as the accel
             * branch so gravity stays parallel to the spoofed accel. Crucially:
             * NO noise floor and NO osc_bob_v here — those are the AC/motion part
             * (they belong to accel and to linear); gravity is pure DC. */
            if (g_profile.sensor_held_enabled) {
                float g_mag = approx_sqrt(data[0]*data[0] + data[1]*data[1] + data[2]*data[2]);
                if (g_mag < 7.0f || g_mag > 12.0f) g_mag = 9.81f;
                float sp = approx_sin(osc_pitch), cp = approx_cos(osc_pitch);
                float sr = approx_sin(osc_roll),  cr = approx_cos(osc_roll);
                data[0] = CLAMP(g_mag * sr      + off_ax, -ACCEL_MAX, ACCEL_MAX);
                data[1] = CLAMP(g_mag * sp * cr + off_ay, -ACCEL_MAX, ACCEL_MAX);
                data[2] = CLAMP(g_mag * cp * cr + off_az, -ACCEL_MAX, ACCEL_MAX);
            } else {
                data[0] = CLAMP(data[0] + off_ax, -ACCEL_MAX, ACCEL_MAX);
                data[1] = CLAMP(data[1] + off_ay, -ACCEL_MAX, ACCEL_MAX);
                data[2] = CLAMP(data[2] + off_az, -ACCEL_MAX, ACCEL_MAX);
            }
            g_sensor_gravity_spoofed++;
            modified = true;
        }
    }
    kernel_neon_end();

    if (modified) {
        lp_copy_to_user(ubuf, scratch, (long)ret);
    }
}

#ifdef LP_EVENTTIME_DIAG
/* Diagnostic: input on A16 is NOT recvfrom. Probe recvmsg too — parse msghdr,
 * read the first iovec, scan int64s. msghdr (arm64 LP64): msg_iov@16, msg_iovlen@24. */
static void lp_recvmsg_diag(void __user *umsg, long ret)
{
    if (ret < 24 || ret > 4096) return;
    if (lp_current_uid() != LP_EVENTTIME_DIAG_UID) return;
    if (!umsg) return;
    char mh[56];
    if (lp_copy_from_user(mh, umsg, sizeof(mh)) <= 0) return;
    void __user *iov;    __builtin_memcpy(&iov,    mh + 16, 8);
    unsigned long iovlen; __builtin_memcpy(&iovlen, mh + 24, 8);
    if (!iov || iovlen == 0 || iovlen > 8) return;
    char iv[16];
    if (lp_copy_from_user(iv, iov, sizeof(iv)) <= 0) return;
    void __user *base;  __builtin_memcpy(&base, iv + 0, 8);
    unsigned long len;  __builtin_memcpy(&len,  iv + 8, 8);
    if (!base) return;
    long n = (long)len; if (n > ret) n = ret; if (n > 256) n = 256; if (n < 8) return;
    static char dbuf[256];
    if (lp_copy_from_user(dbuf, base, n) <= 0) return;
    __u32 mtype; __builtin_memcpy(&mtype, dbuf, 4);
    pr_info("lukeprivacy: [ETMSG] ret=%ld iovlen=%lu type=%u\n", ret, iovlen, mtype);
    for (long o = 0; o + 8 <= n; o += 4) {
        __s64 v; __builtin_memcpy(&v, dbuf + o, 8);
        if (v > 1000000000LL && v < 1000000000000000LL)
            pr_info("lukeprivacy: [ETMSG]   off=%ld i64=%lld\n", o, v);
    }
}
#endif

/* ── Boot-clock offset: sysinfo(2) ──────────────────────────────────────────
 * struct sysinfo.uptime (long @ off 0) = seconds since boot. Native Ferrite
 * (libferrite-tracer) imports sysinfo → this is its uptime source. Offset it by
 * the SAME X (as seconds) as the input eventTime, gated to the target UID, so the
 * native attestation sees "booted X earlier" consistently. sysinfo struct layout
 * (uptime@0) is stable across Android/kernel versions → no A15/A16 split needed. */
/* NOT WIRED — kept for reference only, faithful to the KPM (which also never
 * registered it). This kernel's do_sysinfo() already runs timens_add_boottime(),
 * so sysinfo().uptime is +X-adjusted by the time-namespace (prctl) hook below.
 * Adding a +X here would DOUBLE-count. Do NOT add a sysinfo call-site. */
__attribute__((unused))
static void lp_sysinfo_hook(void __user *info, long ret)
{
    if (unlikely(!g_hooks_enabled)) return;
    if (likely(!g_profile.eventtime_offset_enabled)) return;
    if (g_profile.eventtime_offset_ns == 0 || g_profile.eventtime_target_uid == 0) return;
    if (ret != 0) return;                             /* sysinfo failed */
    if (lp_current_uid() != g_profile.eventtime_target_uid) return;
    if (!info) return;
    __s64 uptime = 0;
    if (lp_copy_from_user(&uptime, info, 8) <= 0) return;   /* struct sysinfo.uptime @ off0 */
    if (uptime < 1 || uptime > (1LL << 40)) return;          /* sanity: plausible seconds-since-boot */
    __s64 x_sec = g_profile.eventtime_offset_ns / 1000000000LL;
    uptime += x_sec;                                          /* booted X earlier → larger uptime */
    lp_copy_to_user(info, &uptime, 8);
    g_eventtime_offset_applied++;
}

/* ── Boot-clock: TIME NAMESPACE offset (clock_gettime family + /proc starttime) ──
 * Puts the target process (Snap/tester) into a fresh time namespace with +X on
 * CLOCK_MONOTONIC and CLOCK_BOOTTIME, at the setresuid SYSCALL (Zygote specialize
 * sets the app UID; single-threaded, before managed init). NOTE: an earlier version
 * inline-hooked commit_creds → REBOOT (that fn is too hot/critical to hook_wrap);
 * setresuid via fp_hook_syscalln is the safe path at the same timing.
 * CONFIG_GENERIC_VDSO_TIME_NS=y →
 * vDSO applies it, so elapsedRealtime / nanoTime / getStartElapsedRealtime / native
 * libclient clock_gettime / /proc/self/stat starttime ALL read real+X (validated by
 * standalone prototype). Runtime only (kpatch, no kernel flash): struct offsets from
 * device BTF (6.1.145), kernel funcs via kallsyms, sequence from GKI android14-6.1
 * (copy_time_ns → set offsets → timens_commit(vvar) → swap time_ns).
 * ⚠️ Offsets are Pixel 6a / A16 (6.1.145). A15/Pixel6 will need re-measured offsets. */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
/* time_namespace layout — A16/6.1.145 (BTF). timespec64 = {s64 tv_sec; s64 tv_nsec}. */
#define OFF_TASK_CRED      2104
#define OFF_TASK_NSPROXY   2184
#define OFF_CRED_UID       4
#define OFF_NSPROXY_TIMENS 48
#define OFF_NSPROXY_TIMENS_FOR_CHILDREN 56
#define OFF_TN_MONO_SEC    40
#define OFF_TN_MONO_NSEC   48
#define OFF_TN_BOOT_SEC    56
#define OFF_TN_BOOT_NSEC   64

/* Kernel-faithful unshare(CLONE_NEWTIME)+fork path (mirrors ksys_unshare/timens_on_fork).
 * The OLD approach mutated current->nsproxy->time_ns IN PLACE — but an app forked from
 * Zygote SHARES Zygote's nsproxy (refcounted get_nsproxy on fork w/o CLONE flags), so that
 * corrupted Zygote + every sibling app's time_ns and ran timens_commit inconsistently →
 * non-deterministic hang. current_is_single_threaded does NOT catch nsproxy-sharing. */
typedef void *(*create_new_ns_fn_t)(unsigned long flags, void *tsk, void *user_ns, void *new_fs);
typedef void  (*switch_task_ns_fn_t)(void *p, void *newnsp);
typedef int   (*timens_on_fork_fn_t)(void *nsproxy, void *tsk);
typedef int   (*is_single_fn_t)(void);
static create_new_ns_fn_t  fn_create_new_ns;
static switch_task_ns_fn_t fn_switch_task_ns;
static timens_on_fork_fn_t fn_timens_on_fork;
static is_single_fn_t      fn_is_single;
static void *kv_init_user_ns;
static bool timens_hook_installed = false;

/* Choke-point handler — called from the prctl(2) path (kernel/sys.c). The
 * call-site adds:  lp_prctl_hook();  after the prctl work, in the caller's
 * (Zygote-specialize) task context. NOTE: this is a SEPARATE call-site from
 * recvfrom — it belongs to the boot-clock (time-namespace) mechanism, not the
 * sensor stream. Gated internally (target_uid != 0), so it is a no-op until the
 * companion arms an eventTime offset. */
/* __nocfi: lp_prctl_hook calls kernel functions resolved via kallsyms_lookup_name
 * (create_new_namespaces/switch_task_namespaces/timens_on_fork/current_is_single_threaded)
 * through typedef'd pointers whose signatures don't match the targets' kCFI type-hashes.
 * On CONFIG_CFI_CLANG=y (non-permissive) that faults ("CFI failure ... expected type ...",
 * measured panic at +0xf0 on the fn_is_single() call). The calls are ABI-compatible, so we
 * disable the caller-side kCFI check for this function only. */
void __nocfi lp_prctl_hook(void)
{
    if (likely(!g_profile.eventtime_offset_enabled)) return;
    if (g_profile.eventtime_offset_ns == 0 || g_profile.eventtime_target_uid == 0) return;
    if (!fn_create_new_ns || !fn_switch_task_ns || !fn_timens_on_fork || !kv_init_user_ns) return;
    /* UID gate in-context (same proven-safe pattern as recvfrom; NOT the cred path
     * that conflicts with KP su-compat). prctl during Zygote specialize runs AFTER
     * setresuid (uid already the app's) and BEFORE managed init / getStart capture.
     * copy_time_ns internally does ns_capable(CAP_SYS_TIME): succeeds only in the
     * specialize window before Zygote drops caps → otherwise a clean -EPERM no-op. */
    if (lp_current_uid() != g_profile.eventtime_target_uid) return;

    char *t = (char *)get_current();   /* task_struct* (sp_el0; THREAD_INFO_IN_TASK, thread_info@0) */
    if (!t) return;
    char *nsp = *(char **)(t + OFF_TASK_NSPROXY);
    if (!nsp) return;
    char *cur_tn = *(char **)(nsp + OFF_NSPROXY_TIMENS);

    __s64 x = g_profile.eventtime_offset_ns;
    __s64 x_sec  = x / 1000000000LL;
    __s64 x_nsec = x % 1000000000LL;
    /* self-marker: already in OUR offset namespace (prctl fires many times per process) */
    if (cur_tn && *(__s64 *)(cur_tn + OFF_TN_BOOT_SEC) == x_sec) return;
    /* switch_task_namespaces / timens_on_fork require single-threaded (like setns) */
    if (fn_is_single && !fn_is_single()) return;

    /* 1. UNSHARE: fresh nsproxy for THIS task with a new time_ns_for_children.
     *    Does NOT touch Zygote's shared nsproxy (that was the corruption/hang bug). */
    void *newnsp = fn_create_new_ns(CLONE_NEWTIME, t, kv_init_user_ns, NULL);
    if (!newnsp || (unsigned long)newnsp >= (unsigned long)-4095UL) return;   /* NULL / IS_ERR (-EPERM) */

    /* 2. write +X into the fresh child time_ns (offsets copied from init = 0) */
    char *tnfc = *(char **)((char *)newnsp + OFF_NSPROXY_TIMENS_FOR_CHILDREN);
    if (tnfc) {
        *(__s64 *)(tnfc + OFF_TN_MONO_SEC)  = x_sec;
        *(__s64 *)(tnfc + OFF_TN_MONO_NSEC) = x_nsec;
        *(__s64 *)(tnfc + OFF_TN_BOOT_SEC)  = x_sec;
        *(__s64 *)(tnfc + OFF_TN_BOOT_NSEC) = x_nsec;
    }

    /* 3. swap ONLY this task's nsproxy (task_lock inside; puts old shared ref) */
    fn_switch_task_ns(t, newnsp);
    /* 4. promote time_ns_for_children -> time_ns and timens_commit(vvar) — kernel fork path */
    fn_timens_on_fork(newnsp, t);
    g_eventtime_offset_applied++;
}

/* SETUP ONLY — no syscall registration. Interception now happens via compiled-in
 * call-sites (net/socket.c → lp_recv_hook; kernel/sys.c prctl → lp_prctl_hook).
 * All this does is resolve the time-namespace kernel functions used by
 * lp_prctl_hook:
 *   - init_user_ns: taken directly (declared, non-static).
 *   - create_new_namespaces: STATIC in kernel/nsproxy.c → kallsyms_lookup_name is
 *     the only in-tree access without patching that file. (FLAG)
 *   - switch_task_namespaces / timens_on_fork / current_is_single_threaded: non-static;
 *     resolved via kallsyms here for uniformity but COULD be direct calls (FLAG).
 * kallsyms_lookup_name is callable from built-in kernel code (CONFIG_KALLSYMS=y on GKI). */
int sensor_hook_init(void)
{
    kv_init_user_ns   = &init_user_ns;
    fn_create_new_ns  = (create_new_ns_fn_t) kallsyms_lookup_name("create_new_namespaces");
    fn_switch_task_ns = (switch_task_ns_fn_t)kallsyms_lookup_name("switch_task_namespaces");
    fn_timens_on_fork = (timens_on_fork_fn_t)kallsyms_lookup_name("timens_on_fork");
    fn_is_single      = (is_single_fn_t)     kallsyms_lookup_name("current_is_single_threaded");
    if (fn_create_new_ns && fn_switch_task_ns && fn_timens_on_fork) {
        timens_hook_installed = true;
        pr_info("lukeprivacy: bootclock timens funcs resolved\n");
    } else {
        pr_err("lukeprivacy: timens kfuncs missing (bootclock disabled)\n");
    }
    return 0;
}

void sensor_hook_exit(void)
{
    timens_hook_installed = false;
}
