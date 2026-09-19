/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy — human touch-gesture injection (birthday-picker swipes).
 *
 * WHY: SnapAuto's shell swipe (sendevent, ~20 ms/event) can only emit ~12
 * constant-velocity samples with one fixed pressure and no ABS_MT_ORIENTATION
 * drift — a robotic signature on the date wheel. A real finger on this "fts"
 * panel reports ~40 samples at a ~5.4 ms hardware interval (~185 Hz), following
 * an ease-in/out velocity curve, with pressure arcing up then releasing and
 * ABS_MT_ORIENTATION drifting by thousands across the gesture (captured with
 * TouchCap, 40 real swipes, 2026-07-14). Userspace can't reproduce the 5.4 ms
 * cadence — measured floor ~20 ms/event via fork+exec or IPC. Only the kernel
 * can pace at 5.4 ms (usleep_range), so we replay the gesture here.
 *
 * HOW: we call the input core's input_event() directly on the "fts" input_dev,
 * exactly as the driver / an evdev inject would — so at the evdev level (what
 * Android InputReader + Snapchat's MotionEvents see) it is indistinguishable
 * from a finger. We do NOT go through the GTI offload path; that only feeds the
 * heatmap channel, not the pointer/MotionEvent stream.
 *
 * PORT NOTE (built-in kernel, direct call-sites — no KernelPatch hook_wrap):
 *   - fts input_dev acquisition: SnapAuto's own sendevent taps go through
 *     evdev_write -> input_inject_event(). The built-in call-site adds, at the
 *     TOP of input_inject_event() in drivers/input/input.c:
 *         lp_touch_capture_hook(handle, type, code, value);
 *     The FIRST EV_ABS event on a device whose ->name begins "fts" gives us the
 *     pointer; we cache it and every later call early-returns (near-free). Real
 *     finger touches go driver -> input_event -> input_handle_event and NEVER
 *     pass through input_inject_event, so this is off the real-touch hot path.
 *   - injection itself calls input_event() directly (resolved by the linker,
 *     not kallsyms), pacing with usleep_range_state().
 *   - touch_inject_cmd() is invoked from the control node (proc/ctl0 dispatch),
 *     "swipe:sx,sy,ex,ey,flick,n".
 *
 * Pure integer math (no FP anywhere → compiles under arm64 -mgeneral-regs-only).
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/input.h>     /* struct input_handle/input_dev, EV_*, ABS_MT_*, BTN_TOUCH, SYN_REPORT, input_event() */
#include <linux/delay.h>     /* usleep_range_state() */
#include <linux/sched.h>     /* TASK_UNINTERRUPTIBLE */

static void   *g_fts_dev;          /* cached "fts" struct input_dev* */

/* ── captured human swipe profile (20-pt curves, TouchCap 2026-07-14) ──────────
 * CONTROLLED = decelerates to a near-stop (how we step the year wheel).
 * ease is per-mille (fraction of total distance covered vs normalised time). */
static const int EASE_CTRL[20]  = {0,0,20,60,100,160,230,290,360,430,510,590,670,740,810,870,910,950,980,1000};
/* FLICK re-captured on the real YEAR wheel (13 flicks, 2026-07-14): fast (~19
 * samples / ~104 ms), flat start then a steep tail — releases at ~6000 px/s, so the
 * NumberPicker's VelocityTracker registers a FLING and momentum carries it several
 * years. The old gentle curve released slow → no fling → only the drag distance
 * moved (~one year), which is what looked wrong on screen. */
static const int EASE_FLICK[20] = {0,0,0,0,3,11,26,50,84,130,190,264,352,446,542,640,732,824,915,1000};
static const int PRESS_CTRL[20] = {62,68,74,79,83,86,88,91,93,94,96,96,97,97,98,98,98,96,94,72};
static const int PRESS_FLICK[20]= {58,64,68,71,74,78,83,91,97,104,111,114,116,116,116,117,117,116,108,79};
static const int MAJ_CTRL[20]   = {148,155,162,167,171,175,178,180,182,185,186,187,188,188,188,188,188,187,185,163};
static const int MAJ_FLICK[20]  = {140,150,159,162,166,172,178,190,201,213,225,231,237,238,239,239,238,235,223,189};
static const int MIN_CTRL[20]   = {126,141,148,153,156,159,161,162,164,165,166,166,167,167,168,168,168,167,165,139};
static const int MIN_FLICK[20]  = {124,131,138,141,143,146,150,154,157,160,162,163,163,163,163,164,163,162,157,133};
/* NAV = navigation flick, averaged from 37 real up/down/back/forward swipes on the
 * fts panel (TouchCap Pixel 6a, 2026-07-15; Pixel 6 identical). Faster+firmer than the
 * birthday FLICK: pressure saturates (~125 vs 117), MAJOR higher (~300 vs 239). Used
 * for warm-up scroll/edge-back/forward — direction comes from sx,sy,ex,ey, so ONE
 * curve set serves all four gestures. mode=2. */
static const int EASE_NAV[20]  = {0,2,5,10,19,33,53,80,113,153,200,254,315,384,465,555,657,765,880,1000};
static const int PRESS_NAV[20] = {74,77,81,89,96,101,106,109,111,114,117,119,121,123,124,125,122,119,117,106};
static const int MAJ_NAV[20]   = {185,191,197,211,223,232,239,245,251,257,263,269,276,283,293,302,295,289,287,278};
static const int MIN_NAV[20]   = {130,133,136,141,146,151,155,158,161,163,165,167,167,168,168,168,163,158,153,140};

/* xorshift32 — no FPU, varies per call (seed folded from args each swipe). */
static unsigned int g_rng = 0x1a2b3c4d;
static inline unsigned int rnd(void) {
    unsigned int x = g_rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    g_rng = x; return x;
}
static inline int rnd_between(int lo, int hi) { return lo + (int)(rnd() % (unsigned)(hi - lo + 1)); }

/* linear-interpolate a 20-pt curve at progress p (per-mille, 0..1000). */
static int curve_at(const int *a, int p) {
    int f, lo, frac;
    if (p <= 0) return a[0];
    if (p >= 1000) return a[19];
    f = p * 19;                 /* 0..19000 */
    lo = f / 1000;              /* 0..18   */
    frac = f - lo * 1000;       /* 0..999  */
    return (a[lo] * (1000 - frac) + a[lo + 1] * frac) / 1000;
}

/* ── capture choke-point: grab the "fts" input_dev from SnapAuto's sendevent taps ──
 * Call-site: TOP of input_inject_event() in drivers/input/input.c:
 *     lp_touch_capture_hook(handle, type, code, value);
 * REAL finger touches go driver -> input_event -> input_handle_event and NEVER pass
 * through input_inject_event, so this is off the real-touch hot path. SnapAuto's
 * sendevent taps DO come here (evdev_write -> input_inject_event), which is all we
 * need to acquire the device. handle->dev is the input_dev; its ->name identifies the
 * fts panel. Every deref is sanity-checked as a kernel pointer, so a stale/NULL
 * handle just fails to capture (injection no-ops) instead of crashing. */
static inline bool kptr(const void *p) { return (unsigned long)p >= 0xffff000000000000UL; }

void lp_touch_capture_hook(struct input_handle *handle, unsigned int type,
                           unsigned int code, int value)
{
    struct input_dev *dev;
    const char *name;
    (void)code; (void)value;

    if (likely(g_fts_dev)) return;                 /* already cached — near-free */
    if (type != EV_ABS) return;
    if (!kptr(handle)) return;
    dev = handle->dev;
    if (!kptr(dev)) return;
    name = dev->name;
    if (!kptr(name)) return;
    if (name[0] == 'f' && name[1] == 't' && name[2] == 's') {
        g_fts_dev = dev;
        pr_info("lukeprivacy: touch_hook captured fts input_dev=%px (inject path)\n", dev);
    }
}

static inline void ev(void *dev, unsigned int type, unsigned int code, int val)
{
    input_event((struct input_dev *)dev, type, code, val);
}

/* Replay ONE swipe on the fts panel at the real ~5.4 ms cadence. Runs in the
 * control-node caller's process context (sleeping is allowed). Same start/end/
 * distance as the old shell swipe — the NumberPicker maps distance->items, so the
 * year count is unchanged; only the biometry becomes human. */
static int inject_swipe(int sx, int sy, int ex, int ey, int n, int flick)
{
    /* mode: 0 = CTRL (controlled drag), 1 = FLICK (birthday fling), 2 = NAV (warm-up) */
    const int *ease  = (flick == 2) ? EASE_NAV  : flick ? EASE_FLICK  : EASE_CTRL;
    const int *press = (flick == 2) ? PRESS_NAV : flick ? PRESS_FLICK : PRESS_CTRL;
    const int *maj   = (flick == 2) ? MAJ_NAV   : flick ? MAJ_FLICK   : MAJ_CTRL;
    const int *min   = (flick == 2) ? MIN_NAV   : flick ? MIN_FLICK   : MIN_CTRL;
    void *dev = g_fts_dev;
    int i, tid, o_start, o_end, bow, horiz;

    if (!dev) return -1;
    if (n < 8) n = 8;
    if (n > 64) n = 64;

    /* fold the request into the RNG so jitter differs per swipe */
    g_rng ^= (unsigned)(sx * 131 + sy * 17 + ex * 7 + ey + n * 2654435761u);
    if (g_rng == 0) g_rng = 0x1a2b3c4d;

    tid = rnd_between(200, 60000);
    o_start = (rnd() & 1 ? 1 : -1) * rnd_between(2000, 3600);   /* orientation drift */
    o_end   = (rnd() & 1 ? 1 : -1) * rnd_between(300, 1000);
    bow     = rnd_between(-4, 4);                               /* slight path bow (px) */
    {   /* bow rides the axis PERPENDICULAR to travel: X for a vertical swipe (up/down),
         * Y for a horizontal swipe (back/forward). Old code always bowed X = wrong for
         * edge back/forward. */
        int dxa = ex - sx, dya = ey - sy;
        if (dxa < 0) dxa = -dxa;
        if (dya < 0) dya = -dya;
        horiz = (dxa > dya);
    }

    for (i = 0; i < n; i++) {
        int p = (n > 1) ? (i * 1000 / (n - 1)) : 1000;
        int d = curve_at(ease, p);                             /* per-mille distance */
        /* triangular bow, peaks mid-gesture; perpendicular to a vertical swipe = x */
        int btri = (p < 500 ? p : 1000 - p);                   /* 0..500 */
        int boff = bow * btri / 500;
        int x = sx + (ex - sx) * d / 1000 + (horiz ? 0 : boff) + rnd_between(-1, 1);
        int y = sy + (ey - sy) * d / 1000 + (horiz ? boff : 0) + rnd_between(-1, 1);
        int pr = curve_at(press, p) + rnd_between(-3, 3);
        int ma = curve_at(maj, p) + rnd_between(-4, 4);
        int mi = curve_at(min, p) + rnd_between(-4, 4);
        int o  = o_start + (o_end - o_start) * p / 1000 + rnd_between(-180, 180);
        if (pr < 1) pr = 1;
        if (o > 4096) o = 4096; else if (o < -4096) o = -4096;

        ev(dev, EV_ABS, ABS_MT_SLOT, 0);
        if (i == 0) ev(dev, EV_ABS, ABS_MT_TRACKING_ID, tid);
        ev(dev, EV_ABS, ABS_MT_POSITION_X, x);
        ev(dev, EV_ABS, ABS_MT_POSITION_Y, y);
        ev(dev, EV_ABS, ABS_MT_TOUCH_MAJOR, ma);
        ev(dev, EV_ABS, ABS_MT_TOUCH_MINOR, mi);
        ev(dev, EV_ABS, ABS_MT_ORIENTATION, o);
        ev(dev, EV_ABS, ABS_MT_PRESSURE, pr);
        if (i == 0) ev(dev, EV_KEY, BTN_TOUCH, 1);
        ev(dev, EV_SYN, SYN_REPORT, 0);

        /* ~5.4 ms real report interval, ±jitter (human dt_sd ~1 ms). Range tuned so
         * the delivered median (usleep_range + input_event overhead) lands ~5.4 ms. */
        usleep_range_state(3500 + (rnd() % 900), 5100 + (rnd() % 900), TASK_UNINTERRUPTIBLE);
    }

    /* release: lift the contact */
    ev(dev, EV_ABS, ABS_MT_SLOT, 0);
    ev(dev, EV_ABS, ABS_MT_PRESSURE, 0);
    ev(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
    ev(dev, EV_KEY, BTN_TOUCH, 0);
    ev(dev, EV_SYN, SYN_REPORT, 0);
    return 0;
}

/* control-node entry: "swipe:sx,sy,ex,ey,flick,n". Returns 0 on inject, <0 on error. */
int touch_inject_cmd(const char *args)
{
    int v[6] = {0, 0, 0, 0, 0, 40};
    int idx = 0, sign, got;
    const char *p = args;

    if (!g_fts_dev) {
        pr_warn("lukeprivacy: swipe requested but fts input_dev not captured yet\n");
        return -1;
    }

    while (*p && idx < 6) {                        /* parse up to 6 signed ints */
        sign = 1; got = 0;
        while (*p == ' ') p++;
        if (*p == '-') { sign = -1; p++; }
        v[idx] = 0;
        while (*p >= '0' && *p <= '9') { v[idx] = v[idx] * 10 + (*p - '0'); p++; got = 1; }
        if (got) v[idx] *= sign;
        idx++;
        if (*p == ',') p++;
    }
    return inject_swipe(v[0], v[1], v[2], v[3], v[5], v[4]);
}

/* SETUP ONLY — no hook registration. input_event() / usleep_range_state() are
 * called directly (linker-resolved). Device acquisition is via the compiled-in
 * lp_touch_capture_hook() call-site in input_inject_event(). No-op init/exit. */
int touch_hook_init(void)
{
    return 0;
}

void touch_hook_exit(void)
{
}
