/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LukePrivacy — built-in per-UID device-id compat call-site hooks.
 * Included by the choke-point files in fs/, net/, drivers/android, drivers/input,
 * kernel/. All logic lives in drivers/lukeprivacy/. When CONFIG_LUKEPRIVACY is
 * off, every entry is a no-op static inline so call-sites cost nothing.
 */
#ifndef _LINUX_LUKEPRIVACY_H
#define _LINUX_LUKEPRIVACY_H

#include <linux/types.h>

#define LP_STAT_NEWFSTATAT 0
#define LP_STAT_STATX      1
#define LP_STAT_FSTAT      2

#ifdef CONFIG_LUKEPRIVACY

struct binder_alloc;
struct binder_buffer;
struct input_handle;

/* binder parcel rewrite — binder_alloc.c */
void lp_binder_copy_to_buffer_hook(struct binder_alloc *alloc, struct binder_buffer *buffer,
				   u64 buffer_offset, const void __user *from, size_t bytes);
void lp_binder_copy_to_buffer_gnss_hook(const void *src, size_t bytes);
void lp_binder_alloc_init_hook(struct binder_alloc *alloc);
void lp_binder_alloc_release_hook(struct binder_alloc *alloc);

/* vfs read / open / close — fs/read_write.c, fs/open.c */
long lp_read_hook(int fd, char __user *buf, long ret);
void lp_openat_hook(int dfd, const char __user *filename, int flags, long ret_fd);
int  lp_openat_deny(const char __user *filename);
int  lp_stat_deny(const char __user *filename);    /* U14: /proc/config.gz stat -> -ENOENT (app uids) */
int  lp_access_deny(const char __user *filename);  /* U14: /proc/config.gz access -> -ENOENT (app uids) */
void lp_close_hook(int fd);

/* stat / statfs — fs/stat.c, fs/statfs.c */
void lp_stat_hook(int kind, const char __user *upath, void __user *ubuf, long ret);
void lp_statfs_hook(void __user *buf, long ret);

/* binder ioctl — drivers/android/binder.c */
void lp_ioctl_hook(unsigned int cmd, unsigned long arg, long ret);

/* socket recv (sensor stream) — net/socket.c */
void lp_recv_hook(int fd, void __user *ubuf, size_t len, long ret, bool is_msg);

/* input inject capture (touch) — drivers/input/input.c */
void lp_touch_capture_hook(struct input_handle *handle, unsigned int type,
			   unsigned int code, int value);

/* prctl (eventtime timeline; inert until armed) — kernel/sys.c */
void lp_prctl_hook(void);

#else /* !CONFIG_LUKEPRIVACY */

struct binder_alloc;
struct binder_buffer;
struct input_handle;

static inline void lp_binder_copy_to_buffer_hook(struct binder_alloc *a, struct binder_buffer *b,
			u64 o, const void __user *f, size_t n) { }
static inline void lp_binder_copy_to_buffer_gnss_hook(const void *s, size_t n) { }
static inline void lp_binder_alloc_init_hook(struct binder_alloc *a) { }
static inline void lp_binder_alloc_release_hook(struct binder_alloc *a) { }
static inline long lp_read_hook(int fd, char __user *buf, long ret) { return ret; }
static inline void lp_openat_hook(int d, const char __user *f, int fl, long r) { }
static inline int  lp_openat_deny(const char __user *f) { return 0; }
static inline int  lp_stat_deny(const char __user *f) { return 0; }
static inline int  lp_access_deny(const char __user *f) { return 0; }
static inline void lp_close_hook(int fd) { }
static inline void lp_stat_hook(int k, const char __user *p, void __user *b, long r) { }
static inline void lp_statfs_hook(void __user *b, long r) { }
static inline void lp_ioctl_hook(unsigned int c, unsigned long a, long r) { }
static inline void lp_recv_hook(int fd, void __user *b, size_t l, long r, bool m) { }
static inline void lp_touch_capture_hook(struct input_handle *h, unsigned int t,
			unsigned int c, int v) { }
static inline void lp_prctl_hook(void) { }

#endif /* CONFIG_LUKEPRIVACY */

#endif /* _LINUX_LUKEPRIVACY_H */
