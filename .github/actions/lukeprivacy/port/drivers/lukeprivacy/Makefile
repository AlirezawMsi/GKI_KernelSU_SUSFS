# LukePrivacy built-in device-id compat layer
obj-$(CONFIG_LUKEPRIVACY) += lukeprivacy.o
obj-$(CONFIG_LUKEPRIVACY) += binder_hook.o
obj-$(CONFIG_LUKEPRIVACY) += sensor_hook.o
obj-$(CONFIG_LUKEPRIVACY) += read_hook.o
obj-$(CONFIG_LUKEPRIVACY) += openat_hook.o
obj-$(CONFIG_LUKEPRIVACY) += stat_hook.o
obj-$(CONFIG_LUKEPRIVACY) += statfs_hook.o
obj-$(CONFIG_LUKEPRIVACY) += ioctl_hook.o
obj-$(CONFIG_LUKEPRIVACY) += touch_hook.o
obj-$(CONFIG_LUKEPRIVACY) += props_hook.o
obj-$(CONFIG_LUKEPRIVACY) += exclude_resolver.o

# local headers (profile.h, uaccess.h, lp_log.h) live in this dir
ccflags-y += -I$(srctree)/drivers/lukeprivacy
# A few hooks (lp_ctl status/stats, lp_binder/lp_read parcel scratch) run large
# on-stack buffers; arm64 kernel stack is 16K so raise the per-object frame warn
# limit for this driver. TODO: move the hot-path scratch buffers off-stack.
ccflags-y += -Wframe-larger-than=8192

# sensor_hook does float math (oscillators / approx sin,cos,sqrt / jitter) inside
# kernel_neon_begin()/kernel_neon_end() brackets. arm64 kernels build with
# -mgeneral-regs-only (no FP/SIMD codegen); remove it for THIS object only so the
# compiler may emit FP, exactly as crypto/ and lib/raid6/ do for their NEON code.
CFLAGS_REMOVE_sensor_hook.o := -mgeneral-regs-only
