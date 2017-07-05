LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_DEPS := \
	lib/libc \
	lib/debug \
	lib/heap

MODULE_SRCS := \
	$(LOCAL_DIR)/asan.c

# some dummy flags to prevent default (asan-enabled) flags
# TODO(astarasikov): introduce MODULE_SKIP_KASAN variable
MODULE_CFLAGS := -W

include make/module.mk
