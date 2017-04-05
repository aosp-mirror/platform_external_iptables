LOCAL_PATH:= $(call my-dir)

commonFlags:= \
	-Wno-missing-field-initializers \
	-Wno-sign-compare \
	-Wno-pointer-arith \
	-Wno-unused-parameter \
	-Wno-parentheses-equality \
	-Werror

#----------------------------------------------------------------
# The iptables lock file
include $(CLEAR_VARS)

LOCAL_MODULE := xtables.lock
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc
LOCAL_SRC_FILES := $(LOCAL_MODULE)

include $(BUILD_PREBUILT)

#----------------------------------------------------------------
# iptables

include $(CLEAR_VARS)

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/../include/ \
	$(LOCAL_PATH)/../

LOCAL_CFLAGS:=-DNO_SHARED_LIBS=1
LOCAL_CFLAGS+=-DALL_INCLUSIVE
LOCAL_CFLAGS+=-DXTABLES_INTERNAL
LOCAL_CFLAGS+=-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DENABLE_IPV4
# Accommodate arm-eabi-4.4.3 tools that don't set __ANDROID__
LOCAL_CFLAGS+=-D__ANDROID__
LOCAL_CFLAGS += $(commonFlags)

LOCAL_REQUIRED_MODULES := xtables.lock

LOCAL_SRC_FILES:= \
	xtables-multi.c iptables-xml.c xshared.c \
	iptables-save.c iptables-restore.c \
	iptables-standalone.c iptables.c

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:=iptables

LOCAL_STATIC_LIBRARIES := \
	libext \
	libext4 \
	libip4tc \
	libxtables

LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_OUT)/bin; \
    ln -sf iptables $(TARGET_OUT)/bin/iptables-save; \
    ln -sf iptables $(TARGET_OUT)/bin/iptables-restore

LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../NOTICE

include $(BUILD_EXECUTABLE)

#----------------------------------------------------------------
# ip6tables
include $(CLEAR_VARS)

LOCAL_C_INCLUDES:= \
	$(LOCAL_PATH)/../include/ \
	$(LOCAL_PATH)/../

LOCAL_CFLAGS:=-DNO_SHARED_LIBS=1
LOCAL_CFLAGS+=-DALL_INCLUSIVE
LOCAL_CFLAGS+=-DXTABLES_INTERNAL
LOCAL_CFLAGS+=-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DENABLE_IPV6
# Accommodate arm-eabi-4.4.3 tools that don't set __ANDROID__
LOCAL_CFLAGS+=-D__ANDROID__
LOCAL_CFLAGS += $(commonFlags)

LOCAL_REQUIRED_MODULES := xtables.lock

LOCAL_SRC_FILES:= \
	xtables-multi.c iptables-xml.c xshared.c \
	ip6tables-save.c ip6tables-restore.c \
	ip6tables-standalone.c ip6tables.c

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE:=ip6tables

LOCAL_STATIC_LIBRARIES := \
	libext \
	libext6 \
	libip6tc \
	libxtables

LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_OUT)/bin; \
    ln -sf ip6tables $(TARGET_OUT)/bin/ip6tables-save; \
    ln -sf ip6tables $(TARGET_OUT)/bin/ip6tables-restore

LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../NOTICE

include $(BUILD_EXECUTABLE)

#----------------------------------------------------------------
