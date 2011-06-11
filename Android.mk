ifneq ($(TARGET_SIMULATOR),true)
  BUILD_IPTABLES_V14 := 1
endif

ifeq ($(BUILD_IPTABLES_V14),1)

LOCAL_PATH:= $(call my-dir)

include $(call all-subdir-makefiles)

#----------------------------------------------------------------
#----------------------------------------------------------------
endif
