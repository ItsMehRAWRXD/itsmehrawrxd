LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := encrypted_root_engine
LOCAL_SRC_FILES := EncryptedRootEngine.cpp
LOCAL_LDLIBS := -llog -landroid -lssl -lcrypto
LOCAL_CFLAGS := -Wall -Wextra -O2 -fvisibility=hidden
LOCAL_CPPFLAGS := -std=c++17

include $(BUILD_SHARED_LIBRARY)
