GO_EASY_ON_ME = 1
FINALPACKAGE=1
DEBUG=0

ARCHS := arm64
TARGET := iphone:clang:14.4:14.4

THEOS_DEVICE_IP = 127.0.0.1 -p 2222

include $(THEOS)/makefiles/common.mk

TOOL_NAME = noncetest

noncetest_FILES = main.m krw.m nonce.m
noncetest_FRAMEWORKS = IOKit
noncetest_CFLAGS = -fobjc-arc
noncetest_CODESIGN_FLAGS = -Sentitlements.plist
noncetest_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk

before-package::
	ldid -Sentitlements.plist $(THEOS_STAGING_DIR)/usr/local/bin/noncetest