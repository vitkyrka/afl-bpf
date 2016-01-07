# Run ./init.sh before running make

ARCH=x86

HOST_CFLAGS_arm = -m32
CROSS_COMPILE_arm = arm-linux-gnueabihf-
CROSS_COMPILE_arm64 = aarch64-buildroot-linux-gnu-

ifneq ($(ARCH),x86)
	HOST_CFLAGS += -D__BPF_TEST_HOST
	HOST_CFLAGS += -Wl,--just-symbols=runner-syms
	MAIN_DEPS += runner-syms
	OBJS += runner main-native
endif

CROSS_COMPILE = $(CROSS_COMPILE_$(ARCH))
AFLCC=afl-gcc
TARGETCC = $(CROSS_COMPILE)gcc

CFLAGS = -g -O2 -Wall -D__BPF_TEST -DARCH_$(ARCH)
HARNESS_CFLAGS = -I. -Iinclude -I arch/$(ARCH)/include
TARGET_CFLAGS = -static
HOST_CFLAGS += $(HOST_CFLAGS_$(ARCH))

COMMON = kernel/bpf/core.c net/core/filter.c compat.c arch/$(ARCH)/*/*.c $(wildcard arch/$(ARCH)/*/*.S)
COMMON_H = compat.h skbs.h

OBJS += skbs2pcap dump main main-afl

.PHONY: all clean distclean
all: $(OBJS)

skbs.h: genskbs.sh
	./genskbs.sh > $@

skbs2pcap:  skbs2pcap.c skbs.h
	$(CC) -o $@ $(CFLAGS) $< -lpcap

runner: runner.c $(COMMON_H) $(COMMON)
	$(TARGETCC) $(CFLAGS) $(HARNESS_CFLAGS) $(TARGET_CFLAGS) $(COMMON) $< -o $@

runner-syms: runner symextract.sh
	./symextract.sh $< > $@

define main_rule =
$(1): main.c $(MAIN_DEPS) $(COMMON_H) $(COMMON)
	$(2) $(CFLAGS) $(HARNESS_CFLAGS) $(3) $(COMMON) main.c -o $(1)
endef

$(eval $(call main_rule, main, $(CC), $(HOST_CFLAGS)))
$(eval $(call main_rule, main-afl, $(AFLCC), $(HOST_CFLAGS)))
$(eval $(call main_rule, main-native, $(TARGETCC), $(TARGET_CFLAGS)))

clean:
	@rm -f $(OBJS) runner-syms

distclean: clean
	@rm -rf cscope.* tags arch kernel net include skbs.h skbs.pcap
