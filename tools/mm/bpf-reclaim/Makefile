# SPDX-License-Identifier: GPL-2.0
# Build bpf_reclaim against this tree's libbpf, bpftool and vmlinux, which
# must have the BPF kthread kfuncs.  STATIC=1 links libelf, zlib and zstd
# statically, leaving only glibc dynamic.
include ../../build/Build.include
include ../../scripts/Makefile.arch
include ../../scripts/Makefile.include

all: all_targets

CURDIR := $(abspath .)
TOOLSDIR := $(abspath ../..)
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi

ifeq ($(O),)
OUTPUT_DIR := $(CURDIR)/build
else
OUTPUT_DIR := $(O)/build
endif
OBJ_DIR := $(OUTPUT_DIR)/obj
INCLUDE_DIR := $(OUTPUT_DIR)/include
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
BINDIR := $(OUTPUT_DIR)/bin
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
DEFAULT_BPFTOOL := $(OUTPUT_DIR)/sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)

VMLINUX_BTF_PATHS ?= $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)		\
		     ../../../vmlinux						\
		     /sys/kernel/btf/vmlinux					\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))
ifeq ($(VMLINUX_BTF)$(VMLINUX_H),)
$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

ifeq ($(origin msg),undefined)
msg = @printf '  %-8s%s %s%s\n' "$(1)" "$(if $(2), [$(2)])" "$(notdir $(3))" "$(4)";
endif

CFLAGS += -g -O2 -Wall -Werror -I$(INCLUDE_DIR) -I$(TOOLSINCDIR) -I$(APIDIR) -I$(CURDIR)
ifeq ($(STATIC),1)
LDLIBS += -Wl,-Bstatic -lelf -lz -lzstd -Wl,-Bdynamic
else
LDLIBS += -lelf -lz
endif

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null |				\
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
endef

BPF_CFLAGS = -g -O2 -mcpu=v3 -D__TARGET_ARCH_$(SRCARCH)				\
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)		\
	     -I$(INCLUDE_DIR) -I$(APIDIR) -I$(CURDIR)				\
	     $(call get_sys_includes,$(CLANG))					\
	     -Wall -Wno-compare-distinct-pointer-types -Wno-missing-declarations

MAKE_DIRS := $(BPFOBJ_DIR) $(OBJ_DIR)/bpftool $(INCLUDE_DIR) $(BINDIR)

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile)			\
	   $(APIDIR)/linux/bpf.h | $(BPFOBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR)				\
		    OUTPUT=$(BPFOBJ_DIR)/ ARCH= CROSS_COMPILE=			\
		    CC="$(HOSTCC)" LD=$(HOSTLD) EXTRA_CFLAGS='-g -O2 -fPIC'	\
		    DESTDIR=$(OUTPUT_DIR) prefix= all install_headers

$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile)	\
		    $(BPFOBJ) | $(OBJ_DIR)/bpftool
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR)				\
		    ARCH= CROSS_COMPILE= CC="$(HOSTCC)" LD=$(HOSTLD)		\
		    EXTRA_CFLAGS='-g -O0'					\
		    OUTPUT=$(OBJ_DIR)/bpftool/					\
		    LIBBPF_OUTPUT=$(BPFOBJ_DIR)/				\
		    LIBBPF_DESTDIR=$(OUTPUT_DIR)/				\
		    prefix= DESTDIR=$(OUTPUT_DIR)/ install-bin

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

$(OBJ_DIR)/reclaim.bpf.o: reclaim.bpf.c reclaim.h $(INCLUDE_DIR)/vmlinux.h | $(BPFOBJ)
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) --target=bpf -c $< -o $@

$(INCLUDE_DIR)/reclaim.bpf.skel.h: $(OBJ_DIR)/reclaim.bpf.o $(BPFTOOL)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< name reclaim_bpf > $@

$(BINDIR)/bpf_reclaim: bpf_reclaim.c reclaim.h $(INCLUDE_DIR)/reclaim.bpf.skel.h $(BPFOBJ) | $(BINDIR)
	$(call msg,CC,,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(BPFOBJ) $(LDLIBS)

bpf_reclaim: $(BINDIR)/bpf_reclaim

all_targets: bpf_reclaim

clean:
	rm -rf $(OUTPUT_DIR)

.PHONY: all all_targets bpf_reclaim clean

.DELETE_ON_ERROR:
.SECONDARY:
