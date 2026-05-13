# Out-of-tree: selhide-popsicle (Phase 1)
# For Xiaomi Mi 17 Pro Max (popsicle), kernel 6.12.x-android16-5.
KDIR ?= /workdir/ack-android16-6.12
ARCH ?= arm64
SELINUX_HDR_ROOT := $(if $(wildcard $(KDIR)/security/selinux),$(KDIR),$(srctree))

obj-m := selhide.o
selhide-y := selhide_entry.o selhide_hook_entry.o selhide_main.o selhide_patch_memory.o

ccflags-y += -I$(SELINUX_HDR_ROOT)/security/selinux
ccflags-y += -I$(SELINUX_HDR_ROOT)/security/selinux/include
ccflags-y += -Wno-unused-function -Wno-unused-variable

# The stop_machine callback reaches selhide_patch_text_cb_entry first, which
# supplies the runtime-required KCFI type ID. Keep the C implementation plain:
# this target has repeatedly FPACed in the compiler-generated PAC/SCS epilogue
# of selhide_patch_text_cb_impl on stopper threads.
CFLAGS_REMOVE_selhide_patch_memory.o += -mbranch-protection=pac-ret
CFLAGS_REMOVE_selhide_patch_memory.o += -fsanitize=shadow-call-stack

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=$(LLVM) ARCH=$(ARCH) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: modules clean
