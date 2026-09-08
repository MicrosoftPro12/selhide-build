# Out-of-tree: selhide-popsicle (Phase 1)
# For Xiaomi Mi 17 Pro Max (popsicle), kernel 6.12.x-android16-5.
KDIR ?= /workdir/ack-android16-6.12
ARCH ?= arm64
SELINUX_MODULE_SRC := $(if $(src),$(src),$(CURDIR))
SELINUX_BUNDLED_HDR_ROOT := $(SELINUX_MODULE_SRC)/selinux-headers
SELINUX_HDR_ROOT := $(if $(wildcard $(KDIR)/security/selinux),$(KDIR),$(if $(wildcard $(srctree)/security/selinux),$(srctree),$(SELINUX_BUNDLED_HDR_ROOT)))
SELHIDE_KCFI_FLAGS := $(if $(SELHIDE_WRITE_ACCESS_KCFI_WORD),-DSELHIDE_WRITE_ACCESS_KCFI_WORD=$(SELHIDE_WRITE_ACCESS_KCFI_WORD),)
SELHIDE_KCFI_FLAGS += $(if $(SELHIDE_WRITE_CONTEXT_KCFI_WORD),-DSELHIDE_WRITE_CONTEXT_KCFI_WORD=$(SELHIDE_WRITE_CONTEXT_KCFI_WORD),)
SELHIDE_KCFI_FLAGS += $(if $(SELHIDE_SETPROCATTR_KCFI_WORD),-DSELHIDE_SETPROCATTR_KCFI_WORD=$(SELHIDE_SETPROCATTR_KCFI_WORD),)

obj-m := selhide.o
SELHIDE_ASM_INIT ?= 0
selhide-y := selhide_hook_entry.o selhide_main.o selhide_patch_memory.o
ifeq ($(SELHIDE_ASM_INIT),1)
selhide-y += selhide_entry.o
ccflags-y += -DSELHIDE_ASM_INIT=1
endif

ccflags-y += -I$(SELINUX_HDR_ROOT)/security/selinux
ccflags-y += -I$(SELINUX_HDR_ROOT)/security/selinux/include
ccflags-y += -I$(SELINUX_BUNDLED_HDR_ROOT)/security/selinux
ccflags-y += -I$(SELINUX_BUNDLED_HDR_ROOT)/security/selinux/include
ccflags-y += -Wno-unused-function -Wno-unused-variable
ccflags-y += $(SELHIDE_KCFI_FLAGS)
asflags-y += $(SELHIDE_KCFI_FLAGS)
AFLAGS_selhide_hook_entry.o += $(SELHIDE_KCFI_FLAGS)

# The stop_machine callback reaches selhide_patch_text_cb_entry first, which
# supplies the runtime-required KCFI type ID. Keep the C implementation free of
# PAC/SCS: this target has repeatedly FPACed in the compiler-generated PAC/SCS
# epilogue of selhide_patch_text_cb_impl on stopper threads. Preserve BTI on
# BTI kernels only; Android 12/5.4 builds otherwise hit LLVM module-flag
# conflicts when selhide.mod.o is linked without branch-target-enforcement.
CFLAGS_REMOVE_selhide_patch_memory.o += -mbranch-protection=pac-ret
CFLAGS_REMOVE_selhide_patch_memory.o += -fsanitize=shadow-call-stack
CFLAGS_selhide_patch_memory.o += -fno-sanitize=shadow-call-stack
ifeq ($(CONFIG_ARM64_BTI_KERNEL),y)
CFLAGS_selhide_patch_memory.o += -mbranch-protection=bti
endif

# The SEL_ACCESS/SEL_CONTEXT/setprocattr hook callbacks are entered from
# kernel-owned callback tables through our hand-written KCFI wrappers. On
# popsicle/6.12, SEL_ACCESS has also FPACed in the compiler-generated PAC/SCS
# epilogue, so keep PAC/SCS off and let the wrappers own the KCFI landing
# contract. Keep BTI on BTI-enabled kernels so compiler-generated CFI jump
# tables remain valid indirect branch targets.
CFLAGS_REMOVE_selhide_main.o += -mbranch-protection=pac-ret
CFLAGS_REMOVE_selhide_main.o += -fsanitize=shadow-call-stack
CFLAGS_selhide_main.o += -fno-sanitize=shadow-call-stack
ifeq ($(CONFIG_ARM64_BTI_KERNEL),y)
CFLAGS_selhide_main.o += -mbranch-protection=bti
endif

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=$(LLVM) ARCH=$(ARCH) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: modules clean
