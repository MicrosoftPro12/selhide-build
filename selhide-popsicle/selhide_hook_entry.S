/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Runtime-patched KCFI callback wrapper.
 *
 * The local compiler cannot emit -fsanitize=kcfi. Unlike module init/exit, this
 * callback's type ID can be copied from the original SELinux write_op target at
 * module init time before the function pointer is installed.
 */

	.section ".text", "ax"
	.balign 4
	.globl selhide_write_access_kcfi_word
selhide_write_access_kcfi_word:
#ifdef SELHIDE_WRITE_ACCESS_KCFI_WORD
	.word SELHIDE_WRITE_ACCESS_KCFI_WORD
#else
	.word 0
#endif
	.globl selhide_write_access_entry
	.type selhide_write_access_entry, %function
selhide_write_access_entry:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	bl selhide_write_access_impl
	ldp x29, x30, [sp], #16
	ret
	.size selhide_write_access_entry, . - selhide_write_access_entry

	.balign 4
	.globl selhide_write_context_kcfi_word
selhide_write_context_kcfi_word:
#ifdef SELHIDE_WRITE_CONTEXT_KCFI_WORD
	.word SELHIDE_WRITE_CONTEXT_KCFI_WORD
#else
	.word 0
#endif
	.globl selhide_write_context_entry
	.type selhide_write_context_entry, %function
selhide_write_context_entry:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	bl selhide_write_context_impl
	ldp x29, x30, [sp], #16
	ret
	.size selhide_write_context_entry, . - selhide_write_context_entry

	.balign 4
	.globl selhide_setprocattr_kcfi_word
selhide_setprocattr_kcfi_word:
#ifdef SELHIDE_SETPROCATTR_KCFI_WORD
	.word SELHIDE_SETPROCATTR_KCFI_WORD
#else
	.word 0
#endif
	.globl selhide_setprocattr_entry
	.type selhide_setprocattr_entry, %function
selhide_setprocattr_entry:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	bl selhide_setprocattr_impl
	ldp x29, x30, [sp], #16
	ret
	.size selhide_setprocattr_entry, . - selhide_setprocattr_entry

	.balign 4
	.word 0xc069e464
	.globl selhide_patch_text_cb_entry
	.type selhide_patch_text_cb_entry, %function
selhide_patch_text_cb_entry:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	bl selhide_patch_text_cb_impl
	ldp x29, x30, [sp], #16
	ret
	.size selhide_patch_text_cb_entry, . - selhide_patch_text_cb_entry

/*
 * Raw-call trampolines for SELinux internal helpers resolved from kallsyms.
 *
 * Some vendor kernels expose internal static symbols whose KCFI type IDs do
 * not match the DDK/compiler view used by this external module, even when the
 * AAPCS64 ABI shape is compatible. Calling them through C function pointers
 * lets clang emit an indirect-call KCFI check and can panic the device. These
 * tiny assembly shims shift arguments and perform the BLR without a compiler
 * generated KCFI check.
 */
	.balign 4
	.globl selhide_call_string_to_context_struct
	.type selhide_call_string_to_context_struct, %function
selhide_call_string_to_context_struct:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	mov x2, x3
	mov x3, x4
	mov x4, x5
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_string_to_context_struct, . - selhide_call_string_to_context_struct

	.balign 4
	.globl selhide_call_sidtab_context_to_sid
	.type selhide_call_sidtab_context_to_sid, %function
selhide_call_sidtab_context_to_sid:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	mov x2, x3
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_sidtab_context_to_sid, . - selhide_call_sidtab_context_to_sid

	.balign 4
	.globl selhide_call_context_struct_compute_av
	.type selhide_call_context_struct_compute_av, %function
selhide_call_context_struct_compute_av:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	mov x2, x3
	mov x3, x4
	mov x4, x5
	mov x5, x6
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_context_struct_compute_av, . - selhide_call_context_struct_compute_av

	.balign 4
	.globl selhide_call_kallsyms_lookup_name
	.type selhide_call_kallsyms_lookup_name, %function
selhide_call_kallsyms_lookup_name:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_kallsyms_lookup_name, . - selhide_call_kallsyms_lookup_name

	.balign 4
	.globl selhide_call_policydb_read
	.type selhide_call_policydb_read, %function
selhide_call_policydb_read:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_policydb_read, . - selhide_call_policydb_read

	.balign 4
	.globl selhide_call_policydb_load_isids
	.type selhide_call_policydb_load_isids, %function
selhide_call_policydb_load_isids:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_policydb_load_isids, . - selhide_call_policydb_load_isids

	.balign 4
	.globl selhide_call_sidtab_init
	.type selhide_call_sidtab_init, %function
selhide_call_sidtab_init:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_sidtab_init, . - selhide_call_sidtab_init

	.balign 4
	.globl selhide_call_policydb_destroy
	.type selhide_call_policydb_destroy, %function
selhide_call_policydb_destroy:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_policydb_destroy, . - selhide_call_policydb_destroy

	.balign 4
	.globl selhide_call_sidtab_destroy
	.type selhide_call_sidtab_destroy, %function
selhide_call_sidtab_destroy:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_sidtab_destroy, . - selhide_call_sidtab_destroy

	.balign 4
	.globl selhide_call_write_op
	.type selhide_call_write_op, %function
selhide_call_write_op:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	mov x2, x3
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_write_op, . - selhide_call_write_op

	.balign 4
	.globl selhide_call_setprocattr
	.type selhide_call_setprocattr, %function
selhide_call_setprocattr:
	stp x29, x30, [sp, #-16]!
	mov x29, sp
	mov x8, x0
	mov x0, x1
	mov x1, x2
	mov x2, x3
	blr x8
	ldp x29, x30, [sp], #16
	ret
	.size selhide_call_setprocattr, . - selhide_call_setprocattr
