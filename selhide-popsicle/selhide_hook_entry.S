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
	.word 0
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
