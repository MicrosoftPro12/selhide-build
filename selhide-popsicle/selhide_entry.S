/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Android KCFI entry wrappers for module init/exit.
 *
 * This is a narrow workaround for phase0 smoke tests built in the local
 * udocker image, whose clang lacks -fsanitize=kcfi. Full hook callbacks still
 * need a real Android KCFI compiler or per-callback KCFI wrappers.
 */

	.section ".init.text", "ax"
	.balign 4
	.word 0x6fbb3035
	.globl init_module
	.type init_module, %function
init_module:
	b selhide_real_init
	.size init_module, . - init_module

	.section ".exit.text", "ax"
	.balign 4
	.word 0xe5c47d60
	.globl cleanup_module
	.type cleanup_module, %function
cleanup_module:
	b selhide_real_exit
	.size cleanup_module, . - cleanup_module
