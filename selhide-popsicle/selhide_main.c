// SPDX-License-Identifier: GPL-2.0
/*
 * selhide Phase-0 for popsicle (SM8850 / kernel 6.12.x-android16-5)
 *
 * Smoke test: exercise every building block that Phase-1 will need,
 * without doing the dangerous write_op[] text patch. If this .ko
 * loads, prints its log and unloads cleanly, we know:
 *   - kprobe-based kallsyms_lookup_name works on this kernel
 *   - the SELinux ss internal symbols are reachable
 *   - /debug_ramdisk/.magisk/selinux/load is readable from kernel
 *   - policydb_read + sidtab_init + policydb_load_isids accept the blob
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/uaccess.h>

#include "include/security.h"
#include "ss/policydb.h"
#include "ss/sidtab.h"
#include "ss/context.h"
#include "selhide_patch_memory.h"

#define SELHIDE_TAG "selhide: "

enum sel_inos {
	SEL_ROOT_INO = 2,
	SEL_LOAD,
	SEL_ENFORCE,
	SEL_CONTEXT,
	SEL_ACCESS,
	SEL_CREATE,
	SEL_RELABEL,
	SEL_USER,
	SEL_POLICYVERS,
	SEL_COMMIT_BOOLS,
	SEL_MLS,
	SEL_DISABLE,
	SEL_MEMBER,
	SEL_CHECKREQPROT,
	SEL_COMPAT_NET,
	SEL_REJECT_UNKNOWN,
	SEL_DENY_UNKNOWN,
	SEL_STATUS,
	SEL_POLICY,
	SEL_VALIDATE_TRANS,
	SEL_INO_NEXT,
};

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);
typedef int (*string_to_context_struct_fn)(struct policydb *, struct sidtab *,
					   char *, struct context *, u32);
typedef int (*sidtab_context_to_sid_fn)(struct sidtab *, struct context *,
					u32 *);
typedef void (*context_struct_compute_av_fn)(struct policydb *,
					     struct context *,
					     struct context *, u16,
					     struct av_decision *,
					     struct extended_perms *);
typedef void (*policydb_destroy_fn)(struct policydb *);
typedef void (*sidtab_destroy_fn)(struct sidtab *);

static const char *const load_paths[] = {
	"/debug_ramdisk/.magisk/selinux/load",
	"/workdir/load",
	NULL,
};

static unsigned long (*p_kallsyms_lookup_name)(const char *name);
static int (*p_policydb_read)(struct policydb *, void *);
static int (*p_policydb_load_isids)(struct policydb *, struct sidtab *);
static int (*p_sidtab_init)(struct sidtab *);
static string_to_context_struct_fn p_string_to_context_struct;
static sidtab_context_to_sid_fn p_sidtab_context_to_sid;
static context_struct_compute_av_fn p_context_struct_compute_av;
static policydb_destroy_fn p_policydb_destroy;
static sidtab_destroy_fn p_sidtab_destroy;
static write_op_fn *p_write_op;

static struct policydb backup_policydb;
static struct sidtab backup_sidtab;
static bool policydb_loaded;
static bool sidtab_inited;
static bool policy_loaded;

static bool enable_access_hook;
module_param_named(access_hook, enable_access_hook, bool, 0644);
MODULE_PARM_DESC(access_hook, "install SEL_ACCESS passthrough hook; default off");

static bool enable_clean_access;
module_param_named(clean_access, enable_clean_access, bool, 0644);
MODULE_PARM_DESC(clean_access,
		 "answer SEL_ACCESS from Magisk clean policy backup; default off");

static bool enable_patch_self_test;
module_param_named(patch_self_test, enable_patch_self_test, bool, 0644);
MODULE_PARM_DESC(patch_self_test,
		 "patch only this module's SEL_ACCESS wrapper KCFI word; default off");

extern ssize_t selhide_write_access_entry(struct file *file, char *buf,
					  size_t size);
extern int selhide_call_string_to_context_struct(void *fn,
						 struct policydb *policydb,
						 struct sidtab *sidtab,
						 char *scontext,
						 struct context *context,
						 u32 def_sid);
extern int selhide_call_sidtab_context_to_sid(void *fn, struct sidtab *sidtab,
					      struct context *context, u32 *sid);
extern void selhide_call_context_struct_compute_av(void *fn,
						   struct policydb *policydb,
						   struct context *scontext,
						   struct context *tcontext,
						   u16 tclass,
						   struct av_decision *avd,
						   struct extended_perms *xperms);

static write_op_fn *access_write_slot;
static write_op_fn orig_access_write;
static bool access_hooked;
static bool access_wrapper_synced;

static int resolve_kallsyms(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);
	if (ret) { pr_err(SELHIDE_TAG "kprobe: %d\n", ret); return ret; }
	p_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	return p_kallsyms_lookup_name ? 0 : -ENOENT;
}

#define LOOKUP(var, name) do {						\
	unsigned long _a = p_kallsyms_lookup_name(name);		\
	if (!_a) { pr_err(SELHIDE_TAG "missing %s\n", name); return -ENOENT; } \
	var = (typeof(var))_a;						\
	pr_info(SELHIDE_TAG "resolved %s\n", name);			\
} while (0)

#define LOOKUP_OPT(var, name) do {					\
	unsigned long _a = p_kallsyms_lookup_name(name);		\
	var = (typeof(var))_a;						\
	if (_a)							\
		pr_info(SELHIDE_TAG "resolved %s\n", name);		\
	else							\
		pr_warn(SELHIDE_TAG "missing optional %s\n", name);	\
} while (0)

static bool clean_access_syms_ready(void)
{
	return p_string_to_context_struct && p_sidtab_context_to_sid &&
	       p_context_struct_compute_av;
}

static int resolve_syms(void)
{
	LOOKUP(p_write_op, "write_op");
	LOOKUP(p_policydb_read, "policydb_read");
	LOOKUP(p_policydb_load_isids, "policydb_load_isids");
	LOOKUP(p_sidtab_init, "sidtab_init");
	LOOKUP_OPT(p_string_to_context_struct, "string_to_context_struct");
	LOOKUP_OPT(p_sidtab_context_to_sid, "sidtab_context_to_sid");
	LOOKUP_OPT(p_context_struct_compute_av, "context_struct_compute_av");
	LOOKUP_OPT(p_policydb_destroy, "policydb_destroy");
	LOOKUP_OPT(p_sidtab_destroy, "sidtab_destroy");
	if (enable_clean_access && !clean_access_syms_ready()) {
		pr_err(SELHIDE_TAG "clean_access requested but helpers are missing\n");
		return -ENOENT;
	}
	return 0;
}

static void destroy_backup_policy(void)
{
	if (sidtab_inited && p_sidtab_destroy)
		p_sidtab_destroy(&backup_sidtab);
	if (policydb_loaded && p_policydb_destroy)
		p_policydb_destroy(&backup_policydb);
	sidtab_inited = false;
	policydb_loaded = false;
	policy_loaded = false;
}

static int load_backup_policy_from(const char *path)
{
	struct file *fp;
	void *buf;
	size_t size;
	loff_t pos = 0;
	int ret;
	struct policy_file pf;

	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_warn(SELHIDE_TAG "open %s: %ld\n", path, PTR_ERR(fp));
		return PTR_ERR(fp);
	}
	size = i_size_read(file_inode(fp));
	pr_info(SELHIDE_TAG "policy path=%s size=%zu\n", path, size);
	if (!size || size > (16 << 20)) {
		filp_close(fp, NULL);
		return -EINVAL;
	}
	buf = vmalloc(size);
	if (!buf) { filp_close(fp, NULL); return -ENOMEM; }
	ret = kernel_read(fp, buf, size, &pos);
	filp_close(fp, NULL);
	if (ret < 0) { vfree(buf); pr_err(SELHIDE_TAG "read: %d\n", ret); return ret; }
	pr_info(SELHIDE_TAG "read %d bytes\n", ret);

	pf.data = buf;
	pf.len = size;

	ret = p_policydb_read(&backup_policydb, &pf);
	vfree(buf);
	if (ret) { pr_err(SELHIDE_TAG "policydb_read: %d\n", ret); return ret; }
	policydb_loaded = true;
	pr_info(SELHIDE_TAG "policydb_read OK\n");

	ret = p_sidtab_init(&backup_sidtab);
	if (ret) {
		pr_err(SELHIDE_TAG "sidtab_init: %d\n", ret);
		destroy_backup_policy();
		return ret;
	}
	sidtab_inited = true;
	pr_info(SELHIDE_TAG "sidtab_init OK\n");

	ret = p_policydb_load_isids(&backup_policydb, &backup_sidtab);
	if (ret) {
		pr_err(SELHIDE_TAG "load_isids: %d\n", ret);
		destroy_backup_policy();
		return ret;
	}
	pr_info(SELHIDE_TAG "load_isids OK\n");

	policy_loaded = true;
	pr_info(SELHIDE_TAG "phase0 policy load complete\n");
	return 0;
}

static int load_backup_policy(void)
{
	int last = -ENOENT;
	int i;

	for (i = 0; load_paths[i]; i++) {
		last = load_backup_policy_from(load_paths[i]);
		if (!last)
			return 0;
	}
	return last;
}

static int backup_context_to_sid(const char *scontext, u32 scontext_len,
				 u32 *sid, u32 def_sid, gfp_t gfp_flags)
{
	struct context context;
	char *scontext2;
	int ret;

	if (!policy_loaded || !clean_access_syms_ready())
		return -EAGAIN;
	if (!scontext_len)
		return -EINVAL;

	scontext2 = kmemdup_nul(scontext, scontext_len, gfp_flags);
	if (!scontext2)
		return -ENOMEM;

	*sid = SECSID_NULL;
	ret = selhide_call_string_to_context_struct(p_string_to_context_struct,
						   &backup_policydb,
						   &backup_sidtab, scontext2,
						   &context, def_sid);
	if (ret)
		goto out;

	ret = selhide_call_sidtab_context_to_sid(p_sidtab_context_to_sid,
						&backup_sidtab, &context, sid);
	context_destroy(&context);
out:
	kfree(scontext2);
	return ret;
}

static void backup_avd_init(struct av_decision *avd)
{
	avd->allowed = 0;
	avd->auditallow = 0;
	avd->auditdeny = 0xffffffff;
	avd->seqno = 0;
	avd->flags = 0;
}

static int backup_compute_av_user(u32 ssid, u32 tsid, u16 tclass,
				  struct av_decision *avd)
{
	struct context *scontext;
	struct context *tcontext;

	if (!policy_loaded || !clean_access_syms_ready())
		return -EAGAIN;

	backup_avd_init(avd);

	scontext = sidtab_search(&backup_sidtab, ssid);
	if (!scontext) {
		pr_warn_ratelimited(SELHIDE_TAG "clean_access: unknown ssid %u\n",
				    ssid);
		return -EINVAL;
	}
	if (ebitmap_get_bit(&backup_policydb.permissive_map, scontext->type))
		avd->flags |= AVD_FLAGS_PERMISSIVE;

	tcontext = sidtab_search(&backup_sidtab, tsid);
	if (!tcontext) {
		pr_warn_ratelimited(SELHIDE_TAG "clean_access: unknown tsid %u\n",
				    tsid);
		return -EINVAL;
	}

	if (unlikely(!tclass)) {
		if (backup_policydb.allow_unknown)
			avd->allowed = 0xffffffff;
		return 0;
	}

	selhide_call_context_struct_compute_av(p_context_struct_compute_av,
					      &backup_policydb, scontext,
					      tcontext, tclass, avd, NULL);
	return 0;
}

static ssize_t compute_clean_access_response(char *buf, size_t size,
					     struct av_decision *out_avd,
					     u16 *out_tclass)
{
	char *scon = NULL;
	char *tcon = NULL;
	u32 ssid;
	u32 tsid;
	u16 tclass;
	struct av_decision avd;
	ssize_t length;
	int ret;

	if (!policy_loaded || !clean_access_syms_ready())
		return -EAGAIN;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	ret = backup_context_to_sid(scon, strlen(scon), &ssid, SECSID_NULL,
				    GFP_KERNEL);
	if (ret) {
		length = ret;
		goto out;
	}

	ret = backup_context_to_sid(tcon, strlen(tcon), &tsid, SECSID_NULL,
				    GFP_KERNEL);
	if (ret) {
		length = ret;
		goto out;
	}

	ret = backup_compute_av_user(ssid, tsid, tclass, &avd);
	if (ret) {
		length = ret;
		goto out;
	}

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,
			   "%x %x %x %x %u %x",
			   avd.allowed, 0xffffffff, avd.auditallow,
			   avd.auditdeny, avd.seqno, avd.flags);
	if (out_avd)
		*out_avd = avd;
	if (out_tclass)
		*out_tclass = tclass;
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t check_original_access(struct file *file, char *buf, size_t size)
{
	char *tmp;
	ssize_t ret;

	if (unlikely(!orig_access_write))
		return -EIO;

	tmp = kmemdup_nul(buf, size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	ret = orig_access_write(file, tmp, size);
	kfree(tmp);
	return ret;
}

static int read_kcfi_typeid(void *fn, u32 *typeid)
{
	if (!fn)
		return -EINVAL;

	return copy_from_kernel_nofault(typeid,
					(void *)((unsigned long)fn - 4),
					sizeof(*typeid));
}

static void log_kcfi_typeid(const char *name, void *fn)
{
	u32 typeid = 0;
	int ret = read_kcfi_typeid(fn, &typeid);

	if (ret)
		pr_warn(SELHIDE_TAG "%s=%pS kcfi read failed: %d\n", name, fn,
			ret);
	else
		pr_info(SELHIDE_TAG "%s=%pS kcfi_typeid=0x%08x\n", name, fn,
			typeid);
}

static void probe_kcfi_targets(void)
{
	unsigned long setprocattr;

	pr_info(SELHIDE_TAG "write_op[] at %p\n", p_write_op);
	log_kcfi_typeid("write_op[SEL_CONTEXT]", p_write_op[SEL_CONTEXT]);
	log_kcfi_typeid("write_op[SEL_ACCESS]", p_write_op[SEL_ACCESS]);

	setprocattr = p_kallsyms_lookup_name("selinux_setprocattr");
	if (setprocattr)
		log_kcfi_typeid("selinux_setprocattr", (void *)setprocattr);
	else
		pr_warn(SELHIDE_TAG "selinux_setprocattr not found\n");
}

ssize_t selhide_write_access_impl(struct file *file, char *buf, size_t size)
{
	static bool logged_passthrough;
	static bool logged_clean;
	static bool logged_fallback;
	struct av_decision avd;
	ssize_t length;
	u16 tclass = 0;

	if (unlikely(!orig_access_write))
		return -EIO;

	if (!enable_clean_access) {
		if (!logged_passthrough) {
			logged_passthrough = true;
			pr_info(SELHIDE_TAG "SEL_ACCESS passthrough hit uid=%u\n",
				current_uid().val);
		}
		return orig_access_write(file, buf, size);
	}

	length = check_original_access(file, buf, size);
	if (length < 0)
		return length;

	length = compute_clean_access_response(buf, size, &avd, &tclass);
	if (length == -EAGAIN) {
		if (!logged_fallback) {
			logged_fallback = true;
			pr_warn(SELHIDE_TAG "clean_access unavailable, falling back to original\n");
		}
		return orig_access_write(file, buf, size);
	}

	if (length >= 0 && !logged_clean) {
		logged_clean = true;
		pr_info(SELHIDE_TAG "SEL_ACCESS clean_access hit uid=%u\n",
			current_uid().val);
		pr_info(SELHIDE_TAG "clean_access result tclass=%u allowed=0x%x flags=0x%x\n",
			tclass, avd.allowed, avd.flags);
	}

	return length;
}

static int sync_wrapper_kcfi_typeid(write_op_fn orig, write_op_fn replacement)
{
	u32 orig_typeid = 0;
	u32 new_typeid = 0;
	int ret;

	ret = read_kcfi_typeid(orig, &orig_typeid);
	if (ret) {
		pr_err(SELHIDE_TAG "read original access KCFI failed: %d\n",
		       ret);
		return ret;
	}

	ret = selhide_patch_text((void *)((unsigned long)replacement - 4),
				 &orig_typeid, sizeof(orig_typeid),
				 SELHIDE_PATCH_FLUSH_DCACHE |
					 SELHIDE_PATCH_FLUSH_ICACHE);
	if (ret) {
		pr_err(SELHIDE_TAG "patch replacement KCFI failed: %d\n", ret);
		return ret;
	}

	ret = read_kcfi_typeid(replacement, &new_typeid);
	if (ret)
		return ret;
	if (new_typeid != orig_typeid) {
		pr_err(SELHIDE_TAG "replacement KCFI mismatch: 0x%08x != 0x%08x\n",
		       new_typeid, orig_typeid);
		return -EINVAL;
	}

	pr_info(SELHIDE_TAG "replacement KCFI synced: 0x%08x\n",
		orig_typeid);
	access_wrapper_synced = true;
	return 0;
}

static int prepare_access_target(void)
{
	access_write_slot = &p_write_op[SEL_ACCESS];
	orig_access_write = READ_ONCE(*access_write_slot);
	if (!orig_access_write) {
		pr_err(SELHIDE_TAG "SEL_ACCESS slot is NULL\n");
		return -ENOENT;
	}

	return 0;
}

static int run_access_wrapper_self_test(void)
{
	write_op_fn replacement = selhide_write_access_entry;
	int ret;

	ret = prepare_access_target();
	if (ret)
		return ret;

	pr_info(SELHIDE_TAG "patch self-test: sync wrapper only orig=%pS repl=%pS slot=%p current=%pS\n",
		orig_access_write, replacement, access_write_slot,
		READ_ONCE(*access_write_slot));

	ret = sync_wrapper_kcfi_typeid(orig_access_write, replacement);
	if (ret)
		return ret;

	pr_info(SELHIDE_TAG "patch self-test OK; SEL_ACCESS slot still %pS\n",
		READ_ONCE(*access_write_slot));
	return 0;
}

static int install_access_passthrough_hook(void)
{
	write_op_fn replacement = selhide_write_access_entry;
	int ret;

	ret = prepare_access_target();
	if (ret)
		return ret;
	if (orig_access_write == replacement) {
		pr_warn(SELHIDE_TAG "SEL_ACCESS hook already installed\n");
		access_hooked = true;
		return 0;
	}

	pr_info(SELHIDE_TAG "install SEL_ACCESS passthrough: orig=%pS repl=%pS slot=%p\n",
		orig_access_write, replacement, access_write_slot);

	if (!access_wrapper_synced) {
		ret = sync_wrapper_kcfi_typeid(orig_access_write, replacement);
		if (ret)
			return ret;
	}

	ret = selhide_patch_text(access_write_slot, &replacement,
				 sizeof(replacement),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret) {
		pr_err(SELHIDE_TAG "patch SEL_ACCESS slot failed: %d\n", ret);
		return ret;
	}

	access_hooked = true;
	pr_info(SELHIDE_TAG "SEL_ACCESS passthrough hook installed\n");
	return 0;
}

static void remove_access_hook(void)
{
	int ret;

	if (!access_hooked || !access_write_slot || !orig_access_write)
		return;

	ret = selhide_patch_text(access_write_slot, &orig_access_write,
				 sizeof(orig_access_write),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret)
		pr_err(SELHIDE_TAG "restore SEL_ACCESS slot failed: %d\n", ret);
	else {
		pr_info(SELHIDE_TAG "SEL_ACCESS hook restored\n");
		access_hooked = false;
	}
}

int __init selhide_real_init(void)
{
	int ret;
	pr_info(SELHIDE_TAG "phase0 loading (kernel %u.%u.%u code=%d)\n",
		(unsigned int)LINUX_VERSION_MAJOR,
		(unsigned int)LINUX_VERSION_PATCHLEVEL,
		(unsigned int)LINUX_VERSION_SUBLEVEL,
		LINUX_VERSION_CODE);

	ret = resolve_kallsyms();
	if (ret) return ret;

	ret = resolve_syms();
	if (ret) return ret;

	probe_kcfi_targets();

	ret = load_backup_policy();
	if (ret) {
		pr_err(SELHIDE_TAG "load_backup_policy failed: %d\n", ret);
		return ret;
	}

	if (enable_patch_self_test) {
		ret = run_access_wrapper_self_test();
		if (ret)
			return ret;
	}

	if (enable_access_hook) {
		ret = install_access_passthrough_hook();
		if (ret)
			return ret;
	} else {
		pr_info(SELHIDE_TAG "SEL_ACCESS hook disabled (access_hook=0)\n");
	}

	pr_info(SELHIDE_TAG "phase0 success\n");
	return 0;
}

void __exit selhide_real_exit(void)
{
	bool had_policy = policy_loaded;
	bool was_hooked = access_hooked;

	remove_access_hook();
	pr_info(SELHIDE_TAG "phase0 unloaded (policy_loaded=%d access_hooked=%d)\n",
		had_policy, was_hooked);
	destroy_backup_policy();
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("selhide");
MODULE_DESCRIPTION("selhide phase0 probe + guarded SEL_ACCESS passthrough (popsicle/6.12)");
MODULE_VERSION("p0.9-cleanaccess");
