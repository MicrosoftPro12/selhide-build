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
#include <linux/lsm_hooks.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "include/security.h"
#include "ss/policydb.h"
#include "ss/sidtab.h"
#include "ss/context.h"
#include "selhide_patch_memory.h"

#ifndef LINUX_VERSION_MAJOR
#define LINUX_VERSION_MAJOR ((LINUX_VERSION_CODE >> 16) & 0xff)
#endif
#ifndef LINUX_VERSION_PATCHLEVEL
#define LINUX_VERSION_PATCHLEVEL ((LINUX_VERSION_CODE >> 8) & 0xff)
#endif
#ifndef LINUX_VERSION_SUBLEVEL
#define LINUX_VERSION_SUBLEVEL (LINUX_VERSION_CODE & 0xff)
#endif

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
typedef int (*setprocattr_fn)(const char *, void *, size_t);
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

#ifndef SELHIDE_HAVE_SETPROCATTR_STATIC_CALLS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define SELHIDE_HAVE_SETPROCATTR_STATIC_CALLS 1
#else
#define SELHIDE_HAVE_SETPROCATTR_STATIC_CALLS 0
#endif
#endif

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
static struct lsm_static_calls_table *p_static_calls_table;
static struct security_hook_heads *p_security_hook_heads;
static setprocattr_fn p_selinux_setprocattr;
static setprocattr_fn p_selinux_setprocattr_cfi_jt;

static struct policydb backup_policydb;
static struct sidtab backup_sidtab;
static bool policydb_loaded;
static bool sidtab_inited;
static bool policy_loaded;

#define SELHIDE_ANDROID_UID_RANGE 100000U
#define SELHIDE_MAX_APPLY_APPIDS 256

static unsigned int apply_appids[SELHIDE_MAX_APPLY_APPIDS];
static unsigned int apply_appid_count;
module_param_array_named(apply_appids, apply_appids, uint,
			 &apply_appid_count, 0644);
MODULE_PARM_DESC(apply_appids,
		 "comma-separated Android appIds that receive clean-policy responses");

static bool enable_apply_filter;
module_param_named(apply_filter, enable_apply_filter, bool, 0644);
MODULE_PARM_DESC(apply_filter,
		 "restrict clean-policy responses to apply_appids; default off");

static unsigned int current_android_appid(void)
{
	return (unsigned int)__kuid_val(current_uid()) %
	       SELHIDE_ANDROID_UID_RANGE;
}

static bool current_appid_is_selected(void)
{
	unsigned int appid;
	unsigned int count;
	unsigned int i;

	if (!READ_ONCE(enable_apply_filter))
		return true;

	appid = current_android_appid();
	count = min_t(unsigned int, READ_ONCE(apply_appid_count),
		      SELHIDE_MAX_APPLY_APPIDS);
	for (i = 0; i < count; i++) {
		if (READ_ONCE(apply_appids[i]) == appid)
			return true;
	}
	return false;
}

static bool enable_access_hook;
module_param_named(access_hook, enable_access_hook, bool, 0644);
MODULE_PARM_DESC(access_hook, "install SEL_ACCESS passthrough hook; default off");

static bool enable_clean_access;
module_param_named(clean_access, enable_clean_access, bool, 0644);
MODULE_PARM_DESC(clean_access,
		 "answer SEL_ACCESS from Magisk clean policy backup; default off");

static bool enable_context_hook;
module_param_named(context_hook, enable_context_hook, bool, 0644);
MODULE_PARM_DESC(context_hook,
		 "answer SEL_CONTEXT from Magisk clean policy backup; default off");

static bool enable_setprocattr_hook;
module_param_named(setprocattr_hook, enable_setprocattr_hook, bool, 0644);
MODULE_PARM_DESC(setprocattr_hook,
		 "hide dirty contexts from /proc/self/attr/current fallback; default off");

static char *setprocattr_cfi_symbol;
module_param_named(setprocattr_cfi_symbol, setprocattr_cfi_symbol, charp, 0644);
MODULE_PARM_DESC(setprocattr_cfi_symbol,
		 "optional exact selinux_setprocattr CFI jump-table symbol name");

static char *backup_policy_path;
module_param_named(policy_path, backup_policy_path, charp, 0644);
MODULE_PARM_DESC(policy_path,
		 "explicit Magisk clean policy backup path; default autodetect");

static bool enable_patch_self_test;
module_param_named(patch_self_test, enable_patch_self_test, bool, 0644);
MODULE_PARM_DESC(patch_self_test,
		 "patch only this module's SEL_ACCESS wrapper KCFI word; default off");

static bool enable_trace_queries;
module_param_named(trace_queries, enable_trace_queries, bool, 0644);
MODULE_PARM_DESC(trace_queries,
		 "trace SEL_ACCESS/SEL_CONTEXT queries for diagnosis; default off");

static int trace_query_limit = 32;
module_param_named(trace_limit, trace_query_limit, int, 0644);
MODULE_PARM_DESC(trace_limit,
		 "number of non-dirty SELinuxfs queries to trace when trace_queries=1");

#if defined(CONFIG_CFI_CLANG)
extern ssize_t selhide_write_access_entry(struct file *file, char *buf,
					  size_t size);
extern ssize_t selhide_write_context_entry(struct file *file, char *buf,
					   size_t size);
extern int selhide_setprocattr_entry(const char *name, void *value,
				     size_t size);
#else
extern char selhide_write_access_entry[];
extern char selhide_write_context_entry[];
extern char selhide_setprocattr_entry[];
#endif
extern unsigned long selhide_call_kallsyms_lookup_name(void *fn,
							const char *name);
extern int selhide_call_policydb_read(void *fn, struct policydb *policydb,
				      void *pf);
extern int selhide_call_policydb_load_isids(void *fn,
					    struct policydb *policydb,
					    struct sidtab *sidtab);
extern int selhide_call_sidtab_init(void *fn, struct sidtab *sidtab);
extern void selhide_call_policydb_destroy(void *fn, struct policydb *policydb);
extern void selhide_call_sidtab_destroy(void *fn, struct sidtab *sidtab);
extern ssize_t selhide_call_write_op(void *fn, struct file *file, char *buf,
				     size_t size);
extern int selhide_call_setprocattr(void *fn, const char *name, void *value,
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

static write_op_fn access_replacement_fn(void)
{
#if defined(CONFIG_CFI_CLANG)
	/*
	 * Android 5.4-style CONFIG_CFI_CLANG validates module function pointers
	 * through the compiler-generated .cfi_jt entry. Installing the raw
	 * assembly address passes KCFI-word style checks but fails CFI slowpath.
	 */
	return selhide_write_access_entry;
#else
	/*
	 * Keep the raw assembly entry address. Declaring this symbol as a C
	 * function lets Clang/LTO canonicalize it to .cfi_jt, whose preceding
	 * word is not the KCFI type ID we deliberately placed at entry - 4.
	 */
	return (write_op_fn)(unsigned long)selhide_write_access_entry;
#endif
}

static write_op_fn context_replacement_fn(void)
{
#if defined(CONFIG_CFI_CLANG)
	return selhide_write_context_entry;
#else
	return (write_op_fn)(unsigned long)selhide_write_context_entry;
#endif
}

static setprocattr_fn setprocattr_replacement_fn(void)
{
#if defined(CONFIG_CFI_CLANG)
	return selhide_setprocattr_entry;
#else
	return (setprocattr_fn)(unsigned long)selhide_setprocattr_entry;
#endif
}

static bool have_setprocattr_target(void)
{
	return p_selinux_setprocattr || p_selinux_setprocattr_cfi_jt;
}

static bool is_selinux_setprocattr_target(setprocattr_fn fn)
{
	return (p_selinux_setprocattr && fn == p_selinux_setprocattr) ||
	       (p_selinux_setprocattr_cfi_jt &&
		fn == p_selinux_setprocattr_cfi_jt);
}

static const char *setprocattr_target_kind(setprocattr_fn fn)
{
	if (p_selinux_setprocattr && fn == p_selinux_setprocattr)
		return "raw";
	if (p_selinux_setprocattr_cfi_jt && fn == p_selinux_setprocattr_cfi_jt)
		return "cfi_jt";
	return "unknown";
}

static write_op_fn *access_write_slot;
static write_op_fn orig_access_write;
static bool access_hooked;
static bool access_wrapper_synced;

static write_op_fn *context_write_slot;
static write_op_fn orig_context_write;
static bool context_hooked;
static bool context_wrapper_synced;

static setprocattr_fn *setprocattr_slot;
static setprocattr_fn orig_setprocattr;
static bool setprocattr_hooked;
static bool setprocattr_wrapper_synced;

static int resolve_kallsyms(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);
	if (ret) { pr_err(SELHIDE_TAG "kprobe: %d\n", ret); return ret; }
	p_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	return p_kallsyms_lookup_name ? 0 : -ENOENT;
}

static unsigned long selhide_lookup_symbol(const char *name)
{
	if (!p_kallsyms_lookup_name)
		return 0;
	return selhide_call_kallsyms_lookup_name(p_kallsyms_lookup_name, name);
}

#define LOOKUP(var, name) do {						\
	unsigned long _a = selhide_lookup_symbol(name);		\
	if (!_a) { pr_err(SELHIDE_TAG "missing %s\n", name); return -ENOENT; } \
	var = (typeof(var))_a;						\
	pr_info(SELHIDE_TAG "resolved %s\n", name);			\
} while (0)

#define LOOKUP_OPT(var, name) do {					\
	unsigned long _a = selhide_lookup_symbol(name);		\
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
	LOOKUP_OPT(p_static_calls_table, "static_calls_table");
	LOOKUP_OPT(p_security_hook_heads, "security_hook_heads");
	LOOKUP_OPT(p_selinux_setprocattr, "selinux_setprocattr");
	LOOKUP_OPT(p_selinux_setprocattr_cfi_jt, "selinux_setprocattr.cfi_jt");
	if (!p_selinux_setprocattr_cfi_jt && setprocattr_cfi_symbol &&
	    setprocattr_cfi_symbol[0]) {
		unsigned long addr = selhide_lookup_symbol(setprocattr_cfi_symbol);

		if (addr) {
			p_selinux_setprocattr_cfi_jt = (setprocattr_fn)addr;
			pr_info(SELHIDE_TAG "resolved %s as selinux_setprocattr.cfi_jt\n",
				setprocattr_cfi_symbol);
		} else {
			pr_warn(SELHIDE_TAG "missing optional %s\n",
				setprocattr_cfi_symbol);
		}
	}
	LOOKUP_OPT(p_string_to_context_struct, "string_to_context_struct");
	LOOKUP_OPT(p_sidtab_context_to_sid, "sidtab_context_to_sid");
	LOOKUP_OPT(p_context_struct_compute_av, "context_struct_compute_av");
	LOOKUP_OPT(p_policydb_destroy, "policydb_destroy");
	LOOKUP_OPT(p_sidtab_destroy, "sidtab_destroy");
	if ((enable_clean_access || enable_context_hook ||
	     enable_setprocattr_hook) &&
	    !clean_access_syms_ready()) {
		pr_err(SELHIDE_TAG "clean policy helpers requested but missing\n");
		return -ENOENT;
	}
	if (enable_context_hook && !enable_clean_access) {
		pr_err(SELHIDE_TAG "context_hook requires clean_access=1\n");
		return -EINVAL;
	}
	if (enable_setprocattr_hook && !enable_clean_access) {
		pr_err(SELHIDE_TAG "setprocattr_hook requires clean_access=1\n");
		return -EINVAL;
	}
	if (enable_setprocattr_hook && !have_setprocattr_target()) {
		pr_err(SELHIDE_TAG "setprocattr_hook requested but selinux_setprocattr is missing\n");
		return -ENOENT;
	}
	if (enable_setprocattr_hook &&
	    !p_static_calls_table && !p_security_hook_heads) {
		pr_err(SELHIDE_TAG "setprocattr_hook requested but LSM hook tables are missing\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

static void destroy_backup_policy(void)
{
	if (sidtab_inited && p_sidtab_destroy)
		selhide_call_sidtab_destroy(p_sidtab_destroy, &backup_sidtab);
	if (policydb_loaded && p_policydb_destroy)
		selhide_call_policydb_destroy(p_policydb_destroy,
					      &backup_policydb);
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
	if ((size_t)ret != size) {
		pr_err(SELHIDE_TAG "short policy read: %d != %zu\n", ret,
		       size);
		vfree(buf);
		return -EIO;
	}
	pr_info(SELHIDE_TAG "read %d bytes\n", ret);

	pf.data = buf;
	pf.len = size;

	ret = selhide_call_policydb_read(p_policydb_read, &backup_policydb,
					     &pf);
	vfree(buf);
	if (ret) { pr_err(SELHIDE_TAG "policydb_read: %d\n", ret); return ret; }
	policydb_loaded = true;
	pr_info(SELHIDE_TAG "policydb_read OK\n");

	ret = selhide_call_sidtab_init(p_sidtab_init, &backup_sidtab);
	if (ret) {
		pr_err(SELHIDE_TAG "sidtab_init: %d\n", ret);
		destroy_backup_policy();
		return ret;
	}
	sidtab_inited = true;
	pr_info(SELHIDE_TAG "sidtab_init OK\n");

	ret = selhide_call_policydb_load_isids(p_policydb_load_isids,
					       &backup_policydb,
					       &backup_sidtab);
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

	if (backup_policy_path && backup_policy_path[0]) {
		last = load_backup_policy_from(backup_policy_path);
		if (!last)
			return 0;
	}

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

static int lookup_clean_context(char *buf, size_t size, u32 *out_sid)
{
	size_t len;
	u32 sid;
	int ret;

	if (!policy_loaded || !clean_access_syms_ready())
		return -EAGAIN;

	len = strnlen(buf, size);
	if (len && buf[len - 1] == '\n')
		len--;
	if (!len)
		return -EINVAL;

	ret = backup_context_to_sid(buf, len, &sid, SECSID_NULL, GFP_KERNEL);
	if (ret)
		return ret;

	if (out_sid)
		*out_sid = sid;

	return 0;
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

	ret = selhide_call_write_op(orig_access_write, file, tmp, size);
	kfree(tmp);
	return ret;
}

#define SELHIDE_TRACE_QUERY_MAX 192

static atomic_t trace_access_seen = ATOMIC_INIT(0);
static atomic_t trace_context_seen = ATOMIC_INIT(0);
static atomic_t trace_setprocattr_seen = ATOMIC_INIT(0);

static char *trace_copy_query(const void *buf, size_t size, size_t *out_len)
{
	size_t len;
	char *query;

	if (!enable_trace_queries || !buf || !size)
		return NULL;

	len = min_t(size_t, size, SELHIDE_TRACE_QUERY_MAX);
	query = kmemdup_nul(buf, len, GFP_KERNEL);
	if (!query)
		return NULL;

	if (out_len)
		*out_len = strnlen(query, len);
	return query;
}

static bool trace_query_is_dirty(const char *query, size_t len)
{
	return strnstr(query, "magisk", len) ||
	       strnstr(query, "lsposed", len) ||
	       strnstr(query, "ksu", len) ||
	       strnstr(query, "xposed", len) ||
	       strnstr(query, "zygisk", len) ||
	       strnstr(query, "adbroot", len);
}

static bool trace_query_should_log(atomic_t *seen, bool dirty)
{
	int n;

	if (!enable_trace_queries)
		return false;
	if (dirty)
		return true;
	if (trace_query_limit <= 0)
		return false;

	n = atomic_inc_return(seen);
	return n <= trace_query_limit;
}

static void trace_access_query(const char *stage, const char *query,
			       size_t query_len, ssize_t ret, u16 tclass,
			       const struct av_decision *avd)
{
	bool dirty;

	if (!query)
		return;

	dirty = trace_query_is_dirty(query, query_len);
	if (!trace_query_should_log(&trace_access_seen, dirty))
		return;

	pr_info(SELHIDE_TAG "trace access[%s] pid=%d uid=%u appid=%u comm=%s ret=%zd tclass=%u allowed=0x%x flags=0x%x dirty=%d query=\"%.*s\"\n",
		stage, current->pid, (unsigned int)__kuid_val(current_uid()),
		current_android_appid(), current->comm, ret, tclass,
		avd ? avd->allowed : 0, avd ? avd->flags : 0, dirty,
		(int)query_len, query);
}

static void trace_context_query(const char *stage, const char *query,
				size_t query_len, ssize_t ret, u32 sid)
{
	bool dirty;

	if (!query)
		return;

	dirty = trace_query_is_dirty(query, query_len);
	if (!trace_query_should_log(&trace_context_seen, dirty))
		return;

	pr_info(SELHIDE_TAG "trace context[%s] pid=%d uid=%u appid=%u comm=%s ret=%zd sid=%u dirty=%d query=\"%.*s\"\n",
		stage, current->pid, (unsigned int)__kuid_val(current_uid()),
		current_android_appid(), current->comm, ret, sid, dirty,
		(int)query_len, query);
}

static void trace_setprocattr_query(const char *stage, const char *name,
				    const char *query, size_t query_len,
				    int ret, int clean_ret, u32 sid)
{
	bool dirty;

	if (!query)
		return;

	dirty = trace_query_is_dirty(query, query_len);
	if (!trace_query_should_log(&trace_setprocattr_seen, dirty))
		return;

	pr_info(SELHIDE_TAG "trace setprocattr[%s] pid=%d uid=%u appid=%u comm=%s name=%s ret=%d clean_ret=%d sid=%u dirty=%d query=\"%.*s\"\n",
		stage, current->pid, (unsigned int)__kuid_val(current_uid()),
		current_android_appid(), current->comm, name ? name : "?",
		ret, clean_ret, sid, dirty, (int)query_len, query);
}

static int read_kcfi_typeid(void *fn, u32 *typeid)
{
	if (!fn)
		return -EINVAL;

	return selhide_read_kernel_nofault(typeid,
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

static bool read_setprocattr_target_typeid(u32 *typeid)
{
	if (p_selinux_setprocattr &&
	    read_kcfi_typeid((void *)p_selinux_setprocattr, typeid) == 0)
		return true;
	if (p_selinux_setprocattr_cfi_jt &&
	    read_kcfi_typeid((void *)p_selinux_setprocattr_cfi_jt,
			     typeid) == 0)
		return true;
	return false;
}

static bool match_setprocattr_candidate(setprocattr_fn fn,
					bool have_target_typeid,
					u32 target_typeid,
					const char **kind)
{
	u32 candidate_typeid = 0;

	if (is_selinux_setprocattr_target(fn)) {
		*kind = setprocattr_target_kind(fn);
		return true;
	}

	if (!have_target_typeid || !fn)
		return false;
	if (read_kcfi_typeid((void *)fn, &candidate_typeid) ||
	    candidate_typeid != target_typeid)
		return false;

	*kind = "kcfi_typeid";
	return true;
}

static void probe_kcfi_targets(void)
{
	pr_info(SELHIDE_TAG "write_op[] at %p\n", p_write_op);
	log_kcfi_typeid("write_op[SEL_CONTEXT]", p_write_op[SEL_CONTEXT]);
	log_kcfi_typeid("write_op[SEL_ACCESS]", p_write_op[SEL_ACCESS]);

	if (p_selinux_setprocattr)
		log_kcfi_typeid("selinux_setprocattr",
				(void *)p_selinux_setprocattr);
	else
		pr_warn(SELHIDE_TAG "selinux_setprocattr not found\n");
	if (p_selinux_setprocattr_cfi_jt)
		log_kcfi_typeid("selinux_setprocattr.cfi_jt",
				(void *)p_selinux_setprocattr_cfi_jt);
}

ssize_t selhide_write_access_impl(struct file *file, char *buf, size_t size)
{
	static bool logged_passthrough;
	static bool logged_clean;
	static bool logged_fallback;
	struct av_decision avd;
	char *query = NULL;
	size_t query_len = 0;
	ssize_t length;
	u16 tclass = 0;
	bool selected;

	if (unlikely(!orig_access_write))
		return -EIO;

	query = trace_copy_query(buf, size, &query_len);
	selected = current_appid_is_selected();

	if (!enable_clean_access || !selected) {
		if (!logged_passthrough) {
			logged_passthrough = true;
			pr_info(SELHIDE_TAG "SEL_ACCESS passthrough hit\n");
		}
		length = selhide_call_write_op(orig_access_write, file, buf, size);
		trace_access_query(selected ? "passthrough" : "not-selected",
				   query, query_len, length, 0,
				   NULL);
		kfree(query);
		return length;
	}

	length = check_original_access(file, buf, size);
	if (length < 0) {
		trace_access_query("original-denied", query, query_len, length,
				   0, NULL);
		kfree(query);
		return length;
	}

	length = compute_clean_access_response(buf, size, &avd, &tclass);
	if (length == -EAGAIN) {
		if (!logged_fallback) {
			logged_fallback = true;
			pr_warn(SELHIDE_TAG "clean_access unavailable, falling back to original\n");
		}
		length = selhide_call_write_op(orig_access_write, file, buf, size);
		trace_access_query("fallback-original", query, query_len,
				   length, 0, NULL);
		kfree(query);
		return length;
	}

	if (length >= 0 && !logged_clean) {
		logged_clean = true;
		pr_info(SELHIDE_TAG "SEL_ACCESS clean_access hit\n");
		pr_info(SELHIDE_TAG "clean_access result tclass=%u allowed=0x%x flags=0x%x\n",
			tclass, avd.allowed, avd.flags);
	}

	trace_access_query(length >= 0 ? "clean" : "clean-error", query,
			   query_len, length, tclass,
			   length >= 0 ? &avd : NULL);
	kfree(query);
	return length;
}

ssize_t selhide_write_context_impl(struct file *file, char *buf, size_t size)
{
	static bool logged_passthrough;
	static bool logged_clean;
	static bool logged_hidden;
	static bool logged_fallback;
	char *query = NULL;
	size_t query_len = 0;
	ssize_t length;
	u32 sid = 0;
	bool selected;

	if (unlikely(!orig_context_write))
		return -EIO;

	query = trace_copy_query(buf, size, &query_len);
	selected = current_appid_is_selected();

	if (!enable_context_hook || !enable_clean_access || !selected) {
		if (!logged_passthrough) {
			logged_passthrough = true;
			pr_info(SELHIDE_TAG "SEL_CONTEXT passthrough hit\n");
		}
		length = selhide_call_write_op(orig_context_write, file, buf,
					       size);
		trace_context_query(selected ? "passthrough" : "not-selected",
				    query, query_len, length, 0);
		kfree(query);
		return length;
	}

	length = lookup_clean_context(buf, size, &sid);
	if (length == -EAGAIN) {
		if (!logged_fallback) {
			logged_fallback = true;
			pr_warn(SELHIDE_TAG "clean_context unavailable, falling back to original\n");
		}
		length = selhide_call_write_op(orig_context_write, file, buf,
					       size);
		trace_context_query("fallback-original", query, query_len,
				    length, 0);
		kfree(query);
		return length;
	}
	if (length < 0) {
		if (!logged_hidden) {
			logged_hidden = true;
			pr_info(SELHIDE_TAG "SEL_CONTEXT hidden dirty context -> %zd\n",
				length);
		}
		trace_context_query("hidden", query, query_len, length, 0);
		kfree(query);
		return length;
	}

	if (length >= 0 && !logged_clean) {
		logged_clean = true;
		pr_info(SELHIDE_TAG "SEL_CONTEXT clean_context hit sid=%u\n",
			sid);
	}

	/*
	 * Clean policy decides existence. Original handler still enforces the
	 * caller's check_context permission and canonicalizes the response.
	 */
	length = selhide_call_write_op(orig_context_write, file, buf, size);
	trace_context_query("clean", query, query_len, length, sid);
	kfree(query);
	return length;
}

int selhide_setprocattr_impl(const char *name, void *value, size_t size)
{
	static bool logged_hidden;
	static bool logged_passthrough;
	char *query = NULL;
	size_t query_len = 0;
	int ret;
	int clean_ret;
	u32 sid = 0;
	bool selected;

	if (unlikely(!orig_setprocattr))
		return -EIO;

	query = trace_copy_query(value, size, &query_len);
	ret = selhide_call_setprocattr(orig_setprocattr, name, value, size);
	selected = current_appid_is_selected();
	if (!enable_setprocattr_hook || !enable_clean_access || !selected) {
		trace_setprocattr_query(selected ? "disabled" : "not-selected",
					name, query, query_len, ret,
					0, 0);
		kfree(query);
		return ret;
	}
	if (ret != -EPERM) {
		trace_setprocattr_query("original", name, query, query_len, ret,
					0, 0);
		kfree(query);
		return ret;
	}
	if (!name || strcmp(name, "current") != 0 || !value || !size) {
		trace_setprocattr_query("ignored", name, query, query_len, ret,
					0, 0);
		kfree(query);
		return ret;
	}

	clean_ret = lookup_clean_context(value, size, &sid);
	if (clean_ret == -EAGAIN) {
		trace_setprocattr_query("fallback-original", name, query,
					query_len, ret, clean_ret, sid);
		kfree(query);
		return ret;
	}
	if (clean_ret == 0) {
		if (!logged_passthrough) {
			logged_passthrough = true;
			pr_info(SELHIDE_TAG "setprocattr current clean context preserved sid=%u\n",
				sid);
		}
		trace_setprocattr_query("clean", name, query, query_len, ret,
					clean_ret, sid);
		kfree(query);
		return ret;
	}
	if (clean_ret == -ENOMEM) {
		trace_setprocattr_query("nomem", name, query, query_len, ret,
					clean_ret, sid);
		kfree(query);
		return ret;
	}

	if (!logged_hidden) {
		logged_hidden = true;
		pr_info(SELHIDE_TAG "setprocattr current hidden dirty context -> EINVAL (clean_ret=%d)\n",
			clean_ret);
	}
	trace_setprocattr_query("hidden", name, query, query_len, -EINVAL,
				clean_ret, sid);
	kfree(query);
	return -EINVAL;
}

static int sync_wrapper_kcfi_typeid(const char *label, void *orig,
				    void *replacement, bool *synced)
{
	u32 orig_typeid = 0;
	u32 replacement_typeid = 0;
	int ret;

#if defined(CONFIG_CFI_CLANG)
	pr_info(SELHIDE_TAG "%s: CONFIG_CFI_CLANG active; using CFI jump table replacement and skipping KCFI word sync\n",
		label);
	*synced = true;
	return 0;
#endif

	ret = read_kcfi_typeid(orig, &orig_typeid);
	if (ret) {
		pr_err(SELHIDE_TAG "%s: read original KCFI failed: %d\n",
		       label, ret);
		return ret;
	}

	ret = read_kcfi_typeid(replacement, &replacement_typeid);
	if (ret) {
		pr_err(SELHIDE_TAG "%s: read replacement KCFI failed: %d\n",
		       label, ret);
		return ret;
	}
	if (replacement_typeid == orig_typeid) {
		pr_info(SELHIDE_TAG "%s: replacement KCFI already synced: 0x%08x\n",
			label, orig_typeid);
		*synced = true;
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
	pr_err(SELHIDE_TAG "%s: replacement KCFI mismatch on legacy kernel: 0x%08x != 0x%08x; rebuild with matching SELHIDE_WRITE_*_KCFI_WORD\n",
	       label, replacement_typeid, orig_typeid);
	return -EOPNOTSUPP;
#endif

	ret = selhide_patch_text((void *)((unsigned long)replacement - 4),
				 &orig_typeid, sizeof(orig_typeid),
					 SELHIDE_PATCH_FLUSH_DCACHE |
					 SELHIDE_PATCH_FLUSH_ICACHE);
	if (ret) {
		pr_err(SELHIDE_TAG "%s: patch replacement KCFI failed: %d\n",
		       label, ret);
		return ret;
	}

	ret = read_kcfi_typeid(replacement, &replacement_typeid);
	if (ret)
		return ret;
	if (replacement_typeid != orig_typeid) {
		pr_err(SELHIDE_TAG "%s: replacement KCFI mismatch: 0x%08x != 0x%08x\n",
		       label, replacement_typeid, orig_typeid);
		return -EINVAL;
	}

	pr_info(SELHIDE_TAG "%s: replacement KCFI synced: 0x%08x\n",
		label, orig_typeid);
	*synced = true;
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
	write_op_fn replacement = access_replacement_fn();
	int ret;

	ret = prepare_access_target();
	if (ret)
		return ret;

	pr_info(SELHIDE_TAG "patch self-test: sync wrapper only orig=%pS repl=%pS slot=%p current=%pS\n",
		orig_access_write, replacement, access_write_slot,
		READ_ONCE(*access_write_slot));

	ret = sync_wrapper_kcfi_typeid("SEL_ACCESS", (void *)orig_access_write,
				       (void *)replacement,
				       &access_wrapper_synced);
	if (ret)
		return ret;

	pr_info(SELHIDE_TAG "patch self-test OK; SEL_ACCESS slot still %pS\n",
		READ_ONCE(*access_write_slot));
	return 0;
}

static int install_access_passthrough_hook(void)
{
	write_op_fn replacement = access_replacement_fn();
	write_op_fn cur;
	int ret;

	ret = prepare_access_target();
	if (ret)
		return ret;
	if (orig_access_write == replacement) {
		pr_warn(SELHIDE_TAG "SEL_ACCESS hook already installed\n");
		access_hooked = true;
		return 0;
	}

	cur = READ_ONCE(*access_write_slot);
	if (cur != orig_access_write) {
		pr_err(SELHIDE_TAG "SEL_ACCESS slot changed before install: current=%pS expected=%pS\n",
		       cur, orig_access_write);
		return -EBUSY;
	}

	pr_info(SELHIDE_TAG "install SEL_ACCESS passthrough: orig=%pS repl=%pS slot=%p\n",
		orig_access_write, replacement, access_write_slot);

	if (!access_wrapper_synced) {
		ret = sync_wrapper_kcfi_typeid("SEL_ACCESS",
					       (void *)orig_access_write,
					       (void *)replacement,
					       &access_wrapper_synced);
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
	write_op_fn replacement = access_replacement_fn();
	write_op_fn cur;
	int ret;

	if (!access_hooked || !access_write_slot || !orig_access_write)
		return;

	cur = READ_ONCE(*access_write_slot);
	if (cur != replacement) {
		pr_warn(SELHIDE_TAG "skip SEL_ACCESS restore: slot=%pS expected=%pS\n",
			cur, replacement);
		access_hooked = false;
		return;
	}

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

static int prepare_context_target(void)
{
	context_write_slot = &p_write_op[SEL_CONTEXT];
	orig_context_write = READ_ONCE(*context_write_slot);
	if (!orig_context_write) {
		pr_err(SELHIDE_TAG "SEL_CONTEXT slot is NULL\n");
		return -ENOENT;
	}

	return 0;
}

static int install_context_hook(void)
{
	write_op_fn replacement = context_replacement_fn();
	write_op_fn cur;
	int ret;

	ret = prepare_context_target();
	if (ret)
		return ret;
	if (orig_context_write == replacement) {
		pr_warn(SELHIDE_TAG "SEL_CONTEXT hook already installed\n");
		context_hooked = true;
		return 0;
	}

	cur = READ_ONCE(*context_write_slot);
	if (cur != orig_context_write) {
		pr_err(SELHIDE_TAG "SEL_CONTEXT slot changed before install: current=%pS expected=%pS\n",
		       cur, orig_context_write);
		return -EBUSY;
	}

	pr_info(SELHIDE_TAG "install SEL_CONTEXT clean hook: orig=%pS repl=%pS slot=%p\n",
		orig_context_write, replacement, context_write_slot);

	if (!context_wrapper_synced) {
		ret = sync_wrapper_kcfi_typeid("SEL_CONTEXT",
					       (void *)orig_context_write,
					       (void *)replacement,
					       &context_wrapper_synced);
		if (ret)
			return ret;
	}

	ret = selhide_patch_text(context_write_slot, &replacement,
				 sizeof(replacement),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret) {
		pr_err(SELHIDE_TAG "patch SEL_CONTEXT slot failed: %d\n",
		       ret);
		return ret;
	}

	context_hooked = true;
	pr_info(SELHIDE_TAG "SEL_CONTEXT clean hook installed\n");
	return 0;
}

static void remove_context_hook(void)
{
	write_op_fn replacement = context_replacement_fn();
	write_op_fn cur;
	int ret;

	if (!context_hooked || !context_write_slot || !orig_context_write)
		return;

	cur = READ_ONCE(*context_write_slot);
	if (cur != replacement) {
		pr_warn(SELHIDE_TAG "skip SEL_CONTEXT restore: slot=%pS expected=%pS\n",
			cur, replacement);
		context_hooked = false;
		return;
	}

	ret = selhide_patch_text(context_write_slot, &orig_context_write,
				 sizeof(orig_context_write),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret)
		pr_err(SELHIDE_TAG "restore SEL_CONTEXT slot failed: %d\n",
		       ret);
	else {
		pr_info(SELHIDE_TAG "SEL_CONTEXT hook restored\n");
		context_hooked = false;
	}
}

#if SELHIDE_HAVE_SETPROCATTR_STATIC_CALLS
static int prepare_setprocattr_target(void)
{
	bool have_target_typeid;
	u32 target_typeid = 0;
	int i;

	if (!p_static_calls_table || !have_setprocattr_target())
		return -ENOENT;

	have_target_typeid = read_setprocattr_target_typeid(&target_typeid);
	for (i = 0; i < MAX_LSM_COUNT; i++) {
		struct lsm_static_call *scall =
			&p_static_calls_table->setprocattr[i];
		struct security_hook_list *hl = READ_ONCE(scall->hl);
		setprocattr_fn *slot;
		setprocattr_fn fn;
		const char *kind;

		if (!hl)
			continue;
		slot = &hl->hook.setprocattr;
		fn = READ_ONCE(*slot);
		if (!match_setprocattr_candidate(fn, have_target_typeid,
						 target_typeid, &kind))
			continue;

		setprocattr_slot = slot;
		orig_setprocattr = fn;
		pr_info(SELHIDE_TAG "found SELinux setprocattr hook slot=%p fn=%pS kind=%s lsm=%s\n",
			setprocattr_slot, orig_setprocattr, kind,
			hl->lsmid ? hl->lsmid->name : "?");
		return 0;
	}

	pr_err(SELHIDE_TAG "SELinux setprocattr hook slot not found\n");
	return -ENOENT;
}
#else
static int find_legacy_setprocattr_by_scan(void)
{
	const unsigned int head_limit = 320;
	const unsigned int node_limit = 24;
	const long window = 160;
	unsigned long base = (unsigned long)p_security_hook_heads;
	bool have_target_typeid;
	u32 target_typeid = 0;
	unsigned int i;

	if (!base || !have_setprocattr_target())
		return -ENOENT;

	have_target_typeid = read_setprocattr_target_typeid(&target_typeid);
	for (i = 0; i < head_limit; i++) {
		unsigned long head = base + i * sizeof(unsigned long);
		unsigned long node = 0;
		unsigned int depth;

		if (selhide_read_kernel_nofault(&node, (void *)head,
						sizeof(node)) || !node)
			continue;

		for (depth = 0; depth < node_limit && node; depth++) {
			long off;
			unsigned long next = 0;

			for (off = -window; off <= window;
			     off += (long)sizeof(unsigned long)) {
				unsigned long addr = node + off;
				unsigned long val = 0;
				const char *kind;

				if (selhide_read_kernel_nofault(&val,
								(void *)addr,
								sizeof(val)))
					continue;
				if (!match_setprocattr_candidate(
						(setprocattr_fn)val,
						have_target_typeid,
						target_typeid, &kind))
					continue;

				setprocattr_slot = (setprocattr_fn *)addr;
				orig_setprocattr = (setprocattr_fn)val;
				pr_info(SELHIDE_TAG "found scanned SELinux setprocattr hook slot=%p fn=%pS kind=%s head_idx=%u depth=%u node=%px off=%ld\n",
					setprocattr_slot, orig_setprocattr,
					kind, i, depth, (void *)node, off);
				return 0;
			}

			if (selhide_read_kernel_nofault(&next, (void *)node,
							sizeof(next)))
				break;
			node = next;
		}
	}

	return -ENOENT;
}

static int prepare_setprocattr_target(void)
{
	struct security_hook_list *hl;
	bool have_target_typeid;
	u32 target_typeid = 0;
	int ret;

	if (!p_security_hook_heads || !have_setprocattr_target())
		return -ENOENT;

	have_target_typeid = read_setprocattr_target_typeid(&target_typeid);
	hlist_for_each_entry(hl, &p_security_hook_heads->setprocattr, list) {
		setprocattr_fn *slot = &hl->hook.setprocattr;
		setprocattr_fn fn = READ_ONCE(*slot);
		const char *kind;

		if (!match_setprocattr_candidate(fn, have_target_typeid,
						 target_typeid, &kind))
			continue;

		setprocattr_slot = slot;
		orig_setprocattr = fn;
		pr_info(SELHIDE_TAG "found legacy SELinux setprocattr hook slot=%p fn=%pS kind=%s lsm=%s\n",
			setprocattr_slot, orig_setprocattr, kind,
			hl->lsm ? hl->lsm : "?");
		return 0;
	}

	ret = find_legacy_setprocattr_by_scan();
	if (ret)
		pr_err(SELHIDE_TAG "legacy SELinux setprocattr hook slot not found\n");
	return ret;
}
#endif

static int install_setprocattr_hook(void)
{
	setprocattr_fn replacement = setprocattr_replacement_fn();
	setprocattr_fn cur;
	int ret;

	ret = prepare_setprocattr_target();
	if (ret)
		return ret;
	if (orig_setprocattr == replacement) {
		pr_warn(SELHIDE_TAG "setprocattr hook already installed\n");
		setprocattr_hooked = true;
		return 0;
	}

	cur = READ_ONCE(*setprocattr_slot);
	if (cur != orig_setprocattr) {
		pr_err(SELHIDE_TAG "setprocattr slot changed before install: current=%pS expected=%pS\n",
		       cur, orig_setprocattr);
		return -EBUSY;
	}

	pr_info(SELHIDE_TAG "install setprocattr clean hook: orig=%pS repl=%pS slot=%p\n",
		orig_setprocattr, replacement, setprocattr_slot);

	if (!setprocattr_wrapper_synced) {
		ret = sync_wrapper_kcfi_typeid("setprocattr",
					       (void *)orig_setprocattr,
					       (void *)replacement,
					       &setprocattr_wrapper_synced);
		if (ret)
			return ret;
	}

	ret = selhide_patch_text(setprocattr_slot, &replacement,
				 sizeof(replacement),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret) {
		pr_err(SELHIDE_TAG "patch setprocattr slot failed: %d\n",
		       ret);
		return ret;
	}

	setprocattr_hooked = true;
	pr_info(SELHIDE_TAG "setprocattr clean hook installed\n");
	return 0;
}

static void remove_setprocattr_hook(void)
{
	setprocattr_fn replacement = setprocattr_replacement_fn();
	setprocattr_fn cur;
	int ret;

	if (!setprocattr_hooked || !setprocattr_slot || !orig_setprocattr)
		return;

	cur = READ_ONCE(*setprocattr_slot);
	if (cur != replacement) {
		pr_warn(SELHIDE_TAG "skip setprocattr restore: slot=%pS expected=%pS\n",
			cur, replacement);
		setprocattr_hooked = false;
		return;
	}

	ret = selhide_patch_text(setprocattr_slot, &orig_setprocattr,
				 sizeof(orig_setprocattr),
				 SELHIDE_PATCH_FLUSH_DCACHE);
	if (ret)
		pr_err(SELHIDE_TAG "restore setprocattr slot failed: %d\n",
		       ret);
	else {
		pr_info(SELHIDE_TAG "setprocattr hook restored\n");
		setprocattr_hooked = false;
	}
}

int __init selhide_real_init(void)
{
	int ret;
	pr_info(SELHIDE_TAG "phase0 loading (built_lvc=%u.%u.%u code=%d)\n",
		(unsigned int)LINUX_VERSION_MAJOR,
		(unsigned int)LINUX_VERSION_PATCHLEVEL,
		(unsigned int)LINUX_VERSION_SUBLEVEL,
		LINUX_VERSION_CODE);

	ret = resolve_kallsyms();
	if (ret) return ret;

	ret = resolve_syms();
	if (ret) return ret;

	probe_kcfi_targets();

	if (enable_clean_access) {
		ret = load_backup_policy();
		if (ret) {
			pr_err(SELHIDE_TAG "load_backup_policy failed: %d\n", ret);
			return ret;
		}
	} else {
		pr_info(SELHIDE_TAG "clean_access disabled; skipping policy load\n");
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

	if (enable_context_hook) {
		ret = install_context_hook();
		if (ret) {
			remove_access_hook();
			return ret;
		}
	} else {
		pr_info(SELHIDE_TAG "SEL_CONTEXT hook disabled (context_hook=0)\n");
	}

	if (enable_setprocattr_hook) {
		ret = install_setprocattr_hook();
		if (ret) {
			remove_context_hook();
			remove_access_hook();
			return ret;
		}
	} else {
		pr_info(SELHIDE_TAG "setprocattr hook disabled (setprocattr_hook=0)\n");
	}

	pr_info(SELHIDE_TAG "phase0 success\n");
	return 0;
}

void __exit selhide_real_exit(void)
{
	bool had_policy = policy_loaded;
	bool was_hooked = access_hooked;
	bool had_context_hook = context_hooked;
	bool had_setprocattr_hook = setprocattr_hooked;

	remove_setprocattr_hook();
	remove_context_hook();
	remove_access_hook();
	pr_info(SELHIDE_TAG "phase0 unloaded (policy_loaded=%d access_hooked=%d context_hooked=%d setprocattr_hooked=%d)\n",
		had_policy, was_hooked, had_context_hook,
		had_setprocattr_hook);
	destroy_backup_policy();
}

#ifndef SELHIDE_ASM_INIT
module_init(selhide_real_init);
module_exit(selhide_real_exit);
#endif

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("selhide");
MODULE_DESCRIPTION("selhide phase0 probe + guarded SEL_ACCESS/SEL_CONTEXT/setprocattr hooks");
MODULE_VERSION("p0.14-applylist-exp");
