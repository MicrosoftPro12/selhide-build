// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal KernelSU-style module loader for Android/aarch64 testing.
 *
 * It mirrors userspace/ksuinit/src/lib.rs from KernelSU:
 *   1. read a .ko into memory
 *   2. resolve SHN_UNDEF symbols from /proc/kallsyms
 *   3. rewrite those symbols to SHN_ABS with absolute kernel addresses
 *   4. call init_module(2) on the modified in-memory image
 *
 * This is intentionally small and ELF64 little-endian only.
 */

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

struct unresolved {
	const char *name;
	Elf64_Sym *sym;
	bool resolved;
};

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-n|--dry-run] [--check-vermagic] [--force-vermagic] [-o patched.ko] module.ko [params...]\n"
		"\n"
		"By default, real loads require either exact module vermagic release\n"
		"or Android KMI-compatible modversions suffix matching. Dry-runs are\n"
		"always allowed. Set ALLOW_UNSAFE_MODULE_LOAD=YES or pass\n"
		"--force-vermagic to override.\n",
		argv0);
}

static int read_file_impl(const char *path, unsigned char **out, size_t *out_len,
			  bool noisy)
{
	int fd;
	struct stat st;
	unsigned char *buf;
	size_t off = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (noisy)
			perror("open module");
		return -1;
	}
	if (fstat(fd, &st) < 0 || st.st_size <= 0) {
		if (noisy)
			perror("stat module");
		close(fd);
		return -1;
	}
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		if (noisy)
			perror("malloc module");
		close(fd);
		return -1;
	}
	while (off < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (noisy)
				perror("read module");
			free(buf);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);
	if (off != (size_t)st.st_size) {
		if (noisy)
			fprintf(stderr, "short read: %zu/%zu\n", off, (size_t)st.st_size);
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = off;
	return 0;
}

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
	return read_file_impl(path, out, out_len, true);
}

static int read_file_quiet(const char *path, unsigned char **out, size_t *out_len)
{
	return read_file_impl(path, out, out_len, false);
}

static int write_file(const char *path, const void *buf, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	size_t off = 0;

	if (fd < 0) {
		perror("open output");
		return -1;
	}
	while (off < len) {
		ssize_t n = write(fd, (const unsigned char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("write output");
			close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	return 0;
}

static bool valid_range(size_t len, uint64_t off, uint64_t size)
{
	return off <= len && size <= len - off;
}

static const char *section_name(const unsigned char *buf, size_t len,
				const Elf64_Ehdr *eh, const Elf64_Shdr *shdrs,
				const Elf64_Shdr *sh)
{
	const Elf64_Shdr *shstr;
	const char *names;

	if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum)
		return NULL;
	shstr = &shdrs[eh->e_shstrndx];
	if (!valid_range(len, shstr->sh_offset, shstr->sh_size) ||
	    sh->sh_name >= shstr->sh_size)
		return NULL;
	names = (const char *)buf + shstr->sh_offset;
	return names + sh->sh_name;
}

static int parse_elf_sections(unsigned char *buf, size_t len, Elf64_Ehdr **out_eh,
			      Elf64_Shdr **out_shdrs)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;

	if (len < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
	    eh->e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh->e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh->e_shentsize != sizeof(Elf64_Shdr) ||
	    !valid_range(len, eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr))) {
		fprintf(stderr, "unsupported or malformed ELF module\n");
		return -1;
	}

	*out_eh = eh;
	*out_shdrs = (Elf64_Shdr *)(buf + eh->e_shoff);
	return 0;
}

static char *dup_cstr(const char *s, size_t len)
{
	char *out;

	out = malloc(len + 1);
	if (!out)
		return NULL;
	memcpy(out, s, len);
	out[len] = '\0';
	return out;
}

static char *modinfo_value(unsigned char *buf, size_t len, const char *key)
{
	Elf64_Ehdr *eh;
	Elf64_Shdr *shdrs;
	size_t key_len = strlen(key);

	if (parse_elf_sections(buf, len, &eh, &shdrs))
		return NULL;

	for (int i = 0; i < eh->e_shnum; i++) {
		const Elf64_Shdr *sh = &shdrs[i];
		const char *name = section_name(buf, len, eh, shdrs, sh);
		const char *p, *end;

		if (!name || strcmp(name, ".modinfo") != 0)
			continue;
		if (!valid_range(len, sh->sh_offset, sh->sh_size))
			return NULL;

		p = (const char *)buf + sh->sh_offset;
		end = p + sh->sh_size;
		while (p < end) {
			size_t left = (size_t)(end - p);
			size_t n = strnlen(p, left);

			if (n == left)
				break;
			if (n > key_len && !memcmp(p, key, key_len) && p[key_len] == '=')
				return dup_cstr(p + key_len + 1, n - key_len - 1);
			p += n + 1;
		}
	}

	return NULL;
}

static bool has_section(unsigned char *buf, size_t len, const char *needle)
{
	Elf64_Ehdr *eh;
	Elf64_Shdr *shdrs;

	if (parse_elf_sections(buf, len, &eh, &shdrs))
		return false;

	for (int i = 0; i < eh->e_shnum; i++) {
		const char *name = section_name(buf, len, eh, shdrs, &shdrs[i]);

		if (name && strcmp(name, needle) == 0)
			return true;
	}

	return false;
}

static bool module_has_modversions(unsigned char *buf, size_t len)
{
	return has_section(buf, len, "__versions") ||
	       has_section(buf, len, "__version_ext_names") ||
	       has_section(buf, len, "__version_ext_crcs");
}

static const char *vermagic_suffix(const char *vermagic)
{
	const char *space;

	if (!vermagic)
		return NULL;
	space = strchr(vermagic, ' ');
	return space ? space : "";
}

static bool vermagic_release_matches(const char *vermagic, const char *release)
{
	size_t release_len;

	if (!vermagic || !release)
		return false;
	release_len = strcspn(vermagic, " ");
	return strlen(release) == release_len &&
	       strncmp(vermagic, release, release_len) == 0;
}

static bool starts_with(const char *s, const char *prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool ends_with(const char *s, const char *suffix)
{
	size_t slen = strlen(s), suffix_len = strlen(suffix);

	return slen >= suffix_len && strcmp(s + slen - suffix_len, suffix) == 0;
}

static char *reference_vermagic_from_text_file(const char *path)
{
	FILE *fp;
	char line[1024];
	size_t len;

	fp = fopen(path, "re");
	if (!fp)
		return NULL;
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	len = strcspn(line, "\r\n");
	if (len == 0)
		return NULL;
	return dup_cstr(line, len);
}

static char *module_vermagic_from_path(const char *path)
{
	unsigned char *buf = NULL;
	size_t len = 0;
	char *vermagic;

	if (read_file_quiet(path, &buf, &len))
		return NULL;
	vermagic = modinfo_value(buf, len, "vermagic");
	free(buf);
	return vermagic;
}

static char *find_reference_vermagic_in_dir(const char *dir, int depth,
					    char *path_out, size_t path_out_len)
{
	DIR *dp;
	struct dirent *de;
	char *vermagic = NULL;

	dp = opendir(dir);
	if (!dp)
		return NULL;

	while ((de = readdir(dp)) != NULL) {
		char path[PATH_MAX];
		struct stat st;

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path))
			continue;
		if (stat(path, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode) && depth > 0) {
			vermagic = find_reference_vermagic_in_dir(path, depth - 1,
								  path_out, path_out_len);
			if (vermagic)
				break;
			continue;
		}
		if (!S_ISREG(st.st_mode) || !ends_with(de->d_name, ".ko"))
			continue;

		vermagic = module_vermagic_from_path(path);
		if (vermagic) {
			snprintf(path_out, path_out_len, "%s", path);
			break;
		}
	}

	closedir(dp);
	return vermagic;
}

static char *find_reference_vermagic(char *path_out, size_t path_out_len)
{
	static const char *const dirs[] = {
		"/vendor/lib/modules",
		"/vendor_dlkm/lib/modules",
		"/odm/lib/modules",
		"/odm_dlkm/lib/modules",
		"/system/lib/modules",
		"/system_dlkm/lib/modules",
		"/lib/modules",
	};
	const char *env_vermagic = getenv("SELHIDE_REFERENCE_VERMAGIC");
	const char *env_file = getenv("SELHIDE_REFERENCE_VERMAGIC_FILE");
	static const char *const files[] = {
		"./reference_vermagic.txt",
		"../reference_vermagic.txt",
	};

	if (env_vermagic && env_vermagic[0]) {
		snprintf(path_out, path_out_len, "env:SELHIDE_REFERENCE_VERMAGIC");
		return dup_cstr(env_vermagic, strlen(env_vermagic));
	}
	if (env_file && env_file[0]) {
		char *vermagic = reference_vermagic_from_text_file(env_file);

		if (vermagic) {
			snprintf(path_out, path_out_len, "file:%s", env_file);
			return vermagic;
		}
	}
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		char *vermagic = reference_vermagic_from_text_file(files[i]);

		if (vermagic) {
			snprintf(path_out, path_out_len, "file:%s", files[i]);
			return vermagic;
		}
	}

	path_out[0] = '\0';
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		char *vermagic = find_reference_vermagic_in_dir(dirs[i], 2,
								path_out, path_out_len);

		if (vermagic)
			return vermagic;
	}

	return NULL;
}

static bool unsafe_load_allowed(bool force_vermagic)
{
	const char *env = getenv("ALLOW_UNSAFE_MODULE_LOAD");

	return force_vermagic || (env && strcmp(env, "YES") == 0);
}

static int check_vermagic_guard(unsigned char *buf, size_t len, bool dry_run,
				bool force_vermagic)
{
	struct utsname uts;
	char *vermagic;
	char *ref_vermagic = NULL;
	char ref_path[PATH_MAX];
	const char *module_suffix;
	const char *ref_suffix;
	size_t release_len;
	bool release_match;
	bool ref_release_match = false;
	bool ref_is_user_supplied = false;
	const char *allow_ref_mismatch;
	bool suffix_match = false;
	bool has_modversions;

	vermagic = modinfo_value(buf, len, "vermagic");
	has_modversions = module_has_modversions(buf, len);
	module_suffix = vermagic_suffix(vermagic);
	if (uname(&uts) < 0) {
		perror("uname");
		free(vermagic);
		return -1;
	}

	fprintf(stderr, "running_release=%s\n", uts.release);
	fprintf(stderr, "module_vermagic=%s\n", vermagic ? vermagic : "(missing)");
	fprintf(stderr, "module_has_modversions=%s\n", has_modversions ? "yes" : "no");

	if (dry_run) {
		fprintf(stderr, "vermagic_guard=dry-run-only\n");
		free(vermagic);
		return 0;
	}

	if (!vermagic) {
		if (unsafe_load_allowed(force_vermagic)) {
			fprintf(stderr, "vermagic_guard=override-missing\n");
			return 0;
		}
		fprintf(stderr,
			"ERROR: refusing to load module without vermagic; set "
			"ALLOW_UNSAFE_MODULE_LOAD=YES only for deliberate crash testing\n");
		return -1;
	}

	release_len = strcspn(vermagic, " ");
	release_match = vermagic_release_matches(vermagic, uts.release);

	ref_vermagic = find_reference_vermagic(ref_path, sizeof(ref_path));
	ref_suffix = vermagic_suffix(ref_vermagic);
	if (ref_vermagic) {
		fprintf(stderr, "reference_module=%s\n", ref_path);
		fprintf(stderr, "reference_vermagic=%s\n", ref_vermagic);
		ref_release_match = vermagic_release_matches(ref_vermagic, uts.release);
		ref_is_user_supplied = starts_with(ref_path, "env:") ||
				       starts_with(ref_path, "file:");
		fprintf(stderr, "reference_release_match=%s\n",
			ref_release_match ? "yes" : "no");
	} else {
		fprintf(stderr, "reference_vermagic=(missing)\n");
	}

	if (module_suffix && module_suffix[0] && ref_suffix && ref_suffix[0])
		suffix_match = strcmp(module_suffix, ref_suffix) == 0;
	fprintf(stderr, "module_vermagic_suffix=%s\n",
		module_suffix && module_suffix[0] ? module_suffix : "(missing)");
	fprintf(stderr, "reference_vermagic_suffix=%s\n",
		ref_suffix && ref_suffix[0] ? ref_suffix : "(missing)");

	if (release_match &&
	    (!ref_vermagic || suffix_match || (ref_is_user_supplied && !ref_release_match))) {
		fprintf(stderr, "vermagic_guard=exact-release-match%s\n",
			!ref_vermagic ? "" :
			suffix_match ? "+suffix-match" : "+ignored-stale-user-reference");
		free(ref_vermagic);
		free(vermagic);
		return 0;
	}

	allow_ref_mismatch = getenv("ALLOW_REFERENCE_RELEASE_MISMATCH");
	if (!release_match && has_modversions && suffix_match &&
	    (!ref_is_user_supplied || ref_release_match ||
	     (allow_ref_mismatch && strcmp(allow_ref_mismatch, "YES") == 0))) {
		fprintf(stderr, "vermagic_guard=kmi-compatible-modversions\n");
		free(ref_vermagic);
		free(vermagic);
		return 0;
	}

	if (unsafe_load_allowed(force_vermagic)) {
		fprintf(stderr, "vermagic_guard=override-mismatch\n");
		free(ref_vermagic);
		free(vermagic);
		return 0;
	}

	fprintf(stderr,
		"ERROR: refusing to load vermagic-mismatched module\n"
		"       module release: %.*s\n"
		"       running uname:  %s\n"
		"       module suffix:  %s\n"
		"       reference suffix: %s\n"
		"       modversions:    %s\n"
		"       ref release ok: %s\n"
		"       dry-run is still allowed; override only for deliberate crash testing\n",
		(int)release_len, vermagic, uts.release,
		module_suffix && module_suffix[0] ? module_suffix : "(missing)",
		ref_suffix && ref_suffix[0] ? ref_suffix : "(missing)",
		has_modversions ? "yes" : "no",
		!ref_vermagic ? "n/a" :
		(!ref_is_user_supplied || ref_release_match ? "yes" : "no"));
	free(ref_vermagic);
	free(vermagic);
	return -1;
}

static char *join_params(int argc, char **argv, int first)
{
	size_t len = 1;
	char *params;

	for (int i = first; i < argc; i++)
		len += strlen(argv[i]) + 1;
	params = calloc(1, len);
	if (!params)
		return NULL;
	for (int i = first; i < argc; i++) {
		if (i != first)
			strcat(params, " ");
		strcat(params, argv[i]);
	}
	return params;
}

static void strip_kallsyms_suffix(char *name)
{
	char *p = strchr(name, '$');
	char *q = strstr(name, ".llvm.");

	if (!p || (q && q < p))
		p = q;
	if (p)
		*p = '\0';
}

static int set_kptr_restrict(char *old, size_t old_len)
{
	int fd;
	ssize_t n;

	fd = open("/proc/sys/kernel/kptr_restrict", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, old, old_len - 1);
	if (n < 0) {
		close(fd);
		return -1;
	}
	old[n] = '\0';
	if (lseek(fd, 0, SEEK_SET) >= 0) {
		ssize_t wr = write(fd, "1\n", 2);

		if (wr < 0) {
			close(fd);
			return -1;
		}
	}
	close(fd);
	return 0;
}

static void restore_kptr_restrict(const char *old)
{
	int fd;

	if (!old || !old[0])
		return;
	fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (write(fd, old, strlen(old)) < 0) {
		close(fd);
		return;
	}
	close(fd);
}

static int collect_unresolved(unsigned char *buf, size_t len,
			      struct unresolved **out, size_t *out_count)
{
	Elf64_Ehdr *eh;
	Elf64_Shdr *shdrs;
	struct unresolved *items = NULL;
	size_t count = 0, cap = 0;

	if (parse_elf_sections(buf, len, &eh, &shdrs))
		return -1;

	for (int i = 0; i < eh->e_shnum; i++) {
		Elf64_Shdr *symsec = &shdrs[i];
		Elf64_Shdr *strsec;
		Elf64_Sym *syms;
		const char *strtab;
		size_t nsyms;

		if (symsec->sh_type != SHT_SYMTAB)
			continue;
		if (symsec->sh_entsize != sizeof(Elf64_Sym) ||
		    symsec->sh_link >= eh->e_shnum ||
		    !valid_range(len, symsec->sh_offset, symsec->sh_size))
			continue;

		strsec = &shdrs[symsec->sh_link];
		if (!valid_range(len, strsec->sh_offset, strsec->sh_size))
			continue;

		syms = (Elf64_Sym *)(buf + symsec->sh_offset);
		nsyms = symsec->sh_size / sizeof(Elf64_Sym);
		strtab = (const char *)(buf + strsec->sh_offset);

		for (size_t j = 1; j < nsyms; j++) {
			const char *name;

			if (syms[j].st_shndx != SHN_UNDEF || syms[j].st_name >= strsec->sh_size)
				continue;
			name = strtab + syms[j].st_name;
			if (!name[0])
				continue;
			if (count == cap) {
				size_t new_cap = cap ? cap * 2 : 64;
				void *tmp = realloc(items, new_cap * sizeof(*items));
				if (!tmp) {
					perror("realloc unresolved");
					free(items);
					return -1;
				}
				items = tmp;
				cap = new_cap;
			}
			items[count++] = (struct unresolved){
				.name = name,
				.sym = &syms[j],
				.resolved = false,
			};
		}
	}

	*out = items;
	*out_count = count;
	return 0;
}

static size_t resolve_from_kallsyms(struct unresolved *items, size_t count)
{
	FILE *fp;
	char old_kptr[32] = {};
	char line[1024];
	size_t left = count;

	(void)set_kptr_restrict(old_kptr, sizeof(old_kptr));
	fp = fopen("/proc/kallsyms", "re");
	if (!fp) {
		perror("open kallsyms");
		restore_kptr_restrict(old_kptr);
		return left;
	}

	while (left && fgets(line, sizeof(line), fp)) {
		unsigned long long addr = 0;
		char type = 0, name[512] = {}, extra[128] = {};
		int fields = sscanf(line, "%llx %c %511s %127s", &addr, &type, name, extra);

		if (fields >= 4)
			break; /* KernelSU stops before module symbols. */
		if (fields < 3 || addr == 0)
			continue;
		strip_kallsyms_suffix(name);
		for (size_t i = 0; i < count; i++) {
			if (items[i].resolved || strcmp(items[i].name, name) != 0)
				continue;
			items[i].sym->st_shndx = SHN_ABS;
			items[i].sym->st_value = (Elf64_Addr)addr;
			items[i].resolved = true;
			left--;
		}
	}

	fclose(fp);
	restore_kptr_restrict(old_kptr);
	return left;
}

int main(int argc, char **argv)
{
	bool dry_run = false;
	bool check_vermagic_only = false;
	bool force_vermagic = false;
	const char *out_path = NULL;
	const char *module_path;
	unsigned char *buf = NULL;
	size_t len = 0, count = 0, left;
	struct unresolved *items = NULL;
	char *params = NULL;
	int argi = 1;
	long ret;

	while (argi < argc) {
		if (!strcmp(argv[argi], "-n") || !strcmp(argv[argi], "--dry-run")) {
			dry_run = true;
			argi++;
		} else if (!strcmp(argv[argi], "--check-vermagic")) {
			check_vermagic_only = true;
			argi++;
		} else if (!strcmp(argv[argi], "--force-vermagic")) {
			force_vermagic = true;
			argi++;
		} else if (!strcmp(argv[argi], "-o") && argi + 1 < argc) {
			out_path = argv[argi + 1];
			argi += 2;
		} else {
			break;
		}
	}
	if (argi >= argc) {
		usage(argv[0]);
		return 64;
	}

	module_path = argv[argi++];
	params = join_params(argc, argv, argi);
	if (!params) {
		perror("params");
		return 1;
	}
	if (read_file(module_path, &buf, &len))
		return 1;
	if (check_vermagic_guard(buf, len, dry_run && !check_vermagic_only, force_vermagic))
		return 3;
	if (check_vermagic_only) {
		free(params);
		free(buf);
		return 0;
	}
	if (collect_unresolved(buf, len, &items, &count))
		return 1;

	fprintf(stderr, "module=%s size=%zu unresolved=%zu\n", module_path, len, count);
	left = resolve_from_kallsyms(items, count);
	fprintf(stderr, "resolved=%zu unresolved_left=%zu\n", count - left, left);
	for (size_t i = 0; i < count; i++) {
		if (!items[i].resolved)
			fprintf(stderr, "warn: unresolved: %s\n", items[i].name);
	}

	if (out_path && write_file(out_path, buf, len))
		return 1;
	if (dry_run) {
		free(items);
		free(params);
		free(buf);
		return left ? 2 : 0;
	}

	ret = syscall(__NR_init_module, buf, len, params);
	if (ret < 0) {
		fprintf(stderr, "init_module failed: %s (errno=%d)\n", strerror(errno), errno);
		return 1;
	}

	free(items);
	free(params);
	free(buf);
	return 0;
}
