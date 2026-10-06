#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/pgtable.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#include <linux/compiler.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <linux/ptrace.h>
#include <linux/fcntl.h>
#include <linux/jump_label.h>

#include "objsec.h"

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif

// Declaration for the chroot check
extern bool current_chrooted(void);

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "compat/kernel_compat.h"
#include "sucompat.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "sulog/event.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

DEFINE_STATIC_KEY_TRUE(ksu_su_compat_enabled);

static int su_compat_feature_get(u64 *value)
{
	*value = static_key_enabled(&ksu_su_compat_enabled) ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	if (enable)
		static_branch_enable(&ksu_su_compat_enabled);
	else
		static_branch_disable(&ksu_su_compat_enabled);
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	unsigned long sp = current_user_stack_pointer();
	sp = (sp - len - 256) & ~0xFUL; 

	char __user *p = (char __user *)sp;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
		int *mode, int *__unused_flags)
{
	const char su[] = SU_PATH;

	if (!static_branch_likely(&ksu_su_compat_enabled)) {
		return 0;
	}

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		return 0;
	}

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		if (current_chrooted()) {
			pr_err("ksu_handle_faccessat: su found but NOT allowed! Because current process is running in chrooted environment\n");
			return 0;
		}
		ksu_compat_sulog('a');
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	const char su[] = SU_PATH;

	if (!static_branch_likely(&ksu_su_compat_enabled)){
		return 0;
	}

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		return 0;
	}

	if (unlikely(!filename_user)) {
		return 0;
	}

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		if (current_chrooted()) {
			pr_err("ksu_handle_stat: su found but NOT allowed! Because current process is running in chrooted environment\n");
			return 0;
		}
		ksu_compat_sulog('s');
		pr_info("newfstatat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#ifdef CONFIG_KSU_SUSFS
static bool ksu_str_ends_with(const char *str, size_t str_len, const char *suffix)
{
	size_t suffix_len = strlen(suffix);
	if (suffix_len > str_len)
		return false;
	return memcmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

static bool ksu_is_zygote_or_adbd(const char *name, size_t len)
{
	if (len < 5)
		return false;
	char last = name[len - 1];
	if (last == 'd')
		return ksu_str_ends_with(name, len, "/adbd");
	if (last == 's')
		return ksu_str_ends_with(name, len, "/app_process");
	if (last == '2')
		return ksu_str_ends_with(name, len, "/app_process32");
	if (last == '4')
		return ksu_str_ends_with(name, len, "/app_process64");
	if (last == 'e')
		return ksu_str_ends_with(name, len, "/stub_zygote");
	return false;
}
#endif

static long ksu_handle_execve_sucompat_common(const char __user **filename_user,
		const char __user *const __user *argv_user, bool execveat,
		const struct pt_regs *regs)
{
	const char su[] = SU_PATH;
	const char __user *fn;
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	char path[sizeof(su) + 1];
	long ret;
	unsigned long addr;

	if (execveat && ((int)PT_REGS_PARM1(regs) != AT_FDCWD ||
			 (int)PT_REGS_SYSCALL_PARM4(regs) != 0))
		goto do_orig_execve;

	if (unlikely(!filename_user))
		goto do_orig_execve;

	addr = untagged_addr((unsigned long)*filename_user);
	fn = (const char __user *)addr;

#ifdef CONFIG_KSU_SUSFS
	{
		char full_path[256];
		memset(full_path, 0, sizeof(full_path));
		strncpy_from_user_nofault(full_path, fn, sizeof(full_path) - 1);
		size_t path_len = strlen(full_path);
		if (likely(!ksu_is_zygote_or_adbd(full_path, path_len)) && !susfs_is_current_proc_no_su()) {
			susfs_set_current_proc_no_su();
		}
	}
#endif

	if (!static_branch_likely(&ksu_su_compat_enabled))
		goto do_orig_execve;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig_execve;

	memset(path, 0, sizeof(path));

	ret = strncpy_from_user_nofault(path, fn, sizeof(path));
	if (ret < 0 && preempt_count()) {
		preempt_enable_no_resched_notrace();
		ret = strncpy_from_user(path, fn, sizeof(path));
		preempt_disable_notrace();
	}

	if (ret < 0) {
		goto do_orig_execve;
	}

	if (likely(memcmp(path, su, sizeof(su))))
		goto do_orig_execve;

	if (current_chrooted()) {
		pr_err("ksu_handle_execve_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
		goto do_orig_execve;
	}

	ksu_compat_sulog('x');

	pr_info("sys_execve su found\n");
	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	*filename_user = ksud_user_path();

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
		ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
		goto do_orig_execve;
	}
	if (preempt_count() > 0) {
		*filename_user = ksud_user_path();
	} else {
		struct file *f = ksu_filp_open_compat(KSUD_PATH, O_RDONLY, 0);
		if (IS_ERR(f)) {
			pr_warn("ksud inaccesible, aplicando fallback a sh\n");
			ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
			*filename_user = sh_user_path();
		} else {
			filp_close(f, NULL);
			ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
			*filename_user = ksud_user_path();
		}
	}
do_orig_execve:
	return 0;
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, const struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(filename_user,
			(const char __user *const __user *)PT_REGS_PARM2(regs),
			false, regs);
}

long ksu_handle_execveat_sucompat_user(const char __user **filename_user, int orig_nr, const struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(filename_user,
			(const char __user *const __user *)PT_REGS_PARM3(regs),
			true, regs);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;
	const char su[] = SU_PATH;
	static const char ksud_path[] = KSUD_PATH;

	if (unlikely(!filename_ptr))
		return 0;

	if (!static_branch_likely(&ksu_su_compat_enabled))
		return 0;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;

#ifdef CONFIG_KSU_SUSFS
	if (likely(!ksu_is_zygote_or_adbd(filename->name, strlen(filename->name))) && !susfs_is_current_proc_no_su()) {
		susfs_set_current_proc_no_su();
	}
#endif

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

	if (current_chrooted()) {
		pr_err("ksu_handle_execveat_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
		return 0;
	}

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

#if defined(CONFIG_KPROBES) && !defined(CONFIG_KSU_SUSFS)
long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_facessat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		if (current_chrooted()) {
			pr_err("ksu_handle_faccessat_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
			goto do_orig_facessat;
		}
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('a');
			pr_info("faccessat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_facessat:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_stat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		if (current_chrooted()) {
			pr_err("ksu_handle_stat_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
			goto do_orig_stat;
		}
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('s');
			pr_info("newfstatat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_stat:
	return ksu_syscall_table[orig_nr](regs);
}

static long ksu_handle_execve_sucompat_common(const char __user **filename_user,
					      const char __user *const __user *argv_user, unsigned long envp,
					      bool execveat, int orig_nr, struct pt_regs *regs)
{
	const char __user *fn;
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	char path[sizeof(su_path) + 1];
	long ret, orig_regs[5];
	unsigned long addr;
	int su_fd = -1;
	int tmp_fd;
	struct file *ksud_file;
	const struct cred *old_cred;

	if (execveat && ((int)PT_REGS_SYSCALL_PARM1(regs) != AT_FDCWD || (int)PT_REGS_PARM5(regs) != 0))
		goto do_orig_execve;

	if (unlikely(!filename_user))
		goto do_orig_execve;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig_execve;

	addr = untagged_addr((unsigned long)*filename_user);
	fn = (const char __user *)addr;
	memset(path, 0, sizeof(path));
	ret = strncpy_from_user(path, fn, sizeof(path));

	if (ret < 0) {
		pr_warn("Access filename when execve failed: %ld", ret);
		goto do_orig_execve;
	}

	if (likely(memcmp(path, su_path, sizeof(su_path))))
		goto do_orig_execve;

	if (current_chrooted()) {
		pr_err("ksu_handle_execve_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
		goto do_orig_execve;
	}

	ksu_compat_sulog('x');
	pr_info("sys_execve su found\n");

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc tmp fd err: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}

	fd_install(tmp_fd, ksud_file);

	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	// execve(file, argv, environ)
	// execveat(fd, file, argv, environ, flags)
	orig_regs[0] = PT_REGS_SYSCALL_PARM1(regs);
	orig_regs[1] = regs->__PT_PARM2_REG;
	orig_regs[2] = regs->__PT_PARM3_REG;
	orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
	orig_regs[4] = regs->__PT_PARM5_REG;
	regs->__PT_PARM5_REG = AT_EMPTY_PATH;
	regs->__PT_SYSCALL_PARM4_REG = envp;
	regs->__PT_PARM3_REG = (unsigned long)argv_user;
	regs->__PT_PARM2_REG = empty_user_path();
	PT_REGS_SYSCALL_PARM1(regs) = tmp_fd;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

	ret = ksu_syscall_table[__NR_execveat](regs);
	if (ret < 0) {
		ksu_close_fd(tmp_fd);
		PT_REGS_SYSCALL_PARM1(regs) = orig_regs[0];
		regs->__PT_PARM2_REG = orig_regs[1];
		regs->__PT_PARM3_REG = orig_regs[2];
		regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
		regs->__PT_PARM5_REG = orig_regs[4];
	} else {
		// Only grant the scoped driver capability after the selected root
		// profile has been applied successfully.
		su_fd = ksu_install_su_fd();
		if (su_fd < 0) {
			pr_warn("install su session fd failed: %d\n", su_fd);
		}
	}
	return ret;

do_orig_execve:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(filename_user, (const char __user *const __user *)PT_REGS_PARM2(regs),
						 PT_REGS_PARM3(regs), false, orig_nr, regs);
}

long ksu_handle_execveat_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	return ksu_handle_execve_sucompat_common(filename_user, (const char __user *const __user *)PT_REGS_PARM3(regs),
						 PT_REGS_SYSCALL_PARM4(regs), true, orig_nr, regs);
}
#endif

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
