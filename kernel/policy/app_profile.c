#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "linux/kallsyms.h"
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/user.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#include "infra/su_mount_ns.h"
#include "hook/hook_manager.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static struct group_info root_groups = { .usage = REFCOUNT_INIT(2) };
#else
static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };
#endif

void setup_groups(struct root_profile *profile, struct cred *cred)
{
    if (profile->groups_count > KSU_MAX_GROUPS) {
        pr_warn("Failed to setgroups, too large group: %d!\n", profile->uid);
        return;
    }

    if (profile->groups_count == 1 && profile->groups[0] == 0) {
        if (cred->group_info)
            put_group_info(cred->group_info);
        cred->group_info = get_group_info(&root_groups);
        return;
    }

    u32 ngroups = profile->groups_count;
    struct group_info *group_info = groups_alloc(ngroups);
    if (!group_info) {
        pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
        return;
    }

    int i;
    for (i = 0; i < ngroups; i++) {
        gid_t gid = profile->groups[i];
        kgid_t kgid = make_kgid(current_user_ns(), gid);
        if (!gid_valid(kgid)) {
            pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
            put_group_info(group_info);
            return;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
        group_info->gid[i] = kgid;
#else
        GROUP_AT(group_info, i) = kgid;
#endif
    }

    groups_sort(group_info);
    set_groups(cred, group_info);
    put_group_info(group_info);
}

void seccomp_filter_release(struct task_struct *tsk);

#define NEED_BACKPORT_COMPAT                                                                                           \
    LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)

#if NEED_BACKPORT_COMPAT
static bool has_call_to_spin_lock = false;
#endif

void disable_seccomp(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                          \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
	struct task_struct *fake;

	fake = kmalloc(sizeof(*fake), GFP_ATOMIC);
	if (!fake) {
		pr_err("%s: cannot allocate fake struct!\n", __func__);
		return;
	}
#endif

    spin_lock_irq(&current->sighand->siglock);
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    clear_syscall_work(SECCOMP);
#else
    clear_thread_flag(TIF_SECCOMP);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                          \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
    memcpy(fake, current, sizeof(*fake));
    atomic_set(&current->seccomp.filter_count, 0);
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) &&                           \
     !defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
    put_seccomp_filter(current);
#endif
    current->seccomp.mode = 0;
    current->seccomp.filter = NULL;

    spin_unlock_irq(&current->sighand->siglock);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                          \
     defined(KSU_OPTIONAL_SECCOMP_FILTER_RELEASE))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    fake->flags |= PF_EXITING;
#elif NEED_BACKPORT_COMPAT
    if (has_call_to_spin_lock) {
        fake->flags |= PF_EXITING;
    } else {
        fake->sighand = NULL;
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    fake->sighand = NULL;
#endif
    seccomp_filter_release(fake);
    kfree(fake);
#endif
}

int escape_with_root_profile(void)
{
    int ret = 0;
    struct cred *cred;
    struct task_struct *p = current;
    struct task_struct *t;
    struct root_profile *profile = NULL;
    struct user_struct *new_user;

    cred = prepare_creds();
    if (!cred) {
        pr_warn("prepare_creds failed!\n");
        return -ENOMEM;
    }

#ifdef CONFIG_KSU_SUSFS
    if (susfs_is_current_ksu_domain()) {
#else
    if (cred->euid.val == 0) {
#endif
        pr_warn("Already root, don't escape!\n");
        goto out_abort_creds;
    }

    if (test_thread_flag(TIF_KSU_DISABLE_ESCAPE_WITH_ROOT)) {
        pr_warn("TIF_KSU_DISABLE_ESCAPE_WITH_ROOT found, don't escape!\n");
        goto out_abort_creds;
    }

    profile = ksu_get_root_profile(cred->uid.val);

    cred->uid.val = profile->uid;
    cred->suid.val = profile->uid;
    cred->euid.val = profile->uid;
    cred->fsuid.val = profile->uid;

    cred->gid.val = profile->gid;
    cred->fsgid.val = profile->gid;
    cred->sgid.val = profile->gid;
    cred->egid.val = profile->gid;
    cred->securebits = 0;

    BUILD_BUG_ON(sizeof(profile->capabilities.effective) != sizeof(kernel_cap_t));

    new_user = alloc_uid(cred->uid);
    if (!new_user) {
        ret = -ENOMEM;
        goto out_abort_creds;
    }

    free_uid(cred->user);
    cred->user = new_user;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    if (set_cred_ucounts(cred)) {
        goto out_abort_creds;
    }
#endif

    u64 cap_for_ksud = profile->capabilities.effective | CAP_DAC_READ_SEARCH;
    memcpy(&cred->cap_effective, &cap_for_ksud, sizeof(cred->cap_effective));
    memcpy(&cred->cap_permitted, &profile->capabilities.effective, sizeof(cred->cap_permitted));
    memcpy(&cred->cap_bset, &profile->capabilities.effective, sizeof(cred->cap_bset));
    if (profile->uid != 0) {
        memcpy(&cred->cap_inheritable, &profile->capabilities.effective, sizeof(cred->cap_inheritable));
        memcpy(&cred->cap_ambient, &profile->capabilities.effective, sizeof(cred->cap_ambient));
    }

    setup_groups(profile, cred);
    setup_selinux(profile->selinux_domain, cred);

    commit_creds(cred);

    if (likely(test_thread_flag(TIF_SECCOMP)))
        disable_seccomp();

    if (profile->flags & FLAG_KSU_NO_NEW_PRIVS) {
        set_thread_flag(TIF_KSU_DISABLE_ESCAPE_WITH_ROOT);
    }

#ifdef KSU_KPROBES_HOOK
#ifndef CONFIG_KSU_SUSFS
    for_each_thread (p, t) {
        ksu_set_task_tracepoint_flag(t);
    }
#endif
#endif

    setup_mount_ns(profile->namespaces);
    ksu_put_root_profile(profile);
    return 0;

out_abort_creds:
    if (profile)
        ksu_put_root_profile(profile);
    abort_creds(cred);
    return ret;
}

int escape_to_root_for_init(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare init's creds!\n");
        return -EINVAL;
    }

    setup_selinux(KERNEL_SU_CONTEXT, cred);
    commit_creds(cred);
    
    return 0;
}

void __init ksu_app_profile_init(void)
{
#if NEED_BACKPORT_COMPAT
    unsigned long size = 0;
    int ret;
    void *raw_spin_lock_irq_sym = find_kernel_symbol_exact("_raw_spin_lock_irq");
    void *seccomp_filter_release_sym = find_kernel_symbol_exact("seccomp_filter_release");
    ret = kallsyms_lookup_size_offset(seccomp_filter_release_sym, &size, NULL);
    if (!ret || !size) {
        pr_err("failed to get size of seccomp_filter_release: %d, use 128\n", ret);
        size = 128;
    }
    has_call_to_spin_lock = scan_call_to(seccomp_filter_release_sym, size, raw_spin_lock_irq_sym) != NULL;
    pr_info("seccomp_filter_release has_call_to_spin_lock = %d\n", has_call_to_spin_lock);
#endif
}