#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/compat.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init(void);
void ksu_ksud_exit(void);

void ksu_stop_input_hook_runtime(void);

extern bool ksu_execveat_hook __read_mostly;

// GKI SuSFS Structs & Declarations
#define MAX_ARG_STRINGS 0x7FFFFFFF
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
                             struct user_arg_ptr *argv,
                             struct user_arg_ptr *envp, int *flags);
#endif

#endif