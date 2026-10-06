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

#endif