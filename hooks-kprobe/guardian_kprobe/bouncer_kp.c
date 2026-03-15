// SPDX-License-Identifier: GPL-2.0
/*
 * bouncer_kp.c — Guardian Module (kprobe variant), Part 2
 *
 * Kprobe on __arm64_sys_openat: blocks access to PROTECTED_PATH
 * unless the caller has MAGIC_GID.
 *
 * AArch64 double pt_regs:
 *   regs->regs[0] -> user pt_regs
 *   user_regs->regs[1] -> filename
 * Deny by zeroing user_regs->regs[1] -> EFAULT
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <asm/ptrace.h>
#include "guardian_kprobe.h"

static int bouncer_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
  int ret;
  char path[MAX_PATH_LEN];
  size_t pp_len;

  struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
  char __user *filename = (char __user *)user_regs->regs[1];

  ret = strncpy_from_user(path, filename, sizeof(path));
  if (ret < 0) return 0;

  pp_len = sizeof(PROTECTED_PATH) - 1;
  if (strncmp(path, PROTECTED_PATH, pp_len) == 0){
    if (path[pp_len] == '\0' || path[pp_len] == '/') {
      if (guardian_has_magic_gid() == false) {
        user_regs->regs[1] = 0;
        guardian_log_event(path, false);
      } else {
        guardian_log_event(path, true);
      }
    } 
  }

  return 0;
}

static struct kprobe bouncer_kp = {
	.symbol_name = "__arm64_sys_openat",
	.pre_handler = bouncer_pre_handler,
};

int bouncer_init(void)
{
  int ret;
  ret = register_kprobe(&bouncer_kp);
  if (ret < 0){
    pr_err("trace_openat: failed to register kprobe: %d\n", ret);
    return ret;
  }

  return 0;
}

void bouncer_exit(void)
{
  unregister_kprobe(&bouncer_kp);
  pr_info("trace_openat: kprobes unregistered\n");
}
