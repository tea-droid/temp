// SPDX-License-Identifier: GPL-2.0
/*
 * bouncer_ft.c — Guardian Module (ftrace variant), Part 2
 *
 * Ftrace hook on do_sys_openat2: blocks access to PROTECTED_PATH
 * unless the caller has MAGIC_GID.
 *
 * do_sys_openat2 receives args directly: x0=dfd, x1=filename, x2=how
 * No double pt_regs indirection (unlike kprobe on __arm64_sys_openat).
 *
 * Deny by zeroing fregs->regs[1] (filename) -> EFAULT.
 */

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include "guardian_ftrace.h"

static unsigned long bouncer_target_addr;

static unsigned long kprobe_lookup(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static void notrace bouncer_callback(unsigned long ip, unsigned long parent_ip,
				     struct ftrace_ops *op,
				     struct ftrace_regs *fregs)
{
    // TODO: Your implementation here
  int ret;
  char path[MAX_PATH_LEN];
  size_t pp_len = sizeof(PROTECTED_PATH) - 1;

  const char __user *filename = (const char __user *)ftrace_regs_get_argument(fregs, 1);
  
  ret = strncpy_from_user(path, filename, sizeof(path));
  if (ret < 0) return;

  if (strncmp(path, PROTECTED_PATH, pp_len) == 0){
    if (path[pp_len] == '\0' || path[pp_len] == '/') {
      if (guardian_has_magic_gid() == false) {
        fregs->regs[1] = 0;               //deny access
        guardian_log_event(path, false);
      } else {
        guardian_log_event(path, true);
      }
    } 
  }

  return;
}

static struct ftrace_ops bouncer_ops = {
	.func  = bouncer_callback,
	/*
	 * Do NOT set FTRACE_OPS_FL_SAVE_REGS on arm64 — it requires
	 * HAVE_DYNAMIC_FTRACE_WITH_REGS which arm64 doesn't have.
	 * FL_IPMODIFY needed because we modify register state.
	 */
	.flags = FTRACE_OPS_FL_IPMODIFY |
		 FTRACE_OPS_FL_RECURSION,
};

int bouncer_init(void)
{
  int ret;

  bouncer_target_addr = kprobe_lookup("do_sys_openat2");
  if (bouncer_target_addr == 0) return -ENOENT;

  ret = ftrace_set_filter_ip(&bouncer_ops, bouncer_target_addr, 0, 0);
  if (ret < 0) return ret;

  ret = register_ftrace_function(&bouncer_ops);
  if (ret < 0) {
    ftrace_set_filter_ip(&bouncer_ops, bouncer_target_addr, 1, 0);
    return ret;
  }

  return 0;
}

void bouncer_exit(void)
{
  unregister_ftrace_function(&bouncer_ops);
  ftrace_set_filter_ip(&bouncer_ops, bouncer_target_addr, 1, 0);

  pr_info("trace_openat: ftrace unregistered\n");
}
