// SPDX-License-Identifier: GPL-2.0
/*
 * guardian_table_main.c — Guardian Module (syscall table variant)
 *
 * Part 1: Character device + kfifo + magic GID + PTE utilities + symbol resolution
 *
 * Patches sys_call_table[] directly — the kernel equivalent of GOT/PLT
 * patching in userland. Uses a single read-write window for both the
 * openat and getdents64 hooks.
 *
 * PTE manipulation:
 *   sys_call_table is in .rodata (CONFIG_STRICT_KERNEL_RWX).
 *   We walk the kernel page tables to find the PTE/PMD mapping the table,
 *   clear PTE_RDONLY, modify entries, then restore read-only protection.
 *
 * WARNING: Educational use only.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/kfifo.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/unistd.h>
#include "guardian_table.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Course Instructor");
MODULE_DESCRIPTION("Guardian (syscall table) — directory protector via table patching");
MODULE_VERSION("1.0");

/* --- Private state — accessed only through helper functions --- */
DEFINE_KFIFO(event_log, struct guardian_event, EVENT_LOG_SIZE);
DEFINE_SPINLOCK(event_lock);

/* --- Shared state — referenced by bouncer_tbl.c and cloak_tbl.c --- */
syscall_fn_t *sys_call_table_ptr;
syscall_fn_t original_openat;
syscall_fn_t original_getdents64;

/* --- Private state --- */
static dev_t          dev_num;
static struct cdev    my_cdev;
static struct class   *dev_class;
static struct device  *dev_device;

/* PTE state */
static pte_t  saved_pte;
static pte_t *saved_ptep;
static struct mm_struct *p_init_mm;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

/* --- Symbol resolution --- */

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

/* --- PTE manipulation --- */

static pte_t *resolve_pte(unsigned long addr, unsigned int *levelp)
{
  pgd_t *pgdp;
  p4d_t *p4dp;
  pud_t *pudp;
  pmd_t *pmdp;
  pte_t *ptep;

  pgdp = pgd_offset(p_init_mm, addr);
  if (pgd_none(*pgdp) || pgd_bad(*pgdp))
    goto out;

  p4dp = p4d_offset(pgdp, addr);
  if (p4d_none(*p4dp) || p4d_bad(*p4dp))
    goto out;

  pudp = pud_offset(p4dp, addr);
  if (pud_none(*pudp) || pud_bad(*pudp))
    goto out;
  if (pud_sect(READ_ONCE(*pudp))) {
    *levelp = 1;
    return (pte_t *)pudp;
  }

  pmdp = pmd_offset(pudp, addr);
  if (pmd_none(*pmdp) || pmd_bad(*pmdp))
    goto out;
  if (pmd_sect(READ_ONCE(*pmdp))) {
    *levelp = 2;
    return (pte_t *)pmdp;
  }

  ptep = pte_offset_kernel(pmdp, addr);
  if (pte_none(*ptep) || pte_bad(*ptep))
    goto out;
  *levelp = 3;
  return ptep;

  out:
    return 0;
}

static int set_table_rw(void)
{
  pte_t new;
  unsigned int level;

  saved_ptep = resolve_pte((unsigned long)sys_call_table_ptr, &level);
  if (!saved_ptep) {
    pr_err("guardian: failed to resolve PTE for sys_call_table\n");
    return -EFAULT;
  }

  saved_pte = READ_ONCE(*saved_ptep);

  new = __pte(pte_val(saved_pte) & ~PTE_RDONLY);
  WRITE_ONCE(*saved_ptep, new);

  flush_tlb_all();

  return 0; 
}

static void set_table_ro(void)
{
   if (!saved_ptep) {
    pr_err("guardian: set_table_ro called without a saved PTE\n");
    return;
  }

  WRITE_ONCE(*saved_ptep, saved_pte);
  flush_tlb_all();
}

/* --- Shared helpers --- */

bool guardian_has_magic_gid(void)
{
  if (in_group_p(KGIDT_INIT(MAGIC_GID)) == 1){
    return true;
  }
  return false;
}

void guardian_log_event(const char *path, bool allowed)
{
  struct guardian_event gev;

  // filling struct guardian_event 
  gev.timestamp = ktime_get_ns();
  gev.pid = current->pid;
  gev.uid = from_kuid(&init_user_ns, current_uid());
  gev.allowed = allowed;
  strscpy(gev.path, path, sizeof(gev.path));
  strscpy(gev.comm, current->comm, sizeof(gev.comm));

  // acquire lock -> put kfifo -> release lock 
  spin_lock(&event_lock);
  kfifo_put(&event_log, gev);
  spin_unlock(&event_lock);
}

/* --- Credential modification --- */

static int grant_magic_gid(void)
{
  int i;

  //1. copy 
  struct cred *new_cred;
  new_cred = prepare_creds();
  if (!new_cred) {return -ENOMEM;}

  //2. modify
  struct group_info *old_grp_info = new_cred->group_info;
  struct group_info *new_grp_info;
  int ngroups = old_grp_info->ngroups;

  new_grp_info = groups_alloc(ngroups + 1);
  if (!new_grp_info) {
    abort_creds(new_cred);
    return -ENOMEM;
  }

  //loop through the old list and copy each GID into the new list
  for (i=0; i < old_grp_info->ngroups; i++)
  {
    GROUP_AT(new_grp_info, i) = GROUP_AT(old_grp_info, i);
  }
  
  GROUP_AT(new_grp_info, ngroups) = KGIDT_INIT(MAGIC_GID);
  groups_sort(new_grp_info);

  //3. commit
  set_groups(new_cred, new_grp_info);
  commit_creds(new_cred);

  return 0;
}

/* --- Character device ops --- */

static int guardian_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int guardian_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t guardian_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
  uint32_t device_buffer;
  uint32_t target = MAGIC_BYTES;

  // getting 4 bytes in kernel space 
  if (count == 4){
    if (copy_from_user(&device_buffer, buf, 4)){
      return -EFAULT; 
    }
  } else{
    return -EINVAL;
  }

  // comparison
  if(memcmp(&device_buffer, &target, 4) == 0){
    grant_magic_gid();
  }
  else {
    pr_info("buffer mismatch");
  }

  return count;
}

static ssize_t guardian_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
  struct guardian_event gev;
  size_t char_written;
  int ret;
  char l_buff[256];

  spin_lock(&event_lock);
  ret= kfifo_get(&event_log, &gev);
  if(ret == 0){
    spin_unlock(&event_lock);
    return -EAGAIN;
  }
  spin_unlock(&event_lock);

  char_written = snprintf(l_buff, min(count, sizeof(l_buff)), "[%llu] pid=%d uid=%d access=%s path=%s comm=%s\n", gev.timestamp, gev.pid, gev.uid, gev.allowed ? "ALLOWED" : "DENIED", gev.path, gev.comm);
  if (char_written >= sizeof(l_buff)) {
    char_written = sizeof(l_buff) - 1;
  }
  
  if (copy_to_user(buf, l_buff, char_written)) {
    return -EFAULT;
  } 

  return char_written;
}

static const struct file_operations guardian_fops = {
	.owner   = THIS_MODULE,
	.open    = guardian_open,
	.release = guardian_release,
	.read    = guardian_read,
	.write   = guardian_write,
};

/* --- Module init / exit --- */

static int __init guardian_init(void)
{
  int ret;
  kallsyms_lookup_name_t kallsyms_lookup_name_fn;
  syscall_fn_t openat_hook, getdents64_hook;

  kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kprobe_lookup("kallsyms_lookup_name");
  if (!kallsyms_lookup_name_fn) {
    pr_err("guardian: failed to resolve kallsyms_lookup_name\n");
    return -ENOENT;
  }

  sys_call_table_ptr = (syscall_fn_t *)kallsyms_lookup_name_fn("sys_call_table");
  if (!sys_call_table_ptr) {
    pr_err("guardian: failed to resolve sys_call_table\n");
    return -ENOENT;
  }

  p_init_mm = (struct mm_struct *)kallsyms_lookup_name_fn("init_mm");
  if (!p_init_mm) {
    pr_err("guardian: failed to resolve init_mm\n");
    return -ENOENT;
  }

  pr_info("guardian: sys_call_table @ %px, init_mm @ %px\n",
          sys_call_table_ptr, p_init_mm);

  ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
  if (ret < 0) {
    pr_err("guardian: alloc_chrdev_region failed (%d)\n", ret);
    return ret;
  }

  cdev_init(&my_cdev, &guardian_fops);
  my_cdev.owner = THIS_MODULE;
  ret = cdev_add(&my_cdev, dev_num, 1);
  if (ret < 0) {
    pr_err("guardian: cdev_add failed (%d)\n", ret);
    goto err_cdev;
  }

  dev_class = class_create(DEVICE_NAME);
  if (IS_ERR(dev_class)) {
    ret = PTR_ERR(dev_class);
    pr_err("guardian: class_create failed (%d)\n", ret);
    goto err_class;
  }

  dev_device = device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME);
  if (IS_ERR(dev_device)) {
    ret = PTR_ERR(dev_device);
    pr_err("guardian: device_create failed (%d)\n", ret);
    goto err_device;
  }

  original_openat    = sys_call_table_ptr[__NR_openat];
  original_getdents64 = sys_call_table_ptr[__NR_getdents64];

  openat_hook     = bouncer_get_hook();
  getdents64_hook = cloak_get_hook();

  ret = set_table_rw();
  if (ret) {
    pr_err("guardian: set_table_rw failed (%d)\n", ret);
    goto err_rw;
  }

  sys_call_table_ptr[__NR_openat]     = openat_hook;
  sys_call_table_ptr[__NR_getdents64]  = getdents64_hook;

  set_table_ro();

  pr_info("guardian: module loaded — syscall table patched\n");
  return 0;

err_rw:
  device_destroy(dev_class, dev_num);
err_device:
  class_destroy(dev_class);
err_class:
  cdev_del(&my_cdev);
err_cdev:
  unregister_chrdev_region(dev_num, 1);
  return ret;
}

static void __exit guardian_exit(void)
{
  int ret;

  /* Restore original syscall handlers */
  ret = set_table_rw();
  if (ret) {
    pr_err("guardian: set_table_rw failed on exit (%d) — table NOT restored!\n", ret);
  } else {
    sys_call_table_ptr[__NR_openat]     = original_openat;
    sys_call_table_ptr[__NR_getdents64]  = original_getdents64;
    set_table_ro();
    pr_info("guardian: syscall table restored\n");
  }

  /* Tear down char device */
  device_destroy(dev_class, dev_num);
  class_destroy(dev_class);
  cdev_del(&my_cdev);
  unregister_chrdev_region(dev_num, 1);

  pr_info("guardian: module unloaded\n");
}

module_init(guardian_init);
module_exit(guardian_exit);
