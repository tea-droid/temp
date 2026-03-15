// SPDX-License-Identifier: GPL-2.0
/*
 * guardian_ftrace_main.c — Guardian Module (ftrace variant)
 *
 * Part 1: Character device + kfifo event log + magic GID credential modification
 *
 * Write 0xDEADBEEF to /dev/guardian to grant GID 1337 (bypass).
 * Read /dev/guardian to drain the event log.
 * Hooks are in bouncer_ft.c (Part 2) and cloak_ft.c (Part 3).
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
#include "guardian_ftrace.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Course Instructor");
MODULE_DESCRIPTION("Guardian (ftrace) — directory protector with magic GID bypass");
MODULE_VERSION("1.0");

/* --- Private state — accessed only through helper functions --- */
DEFINE_KFIFO(event_log, struct guardian_event, EVENT_LOG_SIZE);
DEFINE_SPINLOCK(event_lock);

/* --- Private state --- */
static dev_t          dev_num;
static struct cdev    my_cdev;
static struct class   *dev_class;
static struct device  *dev_device;

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
  // alloacate device num 
  int ret;

  ret = alloc_chrdev_region(&dev_num, 0, 1, "guardian");
  if (ret < 0) {
    return ret;
  }
  
  // init cdev and link to fops
  cdev_init(&my_cdev, &guardian_fops);
  my_cdev.owner = THIS_MODULE;

  // add to system
  ret = cdev_add(&my_cdev, dev_num, 1);
  if (ret < 0) {
    goto errorpoint1;
  }

  // create the class
  dev_class = class_create(CLASS_NAME);
  if (IS_ERR(dev_class)) {
    ret = PTR_ERR(dev_class);
    goto errorpoint2;
  }

  // create the device 
  dev_device = device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME);
  if (IS_ERR(dev_device)) {
    ret = PTR_ERR(dev_device);
    goto errorpoint3;
  }

  ret = bouncer_init();
  if (ret < 0) {
    goto errorpoint4;
  }
  ret = cloak_init();
  if (ret < 0) {
    goto errorpoint5;
  }

  pr_info("guardian: module loaded\n");
  return 0;


  //better goto based error winding
  errorpoint5:
    bouncer_exit();
  errorpoint4:
    device_destroy(dev_class, dev_num);
  errorpoint3:  
    class_destroy(dev_class);
  errorpoint2:  
    cdev_del(&my_cdev);
  errorpoint1:
    unregister_chrdev_region(dev_num, 1);
  
  return ret;
}

static void __exit guardian_exit(void)
{
  pr_info("Unloading all modules...");

  cloak_exit();
  bouncer_exit();
  device_destroy(dev_class, dev_num);
  class_destroy(dev_class);
  cdev_del(&my_cdev);
  unregister_chrdev_region(dev_num, 1);

  pr_info("Reverse teardown complete.");
}

module_init(guardian_init);
module_exit(guardian_exit);
