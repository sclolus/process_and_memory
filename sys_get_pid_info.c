// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/fdtable.h> // remove this latter
#include <linux/path.h> // remove this latter
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched/cputime.h>
#include <linux/timekeeping.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>

# define LOG "get_pid_info: "

static void debug_print_kernel_stack(void *kstack, uint64_t len)
{
	static char buffer[49];
	uint64_t    i = 0;

	while (i < len) {
		uint64_t    u;

		memset(buffer, ' ', 48);
		u = 0;
		while (u < 16 && u + i < len) {
			sprintf(buffer + u * 3, "%02hhx ", *(char *)(kstack + i + u));
			u++;
		}
		printk(KERN_INFO LOG "%s\n", buffer);
		i += 16;
	}
}

static int kernel_stack_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct task_struct *task = file->private_data;
	struct page	    *kstack = vmalloc_to_page(task->stack);

	if (kstack == NULL) {
		printk(KERN_WARNING LOG "Failed to get kernel stack page struct\n");
		return -EINVAL;
	}

	if (0 != vm_insert_page(vma, vma->vm_start, kstack)) {
		printk(KERN_WARNING LOG "Failed to insert page into process' vma\n");
		return -EINVAL;
	}
	return 0;
}

static struct file_operations	get_pid_stack_fops = {
	.mmap = kernel_stack_mmap
};

static int32_t  get_user_path_from_struct_path(struct path *path, char *buffer, uint64_t size)
{
	char	*ret;

	ret = dentry_path_raw(path->dentry, buffer, size);
	if (IS_ERR(ret))
		return -1;
	memcpy(buffer, ret, size);
	return 0;
}


static void	printk_file_path(struct file *file, char *prefix)
{
	static char buffer[PAGE_SIZE];
	char	    *ptr;

	ptr = dentry_path_raw(file->f_path.dentry, buffer, sizeof(buffer));
	if (IS_ERR(ptr)) {
		printk(KERN_INFO LOG "Was unable to print some file's path\n");
		return ;
	}

	printk(KERN_INFO LOG "%s%s", prefix, ptr);
}

static int32_t	test_function(void *data)
{
	struct fdtable	    *fdtable = &current->files->fdtab;
	struct file	    *tmp_file;
	uint64_t	    i = 0;

	while (fdtable->fd[i] != NULL)
	{
		tmp_file = get_file(fdtable->fd[i]);
		printk_file_path(tmp_file, "Opened fd: ");
		fput_atomic(tmp_file);
		i++;
	}
	return (0);
}

uint64_t    klist_len(const struct list_head *list) {
	uint64_t	     __len = 0;
	struct list_head    *pos = NULL;

	list_for_each(pos, list) {
		__len++;
	}
	return __len;
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, to, int, pid)
{
	struct pid_info	    *info;
	struct task_struct  *task;
	int64_t		    ret;
	uint64_t	    required_child_array_size;

	printk(KERN_INFO LOG "get_pid_info() was called by pid: %d\n", current->pid);

	if (NULL == (info = kmalloc(sizeof(struct pid_info), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	if (0 != copy_from_user(info, to, sizeof(struct pid_info))) {
		kfree(info);
		ret = -EPERM;
		goto err;
	}

	rcu_read_lock();
	if (NULL == (task = find_task_by_pid_ns(pid, task_active_pid_ns(current)))) {
		ret = -ESRCH;
		goto err;
	}
	ret = 0;

 	rcu_read_unlock();
	get_task_struct(task);
	task_lock(task);
	info->pid = task_tgid_vnr(task);
	info->state = task->state;
	info->stack = task->stack;

	printk(KERN_INFO LOG "task->stack ptr: %px, current sp: %px\n", info->stack, &info);


	/* struct page *kstack = virt_to_page((unsigned long)info->stack); */
	/* struct vm_area_struct *kstack_vma = find_vma(&init_mm, (unsigned long)info->stack); */

	/* printk(KERN_INFO LOG "return of vm_insert_page: %d\n", vm_insert_page(current->mm->mmap, (unsigned long)info->stack, kstack)); */
	struct file *stack_file = anon_inode_getfile("get_pid_info_stack", &get_pid_stack_fops, task, O_RDONLY);

	if (IS_ERR(stack_file)) {
		printk(KERN_WARNING LOG "Failed to get anonymous inode\n");
		ret = -EIO; // change this
		goto err_tlock_held;
	}
	printk(KERN_INFO LOG "First long word of kernel stack pid: %d -> %lx\n", info->pid, *(long *)info->stack);
	debug_print_kernel_stack(info->stack, 256);
	info->stack = vm_mmap(stack_file, 0, THREAD_SIZE * 2, PROT_READ, MAP_PRIVATE, 0);
	if (IS_ERR(info->stack)) {
		printk(KERN_WARNING LOG "Failed to vm_mmap kernel stack\n");
		ret = -EPERM;
		goto err_tlock_held;
	}
	printk(KERN_WARNING LOG "Kernel stack of process: %d has been mapped to %px\n", info->pid, info->stack);


	/* int ret_remap = remap_pfn_range(current->mm->mmap, info->stack, __pa(info->stack), THREAD_SIZE * 2, PAGE_READONLY); */
	/* printk(KERN_INFO LOG "return of remap_pfn_range: %d\n", ret_remap); */

	/* printk(KERN_INFO LOG "page addr: %px, vma addr: %px\n", kstack, kstack_vma); */



	info->age = ktime_get_ns() - task->start_time;
	printk(KERN_INFO LOG "age in seconds = %llu\n", info->age / NSEC_PER_SEC);
	printk(KERN_INFO LOG "remaining age in ns = %llu\n", info->age % NSEC_PER_SEC);

	// Need to reacquire rcu lock for dereferencing the __rcu protected real_parent member
	rcu_read_lock();
	info->parent_pid = task_tgid_vnr(rcu_dereference(task->real_parent));
	rcu_read_unlock();

	ret = get_user_path_from_struct_path(&task->fs->root, info->root_path, sizeof(info->root_path));
	ret |= get_user_path_from_struct_path(&task->fs->pwd, info->cwd, sizeof(info->cwd));
	required_child_array_size = klist_len(&task->children) * sizeof(pid_t);
	if (ret != 0) {
		kfree(info);
		ret = -EPERM;
		goto err_tlock_held;
	}

	info->syscall_status = SUCCESS;
	if (required_child_array_size > info->child_array_size) {
		info->child_array_size = required_child_array_size;
		info->syscall_status = ERR_CHILD_ARRAY_TOO_SMALL;
		ret = -ENOMEM;
		printk(KERN_INFO LOG "child_array was too small\n");
	} else {
		struct task_struct *pos = NULL;
		uint64_t	    i = 0;
		pid_t		    vpid;

		list_for_each_entry(pos, &task->children, sibling) {
			vpid = task_tgid_vnr(pos);
			copy_to_user(&info->child_array[i], &vpid, sizeof(pid_t)); // check return value and maybe make it a single call
			i++;
		}
		info->child_array_size = required_child_array_size;
	}

	if (0 != copy_to_user(to, info, sizeof(struct pid_info))) {
		kfree(info);
		ret = -EPERM;
		goto err_tlock_held;
	}

	kfree(info);
	/* test_function(NULL); */
	task_unlock(task); //should need this though...
	put_task_struct(task);
	return ret;
err_tlock_held:
	task_unlock(task);
	put_task_struct(task);
err:
	return ret;
}
