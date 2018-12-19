// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>

# define LOG "get_pid_info: "


static int32_t  get_user_path_from_struct_path(struct path *path, char *buffer, uint64_t size)
{
	char	*ret;

	ret = dentry_path_raw(path->dentry, buffer, size);
	if (IS_ERR(ret))
		return -1;
	memcpy(buffer, ret, size);
	return 0;

}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, to, int, pid)
{
	struct pid_info	    *info;
	struct task_struct  *task;
	int32_t		    ret;

	printk(KERN_INFO LOG "get_pid_info() was called by pid: %d\n", current->pid);

	if (NULL == (info = kmalloc(sizeof(struct pid_info), GFP_KERNEL)))
		return (-ENOMEM);
	if (NULL == (task = find_task_by_pid_ns(pid, current->nsproxy->pid_ns_for_children)))
		return (-ESRCH);

	info->pid = task->pid;
	info->state = task->state;
	info->stack = task->stack;
	info->age = /* task->start_time */ task->cputime_expires.sum_exec_runtime;
	info->parent_pid = task->real_parent->pid;
	ret = get_user_path_from_struct_path(&task->fs->root, info->root_path, sizeof(info->root_path));
	ret |= get_user_path_from_struct_path(&task->fs->pwd, info->cwd, sizeof(info->cwd));

	if (ret != 0) {
		kfree(info);
		return (-EPERM);
	}

	if (0 != copy_to_user(to, info, sizeof(struct pid_info)))
		return (-EPERM);
	kfree(info);
	return (0);
}
