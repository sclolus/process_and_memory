// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>

# define LOG "get_pid_info: "


static char *get_user_path_from_struct_path(struct path *path, void **free_buffer)
{
	char	*buffer;
	char	*ret;

	if (NULL == (buffer = kmalloc(PAGE_SIZE, GFP_USER)))
		return (NULL);
	ret = dentry_path_raw(path->dentry, buffer, PAGE_SIZE);
	printk(KERN_INFO LOG "Dentry_path_row returned %s\n", ret);
	*free_buffer = buffer;
	return (ret);
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, to, int, pid)
{
	struct pid_info	    *info;
	struct task_struct  *task;
	char		    *path;
	void		    *free_buffer;

	printk(KERN_INFO LOG "get_pid_info() was called by pid: %d\n", current->pid);

	if (NULL == (info = kmalloc(sizeof(struct pid_info), GFP_KERNEL)))
		return (-ENOMEM);
	if (NULL == (task = find_task_by_pid_ns(pid, current->nsproxy->pid_ns_for_children)))
		return (-ESRCH);
	info->pid = task->pid;
	info->state = task->state;
	info->stack = task->stack;
	info->age = task->start_time;
	info->parent_pid = task->real_parent->pid;
	path = get_user_path_from_struct_path(&task->fs->root, &free_buffer);
	memcpy(&info->root_path, path, PAGE_SIZE);
	kfree(free_buffer);
	path = get_user_path_from_struct_path(&task->fs->pwd, &free_buffer);
	memcpy(&info->cwd, path, PAGE_SIZE);
	kfree(free_buffer);
	if (0 != copy_to_user(to, info, sizeof(struct pid_info)))
		return (-EPERM);
	kfree(info);
	return (0);
}
