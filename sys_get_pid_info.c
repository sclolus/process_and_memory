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

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, to, int, pid)
{
	struct pid_info	    *info;
	struct task_struct  *task;
	int64_t		    ret;

	printk(KERN_INFO LOG "get_pid_info() was called by pid: %d\n", current->pid);

	if (NULL == (info = kmalloc(sizeof(struct pid_info), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	rcu_read_lock();
	if (NULL == (task = find_task_by_pid_ns(pid, task_active_pid_ns(current)))) {
		ret = -ESRCH;
		goto err;
	}
	rcu_read_unlock();
	task_lock(task);

	info->pid = task->pid;
	info->state = task->state;
	info->stack = task->stack;
	info->age = /* task->start_time */ task->cputime_expires.sum_exec_runtime;
	info->parent_pid = task->real_parent->pid;
	ret = get_user_path_from_struct_path(&task->fs->root, info->root_path, sizeof(info->root_path));
	ret |= get_user_path_from_struct_path(&task->fs->pwd, info->cwd, sizeof(info->cwd));

	if (ret != 0) {
		kfree(info);
		ret = -EPERM;
		goto err_tlock_held;
	}

	if (0 != copy_to_user(to, info, sizeof(struct pid_info))) {
		kfree(info);
		ret = -EPERM;
		goto err_tlock_held;
	}

	kfree(info);
	test_function(NULL);
	task_unlock(task);
	return 0;
err_tlock_held:
	task_unlock(task);
err:
	return ret;
}
