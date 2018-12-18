// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/types.h>

struct pid_info {
	pid_t	pid;
	long	state;
	void	*stack;
	u64	age; //Not sure about this
	pid_t	*child_array; //where is max child ?
	pid_t	parent_pid;
	char	*root_path;
	char	*cwd;
};

long	sys_get_pid_info(struct pid_info *ret, int pid)
{

}
