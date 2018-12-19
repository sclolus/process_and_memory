#ifndef GET_PID_INFO_H
# define GET_PID_INFO_H

struct pid_info {
	pid_t	pid;
	long	state;
	void	*stack;
	u64	age; //Not sure about this
	pid_t	*child_array; //where is max child ?
	pid_t	parent_pid;
	char	root_path[PATH_MAX];
	char	cwd[PATH_MAX];
};

long	sys_get_pid_info(struct pid_info __user *ret, int pid);

#endif
