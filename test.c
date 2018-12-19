#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>


/* #define __NR_get_pid_info 293 */
#define __NR_get_pid_info 335

struct pid_info {
	pid_t	    pid;
	long	    state;
	void	    *stack;
	uint64_t    age; //Not sure about this
	pid_t	    *child_array; //where is max child ?
	pid_t	    parent_pid;
	char	    root_path[PATH_MAX];
	char	    cwd[PATH_MAX];
};

static void print_pid_info(struct pid_info *info)
{
	printf("pid: %d\nstate:%ld\nstack_ptr: %p\nage: %lu, child_array: %p, parent_pid: %d\nroot_path: %s\ncwd: %s\n",
		info->pid,
		info->state,
		info->stack,
		info->age,
		info->child_array,
		info->parent_pid,
		info->root_path,
		info->cwd);
}

int main(void)
{
	struct pid_info	info;


	sleep(1);
	if (-1 == syscall(__NR_get_pid_info, &info, getpid()))
	{
		printf("get_pid_info returned -1\n");
		return EXIT_FAILURE;
	}
	print_pid_info(&info);
	return 0;
}
