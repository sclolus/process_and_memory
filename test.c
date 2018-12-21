#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>


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

static int32_t test_function(void)
{
	DIR		*dir;
	struct dirent	*entry;

	if (NULL == (dir = opendir(".")))
		return -1;
	while ((entry = readdir(dir)) != NULL) {
		printf("Opening: %s ->", entry->d_name);
		if (open(entry->d_name, O_RDONLY) != -1)
			printf("SUCCESS\n");
		else
			printf("FAIL\n");
	}
	/* int fds[2]; */

	/* pipe(fds); */
	return (0);
}



int main(void)
{
	struct pid_info	info;


	sleep(1);
		test_function() == 0 ? printf("Test_function was successfull\n")
		: printf("Test_function was successfull\n");

	if (-1 == syscall(__NR_get_pid_info, &info, getpid()))
	{
		printf("get_pid_info returned -1\n");
		return EXIT_FAILURE;
	}

	print_pid_info(&info);

	return 0;
}
