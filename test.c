#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <assert.h>


/* #define __NR_get_pid_info 293 */
#define __NR_get_pid_info 335


/* Further describe the reason of error if the sys_get_pid_info fails */
enum	get_pid_info_status {
	SUCCESS,
	ERR_CHILD_ARRAY_TOO_SMALL,
	ERR_UNKNOWN,
};

struct pid_info {
	pid_t			     pid;
	long			     state;
	void			    *stack;
	uint64_t		     age;   //Not sure about this
	pid_t			    *child_array;   //where is max child ?
	size_t			     child_array_size;
	enum get_pid_info_status     syscall_status;
	pid_t			     parent_pid;
	char			     root_path[PATH_MAX];
	char			     cwd[PATH_MAX];
};

static void print_children_info(struct pid_info *info)
{
	uint64_t    i = 0;

	assert(info->syscall_status == SUCCESS);
	assert(sizeof(pid_t) == 4);
	while (i < info->child_array_size / sizeof(pid_t)) {
		printf("Pid for child: %lu -> %u\n", i, info->child_array[i]);
		i++;
	}
}

static void print_pid_info(struct pid_info *info)
{
	printf("pid: %d\nstate:%ld\nstack_ptr: %p\nage: %lu, child_array: %p, no_children = %lu, parent_pid: %d\nroot_path: %s\ncwd: %s\n",
		info->pid,
		info->state,
		info->stack,
		info->age,
		info->child_array,
		info->child_array_size / sizeof(pid_t),
		info->parent_pid,
		info->root_path,
		info->cwd);
	print_children_info(info);
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


static int32_t	wrapper_get_pid_info(struct pid_info *info, pid_t pid) {
	uint64_t    current_array_size = 32;

	do {
		if (NULL == (info->child_array = malloc(sizeof(pid_t) * current_array_size))) {
			perror(NULL);
			exit(EXIT_FAILURE);
		}
		info->child_array_size = current_array_size * sizeof(pid_t);
		current_array_size *= 2;
		printf("Calling get_pid_info with child_array of size: %lu\n", info->child_array_size);
		if (-1 == syscall(__NR_get_pid_info, info, pid))
		{
			if (info->syscall_status == ERR_CHILD_ARRAY_TOO_SMALL) {
				printf("get_pid_info informed that the child_array was too small for size: %lu\n", current_array_size);
				current_array_size *= 2;
				free(info->child_array);
				continue ;
			}
			printf("get_pid_info returned -1\n");
			free(info->child_array);
			return (-1);
		}

		return (0);
	} while (info->syscall_status != SUCCESS);
	/// ???
	return (0);
}


int main(void)
{
	struct pid_info	info;
	uint32_t    i = 0;

	while (i < 5) {
		if (0 == fork()) {
			assert(sleep(2) == 0);
			exit(0);
		}
		i++;
	}

	(void)test_function;
	/* sleep(1); */
	/* test_function() == 0 ? printf("Test_function was successfull\n") */
	/* 	: printf("Test_function was successfull\n"); */
	if (-1 == wrapper_get_pid_info(&info, 1))
		exit(EXIT_FAILURE);
	print_pid_info(&info);
	return 0;
}
