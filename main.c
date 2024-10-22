#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <syscall.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "print_syscall.h"

int num_syscalls = 0;

void report_num_sycalls(void)
{
	printf("%d syscalls\n", num_syscalls);
}

void child(char **args);
void parent(pid_t pid);
void my_wait(pid_t pid);
int custom_print_ptrace_syscall_info(pid_t pid,
				     struct ptrace_syscall_info *info);
const char *peek_tracee_string(pid_t pid, unsigned
			       long long addr, int len);
int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <file> [args...]\n", argv[0]);
		exit(1);
	}

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	if (pid == 0) {
		child(&argv[1]);
	}

	atexit(report_num_sycalls);
	parent(pid);
}

void child(char **args)
{
	int fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	dup2(fd, STDIN_FILENO);

	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_TRACEME, ...)");
		exit(1);
	}

	/* Can't write to stdout for some reason */
	if (execvp(args[0], args) < 0) {
		perror("execvp");
		exit(1);
	}
}

void parent(pid_t pid)
{
	struct ptrace_syscall_info info = { 0 };
	my_wait(pid);
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) < 0) {
		perror("ptrace(PTRACE_SETOPTIONS, ...)");
		exit(1);
	}

	for (;;) {
		if (ptrace(PTRACE_SYSCALL, pid, NULL, SIGSTOP) < 0) {
			perror("ptrace(PTRACE_SYSCALL, ...)");
			exit(1);
		}

		my_wait(pid);
		if (ptrace
		    (PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) {
			perror("ptrace(PTRACE_GET_SYSCALL_INFO, ...)");
			exit(1);
		}

		if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
			num_syscalls++;
		}

		if (!custom_print_ptrace_syscall_info(pid, &info)) {
			print_ptrace_syscall_info(&info);
		}
	}
}

void my_wait(pid_t pid)
{
	int status;
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		exit(1);
	}

	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		printf("\nchild exited with exit code %d\n", status);
		exit(0);
	}

	if (!WIFSTOPPED(status)) {
		printf("\nchild did not exit and was not stopped\n");
		exit(1);
	}
}

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define RESET "\x1b[0m"

int custom_print_ptrace_syscall_info(pid_t pid, struct
				     ptrace_syscall_info
				     *info)
{
	if (info->op != PTRACE_SYSCALL_INFO_ENTRY)
		return 0;
	switch (info->entry.nr) {
	case SYS_write:
		{
			int fd = info->entry.args[0];
			unsigned long long addr = info->entry.args[1];
			size_t length = info->entry.args[2];
			const char *str = peek_tracee_string(pid, addr, length);
			if (str) {
				printf(YELLOW "write" RESET "(%d, " GREEN
				       "\"%s\"" RESET ", %zu)", fd, str,
				       length);
			} else {
				printf(YELLOW "write" RESET "(%d, " BLUE "%p"
				       RESET ", %zu)", fd, (void *)addr,
				       length);
			}
			break;
		}
	case SYS_openat:
		{
			int dirfd = info->entry.args[0];
			unsigned long long addr = info->entry.args[1];
			int flags = info->entry.args[1];
			const char *str = peek_tracee_string(pid, addr, -1);
			assert(str);
			printf(YELLOW "openat" RESET "(%d, " GREEN "\"%s\""
			       RESET ", %d, ...)", dirfd, str, flags);
			break;
		}
	case SYS_access:
		{
			unsigned long long addr = info->entry.args[0];
			int mode = info->entry.args[1];
			const char *str = peek_tracee_string(pid, addr, -1);
			assert(str);
			printf(YELLOW "access" RESET "(" GREEN "\"%s\"" RESET
			       ", %d)", str, mode);
			break;
		}
	default:
		return 0;
	}

	return 1;
}

typedef unsigned long long word_t;
#define STR_BUF_WORD_COUNT 6
const char *peek_tracee_string(pid_t pid, unsigned
			       long long addr, int len)
{
	static char buf[sizeof(word_t) * STR_BUF_WORD_COUNT + 1];
	memset(buf, 0, sizeof(buf));

	for (unsigned long long offset = 0;
	     (len < 0 || offset < (size_t)len) && offset < sizeof(buf);
	     offset += sizeof(word_t)) {
		errno = 0;
		word_t word = ptrace(PTRACE_PEEKTEXT, pid, addr + offset,
				     0, 0);
		if (errno != 0) {
			perror("ptrace(PTRACE_PEEKTEXT, ...)");
			exit(1);
		}

		memcpy(buf + offset, &word, sizeof(word));
		if (len < 0) {
			int done = 0;
			for (size_t i = 0; i < sizeof(word_t); i++) {
				if (*(buf + offset + i) == 0) {
					done = 1;
					break;
				}
			}
			if (done) {
				break;
			}
		}
	}

	const char *finish = "...";
	memcpy(buf + sizeof(buf) - strlen(finish) -
	       1, finish, strlen(finish) + 1);

	for (char *ptr = buf; *ptr; ptr++) {
		if (*ptr == '\n') {
			*ptr = '^';
		}
	}

	return buf;
}
