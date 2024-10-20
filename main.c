#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>

#include "print_syscall.h"

void child(char **args);
void parent(pid_t pid);
void my_wait(pid_t pid);

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

	parent(pid);
}

void child(char **args)
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_TRACEME, ...)");
		exit(1);
	}

	/* Can't write to stdout for some reason */
	int fd = open("/dev/null", O_WRONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);

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

		if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) <
		    0) {
			perror("ptrace(PTRACE_GET_SYSCALL_INFO, ...)");
			exit(1);
		}

		print_ptrace_syscall_info(&info);
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
		printf("child exited with exit code %d\n", status);
		exit(0);
	}

	if (!WIFSTOPPED(status)) {
		printf("child did not exit and was not stopped\n");
		exit(1);
	}
}
