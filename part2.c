#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
	unsigned int i = 1024;
	while (i-- > 0)
		syscall(SYS_access, NULL, 0);
	return 0;
}
