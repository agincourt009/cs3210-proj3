#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "rdtsc.h"

#define FILE_PATH_UID "/proc/sysmon_uid"
#define FILE_PATH_TOGGLE "/proc/sysmon_toggle"
#define FILE_PATH_LOG "/proc/sysmon_log"

int main(void)
{
	unsigned int syscall_number = 1024;
	unsigned int epoch = 100;
	unsigned int index_syscall = 0;
	unsigned int index_epoch = 0;

	unsigned long long start, end, total;

	printf("access, ");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_access, NULL, 0);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("getpid, ");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getpid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("gettid, ");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_gettid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	return 0;
}
