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
	FILE *file;
	
	file = fopen(FILE_PATH_TOGGLE, "w");
	if(file != NULL){
		fprintf(file, "1", "1");
		fclose(file);
	}else{
		printf("sysmon_toggle not open\n");
		return 1;
	}
	
//	printf("Kprobe toggled ON\n");
	file = fopen(FILE_PATH_UID, "w");
	if(file != NULL){
		fprintf(file, "396531", "396531");
		//fprintf(file, "0", "0");
		fclose(file);
	}else{
		printf("sysmon_uid not open\n");
		return 1;
	}
//	printf("Set UID\n");
/*
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
*/	
	printf("getpid, \n");
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

/*
	printf("gettid, \n");
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


	printf("dup, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_dup, 0);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("dup2, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_dup2, 0, 1);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");


	printf("getpgrp, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getpgrp);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("getgid, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getgid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("getppid, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getppid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("getegid, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getegid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");
	
	printf("getuid, \n");
	for(index_epoch = 0; index_epoch < epoch; index_epoch++){
		start = rdtsc();
		for(index_syscall = 0; index_syscall < syscall_number; index_syscall++){
			syscall(SYS_getuid);
		}
		end = rdtsc();
		total = end - start;
		printf("%llu, \n", total);
	}
	printf("\n");

*/	
	file = fopen(FILE_PATH_TOGGLE, "w");
	if(file != NULL){
		fprintf(file, "0", "0");
		fclose(file);
	}else{
		printf("sysmon_toggle not open\n");
		return 1;
	}
	
//	printf("Kprobe toggled OFF\n");
	return 0;
}
