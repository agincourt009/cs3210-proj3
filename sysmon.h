#ifndef __SYSMON_H_DEFINED__
#define __SYSMON_H_DEFINED__

struct monitor_info {
        struct list_head monitor_flow;
        unsigned int syscall_num;
        int pid;
        int tgid;
	long timestamp;

	unsigned long arg0;
        unsigned long arg1;
        unsigned long arg2;
        unsigned long arg3;
        unsigned long arg4;
        unsigned long arg5;
}; // end of monitor_info

// Global variable

#endif
