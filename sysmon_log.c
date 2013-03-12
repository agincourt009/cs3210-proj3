#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <linux/cdev.h>
#include <linux/rcupdate.h>

static struct proc_dir_entry *proc_entry;

static int sysmon_log_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);

static int sysmon_log_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int pid;
	int tgid;
	long timestamp;
	long unsigned int sysnum;
	uintptr_t arg1;
	char* arg2;
	int arg3;
	struct arg_info *args;

	struct arg_info *traverse_arg;
	struct monitor_info *traverse_monitor;
	struct list_head *temp_monitor_info;
	struct list_head *next_monitor_info;

	struct user_monitor *container = current->monitor_container;

	list_for_each_safe(temp_monitor_info, next_monitor_info, &container->monitor_info_container)
	{
		traverse_monitor = list_entry(temp_monitor_info, struct monitor_info, monitor_flow);
		
     		printk(KERN_INFO "=====traverse monitor_info list\n");

		sysnum = traverse_monitor->syscall_num;
     		printk(KERN_INFO "=====monitor_info: sysmon: %lu\n", sysnum);
		pid = traverse_monitor->pid;
     		printk(KERN_INFO "=====monitor_info: pid: %d\n", pid);
		tgid = traverse_monitor->tgid;
     		printk(KERN_INFO "=====monitor_info: tgid: %d\n", tgid);
		timestamp = traverse_monitor->timestamp;
     		printk(KERN_INFO "=====monitor_info: timestamp: %lu\n", timestamp);
		args = traverse_monitor->arg_info_container;
     		
		printk(KERN_INFO "=====monitor_info: get args pointer\n");

		arg1 = (uintptr_t)args->arg1;
		printk(KERN_INFO "=====monitor_info: args1: 0x%lu\n", arg1);
		arg2 = vmalloc(100 * sizeof(*arg2));
		arg2 = (char*)args->arg2;
		//sprintf(arg2, "%lu", args->arg2);
		printk(KERN_INFO "=====monitor_info: args2: '%s'\n", arg2);
		arg3 = (int)args->arg3;
     		
		printk(KERN_INFO "=====monitor_info: args3: %d\n", arg3);
		
		sprintf(page, "%lu %d %d args 0x%lu '%s' %d\n",
                    	sysnum, pid, tgid,
                    	arg1, arg2, arg3);	

		traverse_arg = traverse_monitor->arg_info_container;
		vfree(traverse_arg);

		list_del(temp_monitor_info);
		vfree(traverse_monitor);
	}//end list_for_each_safe loop
	return count;
}//end sysmon_log_read_proc function

static int __init sysmon_log_module_init(void){
	int rv = 0;
	proc_entry = create_proc_entry("sysmon_log", 0766, NULL);
	if(proc_entry == NULL)
	{
		rv = -ENOMEM;
		printk(KERN_INFO "=====sysmon_log: Couldn't create proc entry\n");
	}
	else
	{
		proc_entry->owner = THIS_MODULE;
		proc_entry->read_proc = sysmon_log_read_proc;
		printk(KERN_INFO "=====sysmon_log_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_log_module_cleanup(void){
	remove_proc_entry("sysmon_log", proc_entry);
	printk(KERN_INFO "=====sysmon_log_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_log_module_init);
module_exit(sysmon_log_module_cleanup);
