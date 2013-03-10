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
	
}//end sysmon_log_read_proc function

static int __init sysmon_log_module_init(void){
	int rv = 0;
	proc_entry = create_proc_entry("sysmon_log", 0400, NULL);
	if(proc_entry == NULL)
	{
		rv = -ENOMEM;
		printk(KERN_INFO "===============sysmon_log: Couldn't create proc entry\n");
	}
	else
	{
		proc_entry->owner = THIS_MODULE;
		proc_entry->read_proc = sysmon_log_read_proc;
		proc_entry->write_proc = sysmon_log_write_proc;
		printk(KERN_INFO "===============sysmon_log_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_log_module_cleanup(void){
	remove_proc_entry("sysmon_log", proc_entry);
	printk(KERN_INFO "===============sysmon_log_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_log_module_init);
module_exit(sysmon_log_module_cleanup);
