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

static int sysmon_uid_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
static int sysmon_uid_write_proc(struct file *file, const char *buf, unsigned long count, void *data);

static int sysmon_uid_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
}//end sysmon_uid_read_proc function


static int sysmon_uid_write_proc(struct file *file, const char *buf, unsigned long count, void *data)
{
}//end sysmon_uid_write_proc function

static int __init sysmon_uid_module_init(void){
	int rv = 0;
	proc_entry = create_proc_entry("sysmon_uid", 0600, NULL);
	if(proc_entry == NULL)
	{
		rv = -ENOMEM;
		printk(KERN_INFO "===============sysmon_uid: Couldn't create proc entry\n");
	}
	else
	{
		proc_entry->owner = THIS_MODULE;
		proc_entry->read_proc = sysmon_uid_read_proc;
		proc_entry->write_proc = sysmon_uid_write_proc;
//?		new_process = vmalloc(sizeof(*new_process));
		printk(KERN_INFO "===============sysmon_uid_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_uid_module_cleanup(void){
	struct list_head *temp_thread;
	struct list_head *next;
	struct thread_id *traverse_thread;

	printk(KERN_INFO "===============free the list\n");
	
	list_for_each_safe(temp_thread, next, &procID->threads){
		traverse_thread = list_entry(temp_thread, struct thread_id, thread_list);
		printk(KERN_INFO "===============free tid: %d\n", traverse_thread->tid);
		list_del(temp_thread);
//?		vfree(traverse_thread);
	}
	
	printk(KERN_INFO "===============free the procID\n");
//?	vfree(procID);
	remove_proc_entry("sysmon_uid", proc_entry);
	printk(KERN_INFO "===============sysmon_uid_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_uid_module_init);
module_exit(sysmon_uid_module_cleanup);
