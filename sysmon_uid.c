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

MODULE_LICENSE("GPL");
static struct proc_dir_entry *proc_entry;

static int sysmon_uid_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
static int sysmon_uid_write_proc(struct file *file, const char *buf, unsigned long count, void *data);

static int sysmon_uid_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int length;  

	length = sprintf(page, "%d", current->monitor_container->monitor_uid);

  	return length;
}//end sysmon_uid_read_proc function


static int sysmon_uid_write_proc(struct file *file, const char *buf, unsigned long count, void *data)
{
	int mon_uid;
	char temp[256];
	char* end;

	if(count> 256)
	{
		count = 256;
	}//end if statement
	
	if(copy_from_user(temp, buf, count))
   	{
   		return -EFAULT;
   	}//end if statement

	temp[count]=0;	
	
	mon_uid = (int)simple_strtol(temp, &end, 10);
	printk(KERN_INFO "the input UID is mon_uid: %d\n", mon_uid);
	current->monitor_container->monitor_uid = mon_uid;

	return count;
}//end sysmon_uid_write_proc function

static int __init sysmon_uid_module_init(void){
	int rv = 0;
	proc_entry = create_proc_entry("sysmon_uid", 0766, NULL);
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
		printk(KERN_INFO "===============sysmon_uid_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_uid_module_cleanup(void){
	remove_proc_entry("sysmon_uid", proc_entry);
	printk(KERN_INFO "===============sysmon_uid_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_uid_module_init);
module_exit(sysmon_uid_module_cleanup);
