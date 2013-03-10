#include <linux/module.h>
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
#include <linux/time.h>

static struct proc_dir_entry *proc_entry;
static struct kprobe probe;

static int sysmon_toggle_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
static int sysmon_toggle_write_proc(struct file *file, const char *buf, unsigned long count, void *data);

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	struct monitor_info *mon_info;
	struct timeval *tv;
	struct arg_info *args;
	
	if (current->uid != 396531)
	{
        	return 0;
	}
	switch (regs->rax) {
        	case __NR_mkdir:
			if(!(list_empty(current->monitor_info_container)==0))
			{
				mon_info = vmalloc(sizeof(mon_info));
				INIT_LIST_HEAD(&mon_info->monitor_flow);
				list_add_tail(&mon_info->monitor_flow, current->monitor_info_container);
			}//end if statement
			else
			{
				mon_info = vmalloc(sizeof(mon_info));
				list_add_tail(&mon_info->monitor_flow, current->monitor_info_container);
			}//end else statement
			mon_info->syscall_num = regs->rax;
			mon_info->pid = current->pid;
			mon_info->tgid = current->tgid;
			do_gettimeofday(tv);
			mon_info->timestamp = tv->tv_usec;
			
			args = vmalloc(sizeof(args));
			mon_info->arg_info_container = args;

			args->arg1 = (uintptr_t)regs->rdi;
			args->arg2 = (char*)regs->rdi;
			args->arg3 = (int)regs->rsi;	
            	break;
        	default:
            		ret = -1;
            	break;
	}
	return ret;
}
 
static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs,
        unsigned long flags)
{
    /* Here you could capture the return code if you wanted. */
}

static int sysmon_toggle_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
}//end sysmon_toggle_read_proc function


static int sysmon_toggle_write_proc(struct file *file, const char *buf, unsigned long count, void *data)
{
	static const int INPUT_SIZE = sizeof(int);
	int input;
	char temp[sizeof(int)];
	char* end;
	struct user_monitor *monitor;
	
	struct list_head *temp_arg_info;
	struct list_head *temp_monitor_info;
	struct list_head *next_arg_info;
	struct list_head *next_monitor_info;
	struct arg_info *traverse_arg;
	struct monitor_info *traverse_monitor;

	struct task_struct *n_thread;
	struct task_struct *temp;

	if(count> INPUT_SIZE)
	{
		count = INPUT_SIZE;
	}//end if statement
	
	if(copy_from_user(temp, buf, count))
   	{
   		return -EFAULT;
   	}//end if statement

	temp[count]=0;	
	
	input = (int)simple_strtol(temp, &end, 10);
	
	if(input == 1)
	{
		probe.symbol_name = "sys_mkdir";
    		probe.pre_handler = sysmon_intercept_before;
    		probe.post_handler = sysmon_intercept_after;
		if (register_kprobe(&probe)) 
		{
     			printk(KERN_ERR MODULE_NAME "register_kprobe failed\n");
       			return -EFAULT;
    		}//end if statement	
		
		monitor = vmalloc(sizeof(*monitor));	
		current->monitor_container = monitor;

		rcu_read_lock();
		do_each_thread(temp, n_thread)
		{
			temp->monitor_container = monitor;
		}while_each_thread(temp, n_thread);
		rcu_read_unlock();

	
	}//end if statement
	else if(input == 0){
		unregister_kprobe(&probe);
		list_for_each_safe(temp_monitor_info, struct monitor_info, current->monitor_container->monitor_info_container){
			traverse_monitor = list_entry(temp_monitor_info, struct monitor_info, monitor_flow);
			list_for_each_safe(temp_arg_info, struct arg_info, traverse_monitor){
				traverse_arg = list_entry(temp_arg_info, struct arg_info, arg_flow);
				list_del(temp_arg_info);
				vfree(traverse_arg);
			}
			list_del(temp_monitor_info);
			vfree(traverse_monitor);
		}
	
		vfree(current->monitor_container);
		
		rcu_read_lock();
		do_each_thread(temp, n_thread)
		{
			temp->monitor_container = NULL;
		}while_each_thread(temp, n_thread);
		rcu_read_unlock();
		
	}//end else if

	else
	{
		return -EINVAL;
	}//end else
	return count;
}//end sysmon_toggle_write_proc function



static int __init sysmon_toggle_module_init(void){
	int rv = 0;
	proc_entry = create_proc_entry("sysmon_toggle", 0600, NULL);
	if(proc_entry == NULL)
	{
		rv = -ENOMEM;
		printk(KERN_INFO "===============sysmon_toggle: Couldn't create proc entry\n");
	}
	else
	{
		proc_entry->owner = THIS_MODULE;
		proc_entry->read_proc = sysmon_toggle_read_proc;
		proc_entry->write_proc = sysmon_toggle_write_proc;
		printk(KERN_INFO "===============sysmon_toggle_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_toggle_module_cleanup(void){
	remove_proc_entry("sysmon_toggle", proc_entry);
	printk(KERN_INFO "===============sysmon_toggle_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_toggle_module_init);
module_exit(sysmon_toggle_module_cleanup);
