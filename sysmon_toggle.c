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
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
#define MODULE_NAME "[sysmon] "

static struct proc_dir_entry *proc_entry;
//static struct kprobe probe;
static struct kprobe *probe;

static int sysmon_toggle_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
static int sysmon_toggle_write_proc(struct file *file, const char *buf, unsigned long count, void *data);

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	struct monitor_info *mon_info;
	struct timeval tv;
	struct arg_info *args;
	
	if (current->uid != 396531)
	{
     		printk(KERN_INFO "=====not sliang32's UID\n");
        	return 0;
	}
	switch (regs->rax) {
        	case __NR_mkdir:
     			printk(KERN_INFO "=====inside mkdir\n");
			if(list_empty(&(current->monitor_container)->monitor_info_container))
			{
     				printk(KERN_INFO "=====list monitor_info_container is empty\n");
				mon_info = vmalloc(sizeof(mon_info));
				INIT_LIST_HEAD(&mon_info->monitor_flow);
				list_add_tail(&mon_info->monitor_flow, &(current->monitor_container)->monitor_info_container);
     				printk(KERN_INFO "=====add new monitor_info\n");
			}//end if statement
			else
			{
				mon_info = vmalloc(sizeof(mon_info));
				list_add_tail(&mon_info->monitor_flow, &(current->monitor_container)->monitor_info_container);
     				printk(KERN_INFO "=====add new monitor_info\n");
			}//end else statement
			mon_info->syscall_num = regs->rax;
			mon_info->pid = current->pid;
			mon_info->tgid = current->tgid;
     			printk(KERN_INFO "=====stored syscall number, pid, tgid\n");

			do_gettimeofday(&tv);
			mon_info->timestamp = tv.tv_usec;
     			printk(KERN_INFO "=====gettimeofday and get timestamp\n");
			
			args = vmalloc(sizeof(args));
			mon_info->arg_info_container = args;
     			printk(KERN_INFO "=====allocate arg_info structure\n");

			args->arg1 = regs->rdi;
			args->arg2 = regs->rdi;
			args->arg3 = regs->rsi;	
     			printk(KERN_INFO "=====add argument to arg_info\n");
            	break;
        	default:
            		ret = 0;
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
	return 0;
}//end sysmon_toggle_read_proc function


static int sysmon_toggle_write_proc(struct file *file, const char *buf, unsigned long count, void *data)
{
	static const int INPUT_SIZE = sizeof(int);
	int input;
	char temp[sizeof(int)];
	char* end;
	struct user_monitor *monitor;
	
	struct list_head *temp_monitor_info;
	struct list_head *next_monitor_info;
	struct arg_info *traverse_arg;
	struct monitor_info *traverse_monitor;

	struct task_struct *n_thread;
	struct task_struct *temp_task;

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
     		printk(KERN_INFO "=====toggle kprobe on\n");
		if(probe == NULL){
			probe = vmalloc(sizeof(*probe));
     			printk(KERN_INFO "=====probe is empty, allocate memory for probe\n");
		}else{
			vfree(probe);
			probe = vmalloc(sizeof(*probe));
		}
		memset(probe, 0, sizeof(*probe));
     		printk(KERN_INFO "=====clear memory of kprobe\n");

		probe->symbol_name = "sys_mkdir";
    		probe->pre_handler = sysmon_intercept_before;
    		probe->post_handler = sysmon_intercept_after;
     		printk(KERN_INFO "=====set handler to kprobe\n");
		
		if (register_kprobe(probe)) 
		{
     			printk(KERN_ERR MODULE_NAME "=====register_kprobe failed\n");
       			return -EFAULT;
    		}//end if statement	
		
     		printk(KERN_INFO "=====register kprobe\n");

		monitor = vmalloc(sizeof(*monitor));	
		current->monitor_container = monitor;
     		printk(KERN_INFO "=====allocate memory for current->monitor_container\n");
		INIT_LIST_HEAD(&(monitor->monitor_info_container));
     		printk(KERN_INFO "=====initial list head for current->monitor_container->monitor_info_container\n");

		rcu_read_lock();
		do_each_thread(temp_task, n_thread)
		{
			temp_task->monitor_container = monitor;
		}while_each_thread(temp_task, n_thread);
		rcu_read_unlock();

	
	}//end if statement
	else if(input == 0){
		
		printk(KERN_INFO "Unregistering kprobe\n");
		unregister_kprobe(probe);
		vfree(probe);
		list_for_each_safe(temp_monitor_info, next_monitor_info, &(current->monitor_container)->monitor_info_container){
			traverse_monitor = list_entry(temp_monitor_info, struct monitor_info, monitor_flow);
			traverse_arg = traverse_monitor->arg_info_container;
			vfree(traverse_arg);
			list_del(temp_monitor_info);
			vfree(traverse_monitor);
		}
	
		vfree(current->monitor_container);
		
		rcu_read_lock();
		do_each_thread(temp_task, n_thread)
		{
			temp_task->monitor_container = NULL;
		}while_each_thread(temp_task, n_thread);
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
	proc_entry = create_proc_entry("sysmon_toggle", 0766, NULL);
	if(proc_entry == NULL)
	{
		rv = -ENOMEM;
		printk(KERN_INFO "=====sysmon_toggle: Couldn't create proc entry\n");
	}
	else
	{
		proc_entry->owner = THIS_MODULE;
		proc_entry->read_proc = sysmon_toggle_read_proc;
		proc_entry->write_proc = sysmon_toggle_write_proc;
		printk(KERN_INFO "=====sysmon_toggle_module_init called. Module now loaded.\n");
	}
	return rv;
}

static void __exit sysmon_toggle_module_cleanup(void){
	remove_proc_entry("sysmon_toggle", proc_entry);
	printk(KERN_INFO "=====sysmon_toggle_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_toggle_module_init);
module_exit(sysmon_toggle_module_cleanup);
