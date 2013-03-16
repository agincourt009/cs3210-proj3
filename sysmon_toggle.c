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
#include <linux/spinlock.h>
#include "sysmon.h"

//#include <linux/timex.h>

MODULE_LICENSE("GPL");
#define MODULE_NAME "[sysmon] "
#define HIDE_MAX 10000

static bool init_write;

int monitor_uid;
EXPORT_SYMBOL(monitor_uid);

bool kprobe_toggle;
EXPORT_SYMBOL(kprobe_toggle);

rwlock_t w_lock;
EXPORT_SYMBOL(w_lock);

struct list_head monitor_info_container;
EXPORT_SYMBOL(monitor_info_container);
LIST_HEAD(monitor_info_container);

static struct proc_dir_entry *proc_entry;

//rwlock_t w_lock;

static struct kprobe *probe_access;	//1. sys_access,	21, 	__NR_access, 	2 args
static struct kprobe *probe_brk;	//2. sys_brk, 		12, 	__NR_brk, 	1 arg
static struct kprobe *probe_chdir;	//3. sys_chdir,		80,	__NR_chdir,	1 arg
static struct kprobe *probe_chmod;	//4. sys_chmod,		90,	__NR_chmod,	2 args
static struct kprobe *probe_clone;	//5. sys_clone,		56,	__NR_clone,	5 args
static struct kprobe *probe_close;	//6. sys_close,		3,	__NR_close,	1 arg
static struct kprobe *probe_dup;	//7. sys_dup, 		32, 	__NR_dup, 	1 arg	
static struct kprobe *probe_dup2;	//8. sys_dup2, 		33, 	__NR_dup2, 	2 args	
static struct kprobe *probe_execve;	//9. sys_execve,	59,	__NR_execve,	4 args
static struct kprobe *probe_exit_group;	//10. sys_exit_group,	231,	__NR_exit_group,1 arg	
static struct kprobe *probe_fcntl;	//11. sys_fcntl,	72,	__NR_fcntl,	3 args
static struct kprobe *probe_fork;	//12. sys_fork,		57,	__NR_fork,	1 arg
static struct kprobe *probe_getdents;	//13. sys_getdents,	78,	__NR_getdent,	3 args
static struct kprobe *probe_getpid;	//14. sys_getpid,	39,	__NR_getpid,	0 arg
static struct kprobe *probe_gettid;	//15. sys_gettid,	186,	__NR_gettid,	0 arg
static struct kprobe *probe_ioctl;	//16. sys_ioctl,	16,	__NR_ioctl,	3 args
static struct kprobe *probe_lseek;	//17. sys_lseek,	8,	__NR_lseek,	3 args

static struct kprobe *probe_mkdir;	//18. sys_mkdir,	83,	__NR_mkdir,	2 args
static struct kprobe *probe_mmap;	//19. sys_mmap,		9,	__NR_mmap,	6 args
static struct kprobe *probe_munmap;	//20. sys_munmap,	11,	__NR_munmap,	2 args
static struct kprobe *probe_open;	//21. sys_open,		2,	__NR_open,	3 args	
static struct kprobe *probe_pipe;	//22. sys_pipe, 	22,	__NR_pipe,	1 arg
static struct kprobe *probe_read;	//23. sys_read,		0,	__NR_read, 	3 args	
static struct kprobe *probe_rmdir;	//24. sys_rmdir,	84,	__NR_rmdir,	1 arg	
static struct kprobe *probe_select;	//25. sys_select,	23,	__NR_select,	5 args
static struct kprobe *probe_stat;	//26. sys_newstat,	4,	__NR_stat,	2 args	
static struct kprobe *probe_fstat;	//27. sys_newfstat,	5,	__NR_fstat,	2 args
static struct kprobe *probe_lstat;	//28. sys_newlstat,	6,	__NR_lstat,	2 args
static struct kprobe *probe_wait4;	//29. sys_wait4,	61,	__NR_wait4,	4 args
static struct kprobe *probe_write;	//30. sys_write,	1,	__NR_write,	3 args	

unsigned long long access_hide;
unsigned long long brk_hide;
unsigned long long chdir_hide;
unsigned long long chmod_hide;
unsigned long long clone_hide;
unsigned long long close_hide;
unsigned long long dup_hide;
unsigned long long dup2_hide;
unsigned long long execve_hide;
unsigned long long exit_group_hide;
unsigned long long fcntl_hide;
unsigned long long fork_hide;
unsigned long long getdents_hide;
unsigned long long getpid_hide;
unsigned long long gettid_hide;
unsigned long long ioctl_hide;
unsigned long long lseek_hide;
unsigned long long mkdir_hide;
unsigned long long mmap_hide;
unsigned long long munmap_hide;
unsigned long long open_hide;
unsigned long long pipe_hide;
unsigned long long read_hide;
unsigned long long rmdir_hide;
unsigned long long select_hide;
unsigned long long stat_hide;
unsigned long long fstat_hide;
unsigned long long lstat_hide;
unsigned long long wait4_hide;
unsigned long long write_hide;

static int sysmon_toggle_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);
static int sysmon_toggle_write_proc(struct file *file, const char *buf, unsigned long count, void *data);

static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
	int ret = 0;
	struct monitor_info *mon_info;
	struct timeval tv;

	if(kprobe_toggle)
	{
     		printk(KERN_INFO "=====current UID: %d\n", current->uid);
		if (current->uid != monitor_uid)
		{
			if(monitor_uid == -1){
				printk(KERN_INFO "=====not set monitor_uid yet\n");
			}else{
     				printk(KERN_INFO "=====%d is not sliang32's UID\n", current->uid);
			}
        		return 0;
		}
		
		write_lock(&w_lock);
		if(list_empty(&monitor_info_container))
		{
     			printk(KERN_INFO "=====list monitor_info_container is empty\n");
			mon_info = vmalloc(sizeof(mon_info));
			INIT_LIST_HEAD(&mon_info->monitor_flow);
			list_add_tail(&mon_info->monitor_flow, &monitor_info_container);
		}//end if statement
		else
		{
			mon_info = vmalloc(sizeof(mon_info));
			list_add_tail(&mon_info->monitor_flow, &monitor_info_container);
		}//end else statement
		mon_info->syscall_num = regs->rax;
		mon_info->pid = current->pid;
		mon_info->tgid = current->tgid;
		do_gettimeofday(&tv);
		mon_info->timestamp = tv.tv_usec;
	
		mon_info->arg0 = regs->rdi;
		mon_info->arg1 = regs->rsi;
		mon_info->arg2 = regs->rdx;
		mon_info->arg3 = regs->r10;
		mon_info->arg4 = regs->r8;
		mon_info->arg5 = regs->r9;
		
		write_unlock(&w_lock);
		
	}//end if statement
		
		return ret;
}	
 
static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs,
        unsigned long flags)
{
	int a, b, c;
	unsigned long long temp;
	if(!kprobe_toggle && current->uid == monitor_uid && regs->rax == 21)
	{
		a = 72384;
		b = 23241;
		c = 8383291;
		switch(regs->rax)
		{
			case __NR_brk:
				temp = brk_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(brk_hide + 1<= HIDE_MAX)
					brk_hide =brk_hide + 1;
				printk(KERN_INFO "===brk_hide: %llu\n", brk_hide);
				write_unlock(&w_lock);
				break;
			case __NR_chdir:
				temp = chdir_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(chdir_hide + 1<= HIDE_MAX)
					chdir_hide =chdir_hide + 1;
				printk(KERN_INFO "===chdir_hide: %llu\n", chdir_hide);
				write_unlock(&w_lock);
				break;
			case __NR_close:
				temp =close_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(close_hide + 1<= HIDE_MAX)
					close_hide = close_hide + 1;
				printk(KERN_INFO "===close_hide: %llu\n", close_hide);
				write_unlock(&w_lock);
				break;
			case __NR_dup:
				temp = dup_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(dup_hide + 1<= HIDE_MAX)
					dup_hide = dup_hide + 1;
				printk(KERN_INFO "===dup_hide: %llu\n", dup_hide);
				write_unlock(&w_lock);
				break;
			case __NR_exit_group:
				temp = exit_group_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(exit_group_hide + 1<= HIDE_MAX)
					exit_group_hide = exit_group_hide + 1;
				printk(KERN_INFO "===exit_group_hide: %llu\n", exit_group_hide);
				write_unlock(&w_lock);
				break;
			case __NR_fork:
				temp = fork_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(fork_hide + 1<= HIDE_MAX)
					fork_hide = fork_hide + 1;
				printk(KERN_INFO "===fork_hide: %llu\n", fork_hide);
				write_unlock(&w_lock);
				break;
			case __NR_pipe:
				temp = pipe_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(pipe_hide + 1<= HIDE_MAX)
					pipe_hide = pipe_hide + 1;
				printk(KERN_INFO "===pipe_hide: %llu\n", pipe_hide);
				write_unlock(&w_lock);
				break;
			case __NR_rmdir:
				temp = rmdir_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(rmdir_hide + 1<= HIDE_MAX)
					rmdir_hide = rmdir_hide + 1;
				printk(KERN_INFO "===rmdir_hide: %llu\n", rmdir_hide);
				write_unlock(&w_lock);
				break;
			case __NR_access:
				temp = access_hide;
				while(temp > 0)
				{
					a = a * b % c;
					printk("\n");
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(access_hide + 1<= HIDE_MAX)
					access_hide = access_hide + 1;
				//printk(KERN_INFO "===access_hide: %llu\n", access_hide);
				write_unlock(&w_lock);
				break;
			case __NR_chmod:
				temp = chmod_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(chmod_hide + 1<= HIDE_MAX)
					chmod_hide = chmod_hide + 1;
				printk(KERN_INFO "===chmod_hide: %llu\n", chmod_hide);
				write_unlock(&w_lock);
				break;
			case __NR_dup2:
				temp = dup2_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(dup2_hide + 1<= HIDE_MAX)
					dup2_hide = dup2_hide + 1;
				printk(KERN_INFO "===dup2_hide: %llu\n", dup2_hide);
				write_unlock(&w_lock);
				break;
			case __NR_mkdir:
				temp = mkdir_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(mkdir_hide + 1<= HIDE_MAX)
					mkdir_hide = mkdir_hide + 1;
				printk(KERN_INFO "===mkdir_hide: %llu\n", mkdir_hide);
				write_unlock(&w_lock);
				break;
			case __NR_munmap:
				temp = munmap_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(munmap_hide + 1<= HIDE_MAX)
					munmap_hide = munmap_hide + 1;
				printk(KERN_INFO "===munmap_hide: %llu\n", munmap_hide);
				write_unlock(&w_lock);
				break;
			case __NR_stat:
				temp = stat_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(stat_hide + 1<= HIDE_MAX)
					stat_hide = stat_hide + 1;
				printk(KERN_INFO "===stat_hide: %llu\n", stat_hide);
				write_unlock(&w_lock);
				break;
			case __NR_fstat:
				temp = fstat_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(fstat_hide + 1<= HIDE_MAX)
					fstat_hide = fstat_hide + 1;
				printk(KERN_INFO "===fstat_hide: %llu\n", fstat_hide);
				write_unlock(&w_lock);
				break;
			case __NR_lstat:
				temp = lstat_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(lstat_hide + 1<= HIDE_MAX)
					lstat_hide = lstat_hide + 1;
				printk(KERN_INFO "===lstat_hide: %llu\n", lstat_hide);
				write_unlock(&w_lock);
				break;
			case __NR_fcntl:
				temp = fcntl_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(fcntl_hide + 1<= HIDE_MAX)
					fcntl_hide = fcntl_hide + 1;
				printk(KERN_INFO "===fcntl_hide: %llu\n", fcntl_hide);
				write_unlock(&w_lock);
				break;
			case __NR_getdents:
				temp = getdents_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(getdents_hide + 1<= HIDE_MAX)
					getdents_hide = getdents_hide + 1;
				printk(KERN_INFO "===getdents_hide: %llu\n", getdents_hide);
				write_unlock(&w_lock);
				break;
			case __NR_ioctl:
				temp = ioctl_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(ioctl_hide + 1<= HIDE_MAX)
					ioctl_hide = ioctl_hide + 1;
				printk(KERN_INFO "===ioctl_hide: %llu\n", ioctl_hide);
				write_unlock(&w_lock);
				break;
			case __NR_lseek:
				temp = lseek_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(lseek_hide + 1<= HIDE_MAX)
					lseek_hide = lseek_hide + 1;
				printk(KERN_INFO "===lseek_hide: %llu\n", lseek_hide);
				write_unlock(&w_lock);
				break;
			case __NR_open:
				temp = open_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(open_hide + 1<= HIDE_MAX)
					open_hide = open_hide + 1;
				printk(KERN_INFO "===open_hide: %llu\n", open_hide);
				write_unlock(&w_lock);
				break;
			case __NR_read:
				temp = read_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(read_hide + 1<= HIDE_MAX)
					read_hide = read_hide + 1;
				printk(KERN_INFO "===read_hide: %llu\n", read_hide);
				write_unlock(&w_lock);
				break;
			case __NR_write:
				temp = write_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(write_hide + 1<= HIDE_MAX)
					write_hide = write_hide + 1;
				printk(KERN_INFO "===write_hide: %llu\n", write_hide);
				write_unlock(&w_lock);
				break;
			case __NR_execve:
				temp = execve_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(execve_hide + 1<= HIDE_MAX)
					execve_hide = execve_hide + 1;
				printk(KERN_INFO "===execve_hide: %llu\n", execve_hide);
				write_unlock(&w_lock);
				break;
			case __NR_wait4:
				temp = wait4_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(wait4_hide + 1<= HIDE_MAX)
					wait4_hide = wait4_hide + 1;
				printk(KERN_INFO "===wait4_hide: %llu\n", wait4_hide);
				write_unlock(&w_lock);
				break;
			case __NR_clone:
				temp = clone_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(clone_hide + 1<= HIDE_MAX)
					clone_hide = clone_hide + 1;
				printk(KERN_INFO "===clone_hide: %llu\n", clone_hide);
				write_unlock(&w_lock);
				break;
			case __NR_select:
				temp = select_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(select_hide + 1<= HIDE_MAX)
					select_hide = select_hide + 1;
				printk(KERN_INFO "===select_hide: %llu\n", select_hide);
				write_unlock(&w_lock);
				break;
			case __NR_mmap:
				temp = mmap_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(mmap_hide + 1<= HIDE_MAX)
					mmap_hide = mmap_hide + 1;
				printk(KERN_INFO "===mmap_hide: %llu\n", mmap_hide);
				write_unlock(&w_lock);
				break;
			case __NR_getpid:
				temp = getpid_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(getpid_hide + 1<= HIDE_MAX)
					getpid_hide = getpid_hide + 1;
				printk(KERN_INFO "===getpid_hide: %llu\n", getpid_hide);
				write_unlock(&w_lock);
				break;
			case __NR_gettid:
				temp = gettid_hide;
				while(temp > 0)
				{
					a = a * b % c;
					temp--;
				}//end while loop
				write_lock(&w_lock);
				if(gettid_hide + 1<= HIDE_MAX)
					gettid_hide = gettid_hide + 1;
				printk(KERN_INFO "===gettid_hide: %llu\n", gettid_hide);
				write_unlock(&w_lock);
				break;
			default:
				break;
		}//end switch statement
	}//end if statement    
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
		kprobe_toggle = 1; 		
	
		if(init_write)
		{
			printk(KERN_INFO "=====toggle kprobe on\n"); //first line of code for kprobe on
			// probe_access
			if(probe_access == NULL){
				probe_access = vmalloc(sizeof(*probe_access));
			}else{
				vfree(probe_access);
				probe_access = vmalloc(sizeof(*probe_access));
			}
			memset(probe_access, 0, sizeof(*probe_access));
	
			probe_access->symbol_name = "sys_access";
	    		probe_access->pre_handler = sysmon_intercept_before;
	    		probe_access->post_handler = sysmon_intercept_after;
		
			if (register_kprobe(probe_access)) 
			{
       				return -EFAULT;
			}
			
			// probe_brk
			if(probe_brk == NULL){
				probe_brk = vmalloc(sizeof(*probe_brk));
			}else{
				vfree(probe_brk);
				probe_brk = vmalloc(sizeof(*probe_brk));
			}
			memset(probe_brk, 0, sizeof(*probe_brk));
	
			probe_brk->symbol_name = "sys_brk";
    				probe_brk->pre_handler = sysmon_intercept_before;
    			probe_brk->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_brk)) 
			{
       				return -EFAULT;
			}
			
			// probe_chdir
			if(probe_chdir == NULL){
				probe_chdir = vmalloc(sizeof(*probe_chdir));
			}else{
				vfree(probe_chdir);
				probe_chdir = vmalloc(sizeof(*probe_chdir));
			}
			memset(probe_chdir, 0, sizeof(*probe_chdir));
	
			probe_chdir->symbol_name = "sys_chdir";
    			probe_chdir->pre_handler = sysmon_intercept_before;
    			probe_chdir->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_chdir)) 
			{
       				return -EFAULT;
			}
	
			// probe_chmod
			if(probe_chmod == NULL){
				probe_chmod = vmalloc(sizeof(*probe_chmod));
			}else{
				vfree(probe_chmod);
				probe_chmod = vmalloc(sizeof(*probe_chmod));
			}
			memset(probe_chmod, 0, sizeof(*probe_chmod));
	
			probe_chmod->symbol_name = "sys_chmod";
    			probe_chmod->pre_handler = sysmon_intercept_before;
    			probe_chmod->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_chmod)) 
			{
       				return -EFAULT;
			}
	
			// probe_clone
			if(probe_clone == NULL){
				probe_clone = vmalloc(sizeof(*probe_clone));
			}else{	
				vfree(probe_clone);
				probe_clone = vmalloc(sizeof(*probe_clone));
			}
			memset(probe_clone, 0, sizeof(*probe_clone));

			probe_clone->symbol_name = "sys_clone";
    			probe_clone->pre_handler = sysmon_intercept_before;
    			probe_clone->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_clone)) 
			{
       				return -EFAULT;
			}
	
			// probe_close
			if(probe_close == NULL){
				probe_close = vmalloc(sizeof(*probe_close));
			}else{
				vfree(probe_close);
				probe_close = vmalloc(sizeof(*probe_close));
			}
			memset(probe_close, 0, sizeof(*probe_close));

			probe_close->symbol_name = "sys_close";
    			probe_close->pre_handler = sysmon_intercept_before;
    			probe_close->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_close)) 
			{
       				return -EFAULT;
			}
	
			// probe_dup
			if(probe_dup == NULL){
				probe_dup = vmalloc(sizeof(*probe_dup));
			}else{
				vfree(probe_dup);
				probe_dup = vmalloc(sizeof(*probe_dup));
			}
			memset(probe_dup, 0, sizeof(*probe_dup));
		
			probe_dup->symbol_name = "sys_dup";
    			probe_dup->pre_handler = sysmon_intercept_before;
    			probe_dup->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_dup)) 
			{
       				return -EFAULT;
			}
	
			// probe_dup2
			if(probe_dup2 == NULL){
				probe_dup2 = vmalloc(sizeof(*probe_dup2));
			}else{
				vfree(probe_dup2);
				probe_dup2 = vmalloc(sizeof(*probe_dup2));
			}
			memset(probe_dup2, 0, sizeof(*probe_dup2));
	
			probe_dup2->symbol_name = "sys_dup2";
    			probe_dup2->pre_handler = sysmon_intercept_before;
    			probe_dup2->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_dup2)) 
			{
       				return -EFAULT;
			}
	
			// probe_execve
			
			if(probe_execve == NULL){
				probe_execve = vmalloc(sizeof(*probe_execve));
			}else{
				vfree(probe_execve);
				probe_execve = vmalloc(sizeof(*probe_execve));
			}
			memset(probe_execve, 0, sizeof(*probe_execve));
	
			probe_execve->symbol_name = "sys_execve";
    			probe_execve->pre_handler = sysmon_intercept_before;
    			probe_execve->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_execve)) 
			{
       				return -EFAULT;
			}
	
			// probe_exit_group
			if(probe_exit_group == NULL){
				probe_exit_group = vmalloc(sizeof(*probe_exit_group));
			}else{
				vfree(probe_exit_group);
				probe_exit_group = vmalloc(sizeof(*probe_exit_group));
			}
			memset(probe_exit_group, 0, sizeof(*probe_exit_group));
	
			probe_exit_group->symbol_name = "sys_exit_group";
    			probe_exit_group->pre_handler = sysmon_intercept_before;
    			probe_exit_group->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_exit_group)) 
			{
       				return -EFAULT;
			}
	
			// probe_fcntl
			if(probe_fcntl == NULL){
				probe_fcntl = vmalloc(sizeof(*probe_fcntl));
			}else{
				vfree(probe_fcntl);
				probe_fcntl = vmalloc(sizeof(*probe_fcntl));
			}
			memset(probe_fcntl, 0, sizeof(*probe_fcntl));
	
			probe_fcntl->symbol_name = "sys_fcntl";
    			probe_fcntl->pre_handler = sysmon_intercept_before;
    			probe_fcntl->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_fcntl)) 
			{
       				return -EFAULT;
			}
	
			// probe_fork
			
			if(probe_fork == NULL){
				probe_fork = vmalloc(sizeof(*probe_fork));
			}else{
				vfree(probe_fork);
				probe_fork = vmalloc(sizeof(*probe_fork));
			}
			memset(probe_fork, 0, sizeof(*probe_fork));
	
			probe_fork->symbol_name = "sys_fork";
    			probe_fork->pre_handler = sysmon_intercept_before;
    			probe_fork->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_fork)) 
			{
       				return -EFAULT;
			}
	
			// probe_getdents
			if(probe_getdents == NULL){
				probe_getdents = vmalloc(sizeof(*probe_getdents));
			}else{
				vfree(probe_getdents);
				probe_getdents = vmalloc(sizeof(*probe_getdents));
			}
			memset(probe_getdents, 0, sizeof(*probe_getdents));
	
			probe_getdents->symbol_name = "sys_getdents";
    			probe_getdents->pre_handler = sysmon_intercept_before;
    			probe_getdents->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_getdents)) 
			{
       				return -EFAULT;
			}
	
			// probe_getpid
			if(probe_getpid == NULL){
				probe_getpid = vmalloc(sizeof(*probe_getpid));
			}else{
				vfree(probe_getpid);
				probe_getpid = vmalloc(sizeof(*probe_getpid));
			}
			memset(probe_getpid, 0, sizeof(*probe_getpid));
	
			probe_getpid->symbol_name = "sys_getpid";
    			probe_getpid->pre_handler = sysmon_intercept_before;
    			probe_getpid->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_getpid)) 
			{
       				return -EFAULT;
			}
	
			// probe_gettid
			if(probe_gettid == NULL){
				probe_gettid = vmalloc(sizeof(*probe_gettid));
			}else{
				vfree(probe_gettid);
				probe_gettid = vmalloc(sizeof(*probe_gettid));
			}
			memset(probe_gettid, 0, sizeof(*probe_gettid));
	
			probe_gettid->symbol_name = "sys_gettid";
    			probe_gettid->pre_handler = sysmon_intercept_before;
    			probe_gettid->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_gettid)) 
			{
       				return -EFAULT;
			}
	
			// probe_ioctl
			if(probe_ioctl == NULL){
				probe_ioctl = vmalloc(sizeof(*probe_ioctl));
			}else{
				vfree(probe_ioctl);
				probe_ioctl = vmalloc(sizeof(*probe_ioctl));
			}
			memset(probe_ioctl, 0, sizeof(*probe_ioctl));
	
			probe_ioctl->symbol_name = "sys_ioctl";
    			probe_ioctl->pre_handler = sysmon_intercept_before;
    			probe_ioctl->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_ioctl)) 
			{
       				return -EFAULT;
			}
	
			// probe_lseek
			if(probe_lseek == NULL){
				probe_lseek = vmalloc(sizeof(*probe_lseek));
			}else{
				vfree(probe_lseek);
				probe_lseek = vmalloc(sizeof(*probe_lseek));
			}
			memset(probe_lseek, 0, sizeof(*probe_lseek));
	
			probe_lseek->symbol_name = "sys_lseek";
    			probe_lseek->pre_handler = sysmon_intercept_before;
    			probe_lseek->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_lseek)) 
			{
       				return -EFAULT;
			}
			
			// probe_mkdir
			if(probe_mkdir == NULL){
				probe_mkdir = vmalloc(sizeof(*probe_mkdir));
			}else{
				vfree(probe_mkdir);
				probe_mkdir = vmalloc(sizeof(*probe_mkdir));
			}
			memset(probe_mkdir, 0, sizeof(*probe_mkdir));
	
			probe_mkdir->symbol_name = "sys_mkdir";
    			probe_mkdir->pre_handler = sysmon_intercept_before;
    			probe_mkdir->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_mkdir)) 
			{
       				return -EFAULT;
			}
	
			// probe_mmap
			if(probe_mmap == NULL){
				probe_mmap = vmalloc(sizeof(*probe_mmap));
			}else{
				vfree(probe_mmap);
				probe_mmap = vmalloc(sizeof(*probe_mmap));
			}
			memset(probe_mmap, 0, sizeof(*probe_mmap));
	
			probe_mmap->symbol_name = "sys_mmap";
    			probe_mmap->pre_handler = sysmon_intercept_before;
    			probe_mmap->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_mmap)) 
			{
       				return -EFAULT;
			}
	
			// probe_munmap
			if(probe_munmap == NULL){
				probe_munmap = vmalloc(sizeof(*probe_munmap));
			}else{
				vfree(probe_munmap);
				probe_munmap = vmalloc(sizeof(*probe_munmap));
			}
			memset(probe_munmap, 0, sizeof(*probe_munmap));
	
			probe_munmap->symbol_name = "sys_munmap";
    			probe_munmap->pre_handler = sysmon_intercept_before;
    			probe_munmap->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_munmap)) 
			{
       				return -EFAULT;
			}
	
			// probe_open
			if(probe_open == NULL){
				probe_open = vmalloc(sizeof(*probe_open));
			}else{
				vfree(probe_open);
				probe_open = vmalloc(sizeof(*probe_open));
			}
			memset(probe_open, 0, sizeof(*probe_open));
	
			probe_open->symbol_name = "sys_open";
    			probe_open->pre_handler = sysmon_intercept_before;
    			probe_open->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_open)) 
			{
       				return -EFAULT;
			}
	
			// probe_pipe
			if(probe_pipe == NULL){
				probe_pipe = vmalloc(sizeof(*probe_pipe));
			}else{
				vfree(probe_pipe);
				probe_pipe = vmalloc(sizeof(*probe_pipe));
			}
			memset(probe_pipe, 0, sizeof(*probe_pipe));
	
			probe_pipe->symbol_name = "sys_pipe";
    			probe_pipe->pre_handler = sysmon_intercept_before;
    			probe_pipe->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_pipe)) 
			{
       				return -EFAULT;
			}
	
			// probe_read
			if(probe_read == NULL){
				probe_read = vmalloc(sizeof(*probe_read));
			}else{
				vfree(probe_read);
				probe_read = vmalloc(sizeof(*probe_read));
			}
			memset(probe_read, 0, sizeof(*probe_read));
	
			probe_read->symbol_name = "sys_read";
    			probe_read->pre_handler = sysmon_intercept_before;
    			probe_read->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_read)) 
			{
       				return -EFAULT;
			}
	
			// probe_rmdir
			if(probe_rmdir == NULL){
				probe_rmdir = vmalloc(sizeof(*probe_rmdir));
			}else{
				vfree(probe_rmdir);
				probe_rmdir = vmalloc(sizeof(*probe_rmdir));
			}
			memset(probe_rmdir, 0, sizeof(*probe_rmdir));
	
			probe_rmdir->symbol_name = "sys_rmdir";
    			probe_rmdir->pre_handler = sysmon_intercept_before;
    			probe_rmdir->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_rmdir)) 
			{
       				return -EFAULT;
			}
	
			// probe_select
			if(probe_select == NULL){
				probe_select = vmalloc(sizeof(*probe_select));
			}else{
				vfree(probe_select);
				probe_select = vmalloc(sizeof(*probe_select));
			}
			memset(probe_select, 0, sizeof(*probe_select));
	
			probe_select->symbol_name = "sys_select";
    			probe_select->pre_handler = sysmon_intercept_before;
    			probe_select->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_select)) 
			{
       				return -EFAULT;
			}
	
			// probe_stat
			if(probe_stat == NULL){
				probe_stat = vmalloc(sizeof(*probe_stat));
			}else{
				vfree(probe_stat);
				probe_stat = vmalloc(sizeof(*probe_stat));
			}
			memset(probe_stat, 0, sizeof(*probe_stat));
	
			probe_stat->symbol_name = "sys_newstat";
    			probe_stat->pre_handler = sysmon_intercept_before;
    			probe_stat->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_stat)) 
			{
       				return -EFAULT;
			}
	
			// probe_fstat
			if(probe_fstat == NULL){
				probe_fstat = vmalloc(sizeof(*probe_fstat));
			}else{
				vfree(probe_fstat);
				probe_fstat = vmalloc(sizeof(*probe_fstat));
			}
			memset(probe_fstat, 0, sizeof(*probe_fstat));
	
			probe_fstat->symbol_name = "sys_newfstat";
    			probe_fstat->pre_handler = sysmon_intercept_before;
    			probe_fstat->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_fstat)) 
			{
       				return -EFAULT;
			}
	
			// probe_lstat
			if(probe_lstat == NULL){
				probe_lstat = vmalloc(sizeof(*probe_lstat));
			}else{
				vfree(probe_lstat);
				probe_lstat = vmalloc(sizeof(*probe_lstat));
			}
			memset(probe_lstat, 0, sizeof(*probe_lstat));
	
			probe_lstat->symbol_name = "sys_newlstat";
    			probe_lstat->pre_handler = sysmon_intercept_before;
    			probe_lstat->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_lstat)) 
			{
       				return -EFAULT;
			}
	
			// probe_wait4
			if(probe_wait4 == NULL){
				probe_wait4 = vmalloc(sizeof(*probe_wait4));
			}else{
				vfree(probe_wait4);
				probe_wait4 = vmalloc(sizeof(*probe_wait4));
			}
			memset(probe_wait4, 0, sizeof(*probe_wait4));
	
			probe_wait4->symbol_name = "sys_wait4";
    			probe_wait4->pre_handler = sysmon_intercept_before;
    			probe_wait4->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_wait4)) 
			{
       				return -EFAULT;
			}
	
			
			// probe_write
			if(probe_write == NULL){
				probe_write = vmalloc(sizeof(*probe_write));
			}else{
				vfree(probe_write);
				probe_write = vmalloc(sizeof(*probe_write));
			}
			memset(probe_write, 0, sizeof(*probe_write));
	
			probe_write->symbol_name = "sys_write";
    			probe_write->pre_handler = sysmon_intercept_before;
    			probe_write->post_handler = sysmon_intercept_after;
			
			if (register_kprobe(probe_write)) 
			{
       				return -EFAULT;
			}
			
			init_write = 0;
		}//end if statement	
     		printk(KERN_INFO "=====register kprobe\n");
	
	}//end if statement

	else if(input==0)
	{
		kprobe_toggle = 0;
		write_lock(&w_lock);
		access_hide = 0;
		brk_hide = 0;
		chdir_hide = 0;
		chmod_hide = 0;
		clone_hide = 0;
		close_hide = 0;
		dup_hide = 0;
		dup2_hide = 0;
		execve_hide = 0;
		exit_group_hide = 0;
		fcntl_hide = 0;
		fork_hide = 0;
		getdents_hide = 0;
		getpid_hide = 0;
		gettid_hide = 0;
		ioctl_hide = 0;
		lseek_hide = 0;
		mkdir_hide = 0;
		mmap_hide = 0;
		munmap_hide = 0;
		open_hide = 0;
		pipe_hide = 0;
		read_hide = 0;
		rmdir_hide = 0;
		select_hide = 0;
		stat_hide = 0;
		fstat_hide = 0;
		lstat_hide = 0;
		wait4_hide = 0;
		write_hide = 0;
		write_unlock(&w_lock);
	}//end else if statement

	else
	{
		return -EINVAL;
	}//end else
	return count;
}//end sysmon_toggle_write_proc function



static int __init sysmon_toggle_module_init(void){
	int rv = 0;

	w_lock = RW_LOCK_UNLOCKED;
	init_write = 1;
	kprobe_toggle = 0;
	monitor_uid = -1;
		
	access_hide = 0;
	brk_hide = 0;
	chdir_hide = 0;
	chmod_hide = 0;
	clone_hide = 0;
	close_hide = 0;
	dup_hide = 0;
	dup2_hide = 0;
	execve_hide = 0;
	exit_group_hide = 0;
	fcntl_hide = 0;
	fork_hide = 0;
	getdents_hide = 0;
	getpid_hide = 0;
	gettid_hide = 0;
	ioctl_hide = 0;
	lseek_hide = 0;
	mkdir_hide = 0;
	mmap_hide = 0;
	munmap_hide = 0;
	open_hide = 0;
	pipe_hide = 0;
	read_hide = 0;
	rmdir_hide = 0;
	select_hide = 0;
	stat_hide = 0;
	fstat_hide = 0;
	lstat_hide = 0;
	wait4_hide = 0;
	write_hide = 0;

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
	
	struct list_head *temp_monitor_info;
	struct list_head *next_monitor_info;
	struct monitor_info *traverse_monitor;

	
	list_for_each_safe(temp_monitor_info, next_monitor_info, &monitor_info_container){
		traverse_monitor = list_entry(temp_monitor_info, struct monitor_info, monitor_flow);
		list_del(temp_monitor_info);
		vfree(traverse_monitor);
	}
	
	unregister_kprobe(probe_access);        
        unregister_kprobe(probe_brk);   
        unregister_kprobe(probe_chdir); 
        unregister_kprobe(probe_chmod); 
        unregister_kprobe(probe_clone); 
        unregister_kprobe(probe_close); 
        unregister_kprobe(probe_dup);   
        unregister_kprobe(probe_dup2); 
	unregister_kprobe(probe_execve);        
        unregister_kprobe(probe_exit_group);    
        unregister_kprobe(probe_fcntl); 
        unregister_kprobe(probe_fork);  
        unregister_kprobe(probe_getdents);      
        unregister_kprobe(probe_getpid);        
        unregister_kprobe(probe_gettid);        
        unregister_kprobe(probe_ioctl); 
        unregister_kprobe(probe_lseek);  
	unregister_kprobe(probe_mkdir);
        unregister_kprobe(probe_mmap);
        unregister_kprobe(probe_munmap);
        unregister_kprobe(probe_open);
        unregister_kprobe(probe_pipe);
        unregister_kprobe(probe_read);
        unregister_kprobe(probe_rmdir);
        unregister_kprobe(probe_select);
        unregister_kprobe(probe_stat);
        unregister_kprobe(probe_fstat);
        unregister_kprobe(probe_lstat);
        unregister_kprobe(probe_wait4);
        unregister_kprobe(probe_write);

        vfree(probe_access);
        vfree(probe_brk);
        vfree(probe_chdir);
        vfree(probe_chmod);
        vfree(probe_clone);
        vfree(probe_close);
        vfree(probe_dup);
        vfree(probe_dup2);
        vfree(probe_execve);
	vfree(probe_exit_group);
        vfree(probe_fcntl);
        vfree(probe_fork);
        vfree(probe_getdents);
        vfree(probe_getpid);
        vfree(probe_gettid);
        vfree(probe_ioctl);
        vfree(probe_lseek);
        vfree(probe_mkdir);
        vfree(probe_mmap);
        vfree(probe_munmap);
        vfree(probe_open);
        vfree(probe_pipe);
        vfree(probe_read);
        vfree(probe_rmdir);
        vfree(probe_select);
        vfree(probe_stat);
        vfree(probe_fstat);
        vfree(probe_lstat);
        vfree(probe_wait4);
        vfree(probe_write);
	remove_proc_entry("sysmon_toggle", proc_entry);
	printk(KERN_INFO "=====sysmon_toggle_module_cleanup called. Module unloaded\n");
}

module_init(sysmon_toggle_module_init);
module_exit(sysmon_toggle_module_cleanup);
