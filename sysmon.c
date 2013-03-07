#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
 
MODULE_LICENSE("GPL");
 
#define MODULE_NAME "[sysmon] "
static struct kprobe probe;
 
/* pt_regs defined in include/asm-x86/ptrace.h
 *
 * For information associating registers with function arguments, see:
 * http://lxr.linux.no/linux+v2.6.24.6/arch/x86/kernel/entry_64.S#L182
 */
static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
    int ret = 0;
    if (current->uid != uid)
        return 0;
    switch (regs->rax) {
        case __NR_mkdir:
            printk(KERN_INFO MODULE_NAME
                    /* sycall pid tid args.. */
                    "%lu %d %d args 0x%lu '%s' %d\n",
                    regs->rax, current->pid, current->tgid,
                    (uintptr_t)regs->rdi, (char*)regs->rdi, (int)regs->rsi);
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
 
int init_module(void)
{
    probe.symbol_name = "sys_mkdir";
    probe.pre_handler = sysmon_intercept_before; /* called prior to function */
    probe.post_handler = sysmon_intercept_after; /* called on function return */
    if (register_kprobe(&probe)) {
        printk(KERN_ERR MODULE_NAME "register_kprobe failed\n");
        return -EFAULT;
    }
    printk(KERN_INFO MODULE_NAME "loaded\n");
    return 0;
}
 
void cleanup_module(void)
{
    unregister_kprobe(&probe);
    printk(KERN_INFO MODULE_NAME "unloaded\n");
}
