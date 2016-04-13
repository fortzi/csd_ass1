/*
Source: https://blog.nyanpasu.me/a-proc-file-example/
*/
#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dcache.h>

/* Write Protect Bit (CR0:16) */
#define CR0_WP 						0x00010000 
/* Constants */
#define PROCFS_NAME 			"KMonitor"
#define SYS_CALL_TABLE 		0xffffffff81801460
#define PROCFS_MAX_SIZE		1024

MODULE_LICENSE("GPL");

/* Declerations */
static ssize_t procfile_read(struct file*, char*, size_t, loff_t*);
static ssize_t procfile_write(struct file*, const char __user *, size_t, loff_t*);
ssize_t my_sys_read(int fd, void *buf, size_t count);

/* Globals */
struct proc_dir_entry *Our_Proc_File;
void **syscall_table = (void **) SYS_CALL_TABLE;
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
static char procfs_buffer[PROCFS_MAX_SIZE];

static struct file_operations cmd_file_ops = {  
    .owner = THIS_MODULE,
    .read = procfile_read,
		.write = procfile_write,
};

int init_module() {
		char buffer[128];
		char *path_name;
		unsigned long cr0;	
	
    Our_Proc_File = proc_create(PROCFS_NAME, S_IFREG | S_IRUGO, NULL, &cmd_file_ops);

    if (Our_Proc_File == NULL) {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    /* KUIDT_INIT is a macro defined in the file 'linux/uidgid.h'. KGIDT_INIT also appears here. */
    proc_set_user(Our_Proc_File, KUIDT_INIT(0), KGIDT_INIT(0));
    proc_set_size(Our_Proc_File, 37);
		
	  printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
		
		
		cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    printk(KERN_DEBUG "Houston! We have full write access to all pages. Proceeding...\n");
    orig_sys_read = syscall_table[__NR_read];
    syscall_table[__NR_read] = my_sys_read;

    write_cr0(cr0);
		
    return 0;
}

void cleanup_module() {
		unsigned long cr0;
		
    printk(KERN_INFO "removing /proc/%s\n", PROCFS_NAME);
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
		

    printk(KERN_DEBUG "removing sys_read hook!\n");
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    syscall_table[__NR_read] = orig_sys_read;
    write_cr0(cr0);
    printk(KERN_DEBUG "sys_read hook removed!\n");
}

static ssize_t procfile_read(struct file *file, char *buffer, size_t length, loff_t *offset) {
    static int finished = 0;
    int ret = 0;

    printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROCFS_NAME);

    if (finished) {
        printk(KERN_INFO "procfs_read: END\n");
        finished = 0;
        return 0;
    }   

    finished = 1;
    ret = sprintf(buffer, "Hello,world!\n");
    return ret;
}

static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
	/* get buffer size */
	int procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
		return -EFAULT;
	}
	
	return procfs_buffer_size;
}

ssize_t my_sys_read(int fd, void *buf, size_t count) {

	printk(KERN_INFO "############# my sys_read #############");
	
	return orig_sys_read(fd, buf, count);
}