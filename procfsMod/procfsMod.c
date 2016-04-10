/*
Source: https://blog.nyanpasu.me/a-proc-file-example/
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define procfs_name "helloworld"

static ssize_t procfile_read(struct file*, char*, size_t, loff_t*);

struct proc_dir_entry *Our_Proc_File;

static struct file_operations cmd_file_ops = {  
    .owner = THIS_MODULE,
    .read = procfile_read,
};

int init_module()  
{
    Our_Proc_File = proc_create(procfs_name, S_IFREG | S_IRUGO, NULL, &cmd_file_ops);

    if (Our_Proc_File == NULL) {
        remove_proc_entry(procfs_name, NULL);

        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", procfs_name);
        return -ENOMEM;
    }

    /*
     * KUIDT_INIT is a macro defined in the file 'linux/uidgid.h'. KGIDT_INIT also appears here.
     */
    proc_set_user(Our_Proc_File, KUIDT_INIT(0), KGIDT_INIT(0));
    proc_set_size(Our_Proc_File, 37);

    printk(KERN_INFO "/proc/%s created\n", procfs_name);
    return 0;
}

void cleanup_module()  
{
    //remove_proc_entry(procfs_name, &proc_root);
    remove_proc_entry(procfs_name, NULL);
    printk(KERN_INFO "/proc/%s removed\n", procfs_name);
}

static ssize_t procfile_read(struct file *file, char *buffer, size_t length, loff_t *offset)  
{
    static int finished = 0;
    int ret = 0;

    printk(KERN_INFO "procfile_read (/proc/%s) called\n", procfs_name);

    if (finished) {
        printk(KERN_INFO "procfs_read: END\n");
        finished = 0;
        return 0;
    }   

    finished = 1;
    ret = sprintf(buffer, "Hello,world!\n");
    return ret;
}