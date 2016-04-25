#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/delay.h> 
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/socket.h>



// Write Protect Bit (CR0:16)
#define CR0_WP 0x00010000 

MODULE_LICENSE("GPL");

void **syscall_table = (void**) 0xffffffff81801460;

long (*orig_sys_open)(const char* pathname, int flags);
long (*orig_sys_read)(int fd, void* buf, size_t count);
long (*orig_sys_write)(int fd, const void *buf, size_t count);
long (*orig_sys_listen)(int sockfd, int backlog);


int my_sys_open(const char* pathname, int flags) {
	char *pname, *p;
	int pid;
	struct mm_struct* mm;
	
	printk(KERN_INFO "sys_open\n");
	return orig_sys_open(pathname, flags);
	
	mm	= current->mm;
	pid	= current->pid;
	
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			pname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pname) {
				p = d_path(&mm->exe_file->f_path, pname, PATH_MAX);
//			Now you have the path name of exe in p
			}
		}
		up_read(&mm->mmap_sem);
	}
	printk("%s (pid: %d) is opening %s\n", p, pid, pathname);
	if(pname) kfree(pname);
	return orig_sys_open(pathname, flags);
}

int my_sys_read(int fd, void* buf, size_t count) {
	int pid;
	char *pname, *p;
	struct mm_struct* mm;
	char* pathname;
	char tmp[PATH_MAX];
	struct file *file;
	ssize_t ret;
	
	printk(KERN_INFO "sys_read\n");
	return orig_sys_read(fd, buf, count);
	
	//getting full path of exe
	mm = current->mm;
	pid = current->pid;
	
	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			pname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pname) {
				p = d_path(&mm->exe_file->f_path, pname, PATH_MAX);
				/*Now you have the path name of exe in p*/
			}
		}
		up_read(&mm->mmap_sem);
	}
	//getting name of a file from fd
	file = fget(fd);
	pathname = d_path(&file->f_path, tmp, PATH_MAX);
	fput(file);
	
	ret = orig_sys_read(fd, buf, count);
	printk("%s (pid: %d) is reading %zu bytes from %s\n", p, pid, ret, pathname);

	if(pname) kfree(pname); 
	
	return ret;
}

int my_sys_write(int fd, const void *buf, size_t count) {
	
	int pid;
	//getting full path of exe
	char *pname, *p;
	struct mm_struct* mm;
	char* pathname;
	char tmp[PATH_MAX];
	struct file *file;
	ssize_t ret;
	
	printk(KERN_INFO "sys_wrire\n");
	return orig_sys_write(fd, buf, count);

	mm = current->mm;
	pid = current->pid;

	if (mm) {
		down_read(&mm->mmap_sem);
		if (mm->exe_file) {
			pname = kmalloc(PATH_MAX, GFP_ATOMIC);
			if (pname) {
				p = d_path(&mm->exe_file->f_path, pname, PATH_MAX);
	/*Now you have the path name of exe in p*/
			}
		}
		up_read(&mm->mmap_sem);
	}
	
	//getting name of a file from fd
	file = fget(fd);
	pathname = d_path(&file->f_path, tmp, PATH_MAX);
	fput(file);

	ret = orig_sys_write(fd, buf, count);
	printk("%s (pid: %d) is writing %zu bytes from %s\n", p, pid, ret, pathname);
	if(pname) kfree(pname);
	return ret;
}

int my_sys_listen(int sockfd, int backlog) {
	int type;
	int length = sizeof(int);

	/* getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length); */
	return 0;
}

int __init init_module(void) {
	unsigned long cr0;
	
	printk("<1> The module is loaded!\n");
	
	cr0 = read_cr0();
	write_cr0(cr0 & ~CR0_WP);
	//open
	orig_sys_open = syscall_table[__NR_open];
	syscall_table[__NR_open] = my_sys_open;

	//read
	orig_sys_read = syscall_table[__NR_read];
	syscall_table[__NR_read] = my_sys_read;

	//write
	orig_sys_write = syscall_table[__NR_write];
	syscall_table[__NR_write] = my_sys_write;
	
	write_cr0(cr0);
	
	return 0;
}

void __exit cleanup_module(void) {
	unsigned long cr0;
	printk("<1> The module is unloaded\n");

	cr0 = read_cr0();
	write_cr0(cr0 & ~CR0_WP);
	syscall_table[__NR_open] = orig_sys_open;
	syscall_table[__NR_read] = orig_sys_read;
	syscall_table[__NR_write] = orig_sys_write;
	write_cr0(cr0);
}
