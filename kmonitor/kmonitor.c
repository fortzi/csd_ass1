
/* includes */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */

#include <linux/sched.h>	
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/time.h>
#include <linux/limits.h>
#include <linux/file.h>

/* Constants */
#define CR0_WP 					0x00010000  /* Write Protect Bit (CR0:16) */
#define PROCFS_NAME 			"KMonitor"
#define SYS_CALL_TABLE 			0xffffffff81801460
#define PROCFS_MAX_SIZE			1024
#define HUMAN_TIMESTAMP_SIZE	19
#define PATH_LENGTH				256
#define HISTORY_SIZE			10
#define HISTORY_RECORD			1024

#define PRINT_AND_STORE1(tmp, ...) {;;}

#define PRINT_AND_STORE(tmp,...) {				\
			printk(KERN_INFO __VA_ARGS__); 		\
			spin_lock(&history.lock);			\
			tmp = allocateHistoryRecord();		\
			sprintf(tmp, __VA_ARGS__);			\
			spin_unlock(&history.lock);			\
		}	

/* Declerations */
int getCurrentTime(char*);
char* allocateHistoryRecord(void);
static ssize_t procfile_read(struct file*, char __user *, size_t, loff_t*);
static ssize_t procfile_write(struct file*, const char __user *, size_t, loff_t*);
ssize_t my_sys_read(unsigned int, char __user *, size_t);
ssize_t my_sys_write(unsigned int, const char __user *, size_t);
ssize_t my_sys_open(const char __user *, int, umode_t);
ssize_t my_sys_listen(int, int);
ssize_t my_sys_accept(int, struct sockaddr __user *, int __user *);
ssize_t my_sys_mount(char __user *, char __user *, char __user *, unsigned long, void __user *);

/* Original system calls */
ssize_t (*orig_sys_read)(unsigned int, char __user *, size_t);
ssize_t (*orig_sys_write)(unsigned int, const char __user *, size_t);
ssize_t (*orig_sys_open)(const char __user *, int, umode_t);
ssize_t (*orig_sys_listen)(int, int);
ssize_t (*orig_sys_accept)(int, struct sockaddr __user *, int __user *);
ssize_t (*orig_sys_mount)(char __user *, char __user *, char __user *, unsigned long, void __user *);

MODULE_LICENSE("GPL");

/* Globals */
struct proc_dir_entry *Our_Proc_File;
void **syscall_table = (void **) SYS_CALL_TABLE;
static char procfs_buffer[PROCFS_MAX_SIZE];
atomic_t references;


/* Holds history records to be printed by the module's file_oprations.read */
struct history {
	spinlock_t lock;								/* Lock for write protection */
	char records[HISTORY_SIZE][HISTORY_RECORD];		/* Array to hold history records */
	int count;										/* The amount of entries recorded */
	int index;										/* The index of the records array to write the next entry to */
} history;

/* Describes the features supported by the module */
struct features {
	uint8_t files;									/* Record read, write and open syscalls */
	uint8_t network;								/* Record listen and accept syscalls */
	uint8_t mount;									/* Record mount syscall */
} features;

static struct file_operations cmd_file_ops = {
    .owner = THIS_MODULE,
    .read = procfile_read,
	.write = procfile_write,
};

/*
 * Triggers when the module is initiated.
 * Sets up features and syscall overrides.
 */
int __init init_module() {

	unsigned long cr0;	

	/* Init features and history */
	features.files = 1;
	features.network = 1;
	features.mount = 1;

	spin_lock_init(&history.lock);
	history.count = 0;
	history.index = 0;

    Our_Proc_File = proc_create(PROCFS_NAME, S_IFREG | S_IRUGO | S_IWUGO, NULL, &cmd_file_ops);

    if (Our_Proc_File == NULL) {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    /* KUIDT_INIT is a macro defined in the file 'linux/uidgid.h'. KGIDT_INIT also appears here. */
    proc_set_user(Our_Proc_File, KUIDT_INIT(0), KGIDT_INIT(0));
    /* Set proc dir entry size */
    proc_set_size(Our_Proc_File, 37);
		
	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
	
	/* Disable syscall table write protection */
	cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    /* Override syscalls and keep old syscalls for calling from within the custom syscalls and syscall restore */
    printk(KERN_DEBUG "overriding syscall read (original at %p)...\n", syscall_table[__NR_read]);
    orig_sys_read = syscall_table[__NR_read];
    syscall_table[__NR_read] = my_sys_read;
		
    printk(KERN_DEBUG "overriding syscall write (original at %p)...\n", syscall_table[__NR_write]);
    orig_sys_write = syscall_table[__NR_write];
    syscall_table[__NR_write] = my_sys_write;

	printk(KERN_DEBUG "overriding syscall open (original at %p)...\n",syscall_table[__NR_open]);
    orig_sys_open = syscall_table[__NR_open];
    syscall_table[__NR_open] = my_sys_open;

	printk(KERN_DEBUG "overriding syscall listen (original at %p)...\n", syscall_table[__NR_listen]);
    orig_sys_listen = syscall_table[__NR_listen];
    syscall_table[__NR_listen] = my_sys_listen;

	printk(KERN_DEBUG "overriding syscall accept (original at %p)...\n", syscall_table[__NR_accept]);
    orig_sys_accept = syscall_table[__NR_accept];
    syscall_table[__NR_accept] = my_sys_accept;

	printk(KERN_DEBUG "overriding syscall mount (original at %p)...\n", syscall_table[__NR_mount]);
    orig_sys_mount = syscall_table[__NR_mount];
    syscall_table[__NR_mount] = my_sys_mount;

    /* Restore syscall table write protection */
    write_cr0(cr0);
		
    return 0;
}

/*
 * Triggered on module unload.
 * Restores original syscalls.
 */
void __exit cleanup_module() {
	unsigned long cr0;

    printk(KERN_INFO "removing /proc/%s\n", PROCFS_NAME);
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
	
    printk(KERN_DEBUG "removing system call hooks!\n");
    /* Disable syscall table write protection */
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    /* Reset syscalls to original functions */
    syscall_table[__NR_read] = orig_sys_read;
    syscall_table[__NR_write] = orig_sys_write;
    syscall_table[__NR_open] = orig_sys_open;
    syscall_table[__NR_listen] = orig_sys_listen;
    syscall_table[__NR_accept] = orig_sys_accept;
    syscall_table[__NR_mount] = orig_sys_mount;
  
  	/* Restore syscall table write protection */
    write_cr0(cr0);

    printk(KERN_DEBUG "system call hooks removed!\n");
}

/*
 * Triggered when user reads from the module's proc.
 * Prints out the last HISTORY_SIZE of the recorded syscalls and what is being monitored by the module.
 */
static ssize_t procfile_read(struct file *file, char __user *buffer, size_t length, loff_t *offset) {
    static int finished = 0;
    int ret = 0;
    int i;

    printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROCFS_NAME);

    if (finished) {
        printk(KERN_INFO "procfs_read: END\n");
        finished = 0;
        ret = 0;
        return 0;
    } 

    finished = 1;
    ret += sprintf(buffer, "KMonitor - Last Events:\n");

    /* Print out history */
    for(i=0; i<history.count; i++)
	    ret += sprintf(buffer+ret, "\t%s", history.records[history.index-1-i < 0 ? HISTORY_SIZE + (history.index-1-i) : history.index-1-i]);	

	/* Print out what is being monitored */
    ret += sprintf(buffer+ret, "KMonitor Current Configuration:\n");
    ret += sprintf(buffer+ret, "\tFile Monitoring: %s\n",(features.files ? "Enabled" : "Disabled"));
    ret += sprintf(buffer+ret, "\tNetwork Monitoring: %s\n",(features.network ? "Enabled" : "Disabled"));
    ret += sprintf(buffer+ret, "\tMount Monitoring: %s\n",(features.mount ? "Enabled" : "Disabled"));
    
    return ret;
}

/*
 * Triggered when user writes to the module's proc.
 * Sets features on or off when given [FileMon|NetMon|MountMon 0|1].
 * Ignors any other input.
 */
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
	
	/* Parse user feature request, ignore bad requests */
	if (strncmp(buffer,"FileMon 1" ,9)==0)
		features.files = 1;
	if (strncmp(buffer,"NetMon 1"  ,8)==0)
		features.network = 1;
	if (strncmp(buffer,"MountMon 1",10)==0)
		features.mount = 1;
	if (strncmp(buffer,"FileMon 0" ,9)==0)
		features.files = 0;
	if (strncmp(buffer,"NetMon 0"  ,8)==0)
		features.network = 0;
	if (strncmp(buffer,"MountMon 0",10)==0)
		features.mount = 0;
	
	return procfs_buffer_size;
}

/* Signatures taken from include/linux/syscalls.h */

/* Custom read syscall */
ssize_t my_sys_read(unsigned int fd, char __user *buf, size_t count) {
	char fd_buffer[PATH_LENGTH];
	char exe_buffer[PATH_LENGTH];
	char *fd_path;
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	struct file *file;
	char *tmp_history;
	int ret;

	ret =  orig_sys_read(fd, buf, count);

	/* Failed to execute original syscall, something is wrong */
	if (ret == -1) 
		return ret;

	/* Do nothing if feature is turned off */
	if (!features.files)
		return ret;

	/* Get file using file descriptor, do nothing if it failes */
	if (!(file = fget(fd)))
		return ret;

	fd_path = d_path(&(file->f_path), fd_buffer, PATH_LENGTH);

	/* Releasing the reference to the file */
	fput(file);

	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), exe_buffer, PATH_LENGTH);
	task_unlock(current);

	getCurrentTime(timestamp);

	if (!IS_ERR(exe_path) && !IS_ERR(fd_path)) // error code
		PRINT_AND_STORE(tmp_history,"%s %s (pid: %d) is reading %zu bytes from %s\n", timestamp, exe_path, current->pid, count, fd_path);
		
	return ret;
}

/* Custom write syscall */
ssize_t my_sys_write(unsigned int fd, const char __user *buf, size_t count) {	
	char fd_buffer[PATH_LENGTH];
	char exe_buffer[PATH_LENGTH];
	char *fd_path;
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	struct file *file;
	char *tmp_history;
	int ret;

	ret = orig_sys_write(fd, buf, count);

	/* Failed to execute original syscall, something is wrong */
	if(ret == -1)
		return ret;

	/* Do nothing if feature is turned off */
	if (!features.files)
		return ret;

	/* Get file using file descriptor, do nothing if it failes */
	if(!(file = fget(fd)))
		return ret;

	fd_path = d_path(&(file->f_path), fd_buffer, PATH_LENGTH);

	/* Releasing the reference to the file */
	fput(file);

	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), exe_buffer, PATH_LENGTH);
	task_unlock(current);

	getCurrentTime(timestamp);

	if (IS_ERR(exe_path) || IS_ERR(fd_path)) // error code
		printk(KERN_ALERT "%s sys_write: error in resloving current executable path or fd path\n", timestamp);
	else
		PRINT_AND_STORE(tmp_history,"%s %s (pid: %d) is writing %zu bytes to %s\n", timestamp, exe_path, current->pid, count, fd_path);

	return ret;
}

/* Custom open syscall */
ssize_t my_sys_open(const char __user *filename, int flags, umode_t mode) {
	char buffer[PATH_LENGTH];
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	char *tmp_history;
	int ret;

	ret = orig_sys_open(filename, flags, mode);

	/* Failed to execute original syscall, something is wrong */
	if(ret == -1)
		return ret;
	
	/* Do nothing if feature is turned off */
	if (!features.files)
		return ret;

	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), buffer, PATH_LENGTH);
	task_unlock(current);

	getCurrentTime(timestamp);
	
	if (IS_ERR(exe_path)) // error code
		printk(KERN_ALERT "%s sys_open: error in resloving current executable path\n", timestamp);
	else
		PRINT_AND_STORE(tmp_history,"%s %s (pid: %d) is opening %s\n", timestamp, exe_path, current->pid, filename);
	
	return ret;
}

/* Custom listen syscall */
ssize_t my_sys_listen(int fd, int backlog) {
	char exe_buffer[PATH_LENGTH];
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	struct file *file;
	struct socket *socket;
	unsigned char *ip;
	short port;
	char *tmp_history;
	int ret;

	ret = orig_sys_listen(fd, backlog);

	/* Failed to execute original syscall, something is wrong */
	if (ret == -1)
		return ret;

	/* Do nothing if feature is turned off */
	if (!features.network)
		return ret;

	/* Get file using file descriptor, do nothing if it failes */
	if(!(file = fget(fd)))
		return ret;

	getCurrentTime(timestamp);

	/* Make sure this is really a socked file (error will suggest user mistake) */
	if (!S_ISSOCK(file->f_inode->i_mode)) {
		printk(KERN_ALERT "%s sys_listen: error fd is not of type socket !\n", timestamp);
		fput(file);
		return ret;
	}

	socket = (struct socket*) file->private_data;
	/* Releasing the reference to the file */
	fput(file);

	/* make sure this is a TCP socket */
	/* SOCK_STREAM for TCP and SOCK_DGRAM for UDP */

	if(socket->sk->sk_family != AF_INET && socket->sk->sk_family != AF_INET6) {
		printk(KERN_ALERT "%s sys_listen: socket family is not IP !!\n", timestamp);
		return ret;
	}

	if(socket->sk->sk_type != SOCK_STREAM) {
		printk(KERN_ALERT "%s sys_listen: socket type is not STREAM !!\n", timestamp);
		return ret;
	}

	if(socket->sk->sk_protocol != IPPROTO_IP && socket->sk->sk_protocol != IPPROTO_TCP) {
		printk(KERN_ALERT "%s sys_listen: socket protocal is not TCP !!\n", timestamp);
		return ret;
	}

	/* Extract port and ip address from socket data */
	lock_sock(socket->sk);
	ip = (char*)&socket->sk->__sk_common.skc_rcv_saddr;
	port =  (short)socket->sk->__sk_common.skc_num;
	release_sock(socket->sk);
	
	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), exe_buffer, PATH_LENGTH);
	task_unlock(current);

	if (IS_ERR(exe_path))
		printk(KERN_ALERT "%s sys_listen: error in resloving current executable path or fd path\n", timestamp);
	else
		PRINT_AND_STORE(tmp_history, "%s %s (pid: %d) is listening on %d.%d.%d.%d:%d\n", timestamp, exe_path, current->pid, ip[0], ip[1], ip[2], ip[3], (int)port);

	return ret;
}

/* Custom accept syscall */
ssize_t my_sys_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen) {

	char exe_buffer[PATH_LENGTH];
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	ssize_t ret;
	char *tmp_history;
	struct file *file;
	struct socket *socket;

	ret = orig_sys_accept(fd, upeer_sockaddr, upeer_addrlen);

	/* Failed to execute original syscall, something is wrong */
	if (ret == -1 || ret < 0 )
		return ret;

	/* Do nothing if feature is turned off */
	if (!features.network)
		return ret;

	/* Get file using file descriptor, do nothing if it failes */
	if(!(file = fget(fd)))
		return ret;

	getCurrentTime(timestamp);

	/* Make sure this is really a socked file (error will suggest user mistake) */
	if (!S_ISSOCK(file->f_inode->i_mode)) {
		printk(KERN_ALERT "%s sys_accept: error fd is not of type socket !\n", timestamp);
		fput(file);
		return ret;
	}

	socket = (struct socket*) file->private_data;
	/* Releasing the reference to the file */
	fput(file);

	/* make sure this is a TCP socket */
	/* SOCK_STREAM for TCP and SOCK_DGRAM for UDP */
	if(socket->sk->sk_family != AF_INET && socket->sk->sk_family != AF_INET6) {
		printk(KERN_ALERT "%s sys_accept: socket family is not IP !!\n", timestamp);
		return ret;
	}

	if(socket->sk->sk_type != SOCK_STREAM) {
		printk(KERN_ALERT "%s sys_accept: socket type is not STREAM !!\n", timestamp);
		return ret;
	}

	if(socket->sk->sk_protocol != IPPROTO_IP && socket->sk->sk_protocol != IPPROTO_TCP) {
		printk(KERN_ALERT "%s sys_accept: socket protocal is not TCP !!\n", timestamp);
		return ret;
	}

	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), exe_buffer, PATH_LENGTH);
	task_unlock(current);

	if (IS_ERR(exe_path)) // error code
		printk(KERN_ALERT "%s sys_accept: error in resloving current executable path or fd path\n", timestamp);
	else
		PRINT_AND_STORE(tmp_history, "%s %s (pid: %d) received a connection from %pISpc\n", timestamp, exe_path, current->pid, upeer_sockaddr);
	
	return ret;
}

/* Custom mount syscall */
ssize_t my_sys_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data) {
	
	char exe_buffer[PATH_LENGTH];
	char *exe_path;
	char timestamp[HUMAN_TIMESTAMP_SIZE];
	char *tmp_history;
	int ret;


	ret = orig_sys_mount(dev_name, dir_name, type, flags, data);

	/* Do nothing if feature is turned off */
	if (!features.mount)
		return ret;

	getCurrentTime(timestamp);

	/* Failed to execute original syscall, something is wrong */
	if (ret != 0) {
		printk(KERN_ALERT "%s sys_mount: error occured while mounting\n", timestamp);
		return ret;
	}

	/* Get the path of the executable that called the syscall */
	task_lock(current);
	exe_path = d_path(&(current->mm->exe_file->f_path), exe_buffer, PATH_LENGTH);
	task_unlock(current);

	if (IS_ERR(exe_path)) // error code
		printk(KERN_ALERT "%s sys_mount: error in resloving current executable path or fd path\n", timestamp);
	else
		PRINT_AND_STORE(tmp_history,"%s %s (pid: %d) mounted %s to %s using %s file system\n", timestamp, exe_path, current->pid, dev_name, dir_name, type);

	return ret;
}

/*
 * Puts the current timestamp in a human readable format in the given buffer.
 * Buffer's size is expected to be at least of size HUMAN_TIMESTAMP_SIZE.
 * Return -1 on fail and 0 on success.
 */
int getCurrentTime(char* buffer) {
	struct timeval t;
	struct tm broken;
	
	/* Get current time stamp */
	do_gettimeofday(&t);
	/* Convert timestamp to a format that makes sense */
	time_to_tm(t.tv_sec, 0, &broken);
	snprintf(buffer, HUMAN_TIMESTAMP_SIZE, "%d/%d/%ld %d:%d:%d",
		broken.tm_mday,
		broken.tm_mon,
		broken.tm_year + 1900,
		broken.tm_hour,
		broken.tm_min,
		broken.tm_sec);

	return 0;
}

/*
 * Return a buffer to write a history entry into.
 * History is cyclic modulu HISTORY_SIZE.
 */
char *allocateHistoryRecord(void) {
	char* ret;

	ret = history.records[history.index];
	history.index = (history.index + 1) % HISTORY_SIZE;

	if (history.count < HISTORY_SIZE) 
		history.count++;

		return ret;
}

/* TODO: ask shlomi - should module exit wait for all proccess using the hooks ? */

/* INFO: kmalloc http://www.makelinux.net/books/lkd2/ch11lev1sec4 */