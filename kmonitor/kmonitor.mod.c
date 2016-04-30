#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x1e94b2a0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x4ff86f7f, __VMLINUX_SYMBOL_STR(release_sock) },
	{ 0x96242370, __VMLINUX_SYMBOL_STR(lock_sock_nested) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xda3e43d1, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x45777172, __VMLINUX_SYMBOL_STR(fput) },
	{ 0xd4e54270, __VMLINUX_SYMBOL_STR(d_path) },
	{ 0x7378123e, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x41d32f19, __VMLINUX_SYMBOL_STR(fget) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x92a9c60c, __VMLINUX_SYMBOL_STR(time_to_tm) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0xa9aab72c, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0x31c63b91, __VMLINUX_SYMBOL_STR(proc_set_size) },
	{ 0x6e4b35fa, __VMLINUX_SYMBOL_STR(proc_set_user) },
	{ 0xf07c91d, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0x70cb5d65, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3CB7F9DDDBFD2554A779CC9");
