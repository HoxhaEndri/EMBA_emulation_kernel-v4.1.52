#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/reboot.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <net/inet_sock.h>

#include "firmadyne.h"
#include "hooks.h"
#include "hooks-private.h"

#define GET_ARG(n, regs)   \
    ((arch == ARCH_X86_64) ? ((n) == 1 ? regs->di : \
                               (n) == 2 ? regs->si : \
                               (n) == 3 ? regs->dx : \
                               (n) == 4 ? regs->cx : 0) : \
     (arch == ARCH_ARM64) ? ((n) == 1 ? regs->regs[0] : \
                              (n) == 2 ? regs->regs[1] : \
                              (n) == 3 ? regs->regs[2] : \
                              (n) == 4 ? regs->regs[3] : 0) : \
     (arch == ARCH_ARM) ? ((n) == 1 ? regs->uregs[0] : \
                            (n) == 2 ? regs->uregs[1] : \
                            (n) == 3 ? regs->uregs[2] : \
                            (n) == 4 ? regs->uregs[3] : 0) : \
     (arch == ARCH_MIPS) ? ((n) == 1 ? regs->regs[4] : \
                             (n) == 2 ? regs->regs[5] : \
                             (n) == 3 ? regs->regs[6] : \
                             (n) == 4 ? regs->regs[7] : 0) : 0)

/* Network related operations; e.g. bind, accept, etc */
#define LEVEL_NETWORK (1 << 0)
/* System operations; e.g. reboot, mount, ioctl, execve, etc */
#define LEVEL_SYSTEM  (1 << 1)
/* Filesystem write operations; e.g. unlink, mknod, etc */
#define LEVEL_FS_W    (1 << 2)
/* Filesystem read operations; e.g. open, close, etc */
#define LEVEL_FS_R    (1 << 3)
/* Process execution operations; e.g. mmap, fork, etc */
#define LEVEL_EXEC    (1 << 4)
/* Process execution checker; e.g. popen, system, execve, etc */
#define LEVEL_ANALYZE (1 << 5)

#define SYSCALL_HOOKS \
	/* Hook network binds */ \
	HOOK("inet_bind", bind_hook, bind_probe) \
	/* Hook accepts */ \
	HOOK("inet_accept", accept_hook, accept_probe) \
	/* Hook VLAN creation */ \
	HOOK("register_vlan_dev", vlan_hook, vlan_probe) \
	/* Hook assignments of IP addresses to network interfaces */ \
	HOOK("__inet_insert_ifa", inet_hook, inet_probe) \
	/* Hook adding of interfaces to bridges */ \
	HOOK("br_add_if", br_hook, br_probe) \
	/* Hook socket calls */ \
	HOOK("sys_socket", socket_hook, socket_probe) \
	/* Hook changes in socket options */ \
	HOOK("sys_setsockopt", setsockopt_hook, setsockopt_probe) \
\
	/* Hook mounting of file systems */ \
	HOOK("do_mount", mount_hook, mount_probe) \
	/* Hook creation of device nodes */ \
	HOOK("vfs_mknod", mknod_hook, mknod_probe) \
	/* Hook deletion of files */ \
	HOOK("vfs_unlink", unlink_hook, unlink_probe) \
	/* Hook IOCTL's on files */ \
	HOOK("do_vfs_ioctl", ioctl_hook, ioctl_probe) \
	/* Hook system reboot */ \
	HOOK("sys_reboot", reboot_hook, reboot_probe) \
\
	/* Hook opening of file descriptors */ \
	HOOK("do_sys_open", open_hook, open_probe) \
/*	HOOK_RET("do_sys_open", NULL, open_ret_hook, open_ret_probe) */ \
	/* Hook closing of file descriptors */ \
	HOOK("sys_close", close_hook, close_probe) \
\
	/* Hook execution of programs */ \
	HOOK("do_execve", execve_hook, execve_probe) \
	/* Hook forking of processes */ \
	HOOK("do_fork", fork_hook, fork_probe) \
	HOOK_RET("do_fork", NULL, fork_ret_hook, fork_ret_probe) \
	/* Hook process exit */ \
	HOOK("do_exit", exit_hook, exit_probe) \
	/* Hook sending of signals */ \
	HOOK("do_send_sig_info", signal_hook, signal_probe) \
\
	/* Hook memory mapping */ \
	HOOK("mmap_region", mmap_hook, mmap_probe)

static char *envp_init[] = { "HOME=/", "TERM=linux", "LD_PRELOAD=/firmadyne/libnvram.so", NULL };

static int socket_hook(struct kprobe *kp, struct pt_regs *regs) {
	int family = (int)GET_ARG(1, regs);
	int type = (int)GET_ARG(2, regs);
	int protocol = (int)GET_ARG(3, regs);
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": sys_socket[PID: %d (%s)]: family:%d, type:%d, protocol:%d\n", task_pid_nr(current), current->comm, family, type, protocol);
	}
  return 0;
}

static int setsockopt_hook(struct kprobe *kp, struct pt_regs *regs) {
	int fd = (int)GET_ARG(1, regs);
	int level = (int)GET_ARG(2, regs);
	int optname = (int)GET_ARG(3, regs);
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": sys_setsockopt[PID: %d (%s)]: fd:%d, level:%d, optname:%d\n", task_pid_nr(current), current->comm, fd, level, optname);
	}
  return 0;
}

static int reboot_hook(struct kprobe *kp, struct pt_regs *regs) {
	long magic1 = (long)GET_ARG(1, regs);
	long magic2 = (long)GET_ARG(2, regs);
	unsigned int cmd = (unsigned int)GET_ARG(3, regs);
	static char *argv_init[] = { "/sbin/init", NULL };
	kernel_cap_t pE, pP, pI;
	struct cred *new;

	if (reboot || syscall & LEVEL_SYSTEM) {
		printk(KERN_INFO MODULE_NAME": sys_reboot[PID: %d (%s)]: magic1:%x, magic2:%x, cmd:%x\n", task_pid_nr(current), current->comm, magic1, magic2, cmd);
	}

	if (reboot && cmd != LINUX_REBOOT_CMD_CAD_OFF && cmd != LINUX_REBOOT_CMD_CAD_ON) {
		if (security_capget(current, &pE, &pI, &pP)) {
			printk(KERN_WARNING MODULE_NAME": security_capget() failed!\n");
			goto out;
		}

		if (!(new = prepare_creds())) {
			printk(KERN_WARNING MODULE_NAME": prepare_creds() failed!\n");
			goto out;
		}

		cap_lower(pE, CAP_SYS_BOOT);
		cap_lower(pI, CAP_SYS_BOOT);
		cap_lower(pP, CAP_SYS_BOOT);

		if (security_capset(new, current_cred(), &pE, &pI, &pP)) {
			printk(KERN_WARNING MODULE_NAME": security_capset() failed!\n");
			abort_creds(new);
			goto out;
		}

		commit_creds(new);
		printk(KERN_INFO MODULE_NAME": sys_reboot: removed CAP_SYS_BOOT, starting init...\n");

		call_usermodehelper(argv_init[0], argv_init, envp_init, UMH_NO_WAIT);
	}

out: 
  return 0;
}

static int mount_hook(struct kprobe *kp, struct pt_regs *regs) {
	char *dev_name = (char *)GET_ARG(1, regs);
	char *dir_name = (char *)GET_ARG(2, regs);
	char* type_page = (char *)GET_ARG(3, regs);
	if (syscall & LEVEL_SYSTEM) {
		printk(KERN_INFO MODULE_NAME": do_mount[PID: %d (%s)]: mountpoint:%s, device:%s, type:%s\n", task_pid_nr(current), current->comm, dir_name, dev_name, type_page);
	}
  return 0;
}

static int ioctl_hook(struct kprobe *kp, struct pt_regs *regs) {
	unsigned int cmd = (unsigned int )GET_ARG(2, regs);
	unsigned long arg = (unsigned long)GET_ARG(3, regs);
	if (syscall & LEVEL_SYSTEM) {
		printk(KERN_INFO MODULE_NAME": vfs_ioctl[PID: %d (%s)]: cmd:0x%x arg:0x%lx\n", task_pid_nr(current), current->comm, cmd, arg);
	}
	//if (syscall & LEVEL_NETWORK && cmd == SIOCSIFHWADDR) {
	//	printk(KERN_INFO MODULE_NAME": ioctl_SIOCSIFHWADDR[PID: %d (%s)]: dev:%s mac:0x%p 0x%p\n", task_pid_nr(current), current->comm, (char *)arg, *(unsigned long *)(arg + offsetof(struct ifreq, ifr_hwaddr)), *(unsigned long *)(arg + offsetof(struct ifreq, ifr_hwaddr) + 4));
	//}
  return 0;
}

static int unlink_hook(struct kprobe *kp, struct pt_regs *regs) {
	struct dentry *dentry = (struct dentry *)GET_ARG(2, regs);
	if (syscall & LEVEL_FS_W) {
		printk(KERN_INFO MODULE_NAME": vfs_unlink[PID: %d (%s)]: file:%s\n", task_pid_nr(current), current->comm, dentry->d_name.name);
	}
  return 0;
}

static int signal_hook(struct kprobe *kp, struct pt_regs *regs) {
	int sig = (int)GET_ARG(1, regs);
	struct task_struct *p = (struct task_struct *)GET_ARG(3, regs);
	if (syscall & LEVEL_EXEC) {
		printk(KERN_INFO MODULE_NAME": do_send_sig_info[PID: %d (%s)]: PID:%d, signal:%u\n", task_pid_nr(current), current->comm, p->pid, sig);
	}
  return 0;
}

static int vlan_hook(struct kprobe *kp, struct pt_regs *regs) {
	struct net_device *dev = (struct net_device *)GET_ARG(1, regs);
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": register_vlan_dev[PID: %d (%s)]: dev:%s vlan_id:%d\n", task_pid_nr(current), current->comm, dev->name, vlan_dev_vlan_id(dev));

	}
  return 0;
}

static int bind_hook(struct kprobe *kp, struct pt_regs *regs) {
	struct socket *sock = (struct socket *)GET_ARG(1, regs);
	struct sockaddr *uaddr = (struct sockaddr *)GET_ARG(2, regs);
	if (syscall & LEVEL_NETWORK) {
		unsigned int sport = htons(((struct sockaddr_in *)uaddr)->sin_port);
		printk(KERN_INFO MODULE_NAME": inet_bind[PID: %d (%s)]: proto:%s, port:%d\n", task_pid_nr(current), current->comm, sock->type == SOCK_STREAM ? "SOCK_STREAM" : (sock->type == SOCK_DGRAM ? "SOCK_DGRAM" : "SOCK_OTHER"), sport);
	}
  return 0;
}

static int accept_hook(struct kprobe *kp, struct pt_regs *regs) {
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": inet_accept[PID: %d (%s)]:\n", task_pid_nr(current), current->comm);
	}
  return 0;
}

static int mmap_hook(struct kprobe *kp, struct pt_regs *regs) {
  struct file *file = (struct file *)GET_ARG(1, regs);
	unsigned long addr = (unsigned long)GET_ARG(2, regs);
	unsigned long len = (unsigned long)GET_ARG(3, regs);
	unsigned long vm_flags = (unsigned long)GET_ARG(4, regs);
	if (syscall & LEVEL_EXEC && (vm_flags & VM_EXEC)) {
		if (file && file->f_path.dentry) {
			printk(KERN_INFO MODULE_NAME": mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx, file:%s\n", task_pid_nr(current), current->comm, addr, addr+len, file->f_path.dentry->d_name.name);
		}
		else {
			printk(KERN_INFO MODULE_NAME": mmap_region[PID: %d (%s)]: addr:0x%lx -> 0x%lx\n", task_pid_nr(current), current->comm, addr, addr+len);
		}
	}
  return 0;
}

static int exit_hook(struct kprobe *kp, struct pt_regs *regs) {
	long code = (long)GET_ARG(1, regs);
	if (syscall & LEVEL_EXEC && strcmp("khelper", current->comm)) {
		printk(KERN_INFO MODULE_NAME": do_exit[PID: %d (%s)]: code:%lu\n", task_pid_nr(current), current->comm, code);
	}
  return 0;
}

static int fork_hook(struct kprobe *kp, struct pt_regs *regs) {
	unsigned long clone_flags = (unsigned long)GET_ARG(1, regs);
	unsigned long stack_size = (unsigned long)GET_ARG(3, regs);
	if (syscall & LEVEL_EXEC && strcmp("khelper", current->comm)) {
		printk(KERN_INFO MODULE_NAME": do_fork[PID: %d (%s)]: clone_flags:0x%lx, stack_size:0x%lx\n", task_pid_nr(current), current->comm, clone_flags, stack_size);
	}
  return 0;
}

static int fork_ret_hook(struct kretprobe_instance *ri, struct pt_regs *regs) {
	if (syscall & LEVEL_EXEC && strcmp("khelper", current->comm)) {
		printk(KERN_INFO MODULE_NAME": do_fork_ret[PID: %d (%s)] = %ld\n", task_pid_nr(current), current->comm, regs_return_value(regs));
	}

	return 0;
}

static int close_hook(struct kprobe *kp, struct pt_regs *regs) {
	unsigned int fd = (unsigned int)GET_ARG(1, regs);
	if (syscall & LEVEL_FS_R) {
		printk(KERN_INFO MODULE_NAME": close[PID: %d (%s)]: fd:%d\n", task_pid_nr(current), current->comm, fd);
	}
  return 0;
}

static int open_ret_hook(struct kretprobe_instance *ri, struct pt_regs *regs) {
	if (syscall & LEVEL_FS_R) {
		printk(KERN_CONT ": close[PID: %d (%s)] = %ld\n", task_pid_nr(current), current->comm, regs_return_value(regs));
	}

	return 0;
}

static int open_hook(struct kprobe *kp, struct pt_regs *regs) {
	const char __user *filename = (const char __user *)GET_ARG(2, regs);
	int flags = (int)GET_ARG(3, regs);
	if (syscall & LEVEL_FS_R) {
		printk(KERN_INFO MODULE_NAME": do_sys_open[PID: %d (%s)]: file:%s\n", task_pid_nr(current), current->comm, filename);
	}
  return 0;
}

static int execve_hook(struct kprobe *kp, struct pt_regs *regs) {
	const char __user *const __user *argv = GET_KERNEL_ARG(regs,1);
	const char __user *const __user *envp = GET_KERNEL_ARG(regs,2);
	int i;
	static char *argv_init[] = { "/firmadyne/console", NULL };

	if (execute > 5) {
		execute = 0;

		printk(KERN_INFO MODULE_NAME": do_execve: %s\n", argv_init[0]);
		call_usermodehelper(argv_init[0], argv_init, envp_init, UMH_NO_WAIT);

		printk(KERN_WARNING "OFFSETS: offset of pid: 0x%x offset of comm: 0x%x\n", offsetof(struct task_struct, pid), offsetof(struct task_struct, comm));
	}
	else if (execute > 0) {
		execute += 1;
	}

	if (syscall & LEVEL_SYSTEM && strcmp("khelper", current->comm)) {
		printk(KERN_INFO MODULE_NAME": do_execve[PID: %d (%s)]: argv:", task_pid_nr(current), current->comm);
		for (i = 0; i >= 0 && i < count(argv, MAX_ARG_STRINGS); i++) {
			printk(KERN_CONT " %s", argv[i]);
		}

		printk(KERN_CONT ", envp:");
		for (i = 0; i >= 0 && i < count(envp, MAX_ARG_STRINGS); i++) {
			printk(KERN_CONT " %s", envp[i]);
		}
	}

	if (syscall & LEVEL_ANALYZE &&
		strcmp("khelper", current->comm) &&
		strcmp("rcS", current->comm) &&
		strcmp("preInit.sh", current->comm) &&
		strcmp("network.sh", current->comm) &&
		strcmp("run_service.sh", current->comm) &&
		argv[0][0] != '[') // generally compare line
	{
		printk("\n\n[ANALYZE] [PID: %d (%s)]:", task_pid_nr(current), current->comm);
		for (i = 0; i >= 0 && argv[i]; i++) {
			printk(KERN_CONT " %s", argv[i]);
		}

		printk(KERN_CONT "\nenvp:");
		for (i = 0; i >= 0 && envp[i]; i++) {
			printk(KERN_CONT " %s", envp[i]);
		}

		printk("\n\n");
	}
  return 0;
}

static int mknod_hook(struct kprobe *kp, struct pt_regs *regs){
	struct dentry *dentry = (struct dentry *)GET_ARG(2, regs);
	dev_t dev = (dev_t)GET_ARG(4, regs);
	if (syscall & LEVEL_FS_W) {
		printk(KERN_INFO MODULE_NAME": vfs_mknod[PID: %d (%s)]: file:%s major:%d minor:%d\n", task_pid_nr(current), current->comm, dentry->d_name.name, MAJOR(dev), MINOR(dev));
	}
  return 0;
}

static int br_hook(struct kprobe *kp, struct pt_regs *regs) {
	struct net_bridge *br = (struct net_bridge *)GET_ARG(1, regs);
	struct net_device *dev = (struct net_device *)GET_ARG(2, regs);
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": br_add_if[PID: %d (%s)]: br:%s dev:%s\n", task_pid_nr(current), current->comm, br->dev->name, dev->name);
	}
  return 0;
}

static int inet_hook(struct kprobe *kp, struct pt_regs *regs) {
	struct in_ifaddr *ifa = (struct in_ifaddr *)GET_ARG(1, regs);
	if (syscall & LEVEL_NETWORK) {
		printk(KERN_INFO MODULE_NAME": __inet_insert_ifa[PID: %d (%s)]: device:%s ifa:0x%08x\n", task_pid_nr(current), current->comm, ifa->ifa_dev->dev->name, ifa->ifa_address);
	}
  return 0;
}

#define HOOK_RET(a, b, c, d) \
static struct kretprobe d = { \
	.entry_handler = b, \
	.handler = c, \
	.kp = { \
		.symbol_name = a, \
	}, \
	.maxactive = 2*NR_CPUS, \
};

#define HOOK(a, b, c) \
static struct kprobe c = { \
	.pre_handler = b, \
	.symbol_name = a, \
};

	SYSCALL_HOOKS
#undef HOOK
#undef HOOK_RET

int register_probes(void) {
	int ret = 0, tmp;

#define HOOK_RET(a, b, c, d) \
	if ((tmp = register_kretprobe(&d)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": register kretprobe: %s = %d\n", d.kp.symbol_name, tmp); \
		ret = tmp; \
	}

#define HOOK(a, b, c) \
	if ((tmp = register_kprobe(&c)) < 0) { \
		printk(KERN_WARNING MODULE_NAME": register kprobe: %s = %d\n", c.symbol_name, tmp); \
		ret = tmp; \
	}

	SYSCALL_HOOKS
#undef HOOK
#undef HOOK_RET

	return ret;
}

void unregister_probes(void) {
#define HOOK_RET(a, b, c, d) \
	unregister_kretprobe(&d);

#define HOOK(a, b, c) \
	unregister_kprobe(&c);

	SYSCALL_HOOKS
#undef HOOK
#undef HOOK_RET
}
