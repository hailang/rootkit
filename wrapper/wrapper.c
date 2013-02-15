/*
 * Name:
 *      Wrapper Module
 * Description:
 *      A system call module that interprets commands and take actions accrodingly
 * Usage:
 *      TODO: Add usage here
 * Author:
 *      Hai Lang
 * Date Created:
 *      2013-02-14
 * Last Update:
 *      2013-02-15
 *
*/
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

/* The system call's arguments */
struct wrapper_args {
    char *str;
};

/* The system call function */
static int wrapper(struct thread *td, void *syscall_args)
{
    struct wrapper_args *args; /* local struct to receive syscall_args */
    args = (struct wrapper_args *)syscall_args; /* receive syscall_args with casting */

    printf("%s\n", args->str);

    return (0);
}

/* Prepare sysent to register the new system call */
static struct sysent wrapper_sysent = {
    1,  /* Number of arguments */
    wrapper /* implementing function */
}

/* Define the offset in sysent[] where the new system call is to be allocated */
static int offset = NO_SYSCALL; /* Default, using the next available slots offset in sysent table */

/* Event handler function for the new system call */
static int load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch(cmd) {
        case MOD_LOAD:
            uprintf("System call loaded at offset %d.\n", offset);
            break;
        case MOD_UNLOAD:
            uprintf("System call unloaded from offset %d.\n", offset);
            break;
        default:
            error = EOPNOTSUPP; /* Operation not supported */
            break;
    }

    return(error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(wrapper, &offset, &wrapper_sysent, load, NULL);
