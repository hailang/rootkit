/*
 * Name:
 *      File Hider Module
 * Description:
 *      A system call module that installs a kernel service.User can send command to hide a path, either a file or a directory
 * Usage:
 *      TODO: Add usage here
 * Author:
 *      Hai Lang
 * Last Update:
 *      2013-02-14
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
struct file_hider_args {
    char *str;
}

/* The system call function */
static int file_hider(struct thread * td, void *syscall_args)
{
    struct file_hider_args *args; /* local struct to receive syscall_args */
    args = (struct file_hider_args *)syscall_args; /* receive syscall_args with casting */

    printf("%s\n", args->str);

    return (0);
}

/* Prepare sysent to register the new system call */
static struct sysent file_hider_sysent = {
    1,  /* Number of arguments */
    file_hider /* implementing function */
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
SYSCALL_MODULE(file_hider, &offset, &file_hider_sysent, load, NULL);
