rootkit
=======

Reference: dl.packetstormsecurity.net/papers/unix/bsdkern.htm

Feature
-------
Retriever:
    - Module
        + A character device that communicates with controller
            - TODO:
                + Implement character device to store received command
    - Application
        + Executioner
            - Userland application to execute the command received by the Retriever module

Harvester:
    - Module
        + A character deveice module that gathers victim's information (log, stats, etc)
            - TODO:
                + Implement character device to store info
    - Application
        + Inquisitor
            - Userland application to report information gathered by the Harvester module

Protector:
    - Module
        + A system call module that protects the rootkit
            - TODO:
                + Hide modules from kldstat
                + Prevent modules from being unloaded
                + Hide processes
                + Prevent processes from getting killed
                + Prevent connections from being closed
    - Application

Notes
-------
1. System Call Service

2. Hooking
    - Immutability 
        + unlink hook 
        + rmdir hook
        + rename hook
        + chmod hook
        + chown hook
        + chflags hook
        + utimes hook
        + truncate hook
    - Invisibility
        + open hook
        + chdir hook
        + getdirentries hook
        + stat hook
        + lstat hook
3. Kernel / User Space Transition
4. Character Device
5. ICMP Injection (Direct Commanding Control)
6. TODO: HTTP Reverse Command Fetching
