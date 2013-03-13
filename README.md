rootkit
=======

Reference: dl.packetstormsecurity.net/papers/unix/bsdkern.htm

Feature
-------
Retriever:
->Module
->Application

Harvester:
->Module:
->Application

Protector:

Notes
-------
1. System Call Service

2. Hooking TODO: Add Module / Process / Connection Protection
    - Immutability 
        + unlink hook 
        + rmdir hook
    rename hook
    chmod hook
    chown hook
    chflags hook
    utimes hook
    truncate hook
->Invisibility
--->open hook
--->chdir hook
--->getdirentries hook
--->stat hook
--->lstat hook
3. Kernel / User Space Transition
4. Character Device
5. ICMP Injection (Director Commanding Control)
