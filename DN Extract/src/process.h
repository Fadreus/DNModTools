#ifdef WIN32
    #include <tlhelp32.h>

    //typedef DWORD   pid_t;
#else
    #include <sys/ptrace.h>

    typedef u32     DWORD;
    typedef u32     HANDLE;
#endif



typedef struct {
    HANDLE  process;
    u8      *name;
    DWORD   pid;
    void    *base;
    int     pos;
    int     size;
    void    *prev;
    void    *next;
} process_file_t;



static  process_file_t   *process_file    = NULL;



u8 *process_list(u8 *myname, DWORD *mypid, DWORD *size) {
#ifdef WIN32
    PROCESSENTRY32  Process;
    MODULEENTRY32   Module;
    HANDLE          snapProcess,
                    snapModule;
    DWORD           retpid = 0;
    int             len;
    BOOL            b;
    u8              tmpbuff[60],
                    *process_name,
                    *module_name,
                    *module_print,
                    *tmp;

    if(mypid) retpid = *mypid;
    if(!myname && !retpid) {
        printf(
            "  pid/addr/size       process/module name\n"
            "  ---------------------------------------\n");
    }

#define START(X,Y) \
            snap##X = CreateToolhelp32Snapshot(Y, Process.th32ProcessID); \
            X.dwSize = sizeof(X); \
            for(b = X##32First(snap##X, &X); b; b = X##32Next(snap##X, &X)) { \
                X.dwSize = sizeof(X);
#define END(X) \
            } \
            CloseHandle(snap##X);

    Process.th32ProcessID = 0;
    START(Process, TH32CS_SNAPPROCESS)
        process_name = Process.szExeFile;

        if(!myname && !retpid) {
            printf("  %-10lu ******** %s\n",
                Process.th32ProcessID,
                process_name);
        }
        if(myname && stristr(process_name, myname)) {
            retpid = Process.th32ProcessID;
        }

        START(Module, TH32CS_SNAPMODULE)
            module_name = Module.szExePath; // szModule?

            len = strlen(module_name);
            if(len >= 60) {
                tmp = strrchr(module_name, '\\');
                if(!tmp) tmp = strrchr(module_name, '/');
                if(!tmp) tmp = module_name;
                len -= (tmp - module_name);
                sprintf(tmpbuff,
                    "%.*s...%s",
                    54 - len,
                    module_name,
                    tmp);
                module_print = tmpbuff;
            } else {
                module_print = module_name;
            }

            if(!myname && !retpid) {
                printf("    %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
            }
            if(!retpid) {
                if(myname && stristr(module_name, myname)) {
                    retpid = Process.th32ProcessID;
                }
            }
            if(retpid && mypid && (Process.th32ProcessID == retpid)) {
                printf("- %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
                *mypid = retpid;
                if(size) *size = Module.modBaseSize;
                return(Module.modBaseAddr);
            }

        END(Module)

    END(Process)

#undef START
#undef END

#else

    //system("ps -eo pid,cmd");
    printf("\n"
        "- use ps to know the pids of your processes, like:\n"
        "  ps -eo pid,cmd\n");

#endif

    return(NULL);
}



int process_common(process_file_t *procfile) {
    #ifdef WIN32

    DWORD   size;
    u8      *baddr;

    if(procfile->process) return(0);    // already set

    if(!procfile->name && !procfile->name[0]) return(-1);

    if(procfile->name) {
        procfile->pid = myatoi(procfile->name);
        // procfile->pid is automatically 0 if invalid
    }

    baddr = process_list(procfile->pid ? NULL : procfile->name, &procfile->pid, &size);
    if(!baddr) {
        printf("\nError: process name/PID not found, use -p\n");
        myexit(-1);
    }

    printf(
        "- pid %u\n"
        "- base address %p\n",
        (u32)procfile->pid, baddr);

    procfile->process = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        procfile->pid);
    if(!procfile->process) winerr();

    procfile->base    = baddr;
    procfile->pos     = 0;
    procfile->size    = size;

    #else

    void    *baddr;

    procfile->pid = atoi(procfile->name);
    baddr = (void *)0x8048000;  // sorry, not completely suppided at the moment

    printf(
        "- pid %u\n"
        "- try using base address %p\n",
        procfile->pid, baddr);

    if(ptrace(PTRACE_ATTACH, procfile->pid, NULL, NULL) < 0) STD_ERR;

    procfile->process = 0;
    procfile->base    = baddr;
    procfile->pos     = 0;
    procfile->size    = 0;

    #endif

    return(0);
}



process_file_t *process_open(u8 *fname) {
    static  int init_process = 0;
    process_file_t  *procfile  = NULL,
                    *procfile_tmp;
    int     len;
    u8      name[256]   = "",
            proto[16]   = "";

    if(!strstr(fname, "://")) return(NULL);

    procfile_tmp = calloc(1, sizeof(process_file_t));
    if(!procfile_tmp) STD_ERR;

    len = sscanf(fname,
        "%10[^:]://%255[^:]",
        proto,
        name);
    // len handling?

    if(
        stricmp(proto, "process") &&
        stricmp(proto, "proc") &&
        stricmp(proto, "mem") &&
        stricmp(proto, "process")
    ) {
        free(procfile_tmp);
        return(NULL);
    }

    if(!enable_process) {
        printf("\n"
            "Error: the script uses processes, if you are SURE about the genuinity of\n"
            "       this script\n"
            "\n"
            "         you MUST use the -p option at command-line.\n"
            "\n"
            "       note that the usage of the processs allows QuickBMS to read and modiy\n"
            "       the memory of the other programs so you MUST really sure about the\n"
            "       script you are using and what you are doing.\n"
            "       this is NOT a feature for extracting files!\n");
        myexit(-1);
    }
    if(!init_process) {
        // nothing to do at the moment
        init_process = 1;
    }

    procfile_tmp->name = mystrdup(name);

    for(procfile = process_file; procfile; procfile = procfile->next) {
        if(
            !stricmp(procfile->name, procfile_tmp->name) &&
            (procfile->pid == procfile_tmp->pid)
        ) {
            free(procfile_tmp->name);
            free(procfile_tmp);
            procfile_tmp = NULL;
            break;
        }
    }
    if(!procfile) {
        if(!process_file) {
            process_file = procfile_tmp;
            procfile = process_file;
        } else {
            // get the last element
            for(procfile = process_file;; procfile = procfile->next) {
                if(procfile->next) continue;
                procfile->next = procfile_tmp;
                procfile_tmp->prev = procfile;
                procfile = procfile_tmp;
                break;
            }
        }
    }

    process_common(procfile);
    return(procfile);
}



int process_read(process_file_t *procfile, u8 *data, int size) {
    DWORD   len;

    process_common(procfile);
    len = size;

    #ifdef WIN32

    if(!ReadProcessMemory(
        procfile->process,
        (void *)(procfile->base + procfile->pos),
        data,
        size,
        &len)
    ) return(-1); //winerr();

    //CloseHandle(process);

    #else

    u32     tmp;
    int     errno;

    errno = 0;
    for(len = 0; len < size; len += 4) {
        tmp = ptrace(PTRACE_PEEKDATA, procfile->pid, (void *)((u8 *)procfile->base + procfile->pos + len), NULL);
        if(errno && (errno != EIO)) return(-1); //STD_ERR;
        memcpy(data + len, &tmp, 4);
    }

    //if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) STD_ERR;

    #endif

    if(len > 0) procfile->pos += len;
    return(len);
}



int process_write(process_file_t *procfile, u8 *data, int size) {
    DWORD   len;

    process_common(procfile);
    len = size;

    #ifdef WIN32

    if(!WriteProcessMemory(
        procfile->process,
        (void *)(procfile->base + procfile->pos),
        data,
        size,
        &len)
    ) return(-1); //winerr();

    #else

    u32     tmp;
    int     errno;

    errno = 0;
    for(len = 0; len < size; len += 4) {
        memcpy(&tmp, data + len, 4);
        tmp = ptrace(PTRACE_POKEDATA, procfile->pid, (void *)((u8 *)procfile->base + procfile->pos + len), tmp);
        if(errno && (errno != EIO)) return(-1); //STD_ERR;
    }

    #endif

    if(len > 0) procfile->pos += len;
    return(len);
}



int process_close(process_file_t *procfile) {
    if(procfile->process) {
#ifdef WIN32
        CloseHandle(procfile->process);
#else
        ptrace(PTRACE_DETACH, procfile->pid, NULL, NULL);
#endif
        procfile->process = 0;
    }
    return(0);
}


