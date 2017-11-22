#ifdef WIN32
    #include <winsock.h>

    #define close   closesocket
    #define sleep   Sleep
    #define sleepms sleep
    #define ONESEC  1000
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>

    #define sleepms(X)  usleep(X * 1000)
    #define ONESEC  1
#endif



#ifndef SO_EXCLUSIVEADDRUSE
    #define SO_EXCLUSIVEADDRUSE ((u_int)(~SO_REUSEADDR))
#endif
#ifndef TCP_NODELAY
    #define TCP_NODELAY 0x0001
#endif



typedef struct {
    struct sockaddr_in  peer;
    int     sd;
    int     sa;
    int     proto;
    u8      *host;
    u16     port;
    int     bind_mode;
    int     pos;
    void    *prev;
    void    *next;
} socket_file_t;



static  socket_file_t   *socket_file    = NULL;



void sock_err(void) {
#ifdef WIN32
    char    *error;

    switch(WSAGetLastError()) {
        case 10004: error = "Interrupted system call"; break;
        case 10009: error = "Bad file number"; break;
        case 10013: error = "Permission denied"; break;
        case 10014: error = "Bad address"; break;
        case 10022: error = "Invalid argument (not bind)"; break;
        case 10024: error = "Too many open files"; break;
        case 10035: error = "Operation would block"; break;
        case 10036: error = "Operation now in progress"; break;
        case 10037: error = "Operation already in progress"; break;
        case 10038: error = "Socket operation on non-socket"; break;
        case 10039: error = "Destination address required"; break;
        case 10040: error = "Message too long"; break;
        case 10041: error = "Protocol wrong type for socket"; break;
        case 10042: error = "Bad protocol option"; break;
        case 10043: error = "Protocol not supported"; break;
        case 10044: error = "Socket type not supported"; break;
        case 10045: error = "Operation not supported on socket"; break;
        case 10046: error = "Protocol family not supported"; break;
        case 10047: error = "Address family not supported by protocol family"; break;
        case 10048: error = "Address already in use"; break;
        case 10049: error = "Can't assign requested address"; break;
        case 10050: error = "Network is down"; break;
        case 10051: error = "Network is unreachable"; break;
        case 10052: error = "Net dropped connection or reset"; break;
        case 10053: error = "Software caused connection abort"; break;
        case 10054: error = "Connection reset by peer"; break;
        case 10055: error = "No buffer space available"; break;
        case 10056: error = "Socket is already connected"; break;
        case 10057: error = "Socket is not connected"; break;
        case 10058: error = "Can't send after socket shutdown"; break;
        case 10059: error = "Too many references, can't splice"; break;
        case 10060: error = "Connection timed out"; break;
        case 10061: error = "Connection refused"; break;
        case 10062: error = "Too many levels of symbolic links"; break;
        case 10063: error = "File name too long"; break;
        case 10064: error = "Host is down"; break;
        case 10065: error = "No Route to Host"; break;
        case 10066: error = "Directory not empty"; break;
        case 10067: error = "Too many processes"; break;
        case 10068: error = "Too many users"; break;
        case 10069: error = "Disc Quota Exceeded"; break;
        case 10070: error = "Stale NFS file handle"; break;
        case 10091: error = "Network SubSystem is unavailable"; break;
        case 10092: error = "WINSOCK DLL Version out of range"; break;
        case 10093: error = "Successful WSASTARTUP not yet performed"; break;
        case 10071: error = "Too many levels of remote in path"; break;
        case 11001: error = "Host not found"; break;
        case 11002: error = "Non-Authoritative Host not found"; break;
        case 11003: error = "Non-Recoverable errors: FORMERR, REFUSED, NOTIMP"; break;
        case 11004: error = "Valid name, no data record of requested type"; break;
        default: error = strerror(errno); break;
    }
    fprintf(stderr, "\nError: %s\n", error);
    myexit(-2);
#else
    STD_ERR;
#endif
}



int create_socket(int pck_proto, int sd_already_set, struct sockaddr_in *peer) {
    static int  first_time  = 1;
    static int  size        = 0xffff;
    static struct linger ling = {1,1};
    static int  on = 1;
    int     sd  = -1;

    for(;;) {
        if(sd_already_set <= 0) {
            for(;;) {
                if(pck_proto < 0) {
                    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                } else if(!pck_proto) {
                    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                } else {
                    sd = socket(AF_INET, SOCK_RAW, pck_proto);
                }
                if(sd > 0) break;
                sleepms(500);
            }
        } else {
            sd = sd_already_set;
            return(sd); // added for quickbms
        }

        if(peer) printf("- %s : %hu\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));

        // SO_LINGER makes the sending a bit slower because it really sends
        // the whole full data and is sure almost at 100% that it's received
        setsockopt(sd, SOL_SOCKET, SO_LINGER,    (char *)&ling, sizeof(ling));
        setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (char *)&on,   sizeof(on));
        setsockopt(sd, SOL_SOCKET, SO_SNDBUF,    (char *)&size, sizeof(size));  // useless
        if(pck_proto >= 0) break;   // packets

        setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *)&on,   sizeof(on));
        if(!peer) break;

        if(peer->sin_addr.s_addr == INADDR_ANY) {
            if(bind(sd, (struct sockaddr *)peer, sizeof(struct sockaddr_in))
              < 0) sock_err();
            if(pck_proto < 0) listen(sd, SOMAXCONN);
            break;
        } else {
            if(!connect(sd, (struct sockaddr *)peer, sizeof(struct sockaddr_in))) {
                if(first_time) first_time = 0;
                break;
            }
        }
        if(first_time) sock_err();
        close(sd);
        sd_already_set = -1;
        sleepms(500);
    }
    return(sd);
}



int timeout(int sock, int secs) {
    struct  timeval tout;
    fd_set  fd_read;

    tout.tv_sec  = secs;
    tout.tv_usec = 0;
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
    if(select(sock + 1, &fd_read, NULL, NULL, &tout)
      <= 0) return(-1);
    return(0);
}



u32 resolv(char *host) {
    struct  hostent *hp;
    u32     host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        hp = gethostbyname(host);
        if(!hp) {
            fprintf(stderr, "\nError: Unable to resolv hostname (%s)\n", host);
            myexit(-1);
        } else host_ip = *(u32 *)hp->h_addr;
    }
    return(host_ip);
}



int socket_common(socket_file_t *sockfile) {
    struct sockaddr_in  peerl;
    int     sd,
            psz;

    if(!sockfile->peer.sin_addr.s_addr && !sockfile->peer.sin_port) {
        sockfile->peer.sin_addr.s_addr  = resolv(sockfile->host);
        if(!sockfile->peer.sin_addr.s_addr) {
            sockfile->bind_mode = 1;
            sockfile->peer.sin_addr.s_addr  = INADDR_ANY;
        }
        sockfile->peer.sin_port         = htons(sockfile->port);
        sockfile->peer.sin_family       = AF_INET;
    }

    sockfile->sd = create_socket(sockfile->proto, sockfile->sd, &sockfile->peer);
    if(sockfile->sd < 0) sock_err();

    sd = sockfile->sd;
    if(sockfile->bind_mode && (sockfile->proto < 0)) {
        if(!sockfile->sa) {
            psz = sizeof(struct sockaddr_in);
            sockfile->sa = accept(sockfile->sd, (struct sockaddr *)&peerl, &psz);
            if(sockfile->sa < 0) sock_err();
        }
        sd = sockfile->sa;
    }
    return(sd);
}



socket_file_t *socket_open(u8 *fname) {
    static  int init_socket = 0;
    socket_file_t   *sockfile  = NULL,
                    *sockfile_tmp;
    int     len;
    i32     force_new   = 0;
    u8      host[256]   = "",
            proto[16]   = "";

    if(!strstr(fname, "://")) return(NULL);

    sockfile_tmp = calloc(1, sizeof(socket_file_t));
    if(!sockfile_tmp) STD_ERR;

    len = sscanf(fname,
        "%10[^:]://%255[^:]:%hu:%u",
        proto,
        host,
        &sockfile_tmp->port,
        &force_new);
    // len handling?

         if(!stricmp(proto, "tcp"))     sockfile_tmp->proto = -1;
    else if(!stricmp(proto, "udp"))     sockfile_tmp->proto = 0;
    else if(!stricmp(proto, "raw"))     sockfile_tmp->proto = IPPROTO_RAW;
    else if(!stricmp(proto, "icmp"))    sockfile_tmp->proto = IPPROTO_ICMP;
    else if(!stricmp(proto, "udp_raw")) sockfile_tmp->proto = IPPROTO_UDP;
    else if(!stricmp(proto, "tcp_raw")) sockfile_tmp->proto = IPPROTO_TCP;
    else {
        // example: 17://
        sockfile_tmp->proto = myatoi(proto);
        if((sockfile_tmp->proto <= 0) || (sockfile_tmp->proto > 0xff)) {
            //sockfile_tmp->proto = -1;
            free(sockfile_tmp);
            return(NULL);
        }
    }

    if(!enable_sockets) {
        printf("\n"
            "Error: the script uses network sockets, if you are SURE about the genuinity of\n"
            "       this script\n"
            "\n"
            "         you MUST use the -n option at command-line.\n"
            "\n"
            "       note that the usage of the sockets allows QuickBMS to send and receive\n"
            "       data to and from other computers so you MUST really sure about the\n"
            "       script you are using and what you are doing.\n"
            "       this is NOT a feature for extracting files!\n");
        myexit(-1);
    }
    if(!init_socket) {
        #ifdef WIN32
        WSADATA    wsadata;
        WSAStartup(MAKEWORD(1,0), &wsadata);
        #endif
        init_socket = 1;
    }

    if(sockfile_tmp->port <= 0) {
        printf("\nError: the specified port is invalid (%d)\n", sockfile_tmp->port);
        myexit(-1);
    }

    sockfile_tmp->host = mystrdup(host);

    for(sockfile = socket_file; sockfile; sockfile = sockfile->next) {
        if(
            (sockfile->proto == sockfile_tmp->proto) &&
            !stricmp(sockfile->host, sockfile_tmp->host) &&
            (sockfile->port == sockfile_tmp->port)
        ) {
            if(force_new && sockfile->sd) {
                if(sockfile->sa) {
                    close(sockfile->sa);
                    sockfile->sa = 0;
                }
                close(sockfile->sd);
                sockfile->sd = 0;
            }
            free(sockfile_tmp->host);
            free(sockfile_tmp);
            sockfile_tmp = NULL;
            break;
        }
    }
    if(!sockfile) {
        if(!socket_file) {
            socket_file = sockfile_tmp;
            sockfile = socket_file;
        } else {
            // get the last element
            for(sockfile = socket_file;; sockfile = sockfile->next) {
                if(sockfile->next) continue;
                sockfile->next = sockfile_tmp;
                sockfile_tmp->prev = sockfile;
                sockfile = sockfile_tmp;
                break;
            }
        }
    }

    socket_common(sockfile);
    return(sockfile);
}



int socket_read(socket_file_t *sockfile, u8 *data, int size) {
    int     sd,
            t,
            len,
            psz;

    sd = socket_common(sockfile);

    if(sockfile->proto < 0) {
        for(len = 0; len < size; len += t) {
            t = recv(sd, data + len, size - len, 0);
            if(t <= 0) break;
        }
    } else {
        psz = sizeof(struct sockaddr_in);
        len = recvfrom(sd, data, size, 0, (struct sockaddr *)&sockfile->peer, &psz);
    }
    if(verbose && (len > 0)) show_dump(2, data, len, stdout);
    if(sockfile->proto >= 0) {
        len = size; // lame way to avoid errors? long story about packets
    }
    if(len > 0) sockfile->pos += len;
    return(len);
}



int socket_write(socket_file_t *sockfile, u8 *data, int size) {
    int     sd,
            len;

    sd = socket_common(sockfile);

    if(verbose && (size > 0)) show_dump(2, data, size, stdout);

    if(sockfile->proto < 0) {
        len = send(sd, data, size, 0);
    } else {
        // an udp socket in listening mode can't send data because there is no destination!
        if((sockfile->peer.sin_addr.s_addr == INADDR_ANY) || (sockfile->peer.sin_addr.s_addr == INADDR_NONE)) return(size);
        len = sendto(sd, data, size, 0, (struct sockaddr *)&sockfile->peer, sizeof(struct sockaddr_in));
    }
    //if(len != size) sock_err();
    if(len > 0) sockfile->pos += len;
    return(len);
}



int socket_close(socket_file_t *sockfile) {
    if(sockfile->sd) {
        close(sockfile->sd);
        sockfile->sd = 0;
    }
    return(0);
}


