/*
    Copyright 2009-2011 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

//#define NOLFS
#ifndef NOLFS   // 64 bit file support not really needed since the tool uses signed 32 bits at the moment, anyway I leave it enabled
    #define _LARGE_FILES        // if it's not supported the tool will work
    #define __USE_LARGEFILE64   // without support for large files
    #define __USE_FILE_OFFSET64
    #define _LARGEFILE_SOURCE
    #define _LARGEFILE64_SOURCE
    #define _FILE_OFFSET_BITS   64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <math.h>
#include "stristr.c"

//typedef int8_t      i8;
typedef uint8_t     u8;
//typedef int16_t     i16;
typedef uint16_t    u16;
typedef int32_t     i32;
typedef uint32_t    u32;
//typedef int64_t     i64;
typedef uint64_t    u64;

typedef int8_t      int8;
typedef uint8_t     uint8;
typedef int16_t     int16;
typedef uint16_t    uint16;
typedef int32_t     int32;
typedef uint32_t    uint32;
typedef int64_t     int64;
typedef uint64_t    uint64;
typedef unsigned char   byte;   // for sflcomp
typedef unsigned short  word;   // for sflcomp

// in case you want to make QuickBMS 64bit compatible
// start
#ifdef QUICKBMS64
    #define INTSZ           64
    #define QUICKBMS_int    int64_t     // trick for forcing the usage of signed 32 bit numbers on any system without modifying the code
    #define QUICKBMS_u_int  uint64_t    // used only in some rare occasions
#else
    #define INTSZ           32
    #define QUICKBMS_int    int32_t     // trick for forcing the usage of signed 32 bit numbers on any system without modifying the code
    #define QUICKBMS_u_int  uint32_t    // used only in some rare occasions
#endif
// end

#include <zlib.h>
#include <bzlib.h>
#ifndef DISABLE_UCL     // add -DDISABLE_UCL at compiling if you don't have UCL
    #include <ucl/ucl.h>
#endif
#ifndef DISABLE_LZO     // add -DDISABLE_LZO at compiling if you don't have LZO
    #include <lzo/lzo1.h>
    #include <lzo/lzo1a.h>
    #include <lzo/lzo1b.h>
    #include <lzo/lzo1c.h>
    #include <lzo/lzo1f.h>
    #include <lzo/lzo1x.h>
    #include <lzo/lzo1y.h>
    #include <lzo/lzo1z.h>
    #include <lzo/lzo2a.h>
#endif
#include "compression/blast.h"
#include "compression/sflcomp.h"
#include "lzma/LzmaDec.h"
#include "lzma/Lzma2Dec.h"
#include "lzma/Bra.h"

#ifndef DISABLE_OPENSSL
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #include <openssl/blowfish.h>
#endif
#include "encryption/tea.h"
#include "encryption/xtea.h"
#include "encryption/xxtea.h"
#include "myenc.h"
#include "encryption/twofish.h"
#include "encryption/seed.h"
#include "encryption/serpent.h"
#include "encryption/ice.h"
#include "encryption/rotor.c"
//#include "encryption/libkirk/kirk_engine.h"
int kirk_CMD0(u8* outbuff, u8* inbuff, int size, int generate_trash);
int kirk_CMD1(u8* outbuff, u8* inbuff, int size, int do_check);
int kirk_CMD4(u8* outbuff, u8* inbuff, int size);
int kirk_CMD7(u8* outbuff, u8* inbuff, int size);
int kirk_CMD10(u8* inbuff, int insize);
int kirk_CMD11(u8* outbuff, u8* inbuff, int size);
int kirk_CMD14(u8* outbuff, int size);
int kirk_init(); //CMD 0xF?
void xtea_crypt_ecb( xtea_context *ctx, int mode, u8 input[8], u8 output[8] );
#ifndef DISABLE_MCRYPT
    #include <mcrypt.h>
#endif
//#define DISABLE_TOMCRYPT    // useless at the moment
#ifndef DISABLE_TOMCRYPT
    #include <tomcrypt.h>
#endif
#include "encryption/zipcrypto.h"
int threeway_setkey(unsigned *key, unsigned char *data, int datalen);
void threeway_encrypt(unsigned *key, unsigned char *data, int datalen);
void threeway_decrypt(unsigned *key, unsigned char *data, int datalen);
void skipjack_makeKey(byte key[10], byte tab[10][256]);
void skipjack_encrypt(byte tab[10][256], byte in[8], byte out[8]);
void skipjack_decrypt(byte tab[10][256], byte in[8], byte out[8]);
#include "encryption/anubis.h"
typedef struct { Byte rk[16*17]; int Nr; } aria_ctx_t;
int ARIA_DecKeySetup(const Byte *mk, Byte *rk, int keyBits);
int ARIA_EncKeySetup(const Byte *mk, Byte *rk, int keyBits);
void ARIA_Crypt(const Byte *i, int Nr, const Byte *rk, Byte *o);
u_int *crypton_set_key(const u_int in_key[], const u_int key_len, u_int l_key[104]);
u_int crypton_encrypt(const u_int in_blk[4], u_int out_blk[4], u_int l_key[104]);
u_int crypton_decrypt(const u_int in_blk[4], u_int out_blk[4], u_int l_key[104]);
u_int *frog_set_key(const u_int in_key[], const u_int key_len);
void frog_encrypt(const u_int in_blk[4], u_int out_blk[4]);
void frog_decrypt(const u_int in_blk[4], u_int out_blk[4]);
typedef struct { u_int iv[2]; u_int key[8]; int type; } gost_ctx_t;
void gost_kboxinit(void);
void gostcrypt(u_int const in[2], u_int out[2], u_int const key[8]);
void gostdecrypt(u_int const in[2], u_int out[2], u_int const key[8]);
void gostofb(u_int const *in, u_int *out, int len, u_int const iv[2], u_int const key[8]);
void gostcfbencrypt(u_int const *in, u_int *out, int len, u_int iv[2], u_int const key[8]);
void gostcfbdecrypt(u_int const *in, u_int *out, int len, u_int iv[2], u_int const key[8]);
void lucifer(unsigned char *);
void lucifer_loadkey(unsigned char *, int);
u_int *mars_set_key(u_int key_blk[], u_int key_len);
void mars_encrypt(u_int in_blk[], u_int out_blk[]);
void mars_decrypt(u_int in_blk[], u_int out_blk[]);
void misty1_keyinit(u_int  *ek, u_int  *k);
void misty1_decrypt_block(u_int  *ek,u_int  c[2], u_int  p[2]);
void misty1_encrypt_block(u_int  *ek, u_int  p[2], u_int  c[2]);
typedef struct { u_int k[4]; } NOEKEONstruct;
void NOEKEONkeysetup(const unsigned char * const key, 
                    NOEKEONstruct * const structpointer);
void NOEKEONencrypt(const NOEKEONstruct * const structpointer, 
                   const unsigned char * const plaintext,
                   unsigned char * const ciphertext);
void NOEKEONdecrypt(const NOEKEONstruct * const structpointer,
                   const unsigned char * const ciphertext,
                   unsigned char * const plaintext);
#include "encryption/seal.h"
#include "encryption/safer.h"

#ifdef __DJGPP__
    #define NOLFS
    char **__crt0_glob_function (char *arg) { return 0; }
    void   __crt0_load_environment_file (char *progname) { }
#endif

#ifdef WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #include <direct.h>
    #include "extra/MemoryModule.h"

    #define PATHSLASH   '\\'
    #define make_dir(x) mkdir(x)
    #define LOADDLL(X)  LoadLibrary(X)
    #define GETFUNC(X)  (void *)GetProcAddress(hlib, X)
    #define CLOSEDLL    FreeLibrary(hlib);

    HWND    mywnd   = NULL;
    char *get_file(char *title, i32 bms, i32 multi);
    char *get_folder(char *title);
#else
    #include <unistd.h>
    #include <dirent.h>
    #include <dlfcn.h>      // -ldl
    #include <sys/mman.h>

    #define LOADDLL(X)  dlopen(X, RTLD_LAZY)
    #define GETFUNC(X)  (void *)dlsym(hlib, X)
    #define CLOSEDLL    dlclose(hlib);
    #define HMODULE     void *
    #define stricmp     strcasecmp
    #define strnicmp    strncasecmp
    //#define stristr     strcasestr
    #define PATHSLASH   '/'
    #define make_dir(x) mkdir(x, 0755)
#endif

#if defined(_LARGE_FILES)
    #if defined(__APPLE__)
        #define fseek   fseeko
        #define ftell   ftello
    #elif defined(__FreeBSD__)
    #elif !defined(NOLFS)       // use -DNOLFS if this tool can't be compiled on your OS!
        #define off_t   off64_t
        #define fopen   fopen64
        #define fseek   fseeko64
        #define ftell   ftello64
    #endif
#endif

# ifndef __cdecl 
#  define __cdecl  __attribute__ ((__cdecl__))
# endif
# ifndef __stdcall
#  define __stdcall __attribute__ ((__stdcall__))
# endif
void __cxa_pure_virtual() { while(1); }



#define VER             "0.5.1"
#define BUFFSZ          8192
#define MAX_ARGS        16      // fixed but exagerated
#define MAX_VARS        512     // fixed but exagerated
#define MAX_FILES       512     // fixed but exagerated
#define MAX_CMDS        2048    // fixed but exagerated
#define MAX_ARRAYS      64      // fixed but exagerated

#define STRINGSZ        256
#define NUMBERSZ        24      // ready for 64 bits, includes also space for the NULL delimiter
#define PATHSZ          1024    // 257 was enough, theoretically the system could support 32kb but it's false
#define ENABLE_DIRECT_COPY

#define MYLITTLE_ENDIAN 0
#define MYBIG_ENDIAN    1

#define int             QUICKBMS_int
#define u_int           QUICKBMS_u_int

#define CMD             command[cmd]
#define ARG             argument
#define NUM(X)          CMD.num[X]
#define STR(X)          CMD.str[X]
#define VARISNUM(X)     variable[CMD.var[X]].isnum
#define VAR(X)          get_var(CMD.var[X])
#define VAR32(X)        get_var32(CMD.var[X])
#define VARSZ(X)        variable[CMD.var[X]].size   // due to the memory enhancement done on this tool, VARSZ returns ever STRINGSZ for sizes lower than this value... so do NOT trust this value!
//#define FILEZ(X)        ((NUM(X) < 0) ? NULL : filenumber[NUM(X)].fd)  // automatic support for MEMORY_FILE
#define DIRECT_ADDVAR(X,Y,Z) \
                        variable[CMD.var[X]].value   = Y; \
                        variable[CMD.var[X]].value32 = 0; \
                        variable[CMD.var[X]].isnum   = 0; \
                        variable[CMD.var[X]].size    = Z;
#define FILEZ(X)        NUM(X)
#define MEMORY_FNAME    "MEMORY_FILE"
#define MEMORY_FNAMESZ  (sizeof(MEMORY_FNAME) - 1)
#define TEMPORARY_FILE  "TEMPORARY_FILE"
#define ALLOC_ERR       alloc_err(__FILE__, __LINE__, __FUNCTION__)
#define STD_ERR         std_err(__FILE__, __LINE__, __FUNCTION__)
#define CHECK_FILENUM   if(!filenumber[fdnum].fd && !filenumber[fdnum].sd && !filenumber[fdnum].pd) { \
                            printf("\nError: the specified file number (%d) has not been opened yet (line %d)\n", (i32)fdnum, (i32)__LINE__); \
                            myexit(-1); \
                        }
#define myatoi(X)       readbase(X, 10, NULL)
#define CSTRING(X,Y)    { \
                        CMD.str[X] = mystrdup(Y); \
                        CMD.num[X] = cstring(CMD.str[X], CMD.str[X], -1, NULL); \
                        }
#define NUMS2BYTES(A,B,C,D) { \
                        tmp = numbers_to_bytes(A, &B); \
                        myalloc(&C, B, &D); \
                        memcpy(C, tmp, B); \
                        }
#define FREEZ(X)        if(X) { \
                            free(X); \
                            X = NULL; \
                        }
#define FREEX(X,Y)      if(X) { \
                            Y; \
                            free(X); \
                            X = NULL; \
                        }
#define MULTISTATIC     4   // this number is simply the amount of static buffers to use so that
                            // we can use the same function MULTISTATIC times without overlapped results!
#define strdup_error    "Error: do NOT use strdup, use re_strdup or mystrdup!"
#define strdup          strdup_error
#define far
#define PRINTF64(X)     (i32)(((X) >> 32) & 0xffffffff), (i32)((X) & 0xffffffff)



enum {
    CMD_NONE = 0,
    CMD_CLog,
    CMD_Do,
    CMD_FindLoc,
    CMD_For,
    CMD_ForTo,  // for an easy handling of For
    CMD_Get,
    CMD_GetDString,
    CMD_GoTo,
    CMD_IDString,
    CMD_ImpType,
    CMD_Log,
    CMD_Math,
    CMD_Next,
    CMD_Open,
    CMD_SavePos,
    CMD_Set,
    CMD_While,
    CMD_String,
    CMD_CleanExit,
    CMD_If,
    CMD_Else,
    CMD_Elif,   // added by me
    CMD_EndIf,
    CMD_GetCT,
    CMD_ComType,
    CMD_ReverseLong,
    CMD_ReverseLongLong,
        // added by me
    CMD_Endian,
    CMD_FileXOR,        // similar job done also by Encryption
    CMD_FileRot13,      // similar job done also by Encryption
    CMD_FileCrypt,      // experimental and useless
    CMD_Break,          // not necessary
    CMD_Strlen,         // not necessary (implemented in Set)
    CMD_GetVarChr,
    CMD_PutVarChr,
    CMD_Debug,          // only for debugging like -v, so not necessary
    CMD_Padding,        // useful but not necessary, can be done with GoTo
    CMD_Append,
    CMD_Encryption,
    CMD_Print,
    CMD_GetArray,
    CMD_PutArray,
    CMD_StartFunction,
    CMD_CallFunction,
    CMD_EndFunction,
    CMD_ScanDir,        // not needed for the extraction jobs
    CMD_CallDLL,
    CMD_Put,            // not needed for the extraction jobs
    CMD_PutDString,     // not needed for the extraction jobs
    CMD_PutCT,          // not needed for the extraction jobs
    CMD_GetBits,        // rarely useful
    CMD_PutBits,        // rarely useful
    CMD_ReverseShort,   // rarely useful
    //CMD_Continue,       // not implemented yet
        // nop
    CMD_NOP
};

#define ISNUMTYPE(X)    ((X > 0) || (X == TYPE_ASIZE))
enum {  // the value is referred to their size which makes the job faster, numbers are positive and the others are negative!
    TYPE_NONE           = 0,
    TYPE_BYTE           = 1,
    TYPE_SHORT          = 2,
    TYPE_THREEBYTE      = 3,
    TYPE_LONG           = 4,
    TYPE_LONGLONG       = 8,
    TYPE_STRING         = -1,
    TYPE_ASIZE          = -2,
    TYPE_PURETEXT       = -3,
    TYPE_PURENUMBER     = -4,
    TYPE_TEXTORNUMBER   = -5,
    TYPE_FILENUMBER     = -6,
        // added by me
    TYPE_FILENAME       = -1000,
    TYPE_BASENAME       = -1001,
    TYPE_EXTENSION      = -1002,
    TYPE_UNICODE        = -1003,
    TYPE_BINARY         = -1004,
    TYPE_LINE           = -1005,
    TYPE_FULLNAME       = -1006,
    TYPE_CURRENT_FOLDER = -1007,
    TYPE_FILE_FOLDER    = -1008,
    TYPE_INOUT_FOLDER   = -1009,
    TYPE_BMS_FOLDER     = -1010,
    TYPE_ALLOC          = -1011,
    TYPE_COMPRESSED     = -1012,
    TYPE_FLOAT          = -1013,
    TYPE_DOUBLE         = -1014,
    TYPE_LONGDOUBLE     = -1015,
    TYPE_VARIABLE       = -1016,    // c & 0x80
    TYPE_VARIABLE2      = -1017,    // unreal index numbers
    TYPE_VARIANT        = -1018,
    TYPE_BITS           = -1019,
        // nop
    TYPE_NOP
};

#define QUICK_COMP_ENUM(X) \
    COMP_##X,
#define QUICK_COMP_ASSIGN(X) \
    } else if(!stricmp(str, #X)) { \
        compression_type = COMP_##X;
#define QUICK_COMP_UNPACK(X,Y) \
                case COMP_##X: { \
                    size = Y(in, zsize, out, size); \
                    break; \
                }
enum {  // note that the order must be not change due to the introduction of the scan feature
    COMP_NONE = 0,
    COMP_ZLIB,          // RFC 1950
    COMP_DEFLATE,       // RFC 1951
    COMP_LZO1,
    COMP_LZO1A,
    COMP_LZO1B,         // scan 5
    COMP_LZO1C,
    COMP_LZO1F,
    COMP_LZO1X,
    COMP_LZO1Y,
    COMP_LZO1Z,         // scan 10
    COMP_LZO2A,
    COMP_LZSS,
    COMP_LZX,
    COMP_GZIP,
    COMP_EXPLODE,       // scan 15
    COMP_LZMA,
    COMP_LZMA_86HEAD,
    COMP_LZMA_86DEC,
    COMP_LZMA_86DECHEAD,
    COMP_LZMA_EFS,      // scan 20
    COMP_BZIP2,
    COMP_XMEMLZX,
    COMP_HEX,
    COMP_BASE64,
    COMP_UUENCODE,      // scan 25
    COMP_ASCII85,
    COMP_YENC,
    COMP_UNLZW,
    COMP_UNLZWX,
    COMP_LZXCAB,        // scan 30
    COMP_LZXCHM,
    COMP_RLEW,
    COMP_LZJB,
    COMP_SFL_BLOCK,
    COMP_SFL_RLE,       // scan 35
    COMP_SFL_NULLS,
    COMP_SFL_BITS,
    COMP_LZMA2,
    COMP_LZMA2_86HEAD,
    COMP_LZMA2_86DEC,   // scan 40
    COMP_LZMA2_86DECHEAD,
    COMP_NRV2b,
    COMP_NRV2d,
    COMP_NRV2e,
    COMP_HUFFBOH,       // scan 45
    COMP_UNCOMPRESS,
    COMP_DMC,
    COMP_LZH,
    COMP_LZARI,
    COMP_TONY,          // scan 50
    COMP_RLE7,
    COMP_RLE0,
    COMP_RLE,
    COMP_RLEA,
    COMP_BPE,           // scan 55
    COMP_QUICKLZ,
    COMP_Q3HUFF,
    COMP_UNMENG,
    COMP_LZ2K,
    COMP_DARKSECTOR,    // scan 60
    COMP_MSZH,
    COMP_UN49G,
    COMP_UNTHANDOR,
    COMP_DOOMHUFF,
    COMP_APLIB,         // scan 65
    COMP_TZARLZSS,
    COMP_LZF,
    COMP_CLZ77,
    COMP_LZRW1,
    COMP_DHUFF,         // scan 70
    COMP_FIN,
    COMP_LZAH,
    COMP_LZH12,
    COMP_LZH13,
    COMP_GRZIP,         // scan 75
    COMP_CKRLE,
    COMP_QUAD,
    COMP_BALZ,
    COMP_DEFLATE64,
    COMP_SHRINK,        // scan 80
    COMP_PPMDI,
    COMP_MULTIBASE,
    COMP_BRIEFLZ,
    COMP_PAQ6,
    COMP_SHCODEC,       // scan 85
    COMP_HSTEST1,
    COMP_HSTEST2,
    COMP_SIXPACK,
    COMP_ASHFORD,
    COMP_JCALG,         // scan 90
    COMP_JAM,
    COMP_LZHLIB,
    COMP_SRANK,
    COMP_ZZIP,
    COMP_SCPACK,        // scan 95
    COMP_RLE3,
    COMP_BPE2,
    COMP_BCL_HUF,
    COMP_BCL_LZ,
    COMP_BCL_RICE,      // scan 100
    COMP_BCL_RLE,
    COMP_BCL_SF,
    COMP_SCZ,
    COMP_SZIP,
    COMP_PPMDI_RAW,     // scan 105
    COMP_PPMDG,
    COMP_PPMDG_RAW,
    COMP_PPMDJ,
    COMP_PPMDJ_RAW,
    COMP_SR3C,          // scan 110
    COMP_HUFFMANLIB,
    COMP_SFASTPACKER,
    COMP_SFASTPACKER2,
    COMP_DK2,
    COMP_LZ77WII,       // scan 115
    COMP_LZ77WII_RAW10,
    COMP_DARKSTONE,
    COMP_SFL_BLOCK_CHUNKED,
    COMP_YUKE_BPE,
    COMP_STALKER_LZA,   // scan 120
    COMP_PRS_8ING,
    COMP_PUYO_CNX,
    COMP_PUYO_CXLZ,
    COMP_PUYO_LZ00,
    COMP_PUYO_LZ01,     // scan 125
    COMP_PUYO_LZSS,
    COMP_PUYO_ONZ,
    COMP_PUYO_PRS,
    COMP_FALCOM,
    COMP_CPK,           // scan 130
    COMP_BZIP2_FILE,
    COMP_LZ77WII_RAW11,
    COMP_LZ77WII_RAW30,
    COMP_LZ77WII_RAW20,
    COMP_PGLZ,          // scan 135
    COMP_SLZ,
    COMP_SLZ_01,
    COMP_SLZ_02,
    COMP_LZHL,
    COMP_D3101,         // scan 140
    COMP_SQUEEZE,
    COMP_LZRW3,
    QUICK_COMP_ENUM(ahuff)
    QUICK_COMP_ENUM(arith)
    QUICK_COMP_ENUM(arith1) // scan 145
    QUICK_COMP_ENUM(arith1e)
    QUICK_COMP_ENUM(arithn)
    QUICK_COMP_ENUM(compand)
    QUICK_COMP_ENUM(huff)
    QUICK_COMP_ENUM(lzss)   // scan 150
    QUICK_COMP_ENUM(lzw12)
    QUICK_COMP_ENUM(lzw15v)
    QUICK_COMP_ENUM(silence)
    COMP_RDC,
    COMP_ILZR,          // scan 155
    COMP_DMC2,
    QUICK_COMP_ENUM(diffcomp)
    COMP_LZR,
    COMP_LZS,
    COMP_LZS_BIG,       // scan 160
    COMP_COPY,
    COMP_MOHLZSS,
    COMP_MOHRLE,
    COMP_YAZ0,
    COMP_BYTE2HEX,      // scan 165
    COMP_UN434A,
    COMP_UNZIP_DYNAMIC,
    COMP_XXENCODE,
    COMP_GZPACK,
    COMP_ZLIB_NOERROR,  // scan 170
    COMP_DEFLATE_NOERROR,
    COMP_PPMDH,
    COMP_PPMDH_RAW,
    COMP_RNC,
    COMP_RNC_RAW,       // scan 175
    COMP_FITD,
    COMP_KENS_Nemesis,
    COMP_KENS_Kosinski,
    COMP_KENS_Kosinski_moduled,
    COMP_KENS_Enigma,   // scan 180
    COMP_KENS_Saxman,
    COMP_DRAGONBALLZ,
    COMP_NITROSDK,
        // nop
    COMP_NOP,
        // compressors
    COMP_ZLIB_COMPRESS      = 10000,
    COMP_DEFLATE_COMPRESS,
    COMP_LZO1_COMPRESS,
    COMP_LZO1X_COMPRESS,
    COMP_LZO2A_COMPRESS,
    COMP_XMEMLZX_COMPRESS,
    COMP_BZIP2_COMPRESS,
    COMP_GZIP_COMPRESS,
    COMP_LZSS_COMPRESS,
    COMP_SFL_BLOCK_COMPRESS,
    COMP_SFL_RLE_COMPRESS,
    COMP_SFL_NULLS_COMPRESS,
    COMP_SFL_BITS_COMPRESS,
    COMP_LZF_COMPRESS,
    COMP_BRIEFLZ_COMPRESS,
    COMP_JCALG_COMPRESS,
    COMP_BCL_HUF_COMPRESS,
    COMP_BCL_LZ_COMPRESS,
    COMP_BCL_RICE_COMPRESS,
    COMP_BCL_RLE_COMPRESS,
    COMP_BCL_SF_COMPRESS,
    COMP_SZIP_COMPRESS,
    COMP_HUFFMANLIB_COMPRESS,
    COMP_LZMA_COMPRESS,
    COMP_LZMA_86HEAD_COMPRESS,
    COMP_LZMA_86DEC_COMPRESS,
    COMP_LZMA_86DECHEAD_COMPRESS,
    COMP_LZMA_EFS_COMPRESS,
    COMP_FALCOM_COMPRESS,
        // nop
    COMP_ERROR
};

enum {
    LZMA_FLAGS_NONE         = 0,
    LZMA_FLAGS_86_HEADER    = 1,
    LZMA_FLAGS_86_DECODER   = 2,
    LZMA_FLAGS_EFS          = 4,
    LZMA_FLAGS_NOP
};

typedef struct {
    u8      *name;          // name of the variable, it can be also a fixed number since "everything" is handled as a variable
    u8      *value;         // it's current value in the form of an allocated string
    int     value32;        // number
    int     isnum;          // 1 if it's a number, 0 if a string
    u8      constant;       // it's 1 if the variable is a fixed number and not a "real" variable
    int     size;           // used for avoiding to waste realloc too much, not so much important and well used in reality
} variable_t;

typedef struct {
    u8      type;           // type of command to execute
    u8      *debug_line;    // used with -v
    int     var[MAX_ARGS];  // pointer to a variable
    int     num[MAX_ARGS];  // simple number
    u8      *str[MAX_ARGS]; // fixed string
} command_t;

#define FDBITS \
    u8      bitchr; \
    u8      bitpos; \
    u_int   bitoff;

typedef struct {
    FILE    *fd;
    u8      *fullname;      // just the same input filename, like c:\myfile.pak or ..\..\myfile.pak
    u8      *filename;      // input filename only, like myfile.pak
    u8      *basename;      // input basename only, like myfile
    u8      *fileext;       // input extension only, like pak
    FDBITS
    void    *sd;            // socket operations
    void    *pd;            // process memory operations
} filenumber_t;

typedef struct {
    u8      *data;
    int     pos;
    int     size;
    int     maxsize;
    FDBITS
} memory_file_t;

typedef struct {
    int     elements;
    u8      **str;
} array_t;

typedef struct {
    u8      *name;
    //int     offset; // unused at the moment
    int     size;
} files_t;

filenumber_t    filenumber[MAX_FILES + 1];
variable_t      variable_main[MAX_VARS + 1];
variable_t      *variable = variable_main;  // remember to reinitialize it every time (to avoid problems with callfunction)
command_t       command[MAX_CMDS + 1];
memory_file_t   memory_file[MAX_FILES + 1];
array_t         array[MAX_ARRAYS + 1];

#ifndef DISABLE_OPENSSL
EVP_CIPHER_CTX  *evp_ctx        = NULL;
EVP_MD_CTX      *evpmd_ctx      = NULL;
BF_KEY          *blowfish_ctx   = NULL;
typedef struct {
    AES_KEY     ctx;
    u8          ivec[AES_BLOCK_SIZE];
    u8          ecount[AES_BLOCK_SIZE];
	unsigned    num;
} aes_ctr_ctx_t;
aes_ctr_ctx_t   *aes_ctr_ctx    = NULL;
#endif
tea_context     *tea_ctx        = NULL;
xtea_context    *xtea_ctx       = NULL;
xxtea_context   *xxtea_ctx      = NULL;
swap_context    *swap_ctx       = NULL;
math_context    *math_ctx       = NULL;
xor_context     *xor_ctx        = NULL;
rot_context     *rot_ctx        = NULL;
rotate_context  *rotate_ctx     = NULL;
inc_context     *inc_ctx        = NULL;
charset_context *charset_ctx    = NULL;
charset_context *charset2_ctx   = NULL;
TWOFISH_context *twofish_ctx    = NULL;
SEED_context    *seed_ctx       = NULL;
serpent_context_t *serpent_ctx  = NULL;
ICE_KEY         *ice_ctx        = NULL; // must be not allocated
Rotorobj        *rotor_ctx      = NULL;
ssc_context     *ssc_ctx        = NULL;
wincrypt_context *wincrypt_ctx  = NULL;
cunprot_context *cunprot_ctx    = NULL;
u32             *zipcrypto_ctx  = NULL;
u32             *threeway_ctx   = NULL;
void            *skipjack_ctx   = NULL;
ANUBISstruct    *anubis_ctx     = NULL;
aria_ctx_t      *aria_ctx       = NULL;
u32             *crypton_ctx    = NULL;
u32             *frog_ctx       = NULL;
gost_ctx_t      *gost_ctx       = NULL;
int             lucifer_ctx     = 0;
u32             *mars_ctx       = NULL;
u32             *misty1_ctx     = NULL;
NOEKEONstruct   *noekeon_ctx    = NULL;
seal_ctx_t      *seal_ctx       = NULL;
safer_key_t     *safer_ctx      = NULL;
int             kirk_ctx        = -1;
#ifndef DISABLE_MCRYPT
    MCRYPT      mcrypt_ctx      = NULL;
#endif
#ifndef DISABLE_TOMCRYPT
    typedef struct {
        int     idx;
        int     cipher;
        int     hash;
        u8      *key;
        int     keysz;
        u8      *ivec;      // allocated
        int     ivecsz;
        u8      *nonce;     // allocated
        int     noncelen;
        u8      *header;    // allocated
        int     headerlen;
        u8      *tweak;     // allocated
    } TOMCRYPT;
    TOMCRYPT    *tomcrypt_ctx   = NULL;
#endif
crc_context     *crc_ctx        = NULL;
FILE    *listfd                 = NULL;
int     bms_line_number         = 0,
        extracted_files         = 0,
        reimported_files        = 0,
        endian                  = MYLITTLE_ENDIAN,
        list_only               = 0,
        force_overwrite         = 0,
        verbose                 = 0,
        variables               = 0,
        quick_gui_exit          = 0,
        compression_type        = COMP_ZLIB,
        *file_xor_pos           = NULL,
        file_xor_size           = 0,
        *file_rot13_pos         = NULL,
        file_rot13_size         = 0,
        *file_crypt_pos         = NULL,
        file_crypt_size         = 0,
        comtype_dictionary_len  = 0,
        comtype_scan            = 0,
        encrypt_mode            = 0,
        append_mode             = 0,
        temporary_file_used     = 0,
        quickbms_version        = 0,
        decimal_notation        = 1,    // myitoa is a bit slower (due to the %/) but is better for some strings+num combinations
        mex_default             = 0,
        write_mode              = 0,
        input_total_files       = 0,
        endian_killer           = 0,
        void_dump               = 0,
        reimport                = 0,
        enable_sockets          = 0,
        enable_process          = 0;
        //min_int               = 1 << ((sizeof(int) << 3) - 1),
        //max_int               = (u_int)(1 << ((sizeof(int) << 3) - 1)) - 1;
u8      current_folder[PATHSZ + 1] = "",  // just the current folder when the program is launched
        bms_folder[PATHSZ + 1]  = "",
        exe_folder[PATHSZ + 1]  = "",
        file_folder[PATHSZ + 1] = "",
        *output_folder          = NULL,     // points to fdir
        *filter_files           = NULL,     // the wildcard
        *filter_in_files        = NULL,     // the wildcard
        *file_xor               = NULL,     // contains all the XOR numbers
        *file_rot13             = NULL,     // contains all the rot13 numbers
        *file_crypt             = NULL,     // nothing
        *comtype_dictionary     = NULL;
int     EXTRCNT_idx             = 0,
        BytesRead_idx           = 0,
        NotEOF_idx              = 0;



u8 *mystrcpy(u8 *dst, u8 *src, int max);
u8 *mystrdup(u8 *str);
u8 *mystrchrs(u8 *str, u8 *chrs);
u8 *mystrrchrs(u8 *str, u8 *chrs);
void show_dump(int left, u8 *data, int len, FILE *stream);
void quick_var_from_name_check(u8 **ret_key, int *ret_keysz);
int perform_compression(u8 *in, int zsize, u8 **ret_out, int size, int *outsize);
int perform_encryption(u8 *data, int datalen);
int get_parameter_numbers(u8 *str, int max_parameters, ...);
int check_extension(u8 *fname, u8 *ext);
void copycut_folder(u8 *input, u8 *output);
u8 *get_main_path(u8 *fname, u8 *argv0, u8 *output);
int check_is_dir(u8 *fname);
QUICKBMS_int readbase(u8 *data, QUICKBMS_int size, QUICKBMS_int *readn);
int myfopen(u8 *fname, int fdnum, int error);
void mex_default_init(int file_only);
void bms_init(int reinit);
void bms_finish(void);
files_t *add_files(u8 *fname, int fsize, int *ret_files);
int quick_simple_tmpname_scanner(u8 *filedir, int filedirsz);
int recursive_dir(u8 *filedir, int filedirsz);
int start_bms(int startcmd, int nop, int *ret_break);
void set_quickbms_arg(u8 *quickbms_arg);
int parse_bms(FILE *fds);
int bms_line(FILE *fd, u8 *input_line, u8 **argument, u8 **debug_line);
int cstring(u8 *input, u8 *output, int maxchars, int *inlen);
int myisalnum(int chr);
int myisdigitstr(u8 *str);
int myisdigit(int chr);
u8 *myitoa(int num);
int myatoifile(u8 *str);
//int myatoi(u8 *str);
u8 *mystrcpy(u8 *dst, u8 *src, int max);
u8 *mystrrchrs(u8 *str, u8 *chrs);
u8 *re_strdup(u8 *dst, u8 *src, int *retlen);
int math_operations(int var1i, int op, int var2i, int sign);
int get_memory_file(u8 *str);
int add_var(int idx, u8 *str, u8 *val, int val32, int valsz);
int dumpa_memory_file(memory_file_t *memfile, u8 **ret_data, int size, int *ret_size);
int dumpa(int fdnum, u8 *fname, int offset, int size, int zsize);
int check_wildcard(u8 *fname, u8 *wildcard);
u8 *create_dir(u8 *name);
int check_overwrite(u8 *fname, int check_if_present_only);
void myalloc(u8 **data, QUICKBMS_int wantsize, QUICKBMS_int *currsize);
int getxx(u8 *tmp, int bytes);
int putxx(u8 *data, u_int num, int bytes);
u8 *fgetss(int fdnum, int chr, int unicode, int line);
int fputss(int fdnum, u8 *data, int chr, int unicode, int line);
int myfgetc(int fdnum);
int myfputc(int c, int fdnum);
int fgetxx(int fdnum, int bytes);
int fputxx(int fdnum, int num, int bytes);
u8 *myfrx(int fdnum, int type, int *ret_num, int *error);
int myfwx(int fdnum, int varn, int type);
void post_fseek_actions(int fdnum, int diff_offset);
void post_fread_actions(int fdnum, u8 *data, int size);
u_int myftell(int fdnum);
int myfeof(int fdnum);
int myfseek(int fdnum, u_int offset, int type);
int myfr(int fdnum, u8 *data, int size);
int myfw(int fdnum, u8 *data, int size);
void myhelp(u8 *arg0);
void quick_bms_list(void);
int calc_quickbms_version(u8 *version);
void alloc_err(const char *fname, int line, const char *func);
void std_err(const char *fname, int line, const char *func);
void winerr(void);
void myexit(int ret);
u_int myhtons(u_int n);
u_int myntohs(u_int n);
u_int myhtonl(u_int n);
u_int myntohl(u_int n);
#include "calling_conventions.h"

// boring 64bit compatibility
#undef int
#undef u_int
#if QUICKBMS_int != 32
    void myalloc32(u8 **data, int wantsize, int *currsize) {
        QUICKBMS_int    lame;
        if(!currsize) {
            myalloc(data, wantsize, NULL);
        } else {
            lame = *currsize;
            myalloc(data, wantsize, &lame);
            *currsize = lame;
        }
    }
    #define myalloc myalloc32
#endif
#include "sign_ext.h"
#include "unz.h"
#include "extra/wcx.c"
#include "sockets.h"
#include "process.h"
#undef myalloc
// restore int and u_int after main()



int main(int argc, char *argv[]) {
#define int             QUICKBMS_int
#define u_int           QUICKBMS_u_int

    static u8   filedir[PATHSZ + 1] = ".",  // don't waste the stack
                bckdir[PATHSZ + 1]  = ".";
    files_t *files      = NULL;
    FILE    *fds;
    time_t  benchmark   = 0;
    int     i,
            mybreak     = 0,
            curr_file   = 0,
            wcx_plugin  = 0,
            quickbms_outname = 0;
    u8      *newdir,
            *bms,
            *fname,
            *fdir,
            *p,
            *tmp,
            *listfile   = NULL,
            *quickbms_arg  = NULL;

    //setbuf(stdout, NULL); // should increase the speed with lot of files
    setbuf(stderr, NULL);
    fflush(stdin);  // useless?

    fputs("\n"
        "QuickBMS generic files extractor and reimporter "VER
#ifdef QUICKBMS64
        " (64bit test)"
#endif
        "\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

#ifdef WIN32
    mywnd = GetForegroundWindow();
    if(GetWindowLong(mywnd, GWL_WNDPROC)) {
        for(i = 1; i < argc; i++) {
            if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
                break;
            }
            switch(argv[i][1]) {
                case 'f': i++;  break;
                case 'F': i++;  break;
                case 'L': i++;  break;
                case 'a': i++;  break;
                default: break;
            }
        }
        if(i > argc) i = argc;
        i = 3 - (argc - i);
        if(i > 0) {
            printf(
                "- GUI mode activated, remember that the tool works also from command-line\n"
                "  where are available various options like folder scanning, filters and so on\n"
                "\n");
            bms = calloc(argc + i + 1, sizeof(char *));
            if(!bms) STD_ERR;
            memcpy(bms, argv, sizeof(char *) * argc);
            argv = (void *)bms;
            argc -= (3 - i);
            if(i >= 3) argv[argc]     = get_file("select the BMS script or plugin to use", 1, 0);
            if(i >= 2) argv[argc + 1] = get_file("select the input archives/files to extract, type \"\" for whole folder and subfolders", 0, 1);
            if(i >= 1) argv[argc + 2] = get_folder("select the output folder where extracting the files");
            argc += 3;
        }
    }
#endif

    if(argc < 4) {
        if((argc >= 2) && (argv[1][1] == 'c')) {
            quick_bms_list();
            myexit(-2);
        }
        myhelp(argv[0]);
        myexit(-2);
    }

    argc -= 3;
    for(i = 1; i < argc; i++) {
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
            printf("\nError: wrong argument (%s)\n", argv[i]);
            myexit(-2);
        }
        switch(argv[i][1]) {
            case '-':
            case '?':
            case 'h': { myhelp(argv[0]);  myexit(-2); } break;
            case 'c': { quick_bms_list(); myexit(-2); } break;
            case 'l': list_only         = 1;            break;
            case 'f': filter_files      = argv[++i];    break;
            case 'F': filter_in_files   = argv[++i];    break;
            case 'o': force_overwrite   = 1;            break;
            case 'v': verbose           = 1;            break;
            case 'V': verbose           = -1;           break;
            case 'L': listfile          = argv[++i];    break;
            case 'R': quick_gui_exit    = 1;            break;  // internal usage for external programs
            case 'x': decimal_notation  = 0;            break;
            case 'w': write_mode        = 1;            break;
            case 'a': quickbms_arg      = argv[++i];    break;
            case 'd': quickbms_outname  = 1;            break;
            case 'E': endian_killer     = 1;            break;
            case '0': void_dump         = 1;            break;
            case 'r': reimport          = 1;            break;
            case 'n': enable_sockets    = 1;            break;
            case 'p': enable_process    = 1;            break;
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                myexit(-2);
            }
        }
    }

    if(reimport) printf("- REIMPORT mode enabled!\n");

    bms   = argv[argc];
    fname = argv[argc + 1];
    fdir  = argv[argc + 2];

    getcwd(current_folder, PATHSZ);

    output_folder = fdir;
    if(!chdir(output_folder)) { // ???
        output_folder = malloc(PATHSZ + 1);
        getcwd(output_folder, PATHSZ);
        chdir(current_folder);
    }

    copycut_folder(fname, file_folder); // this is ok also with windows multifile
    if(!file_folder[0]) getcwd(file_folder, PATHSZ);

    /* problems with multifile, do NOT USE the following!
    if(!chdir(file_folder)) {   // ???
        getcwd(file_folder, PATHSZ);
        chdir(current_folder);
        p = mystrrchrs(fname, "\\/");
        if(p) {
            p++;
        } else {
            p = fname;
        }
        fname = malloc(strlen(file_folder) + 1 + strlen(p) + 1);
        sprintf(fname, "%s%c%s", file_folder, PATHSLASH, p);
    }
    */

    bms_init(0);

    get_main_path(NULL, argv[0], exe_folder);
    if(!exe_folder[0]) getcwd(exe_folder, PATHSZ);

    // the following is used only for calldll so it's not much important
    if(strchr(bms, ':') || (bms[0] == '/') || (bms[0] == '\\')) {   // almost absolute path
        bms_folder[0] = 0;
    } else {
        mystrcpy(bms_folder, current_folder, PATHSZ);
    }
    mystrcpy(bms_folder + strlen(bms_folder), bms, PATHSZ - strlen(bms_folder));
    copycut_folder(NULL, bms_folder);

    newdir = NULL;
#ifdef WIN32
    if(GetWindowLong(mywnd, GWL_WNDPROC) && fname[strlen(fname) + 1]) { // check if there are files after the folder
        newdir = fname;
        getcwd(bckdir, PATHSZ);
        if(chdir(newdir) < 0) STD_ERR;
        for(p = fname;;) {
            p += strlen(p) + 1;
            if(!*p) break;
            add_files(p, 0, NULL);
        }
    } else
#endif
    if(check_is_dir(fname)) {
        mystrcpy(file_folder, fname, PATHSZ);
        newdir = fname;
        printf("- start the scanning of the input folder: %s\n", newdir);
        getcwd(bckdir, PATHSZ);
        if(chdir(newdir) < 0) STD_ERR;
        strcpy(filedir, ".");
        recursive_dir(filedir, PATHSZ);
    }
    // if one of the above was done finish the job
    if(newdir) {
        files = add_files(NULL, 0, &input_total_files);
        curr_file = 0;
        if(input_total_files <= 0) {
            printf("\nError: the input folder is empty\n");
            myexit(-2);
        }
        chdir(bckdir);
    }

    p = strchr(current_folder, ':');    if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(bms_folder, ':');        if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(exe_folder, ':');        if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(file_folder, ':');       if(p && !p[1]) strcpy(p + 1, "\\");
    p = strchr(output_folder, ':');     if(p && !p[1]) strcpy(p + 1, "\\");
    if(verbose) {
        printf("- current_folder: %s\n", current_folder);
        printf("- bms_folder:     %s\n", bms_folder);
        printf("- exe_folder:     %s\n", exe_folder);
        printf("- file_folder:    %s\n", file_folder);
        printf("- output_folder:  %s\n", output_folder);
    }

    set_quickbms_arg(quickbms_arg);

    if(check_extension(bms, "wcx")) wcx_plugin = 1;

redo:
    benchmark = time(NULL);
    if(files) {
        fname = files[curr_file].name;
        curr_file++;
        chdir(bckdir);
        chdir(newdir);
    }
    if(wcx_plugin) {
        if(wcx(NULL, fname) < 0) STD_ERR;
    } else {
        myfopen(fname, 0, 1);
    }
    if(files) {
        chdir(bckdir);
    }

    if(wcx_plugin) {
        printf("- open WCX plugin %s\n", bms);
        if(wcx(bms, fname) < 0) STD_ERR;
    } else {
        printf("- open script %s\n", bms);
        if(!strcmp(bms, "-")) {
            fds = stdin;
        } else {
            fds = fopen(bms, "rb");
            if(!fds) STD_ERR;
        }
        parse_bms(fds);
        if(fds != stdin) fclose(fds);
    }

    if(listfile && !listfd) {
        listfd = fopen(listfile, "wb");
        if(!listfd) STD_ERR;
    }

    if(!list_only && fdir && fdir[0]) {
        printf("- set output folder %s\n", fdir);
        if(chdir(fdir) < 0) STD_ERR;
        if(quickbms_outname) {
            tmp = fname;
            p = mystrrchrs(tmp, "\\/");
            if(p) tmp = p + 1;
            p = strrchr(tmp, '.');
            if(p) *p = 0;   // temporary
            make_dir(tmp);
            if(chdir(tmp) < 0) STD_ERR;
            if(p) *p = '.'; // restore
        }
    }

    printf("\n"
        "  offset   filesize   filename\n"
        "------------------------------\n");

    if(wcx_plugin) {
        wcx(NULL, NULL);
    } else {
        start_bms(-1, 0, &mybreak);
    }

    benchmark = time(NULL) - benchmark;
    if(reimport) {
        printf("\n- %d files reimported in %d seconds\n", (i32)reimported_files, (i32)benchmark);
    } else {
        printf("\n- %d files found in %d seconds\n", (i32)extracted_files, (i32)benchmark);
    }

    if(files && (curr_file < input_total_files)) {
        bms_init(1);
        goto redo;
    }

    bms_finish();
    if(listfile) {
        fclose(listfd);
    }
    myexit(0);
    return(0);
}



void show_dump(int left, u8 *data, int len, FILE *stream) {
    int                 rem;
    static const u8     hex[16] = "0123456789abcdef";
    u8                  leftbuff[80],
                        buff[67],
                        chr,
                        *bytes,
                        *p,
                        *limit,
                        *glimit = data + len;

    if(len < 0) return;
    memset(buff + 2, ' ', 48);
    memset(leftbuff, ' ', sizeof(leftbuff));

    while(data < glimit) {
        limit = data + 16;
        if(limit > glimit) {
            limit = glimit;
            memset(buff, ' ', 48);
        }

        p     = buff;
        bytes = p + 50;
        while(data < limit) {
            chr = *data;
            *p++ = hex[chr >> 4];
            *p++ = hex[chr & 15];
            p++;
            *bytes++ = ((chr < ' ') || (chr >= 0x7f)) ? '.' : chr;
            data++;
        }
        *bytes++ = '\n';

        for(rem = left; rem >= sizeof(leftbuff); rem -= sizeof(leftbuff)) {
            fwrite(leftbuff, sizeof(leftbuff), 1, stream);
        }
        if(rem > 0) fwrite(leftbuff, rem, 1, stream);
        fwrite(buff, bytes - buff, 1, stream);
    }
}



// alternative to sscanf so it's possible to use also commas and hex numbers
int get_parameter_numbers(u8 *s, int max_parameters, ...) {
    va_list ap;
    int     i,
            *par;

    // do NOT reset the parameters because they could have default values different than 0!

    if(!s) return(0);
    va_start(ap, max_parameters);
    for(i = 0; i < max_parameters; i++) {
        par = va_arg(ap, int *);

        while(*s && !myisalnum(*s)) s++;
        if(!*s) break;
        *par = myatoi(s);
        while(*s && myisalnum(*s)) s++;
        if(!*s) break;
    }
    va_end(ap);
    return(i);
}



int check_extension(u8 *fname, u8 *ext) {
    u8      *p;

    if(!fname || !ext) return(0);
    p = strrchr(fname, '.');
    if(!p) return(0);
    p++;
    if(!stricmp(p, ext)) return(1);
    return(0);
}



void copycut_folder(u8 *input, u8 *output) {
    u8      *p;

    if(!output) return;
    if(input) mystrcpy(output, input, PATHSZ);
    p = strrchr(output, '\\');
    if(!p) p = strrchr(output, '/');
    if(!p) {
        if(input) output[0] = 0;
    } else {
        *p = 0;
    }
}



u8 *get_main_path(u8 *fname, u8 *argv0, u8 *output) {
    static u8   fullname[PATHSZ + 1];
    u8      *p;

    if(!output) output = fullname;
#ifdef WIN32
    GetModuleFileName(NULL, output, PATHSZ);
#else
    sprintf(output, "%.*s", PATHSZ, argv0);
#endif

    p = strrchr(output, '\\');
    if(!p) p = strrchr(output, '/');
    if(fname) {
        if(!p) p = output - 1;
        sprintf(p + 1, "%.*s", PATHSZ - (p - output), fname);
    } else {
        if(p) *p = 0;
    }
    return(output);
}



u8 *mystrcpy(u8 *dst, u8 *src, int max) {
    u8      *p,
            *l;

    if(dst) {
        if(!src) src = "";
        p = dst;
        l = dst + max - 1;
        while(p < l) {
            if(!*src) break;
            *p++ = *src++;
        }
        *p = 0;
    }
    return(dst);
}



u8 *mystrdup(u8 *str) { // multiplatform compatible
    int     len;
    u8      *o;

    if(str) {
        len = strlen(str);
        o = malloc(len + 1);
        if(o) {
            memcpy(o, str, len + 1);
            str = o;
        }
    }
    return(str);
}



u8 *mystrchrs(u8 *str, u8 *chrs) {
    int     i;
    u8      *p,
            *ret = NULL;

    if(str && chrs) {
        for(i = 0; chrs[i]; i++) {
            p = strchr(str, chrs[i]);
            if(p && (!ret || (p < ret))) {
                ret = p;
            }
        }
    }
    return(ret);
}



u8 *mystrrchrs(u8 *str, u8 *chrs) {
    int     i;
    u8      *p,
            *ret = NULL;

    if(str && chrs) {
        for(i = 0; chrs[i]; i++) {
            p = strrchr(str, chrs[i]);
            if(p) {
                str = p;
                ret = p;
            }
        }
    }
    return(ret);
}



int check_is_dir(u8 *fname) {
    struct stat xstat;

    if(!fname) return(1);
    if(stat(fname, &xstat) < 0) return(0);
    if(!S_ISDIR(xstat.st_mode)) return(0);
    return(1);
}



#ifdef WIN32
char *get_file(char *title, i32 bms, i32 multi) {
    OPENFILENAME    ofn;
    int     maxlen;
    char    *filename;

    if(multi) {
        maxlen = 32768; // 32k limit ansi, no limit unicode
    } else {
        maxlen = PATHSZ;
    }
    filename = malloc(maxlen + 1);
    if(!filename) STD_ERR;
    filename[0] = 0;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize     = sizeof(ofn);
    if(bms) {
        ofn.lpstrFilter =
            "script/plugin (bms/txt/wcx)\0"  "*.bms;*.txt;*.wcx\0"
            //"WCX plugin\0"  "*.wcx\0"
            "(*.*)\0"       "*.*\0"
            "\0"            "\0";
    } else {
        ofn.lpstrFilter =
            "(*.*)\0"       "*.*\0"
            "\0"            "\0";
    }
    ofn.nFilterIndex    = 1;
    ofn.lpstrFile       = filename;
    ofn.nMaxFile        = maxlen;
    ofn.lpstrTitle      = title;
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST |
                          OFN_LONGNAMES     | OFN_EXPLORER |
                          OFN_HIDEREADONLY  | OFN_ENABLESIZING;
    if(multi) ofn.Flags |= OFN_ALLOWMULTISELECT;

    printf("- %s\n", ofn.lpstrTitle);
    if(!GetOpenFileName(&ofn)) exit(1); // terminate immediately
    return(filename);
}

char *get_folder(char *title) {
    OPENFILENAME    ofn;
    char    *p;
    char    *filename;

    filename = malloc(PATHSZ + 1);
    if(!filename) STD_ERR;

    strcpy(filename, "enter in the output folder and press Save");
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize     = sizeof(ofn);
    ofn.lpstrFilter     = "(*.*)\0" "*.*\0" "\0" "\0";
    ofn.nFilterIndex    = 1;
    ofn.lpstrFile       = filename;
    ofn.nMaxFile        = PATHSZ;
    ofn.lpstrTitle      = title;
    ofn.Flags           = OFN_PATHMUSTEXIST | /*OFN_FILEMUSTEXIST |*/
                          OFN_LONGNAMES     | OFN_EXPLORER |
                          OFN_HIDEREADONLY  | OFN_ENABLESIZING;

    printf("- %s\n", ofn.lpstrTitle);
    if(!GetSaveFileName(&ofn)) exit(1); // terminate immediately
    p = mystrrchrs(filename, "\\/");
    if(p) *p = 0;
    return(filename);
}
#endif



void fgetz(u8 *data, int datalen, FILE *fd, u8 *fmt, ...) {
    va_list ap;
    u8      *p;

    if(!data) return;
    if(datalen <= 0) return;
    if(fmt) {
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    data[0] = 0;
    if(!fgets(data, datalen, fd)) return;
    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
}



int myfopen(u8 *fname, int fdnum, int error) {
    process_file_t  *procfile;
    socket_file_t   *sockfile;
    filenumber_t    *filez;
    u64     filesize;
    u8      tmp[32],
            *p;

    if(!fname) return(0);
    if((fdnum < 0) || !strnicmp(fname, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        printf("\n"
            "Error: the filenumber field is minor than 0, if you want to use MEMORY_FILE\n"
            "       you don't need to \"reopen\" it in this way, just specify MEMORY_FILE\n"
            "       as filenumber in the various commands like:\n"
            "         get VAR long MEMORY_FILE\n");
        myexit(-1);
    } else if(fdnum >= MAX_FILES) {
        printf("\nError: the BMS script uses more files than how much supported by this tool\n");
        myexit(-1);
    }
    filez = &filenumber[fdnum];

    if(!fname[0]) { // flushing only
        fflush(filez->fd);  // flushing is a bad idea, anyway I allow to force it
        return(0);
    }
    if(filez->fd) fclose(filez->fd);
    printf("- open input file %s\n", fname);

    sockfile = socket_open(fname);
    if(sockfile) {
        memset(filez, 0, sizeof(filenumber_t));
        sprintf(tmp, "%u", sockfile->port);
        filez->fullname = mystrdup(fname);
        filez->filename = malloc(strlen(sockfile->host) + 1 + strlen(tmp) + 1);
        sprintf(filez->filename, "%s:%s", sockfile->host, tmp);
        filez->basename = mystrdup(sockfile->host);
        filez->fileext  = mystrdup(tmp);
        filez->sd       = sockfile;
        return(0);
    }

    procfile = process_open(fname);
    if(procfile) {
        memset(filez, 0, sizeof(filenumber_t));
        sprintf(tmp, "%lu", procfile->pid);
        filez->fullname = mystrdup(fname);
        filez->filename = malloc(strlen(procfile->name) + 1 + strlen(tmp) + 1);
        sprintf(filez->filename, "%s:%s", procfile->name, tmp);
        filez->basename = mystrdup(procfile->name);
        filez->fileext  = mystrdup(tmp);
        filez->pd       = procfile;
        return(0);
    }

    if(write_mode) {
        filez->fd = fopen(fname, "r+b");    // do NOT modify, it must be both read/write
        if(!filez->fd) {
            filez->fd = fopen(fname, "w+b");
            if(!filez->fd) {
                if(error) STD_ERR;
                return(-1);
            }
        }
        //setbuf(filez->fd, NULL);    // seems to cause only problems... mah
    } else {
        if(!strcmp(fname, "-")) {
            filez->fd = stdin;  // blah
        } else {
            filez->fd = fopen(fname, "rb");
            if(!filez->fd) {
                if(error) STD_ERR;
                return(-1);
            }
        }
    }

    fseek(filez->fd, 0, SEEK_END);
    filesize = ftell(filez->fd);
    fseek(filez->fd, 0, SEEK_SET);
#ifndef QUICKBMS64
    if(filesize > (u64)0xffffffffLL) {
        fgetz(tmp, sizeof(tmp), stdin,
            "\n"
            "- the file is bigger than 4 gigabytes so it's not supported by QuickBMS,\n"
            "  I suggest you to answer N to the following question and using\n"
            "  quickbms_4gb_files.exe that has no limitations.\n"
            "  are you sure you want to continue in any case (y/N)? ");
        if(tolower(tmp[0]) != 'y') myexit(-1);
    } else if(filesize > (u64)0x7fffffffLL) {
        printf(
            "- the file is bigger than 2 gigabytes, it should work correctly but contact me\n"
            "  or the author of the script in case of problems or invalid extracted files\n"
            "  in case of problems try to use quickbms_4gb_files.exe\n");
    }
#endif

    // filesize
    //filez->filesize = filesize;

    // fullname
    filez->fullname = re_strdup(filez->fullname, fname, NULL);    // allocate

    // filename
    filez->filename = mystrrchrs(filez->fullname, "\\/");
    if(filez->filename) {
        filez->filename++;
    } else {
        filez->filename = filez->fullname;
    }

    // basename
    filez->basename = re_strdup(filez->basename, filez->filename, NULL);  // allocate
    p = strrchr(filez->basename, '.');
    if(p) *p = 0;

    // extension
    filez->fileext = strrchr(filez->filename, '.');
    if(filez->fileext) {
        filez->fileext++;
    } else {
        filez->fileext = filez->filename + strlen(filez->filename);
    }

    // zeroing the rest
    filez->bitchr = 0;
    filez->bitpos = 0;
    filez->bitoff = 0;

    if(mex_default) {
        if(!fdnum) {
            add_var(BytesRead_idx, NULL, NULL, 0, sizeof(int));
            add_var(NotEOF_idx,    NULL, NULL, 1, sizeof(int));
        }
    }
    return(0);
}



int add_datatype(u8 *str) {
    if(str) {
        if(!stricmp(str, "Long"))       return(TYPE_LONG);
        if(!stricmp(str, "Int"))        return(TYPE_SHORT);
        if(!stricmp(str, "Byte"))       return(TYPE_BYTE);
        if(!stricmp(str, "ThreeByte"))  return(TYPE_THREEBYTE);
        if(!stricmp(str, "String"))     return(TYPE_STRING);
        if(!stricmp(str, "ASize"))      return(TYPE_ASIZE);
        // added by me
        if(stristr(str,  "bits"))       return(TYPE_BITS);
        if(!stricmp(str, "Longlong"))   return(TYPE_LONGLONG);
        //if(!stricmp(str, "Llong"))      return(TYPE_LONGLONG);
        if(!stricmp(str, "Short"))      return(TYPE_SHORT);
        if(!stricmp(str, "Char"))       return(TYPE_BYTE);
        if(!stricmp(str, "dword"))      return(TYPE_LONG);
        if(!stricmp(str, "word"))       return(TYPE_SHORT);
        if(!stricmp(str, "FileName"))   return(TYPE_FILENAME);
        if(!stricmp(str, "BaseName"))   return(TYPE_BASENAME);
        if(!stricmp(str, "FullName"))   return(TYPE_FULLNAME);
        if(!stricmp(str, "Extension"))  return(TYPE_EXTENSION);
        if(!stricmp(str, "FileExt"))    return(TYPE_EXTENSION);
        if(!stricmp(str, "current_folder")) return(TYPE_CURRENT_FOLDER);
        if(!stricmp(str, "file_folder")) return(TYPE_FILE_FOLDER);
        if(!stricmp(str, "input_folder")) return(TYPE_INOUT_FOLDER);
        if(!stricmp(str, "output_folder")) return(TYPE_INOUT_FOLDER);
        if(!stricmp(str, "bms_folder")) return(TYPE_BMS_FOLDER);
        if(!stricmp(str, "Unicode"))    return(TYPE_UNICODE);
        if(!stricmp(str, "UTF-16"))     return(TYPE_UNICODE);
        if(!stricmp(str, "UTF16"))      return(TYPE_UNICODE);
        if(!stricmp(str, "Binary"))     return(TYPE_BINARY);
        if(!stricmp(str, "Line"))       return(TYPE_LINE);
        if(!stricmp(str, "UTF-8"))      return(TYPE_STRING);
        if(!stricmp(str, "UTF8"))       return(TYPE_STRING);
        if(!stricmp(str, "Alloc"))      return(TYPE_ALLOC);
        if(!stricmp(str, "Compressed")) return(TYPE_COMPRESSED);
        // ever at the end!
        //if(!stricmp(str, "8"))          return(TYPE_LONGLONG);
        if(!stricmp(str, "4"))          return(TYPE_LONG);
        if(!stricmp(str, "3"))          return(TYPE_THREEBYTE);
        if(!stricmp(str, "2"))          return(TYPE_SHORT);
        if(!stricmp(str, "1"))          return(TYPE_BYTE);
        if(strstr(str,   "64"))         return(TYPE_LONGLONG);
        if(strstr(str,   "32"))         return(TYPE_LONG);
        if(strstr(str,   "24"))         return(TYPE_THREEBYTE);
        if(strstr(str,   "16"))         return(TYPE_SHORT);
        if(strstr(str,   "8"))          return(TYPE_BYTE);
        if(!stricmp(str, "float"))      return(TYPE_FLOAT);
        if(!stricmp(str, "float32"))    return(TYPE_FLOAT);
        if(!stricmp(str, "double"))     return(TYPE_DOUBLE);
        if(!stricmp(str, "float64"))    return(TYPE_DOUBLE);
        if(!stricmp(str, "double64"))   return(TYPE_DOUBLE);
        if(!stricmp(str, "longdouble")) return(TYPE_LONGDOUBLE);
        if(!stricmp(str, "double96"))   return(TYPE_LONGDOUBLE);
        if(!stricmp(str, "bool"))       return(TYPE_LONG);
        if(!stricmp(str, "void"))       return(TYPE_LONG);
        if(!stricmp(str, "variable"))   return(TYPE_VARIABLE);
        if(!stricmp(str, "variable1"))  return(TYPE_VARIABLE);
        if(!stricmp(str, "variable2"))  return(TYPE_VARIABLE2);
        if(!stricmp(str, "unreal"))     return(TYPE_VARIABLE2);
        if(!stricmp(str, "variant"))    return(TYPE_VARIANT);
    }
    printf("\nError: invalid datatype %s at line %d\n", str, (i32)bms_line_number);
    myexit(-1);
    return(-1);
}



int get_var_from_name(u8 *name, int namelen) {  // a memory_file IS NOT a variable!
    int     i;

    if(!name) return(-1);
    if(namelen < 0) namelen = strlen(name);
    for(i = 0; variable[i].name; i++) {
        if(!strnicmp(variable[i].name, name, namelen) && !variable[i].name[namelen]) return(i);
    }
    return(-1);
}



// do NOT enable X4 and memory files here or will be visualized an error!
#define GET_VAR_COMMON(X1,X2,X3,X4) \
    if((idx < 0) || (idx >= MAX_VARS)) { \
        printf("\nError: the variable index is invalid, there is an error in this tool\n"); \
        myexit(-1); \
    } \
    if(variable[idx].isnum) { \
        if(verbose > 0) printf("             <get %s (%d) 0x%08x\n", variable[idx].name, (i32)idx, (i32)variable[idx].value32); \
        /* else if(verbose < 0) printf("               %-10s 0x%08x\n", variable[idx].name, (i32)variable[idx].value32); */ \
        return(X1); \
    } \
    if(variable[idx].value) { \
        if(verbose > 0) printf("             <get %s (%d) \"%s\"\n", variable[idx].name, (i32)idx, variable[idx].value); \
        /* else if(verbose < 0) printf("               %-10s \"%s\"\n", variable[idx].name, variable[idx].value); */ \
        return(X2); \
    } \
    if(variable[idx].name[0] && strnicmp(variable[idx].name, MEMORY_FNAME, MEMORY_FNAMESZ)) { /* "" is for sequential file names */ \
        if(verbose > 0) printf("- variable \"%s\" seems uninitialized, I use its name\n", variable[idx].name); \
        /* else if(verbose < 0) printf("               %-10s \"%s\"\n", variable[idx].name, variable[idx].name); */ \
        /* myexit(-1); */ \
    } \
    if(verbose > 0) printf("             <get %s (%d) \"%s\"\n", variable[idx].name, (i32)idx, variable[idx].name); \
    /* else if(verbose < 0) printf("               %-10s \"%s\"\n", variable[idx].name, variable[idx].name); */ \
    return(X3);



u8 *get_varname(int idx) {
    if((idx < 0) || (idx >= MAX_VARS)) {
        //printf("\nError: the variable index is invalid, there is an error in this tool\n");
        //myexit(-1);
        return("");
    }
    return(variable[idx].name);
}



int get_var32(int idx) {
    GET_VAR_COMMON(
        variable[idx].value32,
        myatoi(variable[idx].value),
        myatoi(variable[idx].name),
        myatoi(memory_file[-get_memory_file(variable[idx].name)].data))
}



u8 *get_var(int idx) {
    GET_VAR_COMMON(
        myitoa(variable[idx].value32),
        variable[idx].value,
        variable[idx].name,
        memory_file[-get_memory_file(variable[idx].name)].data)
}



int get_varsz(int idx) {
    GET_VAR_COMMON(
        sizeof(int),
        strlen(variable[idx].value),
        strlen(variable[idx].name),
        memory_file[-get_memory_file(variable[idx].name)].size)
}



int var_is_a_string(int idx) {
    GET_VAR_COMMON(
        0,
        1,
        1,
        1)
}



int var_is_a_number(int idx) {
    GET_VAR_COMMON(
        1,
        0,
        0,
        0)
}



int var_is_a_memory_file(int idx) {
    GET_VAR_COMMON(
        0,
        0,
        1,  // uhmmm correct?
        1)
}



int var_is_a_constant(int idx) {
    if((idx < 0) || (idx >= MAX_VARS)) {
        printf("\nError: the variable index is invalid, there is an error in this tool\n");
        myexit(-1);
    }
    if(variable[idx].constant) return(1);
    return(0);
}



QUICKBMS_int readbase(u8 *data, QUICKBMS_int size, QUICKBMS_int *readn) {
    static const u8 table[256] =    // fast performances
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff"
            "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    int     num     = 0;
    int     sign;
    u8      c,
            *s,
            *hex_fix;

    s = data;
    if(!data || !size || !data[0]) {
        // do nothing (for readn)
    } else {
        while(*s && (*s <= ' ')) s++;   // useful in some occasions, for example if the input is external!
        if(*s == '-') {
            sign = -1;
            s++;
        } else {
            sign = 0;
        }
        hex_fix = s;
        for(; *s; s++) {
            c = *s;
            //if((c == 'x') || (c == 'X') || (c == '$')) {  // auto base switching
            if(
                (((c == 'h') || (c == 'x') || (c == 'X')) && (s > hex_fix)) // 0x and 100h, NOT x123 or h123
             || (c == '$')                                                  // $1234 or 1234$
            ) {
                size = 16;
                continue;
            }
            c = table[c];
            if(c >= size) break;    // necessary to recognize the invalid chars based on the size
            num = (num * size) + c;
        }
        if(sign) num = -num;
    }
    if(readn) *readn = s - data;
    return(num);
}



u8 *strdupcpy(u8 *dst, int *dstlen, u8 *src, int srclen) {
    if(srclen < 0) {
        if(src) {
            srclen = strlen(src);
        } else {
            srclen = 0;
        }
    }

    // normal solution
    /*
    //if(srclen < STRINGSZ) srclen = STRINGSZ;  // disabled for testing
    if(dstlen) *dstlen = srclen;
    dst = realloc(dst, srclen + 1);
    if(!dst) STD_ERR;
    */

    // optimized solution
    if(!dst || (*dstlen < srclen)) {
        *dstlen = srclen;
        if(*dstlen == -1) ALLOC_ERR;
        if(*dstlen < STRINGSZ) *dstlen = STRINGSZ;    // better for numbers and common filenames
        dst = realloc(dst, *dstlen + 1);
        if(!dst) STD_ERR;
    }

    if(dst) {
        if(src) memcpy(dst, src, srclen);
        else    memset(dst, 0,   srclen);
        dst[srclen] = 0;
    }
    return(dst);
}



u8 *re_strdup(u8 *dst, u8 *src, int *retlen) {  // only for NULL delimited strings, NOT bytes!
    int     dstlen  = -1;

    // dst && src checked by strdupcpy
    if(retlen) dstlen = *retlen;
    dst = strdupcpy(dst, &dstlen, src, -1);
    if(retlen) *retlen = dstlen;
    return(dst);
}



void strdup_replace(u8 **dstp, u8 *src, int src_len, int *dstp_len) {  // should improve a bit the performances
    int     dst_len = -1;
    u8      *dst;

    if(!dstp) return;
    dst = *dstp;

    if(!dstp_len && dst) {
        dst_len = strlen(dst);  // or is it better to use "dst_len = 0"?
    } else if(dstp_len) {
        dst_len = *dstp_len;
    }

    dst = strdupcpy(dst, &dst_len, src, src_len);

    *dstp = dst;
    if(dstp_len) *dstp_len = dst_len;
}



int get_memory_file(u8 *str) {
    int     ret = 0;    // because -1 is returned for MEMORY_FILE

    // MEMORY_FILE  = -1
    // MEMORY_FILE1 = -1
    // MEMORY_FILE2 = -2

    if(str) {
        ret = myatoi(str + MEMORY_FNAMESZ);
        if(!ret) ret++;
        if((ret < 0) || (ret > MAX_FILES)) {
            printf("\nError: too big MEMORY_FILE number\n");
            myexit(-1);
        }
        ret = -ret;
    }
    if(ret >= 0) {
        printf("\nError: the memory file has a positive number\n");
        myexit(-1);
    }
    return(ret);
}



// I have chosen -2 because it's negative and is different than -1, a fast solution
int add_varval(int idx, u8 *val, int val32, int valsz) {
    if(valsz != -2) {
        if(variable[idx].constant) return(-1); //goto quit_error;
        if(val) {
            strdup_replace(&variable[idx].value, val, valsz, &variable[idx].size);
            variable[idx].isnum   = 0;
        } else {
            variable[idx].value32 = val32;
            variable[idx].isnum   = 1;
        }
    }
    return(0);
}



int add_var(int idx, u8 *str, u8 *val, int val32, int valsz) {
    // do NOT touch valsz, it's a job of strdup_replace
    if((idx < 0) || (idx >= MAX_VARS)) {
        printf("\nError: the variable index is invalid, there is an error in this tool\n");
        myexit(-1);
    }
    //if((valsz == -2) && !str) str = ""; // specific for the ARGs, only in case of errors in my programming
    // if(valsz < 0) valsz = STRINGSZ;  do NOT do this, valsz is calculated on the length of val
    if(!str) {  // && (idx >= 0)) {
        //str = variable[idx].name; // unused
        if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;
        //goto quit;
    } else {    // used only when the bms file is parsed at the beginning
        if(!stricmp(str, "EXTRCNT") || !stricmp(str, "BytesRead") || !stricmp(str, "NotEOF")) {
            if(!mex_default) {
                mex_default = 1;    // this avoids to waste cpu for these boring and useless variables
                mex_default_init(0);
            }
        }
        for(idx = 0; variable[idx].name; idx++) {
            if(!stricmp(variable[idx].name, str)) {
                if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;
                goto quit;
            }
        }
        if(idx >= MAX_VARS) {
            printf("\nError: the BMS script uses more variables than how much supported by this tool\n");
            myexit(-1);
        }
        strdup_replace(&variable[idx].name, str, -1, &variable[idx].size);
        if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;

        if(!variable[idx].name[0]) {        // ""
            variable[idx].constant = 1;     // it's like read-only
        }
        // if this "if" is removed the tool will be a bit slower but will be able to handle completely the script in the example below
        if(myisdigitstr(variable[idx].name)) {  // removes the problem of Log "123.txt" 0 0
        //if(myisdigit(variable[idx].name[0])) {  // number: why only the first byte? because decimal and hex (0x) start all with a decimal number or a '-'
            //strdup_replace(&variable[idx].value, variable[idx].name, -1, &variable[idx].size);
            variable[idx].value32  = myatoi(variable[idx].name);
            variable[idx].isnum    = 1;
            variable[idx].constant = 1;     // it's like read-only

            // there is only one incompatibility with the string-only variables, but it's acceptable for the moment:
            //   set NAME string "mytest"
            //   set NUM long 0x1234
            //   string NAME += NUM
            //   print "%NAME%"
            //   set NUM string "0x12349999999999"
            //   string NAME += NUM
            //   print "%NAME%"
        }
    }
quit:
    if(verbose > 0) {
        if(variable[idx].isnum) {
            printf("             >set %s (%d) to 0x%08x\n", variable[idx].name, (i32)idx, (i32)variable[idx].value32);
        } else if(variable[idx].value) {
            printf("             >set %s (%d) to \"%s\"\n", variable[idx].name, (i32)idx, variable[idx].value);
        } else {
            printf("             >set %s (%d) to \"%s\"\n", variable[idx].name, (i32)idx, variable[idx].name);
        }
    /*} else if(verbose < 0) {
        if(variable[idx].isnum) {
            printf("             >%-10s 0x%08x\n", variable[idx].name, (i32)variable[idx].value32);
        } else if(variable[idx].value) {
            printf("             >%-10s \"%s\"\n", variable[idx].name, variable[idx].value);
        } else {
            printf("             >%-10s \"%s\"\n", variable[idx].name, variable[idx].name);
        } */
    }
    return(idx);
quit_error:
    printf("\nError: there is something wrong in the BMS, var %d is a constant number\n", (i32)idx);
    myexit(-1);
    return(-1);
}



int myisdechex_string(u8 *str) {
    int     len;

    // I have already verified that using a quick test only on the first char doesn't improve the performances if compared to the current full check
    if(!str) return(0);
    readbase(str, 10, &len);
    if(len <= 0) return(0); // FALSE
    return(1);              // TRUE
}



int check_condition(int cmd) {
    int     var1n   = 0,
            var2n   = 0,
            res,
            sign    = 0;
    u8      *cond,
            *var1   = NULL,
            *var2   = NULL,
            *p;

    if((CMD.var[0] < 0) || (CMD.var[2] < 0)) return(0); // needed for CMD_Else!
    cond = STR(1);
    if(VARISNUM(0) && VARISNUM(2)) {
        var1n = VAR32(0);
        var2n = VAR32(2);
    } else {
        var1 = VAR(0);
        var2 = VAR(2);
        if(myisdechex_string(var1) && myisdechex_string(var2)) {
            var1 = NULL;
            var2 = NULL;
            var1n = VAR32(0);
            var2n = VAR32(2);
        }
        // in the For command I use a Set instruction at the beginning of the cycle with a String type
        // now the downside is that it's a bit slower but being used only at the beginning of the cycle there is no
        // loss of time (some milliseconds on tons of For cycles) and there is the pro of using also things like:
        //  for i = "hello" != "ciao"
    }

    res = -1;   // replacing strcmp with a switch changes nothing in performance
    if(!cond) return(res);
    if(cond[0] == 'u') {    // only the first and only 'u' to avoid loss of performances
        sign = 1;
        cond++;
    }
    if(!strcmp(cond, "<")) {
        if(var1 && var2) {
            if(stricmp(var1, var2) < 0) res = 0;
        } else {
            if(sign) {
                if((u_int)var1n < (u_int)var2n) res = 0;
            } else {
                if(var1n < var2n) res = 0;
            }
        }
    } else if(!strcmp(cond, ">")) {
        if(var1 && var2) {
            if(stricmp(var1, var2) > 0) res = 0;
        } else {
            if(sign) {
                if((u_int)var1n > (u_int)var2n) res = 0;
            } else {
                if(var1n > var2n) res = 0;
            }
        }
    } else if(!strcmp(cond, "<>") || !strcmp(cond, "!=")) {
        if(var1 && var2) {
            if(stricmp(var1, var2) != 0) res = 0;
        } else {
            if(var1n != var2n) res = 0;
        }
    } else if(!strcmp(cond, "=") || !strcmp(cond, "==")) {
        if(var1 && var2) {
            if(!stricmp(var1, var2)) res = 0;
        } else {
            if(var1n == var2n) res = 0;
        }
    } else if(!strcmp(cond, ">=")) {
        if(var1 && var2) {
            if(stricmp(var1, var2) >= 0) res = 0;
        } else {
            if(sign) {
                if((u_int)var1n >= (u_int)var2n) res = 0;
            } else {
                if(var1n >= var2n) res = 0;
            }
        }
    } else if(!strcmp(cond, "<=")) {
        if(var1 && var2) {
            if(stricmp(var1, var2) <= 0) res = 0;
        } else {
            if(sign) {
                if((u_int)var1n <= (u_int)var2n) res = 0;
            } else {
                if(var1n <= var2n) res = 0;
            }
        }
    // added by me
    } else if(!strcmp(cond, "&")) {
        if(var1 && var2) {
            if(stristr(var1, var2)) res = 0;
        } else {
            if(var1n & var2n) res = 0;
        }
    } else if(!strcmp(cond, "^")) {
        if(var1 && var2) {
            if(!stricmp(var1, var2)) res = 0;
        } else {
            if(var1n ^ var2n) res = 0;
        }
    } else if(!strcmp(cond, "|")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(var1n | var2n) res = 0;
        }
    } else if(!strcmp(cond, "%")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(sign) {
                if(!var2n || ((u_int)var1n % (u_int)var2n)) res = 0;
            } else {
                if(!var2n || (var1n % var2n)) res = 0;
            }
        }
    } else if(!strcmp(cond, "/")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(sign) {
                if(!var2n || ((u_int)var1n / (u_int)var2n)) res = 0;
            } else {
                if(!var2n || (var1n / var2n)) res = 0;
            }
        }
    } else if(!strcmp(cond, "<<")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(sign) {
                if((u_int)var1n << (u_int)var2n) res = 0;
            } else {
                if(var1n << var2n) res = 0;
            }
        }
    } else if(!strcmp(cond, ">>")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(sign) {
                if((u_int)var1n >> (u_int)var2n) res = 0;
            } else {
                if(var1n >> var2n) res = 0;
            }
        }
    } else if(!strcmp(cond, "!")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(!var1n) res = 0;
        }
    } else if(!strcmp(cond, "~")) {
        if(var1 && var2) {
            res = 0;
        } else {
            if(~var1n) res = 0;
        }
    } else if(!stricmp(cond, "ext") || !stricmp(cond, "extension")) {
        if(var1 && var2) {
            p = strrchr(var1, '.');
            if(p && !stricmp(p + 1, var2)) res = 0;
        } else {
            res = 0;
        }
    } else if(!stricmp(cond, "basename")) {
        if(var1 && var2) {
            p = strrchr(var1, '.');
            if(p) {
                *p = 0;
                if(!stricmp(var1, var2)) res = 0;
                *p = '.';
            }
        } else {
            res = 0;
        }
    } else {
        if(var1 && var2) {
            printf("\nError: invalid condition %s\n", cond);
            myexit(-1);
        }
        if(math_operations(var1n, cond[0], var2n, sign)) res = 0;
    }
    if(verbose > 0) printf("             condition %s is%smet\n", cond, res ? " not " : " ");
    return(res);
}



int CMD_CLog_func(int cmd) {
    int     fd,
            offset,
            size,
            zsize;
    u8      *name;

    name    = VAR(0);
    offset  = VAR32(1);
    zsize   = VAR32(2);
    size    = VAR32(5);
    fd      = FILEZ(7);

    if(dumpa(fd, name, offset, size, zsize) < 0) return(-1);
    return(0);
}



int CMD_FindLoc_func(int cmd) {
    static u8   *sign   = NULL,
                *buff   = NULL;
    int     fd,
            i,
            len,
            oldoff,
            tmpoff,
            offset  = -1,
            str_len,
            sign_len;
    u8      *str,
            *s,
            *ret_if_error;

    fd      = FILEZ(3);
    oldoff  = myftell(fd);
    str     = STR(2);   // remember that str can be also a sequence of bytes, included 0x00!
    str_len = NUM(2);
    ret_if_error = STR(4);

    // the following has been disabled because causes troubles with old scripts
    //quick_var_from_name_check(&str, &str_len);  // so it supports also the variables

    if(NUM(1) == TYPE_STRING) {
        sign_len = str_len;
        if(sign_len == -1) ALLOC_ERR;
        sign = realloc(sign, sign_len + 1);
        if(!sign) STD_ERR;
        memcpy(sign, str, sign_len);
        sign[sign_len] = 0;
    } else if(NUM(1) == TYPE_UNICODE) {
        sign_len = (str_len + 1) * 2;  // yeah includes also the NULL delimiter, boring unicode
        if(sign_len == -1) ALLOC_ERR;
        sign = realloc(sign, sign_len + 1);
        if(!sign) STD_ERR;

        s = sign;
        for(i = 0; i < str_len; i++) {
            if(endian == MYLITTLE_ENDIAN) {
                *s++ = str[i];
                *s++ = 0;
            } else {
                *s++ = 0;
                *s++ = str[i];
            }
        }
        *s++ = 0;
        *s++ = 0;
    } else {
        sign_len = NUM(1);  // yeah the type in NUM(1) is written for having the size of the parameter, watch enum
        if(sign_len == -1) ALLOC_ERR;
        sign = realloc(sign, sign_len + 1);
        if(!sign) STD_ERR;
        putxx(sign, myatoi(str), sign_len);
    }
    if(sign_len <= 0) goto quit;
    if(sign_len > BUFFSZ) { // lazy boy
        printf("\nError: the FindLoc function works with a searchable string of max %d bytes\n", BUFFSZ);
        myexit(-1);
    }

    if(!buff) {
        buff = malloc(BUFFSZ + 1);
        if(!buff) STD_ERR;
    }
    tmpoff = oldoff;

    for(;;) {
        len = myfr(fd, buff, -1);   // -1 uses BUFFSZ automatically and doesn't quit if the file terminates
        if(len < sign_len) break;   // performes (len <= 0) too automatically
        for(i = 0; i <= (len - sign_len); i++) {
            if(!memcmp(buff + i, sign, sign_len)) {
                offset = (myftell(fd) - len) + i;
                goto quit;
            }
        }
        tmpoff += i + 1;
        myfseek(fd, tmpoff, SEEK_SET);
        //myfseek(fd, sign_len - 1, SEEK_CUR);
    }

quit:
    myfseek(fd, oldoff, SEEK_SET);
    if(offset == -1) {
        if(ret_if_error) {
            add_var(CMD.var[0], NULL, ret_if_error, 0, -1);
        } else {
            return(-1); // confirmed
        }
    } else {
        add_var(CMD.var[0], NULL, NULL, offset, sizeof(int));
    }
    return(0);
}



// how the bits reading works:
// the idea is having something that doesn't occupy much space in the file arrays (6 bytes per file)
// and that is not touched by the other functions to avoid to loose performances for a rarely used
// function so I have used the following fields:
//  bitchr = the current byte read from the file
//  bitpos = the amount of bits of bitchr that have been consumed (3 bits)
//  bitoff = the current offset, it's necessary to know if in the meantime
//           the user has changed offset and so bitpos must be resetted

u_int fd_read_bits(u_int bits, u8 *bitchr, u8 *bitpos, int fd) {
    u_int   ret = 0;
    int     i,
            t;
    u8      bc  = 0,
            bp  = 0;

    if(bitchr) bc = *bitchr;
    if(bitpos) bp = *bitpos;
    //if(bits > 32) return(0); // it's already called only for max 32 bits
    (bp) &= 7; // just for security
    for(i = 0; i < bits; i++) {
        if(!bp) {
            t = myfgetc(fd);
            bc = (t < 0) ? 0 : t;
        }
        if(endian == MYLITTLE_ENDIAN) { // uhmmm I don't think it's very fast... but works
            ret = (ret >> (u_int)1) | (u_int)((((u_int)bc >> (u_int)bp) & (u_int)1) << (u_int)(bits - 1));
        } else {
            ret = (ret << (u_int)1) | (u_int)((((u_int)bc << (u_int)bp) >> (u_int)7) & (u_int)1);
        }
        (bp)++;
        (bp) &= 7; // leave it here
    }
    if(bitchr) *bitchr = bc;
    if(bitpos) *bitpos = bp;
    return(ret);
}

int fd_write_bits(u_int num, u_int bits, u8 *bitchr, u8 *bitpos, int fd) {
    int     i,
            t,
            bit,
            rem = 0;
    u8      bc  = 0,
            bp  = 0;

    if(bitchr) bc = *bitchr;
    if(bitpos) bp = *bitpos;
    //if(bits > 32) return(0); // it's already called only for max 32 bits
    (bp) &= 7; // just for security
    for(i = 0; i < bits; i++) {
        if(!bp) {
            if(rem) {
                myfseek(fd, -1, SEEK_CUR);
                myfputc(bc, fd);
                rem = 0;
            }
            t = myfgetc(fd);
            if(t < 0) {
                bc = 0;
                myfputc(bc, fd);
            } else {
                bc = t;
            }
        }
        if(endian == MYLITTLE_ENDIAN) { // uhmmm I don't think it's very fast... but works
            t = (u_int)1 << (u_int)bp;
            bit = (num >> (u_int)i) & (u_int)1;
        } else {
            t = (u_int)1 << (u_int)(7 - bp);
            bit = (num >> (u_int)((bits - i) - 1)) & 1;
        }
        if(bit) {
            bc |= t;   // put 1
        } else {
            bc &= ~t;  // put 0
        }
        (bp)++;
        (bp) &= 7; // leave it here
        rem++;
    }
    if(rem) {
        myfseek(fd, -1, SEEK_CUR);
        myfputc(bc, fd);
    }
    if(bitchr) *bitchr = bc;
    if(bitpos) *bitpos = bp;
    return(0);
}

int bits2str(u8 *out, int outsz, int bits, u8 *bitchr, u8 *pos, int fd) {
    int     max8    = 8;
    u8      *o;

    if(!out) return(0);
    //outsz -= (*pos >> 3); pos is 3 bit
    if(outsz <= 0) return(0);
    if(outsz < (bits >> (int)3)) {
        bits = outsz << (int)3;
    }
    for(o = out; bits > 0; bits -= max8) {
        if(bits < 8) max8 = bits;
        *o++ = fd_read_bits(max8, bitchr, pos, fd);
    }
    return(o - out);
}

int str2bits(u8 *in, int insz, int bits, u8 *bitchr, u8 *pos, int fd) {
    int     max8    = 8;
    u8      *o;

    if(!in) return(0);
    //insz -= (*pos >> 3); pos is 3 bit
    if(insz <= 0) return(0);
    if(insz < (bits >> (int)3)) {
        bits = insz << (int)3;
    }
    for(o = in; bits > 0; bits -= max8) {
        if(bits < 8) max8 = bits;
        fd_write_bits(*o++, max8, bitchr, pos, fd);
    }
    return(o - in);
}

void my_fdbits(int fdnum, u8 *out_bitchr, u8 *out_bitpos, u_int *out_bitoff, u8 in_bitchr, u8 in_bitpos, u_int in_bitoff) {
    if(fdnum < 0) {
        if(out_bitchr && out_bitpos && out_bitoff) {
            *out_bitchr = memory_file[-fdnum].bitchr;
            *out_bitpos = memory_file[-fdnum].bitpos;
            *out_bitoff = memory_file[-fdnum].bitoff;
        } else {
            memory_file[-fdnum].bitchr = in_bitchr;
            memory_file[-fdnum].bitpos = in_bitpos;
            memory_file[-fdnum].bitoff = in_bitoff;
        }
        return;
    }
    CHECK_FILENUM
        if(out_bitchr && out_bitpos && out_bitoff) {
            *out_bitchr = filenumber[fdnum].bitchr;
            *out_bitpos = filenumber[fdnum].bitpos;
            *out_bitoff = filenumber[fdnum].bitoff;
        } else {
            filenumber[fdnum].bitchr = in_bitchr;
            filenumber[fdnum].bitpos = in_bitpos;
            filenumber[fdnum].bitoff = in_bitoff;
        }
}

int CMD_GetBits_func(int cmd) {
    FDBITS
    int     fd,
            len     = -1,
            tmpn    = 0,
            bits,
            verbose_offset = 0;
    u8      *tmp    = NULL;

    fd   = NUM(2);
    bits = VAR32(1);

    if(verbose < 0) verbose_offset = myftell(fd);

    my_fdbits(fd, &bitchr, &bitpos, &bitoff, 0, 0, 0);
    if(myftell(fd) != bitoff) {
        bitchr = 0;
        bitpos = 0;
    }
    if(bits <= 32) {
        tmpn = fd_read_bits(bits, &bitchr, &bitpos, fd);
    } else {
        len = ((bits + 7) & (~7)) / 8;
        tmp = calloc(len + 1, 1);
        if(!tmp) STD_ERR;
        len = bits2str(tmp, len, bits, &bitchr, &bitpos, fd);
    }
    my_fdbits(fd, NULL, NULL, NULL, bitchr, bitpos, myftell(fd));

    if(tmp) {
        if(verbose < 0) printf(". %08x getbits %-10s \"%.*s\" %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)len, tmp, (i32)bits);
        add_var(CMD.var[0], NULL, tmp, 0, len);
    } else {
        if(verbose < 0) printf(". %08x getbits %-10s 0x%08x %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)tmpn, (i32)bits);
        add_var(CMD.var[0], NULL, NULL, tmpn, sizeof(int));
    }
    return(0);
}

int CMD_PutBits_func(int cmd) {
    FDBITS
    int     fd,
            len     = -1,
            tmpn    = 0,
            bits,
            verbose_offset = 0;
    u8      *tmp    = NULL;

    fd   = NUM(2);
    bits = VAR32(1);

    if(verbose < 0) verbose_offset = myftell(fd);

    my_fdbits(fd, &bitchr, &bitpos, &bitoff, 0, 0, 0);
    if(myftell(fd) != bitoff) {
        bitchr = 0;
        bitpos = 0;
    }
    if(bits <= 32) {
        tmpn = VAR32(0);
        if(verbose < 0) printf(". %08x putbits %-10s 0x%08x %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)tmpn, (i32)bits);
        fd_write_bits(tmpn, bits, &bitchr, &bitpos, fd);
    } else {
        len = ((bits + 7) & (~7)) / 8;
        tmp = VAR(0);
        if(len > VARSZ(0)) len = VARSZ(0);
        if(verbose < 0) printf(". %08x putbits %-10s \"%.*s\" %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)len, tmp, (i32)bits);
        len = str2bits(tmp, len, bits, &bitchr, &bitpos, fd);
    }
    my_fdbits(fd, NULL, NULL, NULL, bitchr, bitpos, myftell(fd));
    return(0);
}



int CMD_Get_func(int cmd) {
    int     fd,
            type,
            tmpn    = 0,
            error   = 0,
            verbose_offset = 0;
    u8      *tmp    = NULL;

    fd   = FILEZ(2);
    type = NUM(1);

    if(verbose < 0) verbose_offset = myftell(fd);

    tmp = myfrx(fd, type, &tmpn, &error);
    // now tmp can be also NULL because myfrx is string/int
    //if(!tmp) return(-1);    // here should be good to quit... but I leave it as is for back compatibility with the old quickbms!
    if(error) return(-1);
    if(tmp) {
        if(verbose < 0) printf(". %08x get     %-10s \"%s\"\n", (i32)verbose_offset, get_varname(CMD.var[0]), tmp);
        add_var(CMD.var[0], NULL, tmp, 0, -1);
    } else {
        if(verbose < 0) printf(". %08x get     %-10s 0x%08x %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)tmpn, (i32)type);
        add_var(CMD.var[0], NULL, NULL, tmpn, sizeof(int));
    }
    return(0);
}



int CMD_IDString_func(int cmd) {
    static int  buffsz  = 0;
    static u8   *sign   = NULL,
                *buff   = NULL;
    int     fd,
            len;

    fd   = FILEZ(0);
    sign = STR(1);
    len  = NUM(1);
    if(len == -1) ALLOC_ERR;
    myalloc(&buff, len, &buffsz);   // memcmp, so not + 1
    myfr(fd, buff, len);
    if(memcmp(buff, sign, len)) {
        if((len == 4) &&    // automatic endianess... cool
           (buff[0] == sign[3]) && (buff[1] == sign[2]) && 
           (buff[2] == sign[1]) && (buff[3] == sign[0])) {
            endian = (endian == MYLITTLE_ENDIAN) ? MYBIG_ENDIAN : MYLITTLE_ENDIAN;
            return(0);
        }
        printf("\n"
            "- signature doesn't match the one expected by the script:\n"
            "  this one:  \"%.60s\"\n"
            "  expeceted: \"%.60s\"\n",
            buff, sign);
        return(-1);
    }
    return(0);
}



int CMD_GoTo_func(int cmd) {
    int     fd,
            pos;
    u8      *str;

    fd  = FILEZ(1);
    str = VAR(0);

    if(!stricmp(str, "SOF")) {
        myfseek(fd, 0, SEEK_SET);
    } else if(!stricmp(str, "EOF")) {
        myfseek(fd, 0, SEEK_END);
    } else {
        pos = VAR32(0);
        if((NUM(2) == SEEK_SET) && (pos < 0) && var_is_a_constant(CMD.var[0])) {
            myfseek(fd, pos, SEEK_END); // only contants can be negative, not vars
        } else {
            myfseek(fd, pos, NUM(2));   //SEEK_SET);
        }
    }
    return(0);
}



int CMD_SavePos_func(int cmd) {
    int     fd;

    fd  = FILEZ(1);
    add_var(CMD.var[0], NULL, NULL, myftell(fd), sizeof(int));
    return(0);
}



int rol(u_int n1, u_int n2) {
    return((n1 << n2) | (n1 >> ((u_int)INTSZ - n2)));
}



int ror(u_int n1, u_int n2) {
    return((n1 >> n2) | (n1 << ((u_int)INTSZ - n2)));
}



int bitswap(u_int n1, u_int n2) {
    u_int   out,
            rem = 0;

    if(n2 < INTSZ) {
        rem = n1 & (((int)-1) ^ (((int)1 << n2) - (int)1));
    }

    for(out = 0; n2; n2--) {
        out = (out << (int)1) | (n1 & (int)1);
        n1 >>= (u_int)1;
    }
    return(out | rem);
}



int byteswap(u_int n1, u_int n2) {
    u_int   out,
            rem = 0;

    if(n2 < (INTSZ >> 3)) {
        rem = n1 & (((int)-1) ^ (((int)1 << (n2 << (int)3)) - (int)1));
    }

    for(out = 0; n2; n2--) {
        out = (out << (int)8) | (n1 & (int)0xff);
        n1 >>= (u_int)8;
    }
    return(out | rem);
}



int power(int n1, int n2) {
    int     out = 1;

    for(;;) {
        if(n2 & 1) out *= n1;
        n2 >>= (int)1;
        if(!n2) break;
        n1 *= n1;
    }
    return(out);
}



int mysqrt(int num) {
    int    ret    = 0,
           ret_sq = 0,
           b;
    int    s;

    for(s = (INTSZ >> 1) - 1; s >= 0; s--) {
        b = ret_sq + ((int)1 << (s << (int)1)) + ((ret << s) << (int)1);
        if(b <= num) {
            ret_sq = b;
            ret += (int)1 << s;
        }
    }
    return(ret);
}



int radix(int n1, int n2) {
    int     i,
            old,    // due to the
            new;    // lack of bits

    if(!n1 || !n2) return(0);

    if(n2 == 2) return(mysqrt(n1)); // fast way

    for(i = old = 1; ; i <<= 1) {   // faster???
        new = power(i, n2);
        if((new > n1) || (new < old)) break;
        old = new;
    }

    for(i >>= 1; ; i++) {
        new = power(i, n2);
        if((new > n1) || (new < old)) break;
        old = new;
    }
    return(i - 1);
}



int math_operations(int var1i, int op, int var2i, int sign) {
#define DO_MATH_SIGN(var1,var2) \
    switch(op) { \
        case '+': var1 += var2;                 break; \
        case '*': var1 *= var2;                 break; \
        case '/': if(!var2) { var1 = 0; } else { var1 /= var2; } break; \
        case '-': var1 -= var2;                 break; \
        case '^': var1 ^= var2;                 break; \
        case '&': var1 &= var2;                 break; \
        case '|': var1 |= var2;                 break; \
        case '%': if(!var2) { var1 = 0; } else { var1 %= var2; } break; \
        case '!': var1 = !var2;                 break; \
        case '~': var1 = ~var2;                 break; \
        case '<': var1 = var1 << var2;          break; \
        case '>': var1 = var1 >> var2;          break; \
        case 'l': var1 = rol(var1, var2);       break; \
        case 'r': var1 = ror(var1, var2);       break; \
        case 's': var1 = byteswap(var1, var2);  break; \
        case 'w': var1 = bitswap(var1, var2);   break; \
        case '=': var1 = var2;                  break; \
        case 'n': var1 = -var2;                 break; \
        case 'a': var1 = (var2 < 0) ? (-var2) : var2;   break; \
        case 'v': var1 = radix(var1, var2);     break; \
        case 'p': var1 = power(var1, var2);     break; \
        case 'x': if(var2 && (var1 % var2)) { var1 += (var2 - (var1 % var2)); } break; \
        case 'z': { \
            var1 &= (((u_int)1 << (var2 * (u_int)2)) - (u_int)1); \
            var1 = (var1 << var2) | (var1 >> var2); \
            var1 &= (((u_int)1 << (var2 * (u_int)2)) - (u_int)1); \
            break; \
        } \
        default: { \
            printf("\nError: invalid operator \'%c\'\n", (i32)op); \
            myexit(-1); \
            break; \
        } \
    } \
    return(var1);

    u_int   var1u,
            var2u;

    if(sign <= 0) { // signed
        DO_MATH_SIGN(var1i, var2i);
    } else {        // unsigned
        var1u = (u_int)var1i;
        var2u = (u_int)var2i;
        DO_MATH_SIGN(var1u, var2u);
    }
    return(-1);
}



int CMD_Math_func(int cmd) {
    int     op,
            var1,
            var2,
            sign;

    var1 = VAR32(0);
    op   = NUM(1);
    var2 = VAR32(2);
    sign = NUM(2);

    var1 = math_operations(var1, op, var2, sign);

    add_var(CMD.var[0], NULL, NULL, var1, sizeof(int));
    return(0);
}



int CMD_Log_func(int cmd) {
    int     fd,
            offset,
            size;
    u8      *name;

    name    = VAR(0);
    offset  = VAR32(1);
    size    = VAR32(2);
    fd      = FILEZ(5);

    if(dumpa(fd, name, offset, size, 0) < 0) return(-1);
    return(0);
}



int CMD_Next_func(int cmd) {
    int     var;

    if(CMD.var[0] < 0) return(0);   // like } in the C for(;;)
    var = VAR32(0);
    add_var(CMD.var[0], NULL, NULL, var + 1, sizeof(int));
    return(0);
}



int CMD_GetDString_func(int cmd) {
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    int     fd,
            size,
            verbose_offset = 0;

    fd   = FILEZ(2);
    size = VAR32(1);

    if(verbose < 0) verbose_offset = myftell(fd);

    if(size == -1) ALLOC_ERR;
    myalloc(&buff, size + 1, &buffsz);
    myfr(fd, buff, size);
    buff[size] = 0;
    if(verbose < 0) printf(". %08x getdstr %-10s \"%.*s\" %d\n", (i32)verbose_offset, get_varname(CMD.var[0]), (i32)size, buff, (i32)size);
    add_var(CMD.var[0], NULL, buff, 0, size);
    return(0);
}



u_int swap16(u_int n) {
    n = (((n & 0xff00) >> 8) |
         ((n & 0x00ff) << 8));
    return(n);
}



u_int swap32(u_int n) {
    n = (((n & 0xff000000) >> 24) |
         ((n & 0x00ff0000) >>  8) |
         ((n & 0x0000ff00) <<  8) |
         ((n & 0x000000ff) << 24));
    return(n);
}



u_int swap64(u_int n) {
#ifdef QUICKBMS64
    n = (((n & (u_int)0xFF00000000000000ULL) >> (u_int)56) |
         ((n & (u_int)0x00FF000000000000ULL) >> (u_int)40) |
         ((n & (u_int)0x0000FF0000000000ULL) >> (u_int)24) |
         ((n & (u_int)0x000000FF00000000ULL) >> (u_int) 8) |
         ((n & (u_int)0x00000000FF000000ULL) << (u_int) 8) |
         ((n & (u_int)0x0000000000FF0000ULL) << (u_int)24) |
         ((n & (u_int)0x000000000000FF00ULL) << (u_int)40) |
         ((n & (u_int)0x00000000000000FFULL) << (u_int)56));
#else
    n = swap32(n);
#endif
    return(n);
}



u_int myhtons(u_int n) {
    int endian = 1;
    if(!*(char *)&endian) return(n);
    return(swap16(n));
}
u_int myntohs(u_int n) {
    int endian = 1;
    if(!*(char *)&endian) return(n);
    return(swap16(n));
}
u_int myhtonl(u_int n) {
    int endian = 1;
    if(!*(char *)&endian) return(n);
    return(swap32(n));
}
u_int myntohl(u_int n) {
    int endian = 1;
    if(!*(char *)&endian) return(n);
    return(swap32(n));
}



int CMD_ReverseShort_func(int cmd) {
    int     n;

    n = VAR32(0);
    n = swap16(n);
    add_var(CMD.var[0], NULL, NULL, n, sizeof(int));
    return(0);
}



int CMD_ReverseLong_func(int cmd) {
    int     n;

    n = VAR32(0);
    n = swap32(n);
    add_var(CMD.var[0], NULL, NULL, n, sizeof(int));
    return(0);
}



int CMD_ReverseLongLong_func(int cmd) {
    int     n;

    n = VAR32(0);
    n = swap64(n);
    add_var(CMD.var[0], NULL, NULL, n, sizeof(int));
    return(0);
}



int CMD_Set_func(int cmd) {
    static int  tmpsz   = 0;
    static u8   *tmp    = NULL;
    int     i,
            c,
            varn        = 0,
            varsz       = -1;
    u8      *var        = NULL,
            *p;

    if(NUM(1) == TYPE_UNICODE) {    // this is a particular exception for unicode which is enough boring to handle in some cases
        p = VAR(2);
        for(i = 0;; i++) {
            if(endian == MYLITTLE_ENDIAN) {
                c = p[0];
            } else {
                c = p[1];
            }
            if(!c) break;
            if(i >= tmpsz) {
                tmpsz += STRINGSZ;
                tmp = realloc(tmp, tmpsz + 1);
                if(!tmp) STD_ERR;
            }
            tmp[i] = c;
            p += 2;
        }
        if(!tmp) tmp = malloc(1);   // useful
        tmp[i] = 0;
        var   = tmp;
        varsz = -1;
    } else if(NUM(1) == TYPE_BINARY) {
        var   = STR(2);
        varsz = NUM(2);
    } else if(NUM(1) == TYPE_ALLOC) {
        varsz = VAR32(2);
        var   = malloc(varsz + 1);
        if(!var) STD_ERR;
    } else if(NUM(1) == TYPE_FILENAME) {
        var   = VAR(2); // this is var2!!!
        p = mystrrchrs(var, "\\/");
        if(p) {
            p++;
        } else {
            p = var;
        }
        var = re_strdup(NULL, p, NULL);
    } else if(NUM(1) == TYPE_BASENAME) {
        var   = VAR(2); // this is var2!!!
        p = mystrrchrs(var, "\\/");
        if(p) {
            p++;
        } else {
            p = var;
        }
        var = re_strdup(NULL, p, NULL);
        p = strrchr(var, '.');
        if(p) *p = 0;
    } else if(NUM(1) == TYPE_EXTENSION) {
        var   = VAR(2); // this is var2!!!
        p = strrchr(var, '.');
        if(p) {
            p++;
        } else {
            p = var + strlen(var);
        }
        var = re_strdup(NULL, p, NULL);
    } else if(ISNUMTYPE(NUM(1))) { // number type
        varn  = VAR32(2);
        varsz = VARSZ(2);
    } else {
        var   = VAR(2);
        varsz = VARSZ(2);
    }

    if(CMD.var[0] < 0) {    // MEMORY_FILE
        dumpa_memory_file(&memory_file[-CMD.var[0]], &var, varsz, NULL);
    } else {
        if(var) {
            add_var(CMD.var[0], NULL, var, 0, varsz);
        } else {
            add_var(CMD.var[0], NULL, NULL, varn, sizeof(int));
        }
    }
    return(0);
}



u8 *strristr(u8 *s1, u8 *s2) {
    int     s1n,
            s2n;
    u8      *p;

    if(!s1 || !s2) return(NULL);
    s1n = strlen(s1);
    s2n = strlen(s2);
    if(s2n > s1n) return(NULL);
    for(p = s1 + (s1n - s2n); p >= s1; p--) {
        if(!strnicmp(p, s2, s2n)) return(p);
    }
    return(NULL);
}



int vspr(u8 **buff, u8 *fmt, va_list ap) {
    int     len,
            mlen;
    u8      *ret    = NULL;

    if(!fmt) return(0);
    mlen = strlen(fmt) + 128;
    for(;;) {
        ret = realloc(ret, mlen + 1);
        if(!ret) return(0);     // return(-1);
        len = vsnprintf(ret, mlen, fmt, ap);
        if((len >= 0) && (len < mlen)) break;
        mlen += 128;
    }
    *buff = ret;
    return(len);
}



int spr(u8 **buff, u8 *fmt, ...) {
    va_list ap;
    int     len;

    va_start(ap, fmt);
    len = vspr(buff, fmt, ap);
    va_end(ap);
    return(len);
}



int quick_check_printf_write(u8 *str) {
    u8      *s;

    // _set_printf_count_output exists only of msvcr80/90
    if(!str) return(0);
    for(s = str; *s; s++) {
        if(*s != '%') continue;
        for(++s; *s; s++) { // don't use tolower or it could get confused with I32/I64
            if(strchr("cCdiouxXeEfgGaAnpsS%", *s)) break;
        }
        if(*s == 'n') return(1);
    }
    return(0);
}



u_char *find_replace_string(u_char *buf, int *buflen, u_char *old, int oldlen, u_char *new, int newlen) {
    int     i,
            len,
            tlen,
            found;
    u_char  *nbuf,
            *p;

    if(!buf) return(buf);
    found  = 0;
    len = -1;
    if(buflen) len = *buflen;
    if(len < 0) len = strlen(buf);
    if(oldlen < 0) {
        oldlen = 0;
        if(old) oldlen = strlen(old);
    }
    tlen   = len - oldlen;

    for(i = 0; i <= tlen; i++) {
        if(!strnicmp(buf + i, old, oldlen)) found++;
    }
    if(!found) return(buf); // nothing to change: return buf or a positive value

    //if(!new) return(NULL);  // if we want to know only if the searched string has been found, we will get NULL if YES and buf if NOT!!!
    if(newlen < 0) {
        newlen = 0;
        if(new) newlen = strlen(new);
    }

    if(newlen <= oldlen) {  // if the length of new string is equal/minor than the old one don't waste space for another buffer
        nbuf = buf;
    } else {                // allocate the new size
        nbuf = malloc(len + ((newlen - oldlen) * found));
    }

    p = nbuf;
    for(i = 0; i <= tlen;) {
        if(!strnicmp(buf + i, old, oldlen)) {
            memcpy(p, new, newlen);
            p += newlen;
            i += oldlen;
        } else {
            *p++ = buf[i];
            i++;
        }
    }
    while(i < len) {
        *p++ = buf[i];
        i++;
    }
    len = p - nbuf;
    if(buflen) *buflen = len;
    return(nbuf);
}



int CMD_String_func(int cmd) {
    static u8   *var1   = NULL;
    int     i,
            op,
            len1,
            len2,
            num         = 0,
            fixed_len   = -1;
    u8      *var2,
            *p,
            *l;

    len1 = VARSZ(0);    // string/binary alternative to re_strdup
    var1 = realloc(var1, len1 + 1);
    if(!var1) STD_ERR;
    memcpy(var1, VAR(0), len1);
    var1[len1] = 0;
    //var1 = re_strdup(var1, VAR(0), NULL);   // needed for editing
    op   = NUM(1);
    var2 = VAR(2);

    len1 = strlen(var1);
    len2 = strlen(var2);
    if(myisdechex_string(var2)) num = myatoi(var2);
    if(len2) {
        switch(op) {
            case '=': {
                if(num) {
                    for(i = INTSZ - 8; i >= 0; i -= 8) {
                        if(num & ((u_int)0xff << i)) break;
                    }
                    len2 = (i + 8) / 8;
                    var2 = (u8 *)&num;
                }
                var1 = realloc(var1, len2 + 1);
                if(!var1) STD_ERR;
                strncpy(var1, var2, len2);
                var1[len2] = 0;
                break;
            }
            case '+': {
                var1 = realloc(var1, len1 + len2 + 1);
                if(!var1) STD_ERR;
                strcpy(var1 + len1, var2);
                break;
            }
            case '-': { // I know that this is not the same method used in BMS but you can't "substract" a string from the end of another... it means nothing!
                if(num > 0) {
                    if(num <= len1) var1[len1 - num] = 0;
                } else if(num < 0) {
                    num = -num;
                    if(num <= len1) var1[num] = 0;
                } else {
                    while((p = (u8 *)stristr(var1, var2))) {
                        memmove(p, p + len2, strlen(p + len2) + 1);
                    }
                }
                break;
            }
            case '^': {
                if(len2 > 0) {  // avoid possible division by zero
                    for(i = 0; i < len1; i++) {
                        var1[i] ^= var2[i % len2];
                    }
                }
                break;
            }
            case '<': { // var1="thisisastring" var2="4" = "isastring"
                if(num > 0) {
                    if(num <= len1) {
                        p = var1 + num;
                        memmove(var1, p, strlen(p) + 1);
                    }
                } else {
                    for(p = var1;; p = l + 1) {
                        l = (u8 *)stristr(p, var2);
                        if(!l) break;
                        if(!*l) break;
                    }
                    if(p != var1) p[0] = 0;
                    //printf("\nError: no string variable2 supported in String for operator %c\n", (i32)op);
                    //myexit(-1);
                }
                break;
            }
            //case '/': 
            //case '*': 
            case '%': {
                if(num > 0) {
                    var1[len1 % num] = 0;
                } else {
                    printf("\nError: no string variable2 supported in String for operator %c\n", (i32)op);
                    myexit(-1);
                }
                break;
            }
            case '&': { // var1="thisisastring" var2="isa" = "isastring"
                //if(num > 0) {
                    //var1[len1 & num] = 0; // use % for this job, & means nothing
                //} else {
                    p = (u8 *)stristr(var1, var2);
                    if(p) memmove(var1, p, strlen(p) + 1);
                //}
                break;
            }
            case '|': { // var1="thisisastring" var2="isa" = "string"
                p = (u8 *)stristr(var1, var2);
                if(p) memmove(var1, p + len2, strlen(p + len2) + 1);
                break;
            }
            case '>': { // var1="thisisastring" var2="isa" = "this" (from end)
                if(num > 0) {
                    if(num <= len1) {
                        var1[len1 - num] = 0;
                    }
                } else {
                    p = (u8 *)strristr(var1, var2);
                    if(p) *p = 0;
                }
                break;
            }
            case 'r': {
                len1 = len2;
                var1 = realloc(var1, len1 + 1);
                if(!var1) STD_ERR;
                for(i = 0; i < len1; i++) {
                    var1[i] = var2[(len1 - i) - 1];
                }
                var1[i] = 0;
                break;
            }
            case 'b':
                len2 = VARSZ(2);    // binary stuff
            case 'B': {
                len1 = (len2 * 2) + 1;  // checked by byte2hex
                var1 = realloc(var1, len1 + 1);
                if(!var1) STD_ERR;
                len1 = byte2hex(var2, len2, var1, len1);
                var1[len1] = 0; // already done by byte2hex
                break;
            }
            case 'h': {
                len1 = len2;
                if(len1) len1 /= 2;
                var1 = realloc(var1, len1 + 1);
                if(!var1) STD_ERR;
                fixed_len = unhex(var2, len2, var1, len1);
                var1[fixed_len] = 0;
                break;
            }
            case 'e':
                len1 = VARSZ(0);    // binary stuff
                len2 = VARSZ(2);    // binary stuff
            case 'E': {
                if(len1 < len2) {
                    len1 = len2;
                    var1 = realloc(var1, len1 + 1);
                    if(!var1) STD_ERR;
                    var1[len1] = 0;
                }
                memcpy(var1, var2, len1);
                fixed_len = perform_encryption(var1, len1);
                if(fixed_len < 0) fixed_len = len1;
                var1[fixed_len] = 0;
                break;
            }
            case 'c':
                len1 = VARSZ(0);    // binary stuff
                len2 = VARSZ(2);    // binary stuff
            case 'C': {
                if(len1 < len2) {   // at least equal in length
                    len1 = len2;
                    var1 = realloc(var1, len1 + 1);
                    if(!var1) STD_ERR;
                    var1[len1] = 0;
                }
                fixed_len = perform_compression(var2, len2, &var1, len1, &len1);
                if(fixed_len < 0) fixed_len = len1;
                var1[fixed_len] = 0;
                break;
            }
            case 'u': {
                if(len1 < len2) {
                    len1 = len2;
                    var1 = realloc(var1, len1 + 1);
                    if(!var1) STD_ERR;
                }
                for(i = 0; i < len2; i++) {
                    var1[i] = toupper(var2[i]);
                }
                var1[i] = 0;
                break;
            }
            case 'l': {
                if(len1 < len2) {
                    len1 = len2;
                    var1 = realloc(var1, len1 + 1);
                    if(!var1) STD_ERR;
                }
                for(i = 0; i < len2; i++) {
                    var1[i] = tolower(var2[i]);
                }
                var1[i] = 0;
                break;
            }
            case 'p': { // *printf-like
                len1 = 0;
                FREEX(var1,)    // oh yeah this sux, that's why I classify it as experimental work-around
                if(quick_check_printf_write(var2)) var2 = "";
                switch(NUM(0)) {
                    case 1: {
                        len1 = spr(&var1, var2,
                            myisdigitstr(VAR(3)) ? (void *)VAR32(3) : VAR(3));
                        break;
                    }
                    case 2: {
                        len1 = spr(&var1, var2,
                            myisdigitstr(VAR(3)) ? (void *)VAR32(3) : VAR(3),
                            myisdigitstr(VAR(4)) ? (void *)VAR32(4) : VAR(4));
                        break;
                    }
                    case 3: {
                        len1 = spr(&var1, var2,
                            myisdigitstr(VAR(3)) ? (void *)VAR32(3) : VAR(3),
                            myisdigitstr(VAR(4)) ? (void *)VAR32(4) : VAR(4),
                            myisdigitstr(VAR(5)) ? (void *)VAR32(5) : VAR(5));
                        break;
                    }
                    case 4: {
                        len1 = spr(&var1, var2,
                            myisdigitstr(VAR(3)) ? (void *)VAR32(3) : VAR(3),
                            myisdigitstr(VAR(4)) ? (void *)VAR32(4) : VAR(4),
                            myisdigitstr(VAR(5)) ? (void *)VAR32(5) : VAR(5),
                            myisdigitstr(VAR(6)) ? (void *)VAR32(6) : VAR(6));
                        break;
                    }
                    case 5: {
                        len1 = spr(&var1, var2,
                            myisdigitstr(VAR(3)) ? (void *)VAR32(3) : VAR(3),
                            myisdigitstr(VAR(4)) ? (void *)VAR32(4) : VAR(4),
                            myisdigitstr(VAR(5)) ? (void *)VAR32(5) : VAR(5),
                            myisdigitstr(VAR(6)) ? (void *)VAR32(6) : VAR(6),
                            myisdigitstr(VAR(7)) ? (void *)VAR32(7) : VAR(7));
                        break;
                    }
                    default: {
                        len1 = spr(&var1, "%s", var2);
                        break;
                    }
                }
                break;
            }
            case 'R': {
                p = find_replace_string(var1, &len1, var2, -1, VAR(3), -1);
                if(p != var1) FREEX(var1,)
                var1 = p;
                break;
            }
            default: {
                printf("\nError: invalid operator %c\n", (i32)op);
                myexit(-1);
                break;
            }
        }
        add_var(CMD.var[0], NULL, var1, 0, fixed_len);
    }
    return(0);
}



int CMD_ImpType_func(int cmd) {
    if(verbose > 0) printf("- ImpType command %d ignored (not supported)\n", (i32)cmd);
    return(0);
}



int CMD_Open_func(int cmd) {
    static u8   current_dir[PATHSZ + 1]; // used only here so don't waste the stack
    static u8   *fname  = NULL;
    filenumber_t    *filez;
    int     fdnum;
    u8      *fdir,
            *p;

    fdir    = VAR(0);
    fname   = re_strdup(fname, VAR(1), NULL);   // needed for modifying it
    fdnum   = NUM(2);

    getcwd(current_dir, PATHSZ);

    filez = &filenumber[0];     // everything is ever referred to the main file

    if(fname[0] == '?') {
        fname = realloc(fname, PATHSZ + 1);
        if(!fname) STD_ERR;
#ifdef WIN32
        if(GetWindowLong(mywnd, GWL_WNDPROC)) {
            p = get_file("you must choose the name of the other file to load", 0, 0);
            strcpy(fname, p);
            free(p);
        } else
#endif
        fgetz(fname, PATHSZ, stdin,
            "\n- you must choose the name of the other file to load:\n  ");
    }

    if(!stricmp(fdir, "FDDE")) {    // fname is the new extension
        fdir = file_folder;
        p = strrchr(filez->fullname, '.');
        if(p) {
            p++;
        } else {
            p = filez->fullname + strlen(filez->fullname);
        }
        fname = realloc(fname, (p - filez->fullname) + strlen(fname) + 1);
        if(!fname) STD_ERR;
        memmove(fname + (p - filez->fullname), fname, strlen(fname) + 1);
        memcpy(fname, filez->fullname, p - filez->fullname);
    } else if(!stricmp(fdir, "FDSE")) { // I don't know if this is correct because it's not documented!
        fdir = file_folder;
        p = mystrrchrs(filez->fullname, "\\/");
        if(p) {
            p++;
        } else {
            p = filez->fullname;
        }
        fname = realloc(fname, (p - filez->fullname) + strlen(fname) + 1);
        if(!fname) STD_ERR;
        memmove(fname + (p - filez->fullname), fname, strlen(fname) + 1);
        memcpy(fname, filez->fullname, p - filez->fullname);
    } else {
        // nothing to do
    }

    if(fdir && fdir[0]) {
        if(strchr(fdir, ':') || (fdir[0] == '\\') || (fdir[0] == '/') || strstr(fdir, "..")) {
            //strcpy(fdir, ".");
        } else {
            printf("- enter in folder %s\n", fdir);
            if(chdir(fdir) < 0) STD_ERR;
        }
    }

    if(CMD.var[3]) {    // check mode
        if(myfopen(fname, fdnum, 0) < 0) {
            add_var(CMD.var[3], NULL, NULL, 0, sizeof(int));    // doesn't exist
        } else {
            add_var(CMD.var[3], NULL, NULL, 1, sizeof(int));    // exists
        }
    } else {
        myfopen(fname, fdnum, 1);
    }

    chdir(current_dir); // return to the output folder
    return(0);
}



int CMD_GetCT_func(int cmd) {
    int     fd,
            verbose_offset = 0;
    u8      *tmp;

    fd = FILEZ(3);

    if(verbose < 0) verbose_offset = myftell(fd);

    //if(NUM(1) < 0) {
        // ok
    //} else {
        //printf("\nError: GetCT is supported only with String type\n");
        //myexit(-1);
    //}
    tmp = fgetss(fd, VAR32(2), (NUM(1) == TYPE_UNICODE) ? 1 : 0, 0);
    if(!tmp) return(-1);    // compability with old quickbms
    if(verbose < 0) printf(". %08x getct   %-10s \"%s\"\n", (i32)verbose_offset, get_varname(CMD.var[0]), tmp);
    add_var(CMD.var[0], NULL, tmp, 0, -1); // fgetss is handled as a string function at the moment
    return(0);
}



int CMD_ComType_func(int cmd) {
    u8      tmp_str[32],
            *str;

    str = STR(0);
    comtype_dictionary     = STR(1);
    comtype_dictionary_len = NUM(1);
    if(comtype_dictionary_len <= 0) comtype_dictionary = NULL;
    comtype_scan           = 0;

    quick_var_from_name_check(&comtype_dictionary, &comtype_dictionary_len);

    if(!stricmp(str, "?")) {
        fgetz(tmp_str, sizeof(tmp_str), stdin,
            "\n- you must specify the compression algorithm to use:\n  ");
        str = tmp_str;
    }

    if(!strnicmp(str, "COMP_", 5)) str += 5;

    if(!stricmp(str, "zlib") || !stricmp(str, "zlib1")) {
        compression_type = COMP_ZLIB;
    } else if(!stricmp(str, "deflate") || !stricmp(str, "inflate")) {
        compression_type = COMP_DEFLATE;
    } else if(!stricmp(str, "lzo1")) {
        compression_type = COMP_LZO1;
    } else if(!stricmp(str, "lzo1a")) {
        compression_type = COMP_LZO1A;
    } else if(!stricmp(str, "lzo1b")) {
        compression_type = COMP_LZO1B;
    } else if(!stricmp(str, "lzo1c")) {
        compression_type = COMP_LZO1C;
    } else if(!stricmp(str, "lzo1f")) {
        compression_type = COMP_LZO1F;
    } else if(!stricmp(str, "lzo1x") || !stricmp(str, "lzo") || !stricmp(str, "minilzo")) {
        compression_type = COMP_LZO1X;
    } else if(!stricmp(str, "lzo1y")) {
        compression_type = COMP_LZO1Y;
    } else if(!stricmp(str, "lzo1z")) {
        compression_type = COMP_LZO1Z;
    } else if(!stricmp(str, "lzo2a")) {
        compression_type = COMP_LZO2A;
    } else if(!stricmp(str, "lzss")) {
        compression_type = COMP_LZSS;
    } else if(!stricmp(str, "lzx")) {
        compression_type = COMP_LZX;
    } else if(!stricmp(str, "gzip")) {
        compression_type = COMP_GZIP;
    } else if(!stricmp(str, "pkware") || !stricmp(str, "blast") || !stricmp(str, "explode") || !stricmp(str, "implode")) {
        compression_type = COMP_EXPLODE;
    } else if(!stricmp(str, "lzma")) {          // 5 bytes + lzma
        compression_type = COMP_LZMA;
    } else if(!stricmp(str, "lzma86head")) {    // 5 bytes + 8 bytes (size) + lzma
        compression_type = COMP_LZMA_86HEAD;
    } else if(!stricmp(str, "lzma86dec")) {     // 1 byte + 5 bytes + lzma
        compression_type = COMP_LZMA_86DEC;
    } else if(!stricmp(str, "lzma86dechead")) { // 1 byte + 5 bytes + 8 bytes (size) + lzma
        compression_type = COMP_LZMA_86DECHEAD;
    } else if(!stricmp(str, "lzmaefs")) {       // 2 + 2 + x + lzma
        compression_type = COMP_LZMA_EFS;
    } else if(!stricmp(str, "bzip2")) {
        compression_type = COMP_BZIP2;
    } else if(!stricmp(str, "XMemDecompress") || !stricmp(str, "XMEMCODEC_DEFAULT") || !stricmp(str, "XMEMCODEC_LZX") || !stricmp(str, "xcompress")) {
        compression_type = COMP_XMEMLZX;
    } else if(!stricmp(str, "hex") || !stricmp(str, "hex2byte")) {
        compression_type = COMP_HEX;
    } else if(!stricmp(str, "base64")) {
        compression_type = COMP_BASE64;
    } else if(!stricmp(str, "uuencode") || !stricmp(str, "uudecode")) {
        compression_type = COMP_UUENCODE;
    } else if(!stricmp(str, "xxencode") || !stricmp(str, "xxdecode")) {
        compression_type = COMP_XXENCODE;
    } else if(!stricmp(str, "ascii85")) {
        compression_type = COMP_ASCII85;
    } else if(!stricmp(str, "yenc")) {
        compression_type = COMP_YENC;
    } else if(!stricmp(str, "COM_LZW_Decompress")) {
        compression_type = COMP_UNLZW;
    } else if(!stricmp(str, "milestone_lzw")) {
        compression_type = COMP_UNLZWX;
    //} else if(!stricmp(str, "cab") || !stricmp(str, "mscab") || !stricmp(str, "mscf")) {
        //compression_type = COMP_CAB;
    //} else if(!stricmp(str, "chm") || !stricmp(str, "mschm") || !stricmp(str, "itsf")) {
        //compression_type = COMP_CHM;
    //} else if(!stricmp(str, "szdd")) {
        //compression_type = COMP_SZDD;
    } else if(!stricmp(str, "lzxcab") || !stricmp(str, "mslzx")) {
        compression_type = COMP_LZXCAB;
    } else if(!stricmp(str, "lzxchm")) {
        compression_type = COMP_LZXCHM;
    } else if(!stricmp(str, "rlew")) {
        compression_type = COMP_RLEW;
    } else if(!stricmp(str, "lzjb")) {
        compression_type = COMP_LZJB;
    } else if(!stricmp(str, "sfl_block")) {
        compression_type = COMP_SFL_BLOCK;
    } else if(!stricmp(str, "sfl_rle")) {
        compression_type = COMP_SFL_RLE;
    } else if(!stricmp(str, "sfl_nulls")) {
        compression_type = COMP_SFL_NULLS;
    } else if(!stricmp(str, "sfl_bits")) {
        compression_type = COMP_SFL_BITS;
    } else if(!stricmp(str, "lzma2")) {          // 1 bytes + lzma2
        compression_type = COMP_LZMA2;
    } else if(!stricmp(str, "lzma2_86head")) {    // 1 bytes + 8 bytes (size) + lzma2
        compression_type = COMP_LZMA2_86HEAD;
    } else if(!stricmp(str, "lzma2_86dec")) {     // 1 byte + 1 bytes + lzma2
        compression_type = COMP_LZMA2_86DEC;
    } else if(!stricmp(str, "lzma2_86dechead")) { // 1 byte + 1 bytes + 8 bytes (size) + lzma2
        compression_type = COMP_LZMA2_86DECHEAD;
    } else if(!stricmp(str, "NRV2b")) {
        compression_type = COMP_NRV2b;
    } else if(!stricmp(str, "NRV2d")) {
        compression_type = COMP_NRV2d;
    } else if(!stricmp(str, "NRV2e")) {
        compression_type = COMP_NRV2e;
    } else if(!stricmp(str, "huffboh")) {
        compression_type = COMP_HUFFBOH;
    } else if(!stricmp(str, "uncompress") || !stricmp(str, "compress") || !stricmp(str, "lzw")) {
        compression_type = COMP_UNCOMPRESS;
    } else if(!stricmp(str, "dmc")) {
        compression_type = COMP_DMC;
    } else if(!stricmp(str, "lzh") || !stricmp(str, "lzhuf") || !stricmp(str, "lha")) {
        compression_type = COMP_LZH;
    } else if(!stricmp(str, "lzari")) {
        compression_type = COMP_LZARI;
    } else if(!stricmp(str, "tony")) {
        compression_type = COMP_TONY;
    } else if(!stricmp(str, "rle7")) {
        compression_type = COMP_RLE7;
    } else if(!stricmp(str, "rle0")) {
        compression_type = COMP_RLE0;
    } else if(!stricmp(str, "rle")) {
        compression_type = COMP_RLE;
    } else if(!stricmp(str, "rlea")) {
        compression_type = COMP_RLEA;
    } else if(!stricmp(str, "bpe")) {
        compression_type = COMP_BPE;
    } else if(!stricmp(str, "quicklz")) {
        compression_type = COMP_QUICKLZ;
    } else if(!stricmp(str, "q3huff")) {
        compression_type = COMP_Q3HUFF;
    } else if(!stricmp(str, "unmeng")) {
        compression_type = COMP_UNMENG;
    } else if(!stricmp(str, "lz2k")) {
        compression_type = COMP_LZ2K;
    } else if(!stricmp(str, "darksector")) {
        compression_type = COMP_DARKSECTOR;
    } else if(!stricmp(str, "mszh")) {
        compression_type = COMP_MSZH;
    } else if(!stricmp(str, "un49g")) {
        compression_type = COMP_UN49G;
    } else if(!stricmp(str, "unthandor")) {
        compression_type = COMP_UNTHANDOR;
    } else if(!stricmp(str, "doomhuff")) {
        compression_type = COMP_DOOMHUFF;
    } else if(!stricmp(str, "aplib")) {
        compression_type = COMP_APLIB;
    } else if(!stricmp(str, "tzar_lzss")) {
        compression_type = COMP_TZARLZSS;
    } else if(!stricmp(str, "lzf") || !stricmp(str, "fastlz")) { // "It is possible to use FastLZ as a drop-in replacement for Marc Lehmann's LibLZF."
        compression_type = COMP_LZF;
    } else if(!stricmp(str, "clz77")) {
        compression_type = COMP_CLZ77;
    } else if(!stricmp(str, "lzrw1")) {
        compression_type = COMP_LZRW1;
    } else if(!stricmp(str, "dhuff")) {
        compression_type = COMP_DHUFF;
    } else if(!stricmp(str, "fin")) {
        compression_type = COMP_FIN;
    } else if(!stricmp(str, "lzah")) {
        compression_type = COMP_LZAH;
    } else if(!stricmp(str, "lzh12")) { // -lh4-
        compression_type = COMP_LZH12;
    } else if(!stricmp(str, "lzh13")) { // -lh5-
        compression_type = COMP_LZH13;
    } else if(!stricmp(str, "grzip")) {
        compression_type = COMP_GRZIP;
    } else if(!stricmp(str, "ckrle")) {
        compression_type = COMP_CKRLE;
    } else if(!stricmp(str, "quad")) {
        compression_type = COMP_QUAD;
    } else if(!stricmp(str, "balz")) {
        compression_type = COMP_BALZ;
    } else if(!stricmp(str, "inflate64") || !stricmp(str, "deflate64")) {
        compression_type = COMP_DEFLATE64;
    } else if(!stricmp(str, "shrink")) {
        compression_type = COMP_SHRINK;
    } else if(!stricmp(str, "ppmd") || !stricmp(str, "ppmd8") || !strnicmp(str, "ppmdi", 5)) {
        compression_type = COMP_PPMDI;
    //} else if(!stricmp(str, "ppmdraw")) {
        //compression_type = COMP_PPMDRAW;
    } else if(!stricmp(str, "z-base-32")) {
        compression_type = COMP_MULTIBASE;
        comtype_dictionary_len = 32 | (1 << 8);
    } else if(!stricmp(str, "base32hex")) {
        compression_type = COMP_MULTIBASE;
        comtype_dictionary_len = 32 | (2 << 8);
    } else if(!stricmp(str, "base32crockford")) {
        compression_type = COMP_MULTIBASE;
        comtype_dictionary_len = 32 | (3 << 8);
    } else if(!stricmp(str, "base32nintendo")) {
        compression_type = COMP_MULTIBASE;
        comtype_dictionary_len = 32 | (4 << 8);
    } else if(!strnicmp(str, "base", 4)) {  // can handle any base
        compression_type = COMP_MULTIBASE;
        comtype_dictionary_len = myatoi(str + 4);
        if(comtype_dictionary_len <= 0) comtype_dictionary_len = 64;
    } else if(!stricmp(str, "brieflz")) {
        compression_type = COMP_BRIEFLZ;
    } else if(!stricmp(str, "paq6")) {
        compression_type = COMP_PAQ6;
    } else if(!stricmp(str, "shcodec")) {
        compression_type = COMP_SHCODEC;
    } else if(!stricmp(str, "hstest_hs_unpack")) {
        compression_type = COMP_HSTEST1;
    } else if(!stricmp(str, "hstest_unpackc")) {
        compression_type = COMP_HSTEST2;
    } else if(!stricmp(str, "sixpack")) {
        compression_type = COMP_SIXPACK;
    } else if(!stricmp(str, "ashford")) {
        compression_type = COMP_ASHFORD;
    } else if(!stricmp(str, "jcalg")) {
        compression_type = COMP_JCALG;
    } else if(!stricmp(str, "jam")) {
        compression_type = COMP_JAM;
    } else if(!stricmp(str, "lzhlib")) {
        compression_type = COMP_LZHLIB;
    } else if(!stricmp(str, "srank")) {
        compression_type = COMP_SRANK;
    } else if(!stricmp(str, "zzip")) {
        compression_type = COMP_ZZIP;
    } else if(!stricmp(str, "scpack")) {
        compression_type = COMP_SCPACK;
    } else if(!stricmp(str, "rle3")) {
        compression_type = COMP_RLE3;
    } else if(!stricmp(str, "bpe2")) {
        compression_type = COMP_BPE2;
    } else if(!stricmp(str, "bcl_huf")) {
        compression_type = COMP_BCL_HUF;
    } else if(!stricmp(str, "bcl_lz")) {
        compression_type = COMP_BCL_LZ;
    } else if(!stricmp(str, "bcl_rice")) {
        compression_type = COMP_BCL_RICE;
    } else if(!stricmp(str, "bcl_rle")) {
        compression_type = COMP_BCL_RLE;
    } else if(!stricmp(str, "bcl_sf")) {
        compression_type = COMP_BCL_SF;
    } else if(!stricmp(str, "scz")) {
        compression_type = COMP_SCZ;
    } else if(!stricmp(str, "szip")) {
        compression_type = COMP_SZIP;
    } else if(!stricmp(str, "ppmdi_raw") || !stricmp(str, "ppmdi1_raw")) {
        compression_type = COMP_PPMDI_RAW;
    } else if(!stricmp(str, "ppmdg")) {
        compression_type = COMP_PPMDG;
    } else if(!stricmp(str, "ppmdg_raw")) {
        compression_type = COMP_PPMDG_RAW;
    } else if(!stricmp(str, "ppmdj")) {
        compression_type = COMP_PPMDJ;
    } else if(!stricmp(str, "ppmdj_raw")) {
        compression_type = COMP_PPMDJ_RAW;
    } else if(!stricmp(str, "sr3c")) {
        compression_type = COMP_SR3C;
    } else if(!stricmp(str, "huffman")) {
        compression_type = COMP_HUFFMANLIB;
    } else if(!stricmp(str, "sfastpacker")) {
        compression_type = COMP_SFASTPACKER;
    } else if(!stricmp(str, "sfastpacker2")) {
        compression_type = COMP_SFASTPACKER2;
    } else if(!stricmp(str, "dk2") || !stricmp(str, "ea")) {
        compression_type = COMP_DK2;
    } else if(!stricmp(str, "lz77wii")) {
        compression_type = COMP_LZ77WII;
    } else if(!stricmp(str, "lz77wii_raw") || !stricmp(str, "lz77wii_raw10")) {
        compression_type = COMP_LZ77WII_RAW10;
    } else if(!stricmp(str, "darkstone")) {
        compression_type = COMP_DARKSTONE;
    } else if(!stricmp(str, "SFL_BLOCK_CHUNKED")) {
        compression_type = COMP_SFL_BLOCK_CHUNKED;
    } else if(!stricmp(str, "yuke_bpe")) {
        compression_type = COMP_YUKE_BPE;
    } else if(!stricmp(str, "stalker_lza")) {
        compression_type = COMP_STALKER_LZA;
    } else if(!stricmp(str, "prs_8ing")) {
        compression_type = COMP_PRS_8ING;
    } else if(!stricmp(str, "PUYO_CNX")) {
        compression_type = COMP_PUYO_CNX;
    } else if(!stricmp(str, "PUYO_CXLZ")) {
        compression_type = COMP_PUYO_CXLZ;
    } else if(!stricmp(str, "PUYO_LZ00")) {
        compression_type = COMP_PUYO_LZ00;
    } else if(!stricmp(str, "PUYO_LZ01")) {
        compression_type = COMP_PUYO_LZ01;
    } else if(!stricmp(str, "PUYO_LZSS")) {
        compression_type = COMP_PUYO_LZSS;
    } else if(!stricmp(str, "PUYO_ONZ")) {
        compression_type = COMP_PUYO_ONZ;
    } else if(!stricmp(str, "PUYO_PRS")) {
        compression_type = COMP_PUYO_PRS;
    //} else if(!stricmp(str, "PUYO_PVZ")) {
        //compression_type = COMP_PUYO_PVZ;
    } else if(!stricmp(str, "falcom")) {
        compression_type = COMP_FALCOM;
    } else if(!stricmp(str, "cpk")) {
        compression_type = COMP_CPK;
    } else if(!stricmp(str, "bzip2_file")) {
        compression_type = COMP_BZIP2_FILE;
    } else if(!stricmp(str, "lz77wii_raw11")) {
        compression_type = COMP_LZ77WII_RAW11;
    } else if(!stricmp(str, "lz77wii_raw30")) {
        compression_type = COMP_LZ77WII_RAW30;
    } else if(!stricmp(str, "lz77wii_raw20")) {
        compression_type = COMP_LZ77WII_RAW20;
    } else if(!stricmp(str, "pglz")) {
        compression_type = COMP_PGLZ;
    } else if(!stricmp(str, "UnPackSLZ")) {
        compression_type = COMP_SLZ;
    } else if(!stricmp(str, "slz_01")) {
        compression_type = COMP_SLZ_01;
    } else if(!stricmp(str, "slz_02")) {
        compression_type = COMP_SLZ_02;
    } else if(!stricmp(str, "lzhl")) {
        compression_type = COMP_LZHL;
    } else if(!stricmp(str, "d3101")) {
        compression_type = COMP_D3101;
    } else if(!stricmp(str, "squeeze")) {
        compression_type = COMP_SQUEEZE;
    } else if(!stricmp(str, "lzrw3")) {
        compression_type = COMP_LZRW3;
    QUICK_COMP_ASSIGN(ahuff)
    QUICK_COMP_ASSIGN(arith)
    QUICK_COMP_ASSIGN(arith1)
    QUICK_COMP_ASSIGN(arith1e)
    QUICK_COMP_ASSIGN(arithn)
    QUICK_COMP_ASSIGN(compand)
    QUICK_COMP_ASSIGN(huff)
    QUICK_COMP_ASSIGN(lzss)
    QUICK_COMP_ASSIGN(lzw12)
    QUICK_COMP_ASSIGN(lzw15v)
    QUICK_COMP_ASSIGN(silence)
    } else if(!stricmp(str, "rdc")) {
        compression_type = COMP_RDC;
    } else if(!stricmp(str, "ilzr")) {
        compression_type = COMP_ILZR;
    } else if(!stricmp(str, "dmc2")) {
        compression_type = COMP_DMC2;
    QUICK_COMP_ASSIGN(diffcomp)
    } else if(!stricmp(str, "lzr")) {
        compression_type = COMP_LZR;
    } else if(!stricmp(str, "lzs") || !stricmp(str, "mppc")) {
        compression_type = COMP_LZS;
    } else if(!stricmp(str, "lzs_big") || !stricmp(str, "mppc_big")) {
        compression_type = COMP_LZS_BIG;
    } else if(!stricmp(str, "copy")) {
        compression_type = COMP_COPY;
    } else if(!stricmp(str, "mohlzss")) {
        compression_type = COMP_MOHLZSS;
    } else if(!stricmp(str, "mohrle")) {
        compression_type = COMP_MOHRLE;
    } else if(!stricmp(str, "yaz0") || !stricmp(str, "szs")) {
        compression_type = COMP_YAZ0;
    } else if(!stricmp(str, "byte2hex")) {
        compression_type = COMP_BYTE2HEX;
    } else if(!stricmp(str, "un434a")) {
        compression_type = COMP_UN434A;
    } else if(!stricmp(str, "pack")) {
        compression_type = COMP_GZPACK;
    } else if(stristr(str, "zip_dynamic") || !stricmp(str, "zlib_dynamic")) {
        compression_type = COMP_UNZIP_DYNAMIC;
    } else if(!stricmp(str, "ZLIB_NOERROR")) {
        compression_type = COMP_ZLIB_NOERROR;
    } else if(!stricmp(str, "DEFLATE_NOERROR")) {
        compression_type = COMP_DEFLATE_NOERROR;
    } else if(!stricmp(str, "ppmdh") || !stricmp(str, "ppmd7")) {
        compression_type = COMP_PPMDH;
    } else if(!stricmp(str, "ppmdh_raw")) {
        compression_type = COMP_PPMDH_RAW;
    } else if(!stricmp(str, "rnc")) {
        compression_type = COMP_RNC;
    } else if(!stricmp(str, "rnc_raw")) {
        compression_type = COMP_RNC_RAW;
    } else if(!stricmp(str, "PAK_explode") || !stricmp(str, "fitd")) {
        compression_type = COMP_FITD;
    QUICK_COMP_ASSIGN(KENS_Nemesis)
    QUICK_COMP_ASSIGN(KENS_Kosinski)
    QUICK_COMP_ASSIGN(KENS_Kosinski_moduled)
    QUICK_COMP_ASSIGN(KENS_Enigma)
    QUICK_COMP_ASSIGN(KENS_Saxman)
    QUICK_COMP_ASSIGN(DRAGONBALLZ)
    } else if(!stricmp(str, "Nitro") || !stricmp(str, "NitroSDK")) {
        compression_type = COMP_NITROSDK;
    /* compression algorithms like COMP_ZLIB_COMPRESS */
    QUICK_COMP_ASSIGN(ZLIB_COMPRESS)
    QUICK_COMP_ASSIGN(DEFLATE_COMPRESS)
    QUICK_COMP_ASSIGN(LZO1_COMPRESS)
    QUICK_COMP_ASSIGN(LZO1X_COMPRESS)
    QUICK_COMP_ASSIGN(LZO2A_COMPRESS)
    QUICK_COMP_ASSIGN(XMEMLZX_COMPRESS)
    QUICK_COMP_ASSIGN(BZIP2_COMPRESS)
    QUICK_COMP_ASSIGN(GZIP_COMPRESS)
    QUICK_COMP_ASSIGN(LZSS_COMPRESS)
    QUICK_COMP_ASSIGN(SFL_BLOCK_COMPRESS)
    QUICK_COMP_ASSIGN(SFL_RLE_COMPRESS)
    QUICK_COMP_ASSIGN(SFL_NULLS_COMPRESS)
    QUICK_COMP_ASSIGN(SFL_BITS_COMPRESS)
    QUICK_COMP_ASSIGN(LZF_COMPRESS)
    QUICK_COMP_ASSIGN(BRIEFLZ_COMPRESS)
    QUICK_COMP_ASSIGN(JCALG_COMPRESS)
    QUICK_COMP_ASSIGN(BCL_HUF_COMPRESS)
    QUICK_COMP_ASSIGN(BCL_LZ_COMPRESS)
    QUICK_COMP_ASSIGN(BCL_RICE_COMPRESS)
    QUICK_COMP_ASSIGN(BCL_RLE_COMPRESS)
    QUICK_COMP_ASSIGN(BCL_SF_COMPRESS)
    QUICK_COMP_ASSIGN(SZIP_COMPRESS)
    QUICK_COMP_ASSIGN(HUFFMANLIB_COMPRESS)
    QUICK_COMP_ASSIGN(LZMA_COMPRESS)
    QUICK_COMP_ASSIGN(LZMA_86HEAD_COMPRESS)
    QUICK_COMP_ASSIGN(LZMA_86DEC_COMPRESS)
    QUICK_COMP_ASSIGN(LZMA_86DECHEAD_COMPRESS)
    QUICK_COMP_ASSIGN(LZMA_EFS_COMPRESS)
    QUICK_COMP_ASSIGN(FALCOM_COMPRESS)
    } else {
        compression_type = get_var32(get_var_from_name(str, -1));   // cool for the future
        if((compression_type <= COMP_NONE) || (compression_type >= COMP_NOP)) {
            printf("\nError: invalid compression type %s (%d)\n", str, (i32)compression_type);
            myexit(-1);
        }
        comtype_scan = 1;   // avoids the quitting of QuickBMS in case of wrong algo
    }
    return(0);
}



u8 *numbers_to_bytes(u8 *str, int *ret_size) {
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    int     i,
            len,
            num,
            size;

    if(ret_size) *ret_size = 0;
    if(!str) return(NULL);
    for(i = 0; *str; i++) {
        if(*str == '\\') *str = '0';  // yeah so it can handle also \x11\x22\x33
        while(*str && !(myisdigit(*str) || (*str == '$'))) str++;  // this one handles also dots, commas and other bad chars
        num = readbase(str, 10, &len);
        if(len <= 0) break;
        if(i >= buffsz) {
            buffsz += STRINGSZ;
            buff = realloc(buff, buffsz + 1);
            if(!buff) STD_ERR;
        }
        buff[i] = num;
        str += len;
    }
    if(buff) buff[i] = 0; // useless, only for possible new usages in future, return ret as NULL
    size = i;
    if(ret_size) *ret_size = size;
    if(verbose > 0) {
        printf("- numbers_to_bytes of %d bytes\n ", (i32)size);
        for(i = 0; i < size; i++) printf(" 0x%02x", buff[i]);
        printf("\n");
    }
    return(buff);
}



int CMD_FileXOR_func(int cmd) {
    int     fd,
            pos_offset,
            curroff;
    u8      *tmp;

    if(CMD.var[0] >= 0) {
        NUMS2BYTES(VAR(0), CMD.num[1], CMD.str[0], CMD.num[0])
    }
    file_xor            = STR(0);
    file_xor_size       = NUM(1);
    if(!file_xor_size) {
        file_xor        = NULL;
        file_xor_pos    = NULL;
    } else {
        file_xor_pos    = &NUM(2);
        pos_offset      = VAR32(3);
        fd              = FILEZ(4); // not implemented
        if(pos_offset >= 0) {
            curroff = myftell(fd);
            if(curroff >= pos_offset) {
                (*file_xor_pos) = curroff - pos_offset;
            } else {
                (*file_xor_pos) = file_xor_size - ((pos_offset - curroff) % file_xor_size);
            }
        }
    }
    return(0);
}



int CMD_FileRot13_func(int cmd) {
    int     fd,
            pos_offset,
            curroff;
    u8      *tmp;

    if(CMD.var[0] >= 0) {
        NUMS2BYTES(VAR(0), CMD.num[1], CMD.str[0], CMD.num[0])
    }
    file_rot13          = STR(0);
    file_rot13_size     = NUM(1);
    if(!file_rot13_size) {
        file_rot13      = NULL;
        file_rot13_pos  = NULL;
    } else {
        file_rot13_pos  = &NUM(2);
        pos_offset      = VAR32(3);
        fd              = FILEZ(4); // not implemented
        if(pos_offset >= 0) {
            curroff = myftell(fd);
            if(curroff >= pos_offset) {
                (*file_rot13_pos) = curroff - pos_offset;
            } else {
                (*file_rot13_pos) = file_rot13_size - ((pos_offset - curroff) % file_rot13_size);
            }
        }
    }
    return(0);
}



int CMD_FileCrypt_func(int cmd) {
    int     fd,
            pos_offset,
            curroff;
    u8      *tmp;

    if(CMD.var[0] >= 0) {
        NUMS2BYTES(VAR(0), CMD.num[1], CMD.str[0], CMD.num[0])
    }
    file_crypt          = STR(0);
    file_crypt_size     = NUM(1);
    if(!file_crypt_size) {
        file_crypt      = NULL;
        file_crypt_pos  = NULL;
    } else {
        file_crypt_pos  = &NUM(2);
        pos_offset      = VAR32(3);
        fd              = FILEZ(4); // not implemented
        if(pos_offset >= 0) {
            curroff = myftell(fd);
            if(curroff >= pos_offset) {
                (*file_crypt_pos) = curroff - pos_offset;
            } else {
                (*file_crypt_pos) = file_crypt_size - ((pos_offset - curroff) % file_crypt_size);
            }
        }
    }
    return(0);
}


int CMD_Strlen_func(int cmd) {
    add_var(CMD.var[0], NULL, NULL, strlen(VAR(1)), sizeof(int));
    return(0);
}



int CMD_GetVarChr_func(int cmd) {
    int     varsz,
            offset,
            fdnum,
            numsz,
            num;
    u8      *var;

    if(CMD.var[1] < 0) {
        fdnum = -CMD.var[1];
        if((fdnum <= 0) || (fdnum > MAX_FILES)) {
            printf("\nError: invalid MEMORY_FILE number in GetVarChr\n");
            myexit(-1);
        }
        var   = memory_file[fdnum].data;
        varsz = memory_file[fdnum].size;
    } else {
        var   = VAR(1);
        varsz = VARSZ(1);
    }
    offset = VAR32(2);
    numsz  = NUM(3);
    if(numsz < 0) {  // so anything but TYPE_LONG, TYPE_SHORT, TYPE_BYTE, TYPE_THREEBYTE
        printf("\nError: GetVarChr supports only the numerical types\n");
        myexit(-1);
    }

    if((offset < 0) || ((offset + numsz) > varsz)) {
        printf("\nError: offset in GetVarChr (0x%08x) is bigger than the var (0x%08x)\n", (i32)offset, (i32)varsz);
        myexit(-1);
    }

    num = getxx(var + offset, numsz);
    if(verbose < 0) printf(". %08x getvarc %-10s 0x%08x %d\n", (i32)offset, get_varname(CMD.var[0]), (i32)num, (i32)numsz);
    add_var(CMD.var[0], NULL, NULL, num, sizeof(int));
    return(0);
}



int CMD_PutVarChr_func(int cmd) {
    int     varsz,
            offset,
            fdnum = 0,
            numsz,
            num;
    u8      *var;

    if(CMD.var[0] < 0) {
        fdnum = -CMD.var[0];
        if((fdnum <= 0) || (fdnum > MAX_FILES)) {
            printf("\nError: invalid MEMORY_FILE number in PutVarChr\n");
            myexit(-1);
        }
        var   = memory_file[fdnum].data;
        varsz = memory_file[fdnum].size;
    } else {
        var   = VAR(0);
        varsz = VARSZ(0);
    }
    offset = VAR32(1);
    num    = VAR32(2);
    numsz  = NUM(3);
    if(numsz < 0) {  // so anything but TYPE_LONG, TYPE_SHORT, TYPE_BYTE, TYPE_THREEBYTE
        printf("\nError: PutVarChr supports only the numerical types\n");
        myexit(-1);
    }

    if(offset < 0) {    // from the end, should work ONLY with memory_files
        offset = varsz + offset;    // like varsz - (-offset)
        if(offset < 0) {
            printf("\nError: offset in PutVarChr (0x%08x) is negative\n", (i32)offset);
            myexit(-1);
        }
    }
    if((offset + numsz) > varsz) {  // this mode is experimental!
        var = realloc(var, offset + numsz + 1);
        if(!var) STD_ERR;
        memset(var + varsz, 0, (offset + numsz + 1) - varsz); // not needed
        varsz = offset + numsz;
        if(CMD.var[0] < 0) {
            memory_file[fdnum].data    = var;
            memory_file[fdnum].size    = varsz;
            memory_file[fdnum].maxsize = varsz;
        } else {
            //add_var(CMD.var[0], NULL, var, 0, varsz);
            DIRECT_ADDVAR(0, var, varsz);   // saves memory and is faster
        }
        //printf("\nError: offset in PutVarChr (0x%08x) is bigger than the var (0x%08x)\n", (i32)offset, (i32)varsz);
        //myexit(-1);
    }

    if(verbose < 0) printf(". %08x putvarc %-10s 0x%08x %d\n", (i32)offset, get_varname(CMD.var[0]), (i32)num, (i32)numsz);
    putxx(var + offset, num, numsz);
    return(0);
}



int CMD_Debug_func(int cmd) {
    int     type;

    type = NUM(0);
    if(verbose) {   // both positive and negative
        verbose = 0;
    } else {
        verbose = 1;
        if(type) verbose = -1;
    }
    return(0);
}



int CMD_Padding_func(int cmd) {
    int     fd;
    u_int   tmp,
            size,
            offset;

    fd   = FILEZ(1);
    size = VAR32(0);

    offset = myftell(fd);
    tmp = offset % size;
    if(tmp) myfseek(fd, size - tmp, SEEK_CUR);
    return(0);
}



ICE_KEY *do_ice_key(u8 *key, int keysz, int icecrypt) {
    ICE_KEY *ik;
    int     i       = 0,
            k,
            level   = 0;
    u8      buf[1024];

    if(keysz == 8) {
        level = 0;
    } else if(!(keysz % 16)) {
        level = keysz / 16;
    } else {
        printf("\nError: your ICE key has an incorrect size\n");
        myexit(-1);
    }

    if(icecrypt) {
        memset(buf, 0, sizeof(buf));
        for(k = 0; k < keysz; k++) {
            u8      c = key[k] & 0x7f;
            int     idx = i / 8;
            int     bit = i & 7;

            if (bit == 0) {
                buf[idx] = (c << 1);
            } else if (bit == 1) {
                buf[idx] |= c;
            } else {
                buf[idx] |= (c >> (bit - 1));
                buf[idx + 1] = (c << (9 - bit));
            }
            i += 7;
        }
        key = buf;
    }
    ik = ice_key_create(level);
    if(!ik) return(NULL);
    ice_key_set(ik, key);
    return(ik);
}



void quick_var_from_name_check(u8 **ret_key, int *ret_keysz) {
    int     keysz = -1,
            tmp;
    u8      *key,
            *p;

    if(!ret_key || !*ret_key) return;
    if(ret_keysz) keysz = *ret_keysz;
    if(keysz >= 16) return;   // it's useless to make the check for keys over this size
    key = *ret_key;

    tmp = get_var_from_name(key, keysz);
    if(tmp >= 0) {  // variable
        p = get_var(tmp);
        if(p) {
            keysz = get_varsz(tmp);
            key   = p;
        }
    } else if(!strnicmp(key, MEMORY_FNAME, MEMORY_FNAMESZ)) {   // memory_file
        keysz = memory_file[-get_memory_file(key)].size;
        key   = memory_file[-get_memory_file(key)].data;
    }

    if(ret_keysz) *ret_keysz = keysz;
    *ret_key = key;
}



#ifndef DISABLE_MCRYPT
MCRYPT quick_mcrypt_check(u8 *type) {
    u8      tmp[64],
            *p,
            *mode,
            *algo;

    if(!type) type = "";
    mystrcpy(tmp, type, sizeof(tmp));

    // myisalnum gets also the '-' which is a perfect thing
    // NEVER use '-' as delimiter because "rijndael-*" use it

    algo = tmp;
    if(!strnicmp(tmp, "mcrypt", 6)) {
        for(algo = tmp + 6; *algo; algo++) {
            if(myisalnum(*algo)) break;
        }
    }
    p = strchr(algo, '_');
    if(!p) p = strchr(algo, ',');
    if(p) {
        *p = 0;
        mode = p + 1;
    } else {
        mode = MCRYPT_ECB;
    }
    return(mcrypt_module_open(algo, NULL, mode, NULL));
}
#endif



#ifndef DISABLE_TOMCRYPT
// nonce:001122334455667788 header:aabbccddeeff0011 ivec:FFff00112233AAbb tweak:0011223344
void tomcrypt_lame_ivec(TOMCRYPT *ctx, u8 *ivec, int ivecsz) {
    int     t,
            *y;
    u8      *p,
            *s,
            *l,
            **x,
            *limit;

    if(!ctx || !ivec || (ivecsz < 0)) return;
    limit = ivec + ivecsz;  // ivec is NULL delimited

    for(p = ivec; p < limit; p = l + 1) {
        while(*p && (*p <= ' ')) p++;
        l = strchr(p, ' ');
        if(!l) l = strchr(p, '\t');
        if(!l) l = limit;

        if((s = stristr(p, "nonce:")) || (s = stristr(p, "salt:")) ||
           (s = stristr(p, "adata:")) || (s = stristr(p, "skey:")) ||
           (s = stristr(p, "key2:"))  || (s = stristr(p, /*salt_*/"key:"))) {
            x = &ctx->nonce;
            y = &ctx->noncelen;
        } else if((s = stristr(p, "header:"))) {
            x = &ctx->header;
            y = &ctx->headerlen;
        } else if((s = stristr(p, "ivec:"))) {
            x = &ctx->ivec;
            y = &ctx->ivecsz;
        } else if((s = stristr(p, "tweak:"))) {
            x = &ctx->tweak;
            y = NULL;
        } else {
            break;
        }

        s = strchr(s, ':') + 1;
        *x = malloc((l - s) + 1);   // / 2, but it's ok (+1 is not needed)
        if(!*x) STD_ERR;
        if(y) *y = 0;

        t = unhex(s, l - s, *x, l - s);
        if(t < 0) {
            free(*x);
            *x = NULL;
        }
        if((t >= 0) && y) *y = t;
    }

    if(!ctx->ivec) {
        ctx->ivec = malloc(ivecsz);
        memcpy(ctx->ivec, ivec, ivecsz);
        ctx->ivecsz = ivecsz;
    }
}

// implemented not so good because it's intended only as a test
TOMCRYPT *tomcrypt_doit(TOMCRYPT *ctx, u8 *type, u8 *in, int insz, u8 *out, int outsz, i32 *ret) {
    static int      init = 0;
    symmetric_ECB   ecb;
    symmetric_CFB   cfb;
    symmetric_OFB   ofb;
    symmetric_CBC   cbc;
    symmetric_CTR   ctr;
    symmetric_LRW   lrw;
    symmetric_F8    f8;
    symmetric_xts   xts;
    long    tmp;
    i32     stat;
    int     keysz,
            ivecsz,
            noncelen,
            headerlen,
            use_tomcrypt    = 0;
    u8      tag[64] = "",
            desc[64],
            *p,
            *l,
            *key,
            *ivec,
            *nonce,
            *header,
            *tweak;

    static int blowfish_idx = -1;
    static int rc5_idx = -1;
    static int rc6_idx = -1;
    static int rc2_idx = -1;
    static int saferp_idx = -1;
    static int safer_k64_idx = -1;
    static int safer_k128_idx = -1;
    static int safer_sk64_idx = -1;
    static int safer_sk128_idx = -1;
    static int rijndael_idx = -1;
    static int aes_idx = -1;
    static int rijndael_enc_idx = -1;
    static int aes_enc_idx = -1;
    static int xtea_idx = -1;
    static int twofish_idx = -1;
    static int des_idx = -1;
    static int des3_idx = -1;
    static int cast5_idx = -1;
    static int noekeon_idx = -1;
    static int skipjack_idx = -1;
    static int khazad_idx = -1;
    static int anubis_idx = -1;
    static int kseed_idx = -1;
    static int kasumi_idx = -1;
    static int multi2_idx = -1;

    static int chc_idx = -1;
    static int whirlpool_idx = -1;
    static int sha512_idx = -1;
    static int sha384_idx = -1;
    static int sha256_idx = -1;
    static int sha224_idx = -1;
    static int sha1_idx = -1;
    static int md5_idx = -1;
    static int md4_idx = -1;
    static int md2_idx = -1;
    static int tiger_idx = -1;
    static int rmd128_idx = -1;
    static int rmd160_idx = -1;
    static int rmd256_idx = -1;
    static int rmd320_idx = -1;

    if(!init) {
        #define TOMCRYPT_REGISTER_CIPHER(X) \
            register_cipher(&X##_desc); \
            X##_idx = find_cipher(#X);
            //if(X##_idx < 0) goto quit;
        #define TOMCRYPT_REGISTER_HASH(X) \
            register_hash(&X##_desc); \
            X##_idx = find_hash(#X);
            //if(X##_idx < 0) goto quit;

        TOMCRYPT_REGISTER_CIPHER(blowfish)
        TOMCRYPT_REGISTER_CIPHER(rc5)
        TOMCRYPT_REGISTER_CIPHER(rc6)
        TOMCRYPT_REGISTER_CIPHER(rc2)
        //TOMCRYPT_REGISTER_CIPHER(saferp)
        //TOMCRYPT_REGISTER_CIPHER(safer_k64)
        //TOMCRYPT_REGISTER_CIPHER(safer_k128)
        //TOMCRYPT_REGISTER_CIPHER(safer_sk64)
        //TOMCRYPT_REGISTER_CIPHER(safer_sk128)
        register_cipher(&safer_k64_desc);   safer_k64_idx   = find_cipher("safer-k64");
        register_cipher(&safer_k128_desc);  safer_k128_idx  = find_cipher("safer-k128");
        register_cipher(&safer_sk64_desc);  safer_sk64_idx  = find_cipher("safer-sk64");
        register_cipher(&safer_sk128_desc); safer_sk128_idx = find_cipher("safer-sk128");
        TOMCRYPT_REGISTER_CIPHER(rijndael)
        //TOMCRYPT_REGISTER_CIPHER(aes)
        register_cipher(&aes_desc);     aes_idx = find_cipher("rijndael");
        //TOMCRYPT_REGISTER_CIPHER(rijndael_enc)
        //TOMCRYPT_REGISTER_CIPHER(aes_enc)
        TOMCRYPT_REGISTER_CIPHER(xtea)
        TOMCRYPT_REGISTER_CIPHER(twofish)
        TOMCRYPT_REGISTER_CIPHER(des)
        //TOMCRYPT_REGISTER_CIPHER(des3)
        register_cipher(&des3_desc);     des3_idx = find_cipher("3des");
        TOMCRYPT_REGISTER_CIPHER(cast5)
        TOMCRYPT_REGISTER_CIPHER(noekeon)
        TOMCRYPT_REGISTER_CIPHER(skipjack)
        TOMCRYPT_REGISTER_CIPHER(khazad)
        TOMCRYPT_REGISTER_CIPHER(anubis)
        //TOMCRYPT_REGISTER_CIPHER(kseed)
        register_cipher(&kseed_desc);   kseed_idx = find_cipher("seed");
        TOMCRYPT_REGISTER_CIPHER(kasumi)
        TOMCRYPT_REGISTER_CIPHER(multi2)

        TOMCRYPT_REGISTER_HASH(chc)
        TOMCRYPT_REGISTER_HASH(whirlpool)
        TOMCRYPT_REGISTER_HASH(sha512)
        TOMCRYPT_REGISTER_HASH(sha384)
        TOMCRYPT_REGISTER_HASH(sha256)
        TOMCRYPT_REGISTER_HASH(sha224)
        TOMCRYPT_REGISTER_HASH(sha1)
        TOMCRYPT_REGISTER_HASH(md5)
        TOMCRYPT_REGISTER_HASH(md4)
        TOMCRYPT_REGISTER_HASH(md2)
        TOMCRYPT_REGISTER_HASH(tiger)
        TOMCRYPT_REGISTER_HASH(rmd128)
        TOMCRYPT_REGISTER_HASH(rmd160)
        TOMCRYPT_REGISTER_HASH(rmd256)
        TOMCRYPT_REGISTER_HASH(rmd320)

        init = 1;
    }

    if(type) {
        mystrcpy(desc, type, sizeof(desc));

        ctx = calloc(1, sizeof(TOMCRYPT));
        if(!ctx) STD_ERR;
        ctx->idx = -1;  // 0 is AES

        #define TOMCRYPT_IDX(X,Y) \
            else if(!stricmp(p, #X)) { \
                ctx->idx = X##_idx; \
                Y; \
            }

        for(p = desc; *p; p = l + 1) {
            l = strchr(p, ' ');
            if(l) *l = 0;

            while(*p <= ' ') p++;
            if(!strnicmp(p, "tomcrypt", 8)) {
                use_tomcrypt = 1;
                p += 8;
            }
            if(!strnicmp(p, "libtomcrypt", 11)) {
                use_tomcrypt = 1;
                p += 11;
            }
            while(*p <= ' ') p++;

            if(!stricmp(p, "")) {}  // needed because the others are "else"

            TOMCRYPT_IDX(blowfish, ctx->cipher = 1)
            TOMCRYPT_IDX(rc5, ctx->cipher = 1)
            TOMCRYPT_IDX(rc6, ctx->cipher = 1)
            TOMCRYPT_IDX(rc2, ctx->cipher = 1)
            TOMCRYPT_IDX(saferp, ctx->cipher = 1)
            TOMCRYPT_IDX(safer_k64, ctx->cipher = 1)
            TOMCRYPT_IDX(safer_k128, ctx->cipher = 1)
            TOMCRYPT_IDX(safer_sk64, ctx->cipher = 1)
            TOMCRYPT_IDX(safer_sk128, ctx->cipher = 1)
            TOMCRYPT_IDX(rijndael, ctx->cipher = 1)
            TOMCRYPT_IDX(aes, ctx->cipher = 1)
            TOMCRYPT_IDX(rijndael_enc, ctx->cipher = 1)
            TOMCRYPT_IDX(aes_enc, ctx->cipher = 1)
            TOMCRYPT_IDX(xtea, ctx->cipher = 1)
            TOMCRYPT_IDX(twofish, ctx->cipher = 1)
            TOMCRYPT_IDX(des, ctx->cipher = 1)
            TOMCRYPT_IDX(des3, ctx->cipher = 1)
            TOMCRYPT_IDX(cast5, ctx->cipher = 1)
            TOMCRYPT_IDX(noekeon, ctx->cipher = 1)
            TOMCRYPT_IDX(skipjack, ctx->cipher = 1)
            TOMCRYPT_IDX(khazad, ctx->cipher = 1)
            TOMCRYPT_IDX(anubis, ctx->cipher = 1)
            TOMCRYPT_IDX(kseed, ctx->cipher = 1)
            TOMCRYPT_IDX(kasumi, ctx->cipher = 1)
            TOMCRYPT_IDX(multi2, ctx->cipher = 1)

            TOMCRYPT_IDX(chc, ctx->hash = 1)
            TOMCRYPT_IDX(whirlpool, ctx->hash = 1)
            TOMCRYPT_IDX(sha512, ctx->hash = 1)
            TOMCRYPT_IDX(sha384, ctx->hash = 1)
            TOMCRYPT_IDX(sha256, ctx->hash = 1)
            TOMCRYPT_IDX(sha224, ctx->hash = 1)
            TOMCRYPT_IDX(sha1, ctx->hash = 1)
            TOMCRYPT_IDX(md5, ctx->hash = 1)
            TOMCRYPT_IDX(md4, ctx->hash = 1)
            TOMCRYPT_IDX(md2, ctx->hash = 1)
            TOMCRYPT_IDX(tiger, ctx->hash = 1)
            TOMCRYPT_IDX(rmd128, ctx->hash = 1)
            TOMCRYPT_IDX(rmd160, ctx->hash = 1)
            TOMCRYPT_IDX(rmd256, ctx->hash = 1)
            TOMCRYPT_IDX(rmd320, ctx->hash = 1)

            else if(stristr(p, "ecb"))      ctx->cipher = 1;
            else if(stristr(p, "cfb"))      ctx->cipher = 2;
            else if(stristr(p, "ofb"))      ctx->cipher = 3;
            else if(stristr(p, "cbc"))      ctx->cipher = 4;
            else if(stristr(p, "ctr"))      ctx->cipher = 5;
            else if(stristr(p, "lrw"))      ctx->cipher = 6;
            else if(stristr(p, "f8"))       ctx->cipher = 7;
            else if(stristr(p, "xts"))      ctx->cipher = 8;

            else if(stristr(p, "hmac"))     ctx->cipher = 10;
            else if(stristr(p, "omac"))     ctx->cipher = 11;
            else if(stristr(p, "pmac"))     ctx->cipher = 12;
            else if(stristr(p, "eax"))      ctx->cipher = 13;
            else if(stristr(p, "ocb"))      ctx->cipher = 14;
            else if(stristr(p, "ccm"))      ctx->cipher = 15;
            else if(stristr(p, "gcm"))      ctx->cipher = 16;
            else if(stristr(p, "pelican"))  ctx->cipher = 17;
            else if(stristr(p, "xcbc"))     ctx->cipher = 18;
            else if(stristr(p, "f9"))       ctx->cipher = 19;

            if(!l) break;
            *l = ' ';
        }

        if(!use_tomcrypt || (ctx->idx < 0)) {
            free(ctx);
            ctx = NULL;
        }
        return(ctx);
    }

    key         = ctx->key;
    keysz       = ctx->keysz;
    ivec        = ctx->ivec;
    ivecsz      = ctx->ivecsz;
    nonce       = ctx->nonce;
    noncelen    = ctx->noncelen;
    header      = ctx->header;
    headerlen   = ctx->headerlen;
    tweak       = ctx->tweak;

    //if(outsz > insz) outsz = insz;
    tmp = outsz;

    #define TOMCRYPT_CRYPT_MODE(X) \
        if(X##_setiv(ivec, ivecsz, &X)) goto quit; \
        if(encrypt_mode) { if(X##_encrypt(in, out, insz, &X)) goto quit; } \
        else { if(X##_decrypt(in, out, insz, &X)) goto quit; } \
        X##_done(&X);

    if(ret) *ret = 0;
    if(ctx->idx < 0) ctx->idx = 0;
    if(ctx->hash) {
        if(hash_memory(ctx->idx, in, insz, out, &tmp)) goto quit;

    } else if(ctx->cipher == 1) {
        if(ecb_start(ctx->idx, key, keysz, 0, &ecb)) goto quit;
        if(encrypt_mode) { if(ecb_encrypt(in, out, insz, &ecb)) goto quit; }
        else { if(ecb_decrypt(in, out, insz, &ecb)) goto quit; }
        ecb_done(&ecb);

    } else if(ctx->cipher == 2) {
        if(cfb_start(ctx->idx, ivec, key, keysz, 0, &cfb)) goto quit;
        TOMCRYPT_CRYPT_MODE(cfb)

    } else if(ctx->cipher == 3) {
        if(ofb_start(ctx->idx, ivec, key, keysz, 0, &ofb)) goto quit;
        TOMCRYPT_CRYPT_MODE(ofb)

    } else if(ctx->cipher == 4) {
        if(cbc_start(ctx->idx, ivec, key, keysz, 0, &cbc)) goto quit;
        TOMCRYPT_CRYPT_MODE(cbc)

    } else if(ctx->cipher == 5) {
        if(ctr_start(ctx->idx, ivec, key, keysz, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) goto quit;
        TOMCRYPT_CRYPT_MODE(ctr)

    } else if(ctx->cipher == 6) {
        if(lrw_start(ctx->idx, ivec, key, keysz, tweak, 0, &lrw)) goto quit;
        TOMCRYPT_CRYPT_MODE(lrw)

    } else if(ctx->cipher == 7) {
        if(f8_start(ctx->idx, ivec, key, keysz, nonce, noncelen, 0, &f8)) goto quit;
        TOMCRYPT_CRYPT_MODE(f8)

    } else if(ctx->cipher == 8) {
        if(xts_start(ctx->idx, key, nonce, keysz, 0, &xts)) goto quit;
        if(encrypt_mode) { if(xts_encrypt(in, insz, out, tweak, &xts)) goto quit; }
        else { if(xts_decrypt(in, insz, out, tweak, &xts)) goto quit; }
        xts_done(&xts);

    } else if(ctx->cipher == 10) {
        if(hmac_memory(ctx->idx, key, keysz, in, insz, out, &tmp)) goto quit;

    } else if(ctx->cipher == 11) {
        if(omac_memory(ctx->idx, key, keysz, in, insz, out, &tmp)) goto quit;

    } else if(ctx->cipher == 12) {
        if(pmac_memory(ctx->idx, key, keysz, in, insz, out, &tmp)) goto quit;

    } else if(ctx->cipher == 13) {
        tmp = sizeof(tag);
        if(encrypt_mode) {
            if(eax_encrypt_authenticate_memory(
                ctx->idx,
                key, keysz,
                nonce, noncelen,
                header, headerlen,
                in, insz,
                out,
                tag, &tmp)) goto quit;
        } else {
            if(eax_decrypt_verify_memory(
                ctx->idx,
                key, keysz,
                nonce, noncelen,
                header, headerlen,
                in, insz,
                out,
                tag, tmp,
                &stat)) goto quit;
        }
        tmp = insz;

    } else if(ctx->cipher == 14) {
        tmp = sizeof(tag);
        if(encrypt_mode) {
            if(ocb_encrypt_authenticate_memory(
                ctx->idx,
                key, keysz,
                nonce,
                in, insz,
                out,
                tag, &tmp)) goto quit;
        } else {
            if(ocb_decrypt_verify_memory(
                ctx->idx,
                key, keysz,
                nonce,
                in, insz,
                out,
                tag, tmp,
                &stat)) goto quit;
        }
        tmp = insz;

    } else if(ctx->cipher == 15) {
        tmp = sizeof(tag);
        if(ccm_memory(
            ctx->idx,
            key, keysz,
            NULL, //uskey,
            nonce, noncelen,
            header, headerlen,
            in, insz,
            out,
            tag, &tmp,
            encrypt_mode ? CCM_ENCRYPT: CCM_DECRYPT)) goto quit;
        tmp = insz;

    } else if(ctx->cipher == 16) {
        tmp = sizeof(tag);
        if(gcm_memory(
            ctx->idx,
            key, keysz,
            ivec, ivecsz,
            nonce, noncelen, //adata, adatalen,
            in, insz,
            out,
            tag, &tmp,
            encrypt_mode ? GCM_ENCRYPT: GCM_DECRYPT)) goto quit;
        tmp = insz;

    } else if(ctx->cipher == 17) {
        if(pelican_memory(key, keysz, in, insz, out)) goto quit;

    } else if(ctx->cipher == 18) {
        if(xcbc_memory(ctx->idx, key, keysz, in, insz, out, &tmp)) goto quit;

    } else if(ctx->cipher == 19) {
        if(f9_memory(ctx->idx, key, keysz, in, insz, out, &tmp)) goto quit;
    }
    if(ret) *ret = tmp;
    return(ctx);
quit:
    return(NULL);
}
#endif



int CMD_Encryption_func(int cmd) {
#ifndef DISABLE_OPENSSL
#define IVEC_MYCRYPTO(X) \
    mycrypto = ivec ? EVP_##X##_cbc() : EVP_##X##_ecb()
#define AUTO_MYCRYPTO(X) \
    } else if(!stricmp(type, #X)) { \
        mycrypto = EVP_##X();
#define AUTO_MYHASH(X) \
    } else if(!stricmp(type, #X)) { \
        myhash = EVP_##X();

    static int  load_algos      = 0;
    const EVP_CIPHER  *mycrypto = NULL;
    const EVP_MD      *myhash   = NULL;
#endif
    int     keysz,
            ivecsz,
            force_keysz;
    u8      tmp_str[32],
            *type,
            *key,
            *ivec;

    // reset ANY ctx
#ifndef DISABLE_OPENSSL
    FREEX(evp_ctx, EVP_CIPHER_CTX_cleanup(evp_ctx))
    FREEX(evpmd_ctx, EVP_MD_CTX_cleanup(evpmd_ctx))
    FREEX(blowfish_ctx,)
#endif
    FREEX(tea_ctx,)
    FREEX(xtea_ctx,)
    FREEX(xxtea_ctx,)
    FREEX(swap_ctx,)
    FREEX(math_ctx,)
    FREEX(xor_ctx, free(xor_ctx->key))
    FREEX(rot_ctx, free(rot_ctx->key))
    FREEX(rotate_ctx,)
    FREEX(inc_ctx,)
    FREEX(charset_ctx,)
    FREEX(charset2_ctx,)
    FREEX(twofish_ctx,)
    FREEX(seed_ctx,)
    FREEX(serpent_ctx,)
    if(ice_ctx) {
        ice_key_destroy(ice_ctx);
        ice_ctx = NULL;
    }
    if(rotor_ctx) {
        rotor_dealloc(rotor_ctx);
        rotor_ctx = NULL;
    }
    FREEX(ssc_ctx, free(ssc_ctx->key))
    FREEX(wincrypt_ctx,)
    FREEX(cunprot_ctx,)
    FREEX(zipcrypto_ctx,)
    FREEX(threeway_ctx,)
    FREEX(skipjack_ctx,)
    FREEX(anubis_ctx,)
    FREEX(aria_ctx,)
    FREEX(crypton_ctx,)
    if(frog_ctx) frog_ctx = NULL;   // this is different!
    FREEX(gost_ctx,)
    if(lucifer_ctx) lucifer_ctx = 0; // different
    if(mars_ctx) mars_ctx = NULL;   // this is different!
    FREEX(misty1_ctx,)
    FREEX(noekeon_ctx,)
    FREEX(seal_ctx,)
    FREEX(safer_ctx,)
    if(kirk_ctx >= 0) kirk_ctx = -1;
    FREEX(crc_ctx,)
#ifndef DISABLE_MCRYPT
    if(mcrypt_ctx) {
        mcrypt_generic_deinit(mcrypt_ctx);
        mcrypt_module_close(mcrypt_ctx);
        mcrypt_ctx = NULL;
    }
#endif
#ifndef DISABLE_TOMCRYPT
    if(tomcrypt_ctx) {
        if(tomcrypt_ctx->ivec) free(tomcrypt_ctx->ivec);
        if(tomcrypt_ctx->nonce) free(tomcrypt_ctx->nonce);
        if(tomcrypt_ctx->header) free(tomcrypt_ctx->header);
        if(tomcrypt_ctx->tweak) free(tomcrypt_ctx->tweak);
    }
    FREEX(tomcrypt_ctx,)
#endif
    if(cmd < 0) return(0);  // bms init

    type   = VAR(0);
    key    = STR(1);
    keysz  = NUM(1);
    ivec   = STR(2);    // ivec can be NULL (ecb) or a string (CBC)
    ivecsz = NUM(2);
    if(ivecsz <= 0) ivec = NULL; // so can be used "" to skip it
    encrypt_mode = NUM(3);

    quick_var_from_name_check(&key,  &keysz);
    quick_var_from_name_check(&ivec, &ivecsz);
    if(CMD.var[4] >= 0) {
        force_keysz = VAR32(4);
        if(force_keysz > 0) keysz = force_keysz;    // no checks on the length
    }

    if(!stricmp(type, "?")) {
        fgetz(tmp_str, sizeof(tmp_str), stdin,
            "\n- you must specify the encryption algorithm to use:\n  ");
        type = tmp_str;
    }

    if(!strnicmp(type, "EVP_", 4)) type += 4;

#ifndef DISABLE_OPENSSL
    if(!load_algos) {
        OpenSSL_add_all_algorithms();
        load_algos = 1;
    }
#endif

    if(!stricmp(type, "")) {    // || !keysz) {
        // do nothing, disables the encryption

#ifndef DISABLE_OPENSSL
    } else if(!stricmp(type, "des")) {
        IVEC_MYCRYPTO(des);

    } else if(!stricmp(type, "3des2") || !stricmp(type, "3des-112") || !stricmp(type, "des_ede") || !stricmp(type, "des_ede2")) {
        IVEC_MYCRYPTO(des_ede);

    } else if(!stricmp(type, "3des") || !stricmp(type, "3des-168") || !stricmp(type, "des_ede3")) {
        IVEC_MYCRYPTO(des_ede3);

    } else if(!stricmp(type, "desx")) {
        mycrypto = EVP_desx_cbc();

    } else if(!stricmp(type, "rc4") || !stricmp(type, "arc4")) {
        mycrypto = EVP_rc4();

#ifndef OPENSSL_NO_IDEA
    } else if(!stricmp(type, "idea")) {
        IVEC_MYCRYPTO(idea);
#endif

    } else if(!stricmp(type, "rc2")) {
        IVEC_MYCRYPTO(rc2);

    } else if(!stricmp(type, "blowfish")) {
        //IVEC_MYCRYPTO(bf); // blowfish must be handled manually because BF_decrypt != BF_ecb_encrypt
        blowfish_ctx = calloc(1, sizeof(BF_KEY));
        if(!blowfish_ctx) STD_ERR;
        BF_set_key(blowfish_ctx, keysz, key);

    } else if(!stricmp(type, "cast5")) {
        IVEC_MYCRYPTO(cast5);

    } else if(!stricmp(type, "aes") || !stricmp(type, "Rijndael")) {
        switch(keysz << 3) {
            case 128: IVEC_MYCRYPTO(aes_128); break;
            case 192: IVEC_MYCRYPTO(aes_192); break;
            case 256: IVEC_MYCRYPTO(aes_256); break;
            default: {
                printf("\nError: the key for algorithm %s has an invalid size (%d)\n", type, (i32)keysz);
                myexit(-1);
                break;
            }
        }

    } else if(!stricmp(type, "aes_128_ctr") || !stricmp(type, "aes_192_ctr") || !stricmp(type, "aes_256_ctr")) {
        switch(keysz << 3) {
            case 128: break;
            case 192: break;
            case 256: break;
            default: {
                printf("\nError: the key for algorithm %s has an invalid size (%d)\n", type, (i32)keysz);
                myexit(-1);
                break;
            }
        }
        aes_ctr_ctx = calloc(1, sizeof(aes_ctr_ctx_t));
        if(!aes_ctr_ctx) STD_ERR;
        if(!encrypt_mode) {
            AES_set_decrypt_key(key, keysz << 3, &aes_ctr_ctx->ctx);
        } else {
            AES_set_encrypt_key(key, keysz << 3, &aes_ctr_ctx->ctx);
        }
        if((ivecsz > 0) && (ivecsz < AES_BLOCK_SIZE)) memcpy(aes_ctr_ctx->ivec, ivec, ivecsz);
#endif

    } else if(!stricmp(type, "seed")) {
//#ifndef OPENSSL_NO_SEED
//        IVEC_MYCRYPTO(seed);
//#else
        seed_ctx = calloc(1, sizeof(SEED_context));
        if(!seed_ctx) STD_ERR;
        do_seed_setkey(seed_ctx, key, keysz);
//#endif
    } else if(!stricmp(type, "tea")) {
        tea_ctx = calloc(1, sizeof(tea_context));
        if(!tea_ctx) STD_ERR;
        tea_setup(tea_ctx, key);

    } else if(!stricmp(type, "xtea")) {
        xtea_ctx = calloc(1, sizeof(xtea_context));
        if(!xtea_ctx) STD_ERR;
        xtea_setupx(xtea_ctx, key);

    } else if(!stricmp(type, "xxtea")) {
        xxtea_ctx = calloc(1, sizeof(xxtea_context));
        if(!xxtea_ctx) STD_ERR;
        xxtea_setup(xxtea_ctx, key);

    } else if(!stricmp(type, "swap")) {
        swap_ctx = calloc(1, sizeof(swap_context));
        if(!swap_ctx) STD_ERR;
        swap_setkey(swap_ctx, myatoi(key));

    } else if(!stricmp(type, "math")) {
        math_ctx = calloc(1, sizeof(math_context));
        if(!math_ctx) STD_ERR;
        math_setkey(math_ctx, key, ivec);

    } else if(!stricmp(type, "xor")) {
        xor_ctx = calloc(1, sizeof(xor_context));
        if(!xor_ctx) STD_ERR;
        xor_setkey(xor_ctx, key, keysz);

    } else if(!stricmp(type, "rot") || !stricmp(type, "rot13")) {
        rot_ctx = calloc(1, sizeof(rot_context));
        if(!rot_ctx) STD_ERR;
        rot_setkey(rot_ctx, key, keysz);

    } else if(!stricmp(type, "rotate") || !stricmp(type, "ror") || !stricmp(type, "rol")) {
        rotate_ctx = calloc(1, sizeof(rotate_context));
        if(!rotate_ctx) STD_ERR;
        rotate_setkey(rotate_ctx, key, ivec);

    } else if(stristr(type, "incremental")) {
        inc_ctx = calloc(1, sizeof(inc_context));
        if(!inc_ctx) STD_ERR;
        if(stristr(type, "rot") || stristr(type, "add") || stristr(type, "sum") || stristr(type, "sub")) {
            inc_setkey(inc_ctx, 1, myatoi(key), myatoi(ivec));
        } else {
            inc_setkey(inc_ctx, 0, myatoi(key), myatoi(ivec));
        }

    } else if(!stricmp(type, "charset") || !stricmp(type, "chartable")) {
        charset_ctx = calloc(1, sizeof(charset_context));
        if(!charset_ctx) STD_ERR;
        charset_setkey(charset_ctx, key, keysz);

    } else if(!stricmp(type, "charset2") || !stricmp(type, "chartable2")) {
        charset2_ctx = calloc(1, sizeof(charset_context));
        if(!charset2_ctx) STD_ERR;
        charset_setkey(charset2_ctx, key, keysz);

    } else if(!stricmp(type, "twofish")) {
        twofish_ctx = calloc(1, sizeof(TWOFISH_context));
        if(!twofish_ctx) STD_ERR;
        do_twofish_setkey(twofish_ctx, key, keysz);

    } else if(!stricmp(type, "serpent")) {
        serpent_ctx = calloc(1, sizeof(serpent_context_t));
        if(!serpent_ctx) STD_ERR;
        serpent_setkey_internal(serpent_ctx, key, keysz);

    } else if(!stricmp(type, "icecrypt")) {
        ice_ctx = do_ice_key(key, keysz, 1);
        if(!ice_ctx) STD_ERR;

    } else if(!stricmp(type, "ice")) {
        ice_ctx = do_ice_key(key, keysz, 0);
        if(!ice_ctx) STD_ERR;

    } else if(!stricmp(type, "rotor")) {
        rotor_ctx = rotorobj_new(ivec ? myatoi(ivec) : 12, key, keysz);
        if(!rotor_ctx) STD_ERR;

    } else if(!stricmp(type, "ssc")) {
        ssc_ctx = calloc(1, sizeof(ssc_context));
        if(!ssc_ctx) STD_ERR;
        ssc_setkey(ssc_ctx, key, keysz);

    } else if(!stricmp(type, "wincrypt") || !stricmp(type, "CryptDecrypt") || !stricmp(type, "CryptEncrypt")) {
        wincrypt_ctx = calloc(1, sizeof(wincrypt_context));
        if(!wincrypt_ctx) STD_ERR;
        if(wincrypt_setkey(wincrypt_ctx, key, keysz, ivec) < 0) {
            printf("\nError: wincrypt_setkey failed\n");
            myexit(-1);
        }

    } else if(!stricmp(type, "cryptunprotect") || !stricmp(type, "CryptUnprotectData") || !stricmp(type, "cunprot")) {
        cunprot_ctx = calloc(1, sizeof(cunprot_context));
        if(!cunprot_ctx) STD_ERR;
        if(cunprot_setkey(cunprot_ctx, key, keysz) < 0) {
            printf("\nError: cunprot_setkey failed\n");
            myexit(-1);
        }

    } else if(!stricmp(type, "zipcrypto")) {
        zipcrypto_ctx = calloc(3+1, sizeof(u_int)); // the additional 1 is used for the -12 trick
        if(!zipcrypto_ctx) STD_ERR;
        zipcrypto_init_keys(key, zipcrypto_ctx, (void *)get_crc_table());
        if(ivec) zipcrypto_ctx[3] = myatoi(ivec);

#ifndef DISABLE_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x1000000fL
    #define OPENSSL_NO_WHIRLPOOL    // uff, necessary
#endif
    // blah, openssl doesn't catch all the names... boring
    // directly from evp.h with a simple strings substitution
    AUTO_MYHASH(md_null)
#ifndef OPENSSL_NO_MD2
    AUTO_MYHASH(md2)
#endif
#ifndef OPENSSL_NO_MD4
    AUTO_MYHASH(md4)
#endif
#ifndef OPENSSL_NO_MD5
    AUTO_MYHASH(md5)
#endif
#ifndef OPENSSL_NO_SHA
    AUTO_MYHASH(sha)
    AUTO_MYHASH(sha1)
    AUTO_MYHASH(dss)
    AUTO_MYHASH(dss1)
    AUTO_MYHASH(ecdsa)
#endif
#ifndef OPENSSL_NO_SHA256
    AUTO_MYHASH(sha224)
    AUTO_MYHASH(sha256)
#endif
#ifndef OPENSSL_NO_SHA512
    AUTO_MYHASH(sha384)
    AUTO_MYHASH(sha512)
#endif
#ifndef OPENSSL_NO_MDC2
    AUTO_MYHASH(mdc2)
#endif
#ifndef OPENSSL_NO_RIPEMD
    AUTO_MYHASH(ripemd160)
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
    AUTO_MYHASH(whirlpool)    // not all versions support it
#endif
    AUTO_MYCRYPTO(enc_null)        /* does nothing :-) */
#ifndef OPENSSL_NO_DES
    AUTO_MYCRYPTO(des_ecb)
    AUTO_MYCRYPTO(des_ede)
    AUTO_MYCRYPTO(des_ede3)
    AUTO_MYCRYPTO(des_ede_ecb)
    AUTO_MYCRYPTO(des_ede3_ecb)
    AUTO_MYCRYPTO(des_cfb64)
# define EVP_des_cfb EVP_des_cfb64
    AUTO_MYCRYPTO(des_cfb1)
    AUTO_MYCRYPTO(des_cfb8)
    AUTO_MYCRYPTO(des_ede_cfb64)
# define EVP_des_ede_cfb EVP_des_ede_cfb64
#if 0
    AUTO_MYCRYPTO(des_ede_cfb1)
    AUTO_MYCRYPTO(des_ede_cfb8)
#endif
    AUTO_MYCRYPTO(des_ede3_cfb64)
# define EVP_des_ede3_cfb EVP_des_ede3_cfb64
    AUTO_MYCRYPTO(des_ede3_cfb1)
    AUTO_MYCRYPTO(des_ede3_cfb8)
    AUTO_MYCRYPTO(des_ofb)
    AUTO_MYCRYPTO(des_ede_ofb)
    AUTO_MYCRYPTO(des_ede3_ofb)
    AUTO_MYCRYPTO(des_cbc)
    AUTO_MYCRYPTO(des_ede_cbc)
    AUTO_MYCRYPTO(des_ede3_cbc)
    AUTO_MYCRYPTO(desx_cbc)
/* This should now be supported through the dev_crypto ENGINE. But also, why are
 * rc4 and md5 declarations made here inside a "NO_DES" precompiler branch? */
#if 0
# ifdef OPENSSL_OPENBSD_DEV_CRYPTO
    AUTO_MYCRYPTO(dev_crypto_des_ede3_cbc)
    AUTO_MYCRYPTO(dev_crypto_rc4)
    AUTO_MYHASH(dev_crypto_md5)
# endif
#endif
#endif
#ifndef OPENSSL_NO_RC4
    AUTO_MYCRYPTO(rc4)
    AUTO_MYCRYPTO(rc4_40)
#endif
#ifndef OPENSSL_NO_IDEA
    AUTO_MYCRYPTO(idea_ecb)
    AUTO_MYCRYPTO(idea_cfb64)
# define EVP_idea_cfb EVP_idea_cfb64
    AUTO_MYCRYPTO(idea_ofb)
    AUTO_MYCRYPTO(idea_cbc)
#endif
#ifndef OPENSSL_NO_RC2
    AUTO_MYCRYPTO(rc2_ecb)
    AUTO_MYCRYPTO(rc2_cbc)
    AUTO_MYCRYPTO(rc2_40_cbc)
    AUTO_MYCRYPTO(rc2_64_cbc)
    AUTO_MYCRYPTO(rc2_cfb64)
# define EVP_rc2_cfb EVP_rc2_cfb64
    AUTO_MYCRYPTO(rc2_ofb)
#endif
#ifndef OPENSSL_NO_BF
    AUTO_MYCRYPTO(bf_ecb)
    AUTO_MYCRYPTO(bf_cbc)
    AUTO_MYCRYPTO(bf_cfb64)
# define EVP_bf_cfb EVP_bf_cfb64
    AUTO_MYCRYPTO(bf_ofb)
#endif
#ifndef OPENSSL_NO_CAST
    AUTO_MYCRYPTO(cast5_ecb)
    AUTO_MYCRYPTO(cast5_cbc)
    AUTO_MYCRYPTO(cast5_cfb64)
# define EVP_cast5_cfb EVP_cast5_cfb64
    AUTO_MYCRYPTO(cast5_ofb)
#endif
#ifndef OPENSSL_NO_RC5
    AUTO_MYCRYPTO(rc5_32_12_16_cbc)
    AUTO_MYCRYPTO(rc5_32_12_16_ecb)
    AUTO_MYCRYPTO(rc5_32_12_16_cfb64)
# define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
    AUTO_MYCRYPTO(rc5_32_12_16_ofb)
#endif
#ifndef OPENSSL_NO_AES
    AUTO_MYCRYPTO(aes_128_ecb)
    AUTO_MYCRYPTO(aes_128_cbc)
    AUTO_MYCRYPTO(aes_128_cfb1)
    AUTO_MYCRYPTO(aes_128_cfb8)
    AUTO_MYCRYPTO(aes_128_cfb128)
# define EVP_aes_128_cfb EVP_aes_128_cfb128
    AUTO_MYCRYPTO(aes_128_ofb)
#if 0
    AUTO_MYCRYPTO(aes_128_ctr)
#endif
    AUTO_MYCRYPTO(aes_192_ecb)
    AUTO_MYCRYPTO(aes_192_cbc)
    AUTO_MYCRYPTO(aes_192_cfb1)
    AUTO_MYCRYPTO(aes_192_cfb8)
    AUTO_MYCRYPTO(aes_192_cfb128)
# define EVP_aes_192_cfb EVP_aes_192_cfb128
    AUTO_MYCRYPTO(aes_192_ofb)
#if 0
    AUTO_MYCRYPTO(aes_192_ctr)
#endif
    AUTO_MYCRYPTO(aes_256_ecb)
    AUTO_MYCRYPTO(aes_256_cbc)
    AUTO_MYCRYPTO(aes_256_cfb1)
    AUTO_MYCRYPTO(aes_256_cfb8)
    AUTO_MYCRYPTO(aes_256_cfb128)
# define EVP_aes_256_cfb EVP_aes_256_cfb128
    AUTO_MYCRYPTO(aes_256_ofb)
#if 0
    AUTO_MYCRYPTO(aes_256_ctr)
#endif
#endif
#ifndef OPENSSL_NO_CAMELLIA
    AUTO_MYCRYPTO(camellia_128_ecb)
    AUTO_MYCRYPTO(camellia_128_cbc)
    AUTO_MYCRYPTO(camellia_128_cfb1)
    AUTO_MYCRYPTO(camellia_128_cfb8)
    AUTO_MYCRYPTO(camellia_128_cfb128)
# define EVP_camellia_128_cfb EVP_camellia_128_cfb128
    AUTO_MYCRYPTO(camellia_128_ofb)
    AUTO_MYCRYPTO(camellia_192_ecb)
    AUTO_MYCRYPTO(camellia_192_cbc)
    AUTO_MYCRYPTO(camellia_192_cfb1)
    AUTO_MYCRYPTO(camellia_192_cfb8)
    AUTO_MYCRYPTO(camellia_192_cfb128)
# define EVP_camellia_192_cfb EVP_camellia_192_cfb128
    AUTO_MYCRYPTO(camellia_192_ofb)
    AUTO_MYCRYPTO(camellia_256_ecb)
    AUTO_MYCRYPTO(camellia_256_cbc)
    AUTO_MYCRYPTO(camellia_256_cfb1)
    AUTO_MYCRYPTO(camellia_256_cfb8)
    AUTO_MYCRYPTO(camellia_256_cfb128)
# define EVP_camellia_256_cfb EVP_camellia_256_cfb128
    AUTO_MYCRYPTO(camellia_256_ofb)
#endif

#ifndef OPENSSL_NO_SEED
    AUTO_MYCRYPTO(seed_ecb)
    AUTO_MYCRYPTO(seed_cbc)
    AUTO_MYCRYPTO(seed_cfb128)
# define EVP_seed_cfb EVP_seed_cfb128
    AUTO_MYCRYPTO(seed_ofb)
#endif
#endif

#ifndef DISABLE_MCRYPT
    } else if((mcrypt_ctx = quick_mcrypt_check(type))) {    // libmcrypt
        if(mcrypt_generic_init(mcrypt_ctx, key, keysz, ivec) < 0) {
            printf("\nError: mcrypt key failed\n");
            myexit(-1);
        }
#endif

#ifndef DISABLE_TOMCRYPT
    } else if((tomcrypt_ctx = tomcrypt_doit(NULL, type, NULL, 0, NULL, 0, NULL))) {    // libtomcrypt
        tomcrypt_ctx->key   = key;
        tomcrypt_ctx->keysz = keysz;
        tomcrypt_lame_ivec(tomcrypt_ctx, ivec, ivecsz);
#endif

    } else if(!strnicmp(type, "crc", 3) || !stricmp(type, "checksum")) {
        crc_ctx = calloc(1, sizeof(crc_context));
        if(!crc_ctx) STD_ERR;
        crc_ctx->poly  = 0x04C11DB7;    // it's the one where the second element is 0x77073096
        crc_ctx->size  = 32;
        crc_ctx->init  = -1;
        crc_ctx->final = -1;
        crc_ctx->type  = 0;
        crc_ctx->rever = 1;
        if(key && key[0]) crc_ctx->poly = myatoi(key);
        if(ivec) {
            //sscanf(ivec, "%d %d %d %d %d",
            get_parameter_numbers(ivec, 5,
                &crc_ctx->size, &crc_ctx->init, &crc_ctx->final, &crc_ctx->type, &crc_ctx->rever);
        }
        if(!key || !key[0]) {   // useless, in case of key "" and size 16
            if(crc_ctx->size == 16) crc_ctx->poly = 0x8005;
        }
        make_crctable(crc_ctx->table, crc_ctx->poly, crc_ctx->size, crc_ctx->rever);
        add_var(0, "QUICKBMS_CRC", NULL, crc_ctx->table[1], sizeof(u_int)); // used for debugging

    // the following algorithms have been implemented "before" adding the mcrypt
    // library... well I don't want to remove them and the hours I lost
    // note also that those are all untested, just added and not verified
    } else if(!stricmp(type, "3way")) {
        threeway_ctx = calloc(3, sizeof(u_int));
        if(!threeway_ctx) STD_ERR;
        if(threeway_setkey(threeway_ctx, key, keysz) < 0) {
            printf("\nError: threeway_setkey failed\n");
            myexit(-1);
        }

    } else if(!stricmp(type, "skipjack")) {
        skipjack_ctx = calloc(10, 256);
        if(!skipjack_ctx) STD_ERR;
        skipjack_makeKey(key, skipjack_ctx);

    } else if(!stricmp(type, "anubis")) {
        anubis_ctx = calloc(1, sizeof(ANUBISstruct));
        if(!anubis_ctx) STD_ERR;
        anubis_ctx->keyBits = keysz * 8;
        ANUBISkeysetup(key, anubis_ctx);

    } else if(!stricmp(type, "aria")) {
        aria_ctx = calloc(1, sizeof(aria_ctx_t));
        if(!aria_ctx) STD_ERR;
        if(!encrypt_mode) aria_ctx->Nr = ARIA_DecKeySetup(key, aria_ctx->rk, keysz * 8);
        else              aria_ctx->Nr = ARIA_EncKeySetup(key, aria_ctx->rk, keysz * 8);

    } else if(!stricmp(type, "crypton")) {
        crypton_ctx = calloc(104, sizeof(u_int));
        if(!crypton_ctx) STD_ERR;
        crypton_set_key((void *)key, keysz, crypton_ctx);

    } else if(!stricmp(type, "frog")) {
        frog_ctx = frog_set_key((void *)key, keysz);

    } else if(!strnicmp(type, "gost", 4)) {
        gost_ctx = calloc(1, sizeof(gost_ctx_t));
        if(!gost_ctx) STD_ERR;
        gost_kboxinit();
        memcpy(gost_ctx->key, key, 4*8);
        if(ivec) memcpy(gost_ctx->iv, ivec, 4*2);
        if(stristr(type + 4, "ofb")) gost_ctx->type = 1;
        else if(stristr(type + 4, "cfb")) gost_ctx->type = 2;

    } else if(!stricmp(type, "lucifer")) {
        lucifer_ctx = 1;
        if(!encrypt_mode) lucifer_loadkey(key, 0);  // or 1?
        else              lucifer_loadkey(key, 1);  // or 0?

    } else if(!stricmp(type, "kirk")) {
        if(!ivec) {
            kirk_ctx = 1;
        } else {
            kirk_ctx = myatoi(ivec);
        }
        kirk_init();

    } else if(!stricmp(type, "mars")) {
        mars_ctx = mars_set_key((void *)key, keysz);

    } else if(!stricmp(type, "misty1")) {
        misty1_ctx = calloc(4, 4);
        if(!misty1_ctx) STD_ERR;
        misty1_keyinit(misty1_ctx, (void *)key);

    } else if(!stricmp(type, "noekeon")) {
        noekeon_ctx = calloc(1, sizeof(NOEKEONstruct));
        if(!noekeon_ctx) STD_ERR;
        NOEKEONkeysetup(key, noekeon_ctx);

    } else if(!stricmp(type, "seal")) {
        seal_ctx = calloc(1, sizeof(seal_ctx_t));
        if(!seal_ctx) STD_ERR;
        seal_key(seal_ctx, key);

    } else if(!stricmp(type, "safer")) {
        safer_ctx = calloc(1, sizeof(safer_key_t));
        if(!safer_ctx) STD_ERR;
        Safer_Init_Module();
        Safer_Expand_Userkey(key, key + SAFER_BLOCK_LEN, ivec ? myatoi(ivec) : SAFER_K128_DEFAULT_NOF_ROUNDS, 0, (void *)safer_ctx);

    } else {
#ifndef DISABLE_OPENSSL
        mycrypto = EVP_get_cipherbyname(type);
        if(!mycrypto) {
            myhash = EVP_get_digestbyname(type);
            if(!myhash) {
#else
        {   {
#endif
                printf("\nError: unsupported encryption/hashing type (%s)\n",  type);
                myexit(-1);
            }
        }
    }

#ifndef DISABLE_OPENSSL
    if(mycrypto) {  // handled for last because it's global for OpenSSL
        evp_ctx = calloc(1, sizeof(EVP_CIPHER_CTX));
        if(!evp_ctx) STD_ERR;
        EVP_CIPHER_CTX_init(evp_ctx);
        if(!EVP_CipherInit(evp_ctx, mycrypto, NULL, NULL, encrypt_mode)) {
            printf("\nError: EVP_CipherInit failed\n");
            myexit(-1);
        }
        if(!EVP_CIPHER_CTX_set_key_length(evp_ctx, keysz)) {
            printf("\nError: EVP_CIPHER_CTX_set_key_length failed\n");
            myexit(-1);
        }
        //EVP_CIPHER_CTX_set_padding(evp_ctx, 0);   // do not enable it: "If the pad parameter is zero then no padding is performed, the total amount of data encrypted or decrypted must then be a multiple of the block size or an error will occur."
        if(!EVP_CipherInit(evp_ctx, NULL, key, ivec, encrypt_mode)) {
            printf("\nError: EVP_CipherInit key failed\n");
            myexit(-1);
        }
    }
    if(myhash) {    // handled for last because it's global for OpenSSL
        evpmd_ctx = calloc(1, sizeof(EVP_MD_CTX));
        if(!evpmd_ctx) STD_ERR;
        EVP_MD_CTX_init(evpmd_ctx);
        if(!EVP_DigestInit(evpmd_ctx, myhash)) {
            printf("\nError: EVP_DigestInit failed\n");
            myexit(-1);
        }
    }
#endif

    if((verbose > 0) && keysz) printf("- encryption with algorithm %s and key of %d bytes\n", type, (i32)keysz);
    return(0);
}



int CMD_Print_func(int cmd) {
    i32     i,
            idx,
            len,
            force_len,
            hex,
            space;
    u8      *p,
            *msg,
            *var,
            *flags;

    msg = STR(0);
    fprintf(stderr, "- SCRIPT's MESSAGE:\n");

    while(*msg) {
        printf("  ");
        for(i = 0; i < 77; i++) {
            if(!*msg) break;
            if(*msg == '%') {
                msg++;
                p = strchr(msg, '%');
                if(!p) continue;
                hex       = 0;
                space     = 0;
                force_len = -1;
                idx = get_var_from_name(msg, p - msg);
                if(idx < 0) {
                    for(flags = msg; flags < p; flags++) {
                        if(*flags == '|') break;
                    }
                    if(flags >= p) continue;
                    idx = get_var_from_name(msg, flags - msg);
                    if(idx < 0) continue;
                    for(++flags; flags < p; flags++) {
                        if(strchr("hex", tolower(*flags))) {
                            hex = 1;
                        } else {
                            if(strchr(flags, ' ')) space = 1;
                            if(sscanf(flags, "%d%n", &force_len, &len) == 1) {
                                flags += (len - 1); // due to flags++
                            }
                        }
                    }
                }
                var = get_var(idx);
                len = strlen(var);
                if(force_len > 0) {
                    len = variable[idx].size;
                    if(force_len < len) len = force_len;
                }
                if(hex) {
                    while(len--) {
                        fprintf(stdout, "%02x%s", *var, space ? " " : "");
                        var++;
                    }
                } else {
                    fwrite(var, 1, len, stdout);
                }
                msg = p + 1;
            } else {
                if(*msg == '\n') {
                    msg++;
                    break;
                }
                fputc(*msg, stdout);
                msg++;
            }
        }
        fputc('\n', stdout);
    }
    fprintf(stderr, "\n");
    return(0);
}



int CMD_GetArray_func(int cmd) {
    int     index,
            array_num;

    //var       = VAR(0);
    array_num = VAR32(1);
    index     = VAR32(2);

    if((array_num < 0) || (array_num >= MAX_ARRAYS)) {
        printf("\nError: this BMS script uses more arrays than how much supported\n");
        myexit(-1);
    }
    if((index < 0) || (index >= array[array_num].elements)) {
        printf("\nError: this BMS script uses more array elements than how much supported\n");
        myexit(-1);
    }

    if(verbose < 0) printf(". %08x getarr  %-10s \"%s\" %d:%d\n", 0, get_varname(CMD.var[0]), array[array_num].str[index], (i32)array_num, (i32)index);
    add_var(CMD.var[0], NULL, array[array_num].str[index], 0, -1);
    return(0);
}



int CMD_PutArray_func(int cmd) {
    int     i,
            num,
            index,
            array_num;
    u8      *var;

    array_num = VAR32(0);
    index     = VAR32(1);
    var       = VAR(2);

    if((array_num < 0) || (array_num >= MAX_ARRAYS)) {
        printf("\nError: this BMS script uses more arrays than how much supported\n");
        myexit(-1);
    }
    if((index < 0) /*|| (index >= array[array_num].elements)*/) {
        printf("\nError: this BMS script uses more array elements than how much supported\n");
        myexit(-1);
    }

    if(index >= array[array_num].elements) {
        num = (index + 1) * sizeof(u8 *);   // +1 is necessary
        if(num < index) ALLOC_ERR;
        array[array_num].str = realloc(array[array_num].str, num);
        if(!array[array_num].str) STD_ERR;
        for(i = array[array_num].elements; i <= index; i++) {   // <= remember!!! (example 0 and 0)
            array[array_num].str[i] = NULL;
        }
        array[array_num].elements = index + 1;
    }

    if(verbose < 0) printf(". %08x putarr  %-10s \"%s\" %d:%d\n", 0, get_varname(CMD.var[0]), array[array_num].str[index], (i32)array_num, (i32)index);
    array[array_num].str[index] = re_strdup(array[array_num].str[index], var, NULL);
    return(0);
}



int CMD_Function_func(int start_cmd, int nop, int *ret_break) {
    variable_t  *newvar = NULL,
                *oldvar = NULL;
    int     ret,
            cmd,
            i,
            keep_vars;
    u8      *func_name;

    cmd = start_cmd;

    if(CMD.type != CMD_CallFunction) {   // quick skip
        for(cmd++; CMD.type != CMD_NONE; cmd++) {
            if(CMD.type == CMD_EndFunction) return(cmd);
            if(CMD.type == CMD_StartFunction) break;
        }
        printf("\nError: no EndFunction command found\n");
        myexit(-1);
    }
    if(nop) return(start_cmd);

    func_name = STR(0);
    keep_vars = NUM(1);
    for(cmd = 0;; cmd++) {
        if(CMD.type == CMD_NONE) {
            printf("\nError: the function %s has not been found\n", func_name);
            myexit(-1);
        }
        if((CMD.type == CMD_StartFunction) && !stricmp(func_name, STR(0))) break;
    }

    if(!keep_vars) {
        newvar = calloc(variables + 1, sizeof(variable_t));
        if(!newvar) STD_ERR;  // calloc is better so it zeroes also the last variable automatically
        for(i = 0; i < variables; i++) {    // duplicate the strings, the first NULL in re_strdup is NECESSARY!!!
            memcpy(&newvar[i], &variable[i], sizeof(variable_t));
            if(variable[i].name)  newvar[i].name  = re_strdup(NULL, variable[i].name,  NULL);   // not needed
            //if(variable[i].value) newvar[i].value = re_strdup(NULL, variable[i].value, NULL);
            if(variable[i].value) {
                newvar[i].size  = variable[i].size;
                newvar[i].value = malloc(newvar[i].size + 1);  // + 1 is needed for the final NULL byte!
                memcpy(newvar[i].value, variable[i].value, newvar[i].size);
                newvar[i].value[newvar[i].size] = 0;    // final NULL byte
            }
        }
        oldvar   = variable;
        variable = newvar;
    }

    ret = start_bms(cmd + 1, nop, ret_break);

    if(!keep_vars) {
        for(i = 0; i < variables; i++) {
            FREEZ(newvar[i].name)
            FREEZ(newvar[i].value)
        }
        FREEZ(newvar)
        variable = oldvar;
    }

    if(ret < 0) return(ret);
    return(start_cmd);
}



files_t *add_files(u8 *fname, int fsize, int *ret_files) {
    static int      filesi  = 0,
                    filesn  = 0;
    static files_t  *files  = NULL;
    files_t         *ret;

    if(ret_files) {
        *ret_files = filesi;
        files = realloc(files, sizeof(files_t) * (filesi + 1)); // not needed, but it's ok
        if(!files) STD_ERR;
        files[filesi].name   = NULL;
        //files[filesi].offset = 0;
        files[filesi].size   = 0;
        ret    = files;
        filesi = 0;
        filesn = 0;
        files  = NULL;
        return(ret);
    }

    if(!fname) return(NULL);
    if(filter_in_files && (check_wildcard(fname, filter_in_files) < 0)) return(NULL);

    if(filesi >= filesn) {
        filesn += 1024;
        files = realloc(files, sizeof(files_t) * filesn);
        if(!files) STD_ERR;
    }
    files[filesi].name   = mystrdup(fname);
    //files[filesi].offset = 0;
    files[filesi].size   = fsize;
    filesi++;
    return(NULL);
}



int quick_simple_tmpname_scanner(u8 *filedir, int filedirsz) {
    int     plen,
            namelen,
            ret     = -1;
#ifdef WIN32
    u8      *p;
    static int      winnt = -1;
    OSVERSIONINFO   osver;
    WIN32_FIND_DATA wfd;
    HANDLE          hFind = INVALID_HANDLE_VALUE;

    if(winnt < 0) {
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        if(osver.dwPlatformId >= VER_PLATFORM_WIN32_NT) {
            winnt = 1;
        } else {
            winnt = 0;
        }
    }

    p = strrchr(filedir, '.');
    if(p) {
        sprintf(p, ".*");
    } else {
        sprintf(p, "%08x.*", (i32)extracted_files);
    }
    plen = 0;

    if(winnt) { // required to avoid problems with Vista and Windows7!
        hFind = FindFirstFileEx(filedir, FindExInfoStandard, &wfd, FindExSearchNameMatch, NULL, 0);
    } else {
        hFind = FindFirstFile(filedir, &wfd);
    }
    if(hFind == INVALID_HANDLE_VALUE) goto quit;
    do {
        if(!strcmp(wfd.cFileName, ".") || !strcmp(wfd.cFileName, "..")) continue;

        namelen = strlen(wfd.cFileName);
        if((plen + namelen) >= filedirsz) goto quit;
        strcpy(filedir + plen, wfd.cFileName);
        memcpy(filedir + plen, wfd.cFileName, namelen);
        filedir[plen + namelen] = 0;

        if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // no recursion
        } else {
            // file found!
            break;
        }
    } while(FindNextFile(hFind, &wfd));
    ret = 0;

quit:
    if(hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
#else
    // do nothing, not supported
    // you must rename the file as .dat
#endif
    return(ret);
}



int recursive_dir(u8 *filedir, int filedirsz) {
    int     plen,
            namelen,
            ret     = -1;

    if(!filedir) return(ret);
#ifdef WIN32
    static int      winnt = -1;
    OSVERSIONINFO   osver;
    WIN32_FIND_DATA wfd;
    HANDLE          hFind = INVALID_HANDLE_VALUE;

    if(winnt < 0) {
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        if(osver.dwPlatformId >= VER_PLATFORM_WIN32_NT) {
            winnt = 1;
        } else {
            winnt = 0;
        }
    }

    plen = strlen(filedir);
    if((plen + 4) >= filedirsz) goto quit;
    strcpy(filedir + plen, "\\*.*");
    plen++;

    if(winnt) { // required to avoid problems with Vista and Windows7!
        hFind = FindFirstFileEx(filedir, FindExInfoStandard, &wfd, FindExSearchNameMatch, NULL, 0);
    } else {
        hFind = FindFirstFile(filedir, &wfd);
    }
    if(hFind == INVALID_HANDLE_VALUE) goto quit;
    do {
        if(!strcmp(wfd.cFileName, ".") || !strcmp(wfd.cFileName, "..")) continue;

        namelen = strlen(wfd.cFileName);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, wfd.cFileName);
        memcpy(filedir + plen, wfd.cFileName, namelen);
        filedir[plen + namelen] = 0;

        if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + 2, wfd.nFileSizeLow, NULL);
        }
    } while(FindNextFile(hFind, &wfd));
    ret = 0;

quit:
    if(hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
#else
    struct  stat    xstat;
    struct  dirent  **namelist;
    int     n,
            i;

    n = scandir(filedir, &namelist, NULL, NULL);
    if(n < 0) {
        if(stat(filedir, &xstat) < 0) {
            printf("**** %s", filedir);
            STD_ERR;
        }
        add_files(filedir + 2, xstat.st_size, NULL);
        return(0);
    }

    plen = strlen(filedir);
    if((plen + 1) >= filedirsz) goto quit;
    strcpy(filedir + plen, "/");
    plen++;

    for(i = 0; i < n; i++) {
        if(!strcmp(namelist[i]->d_name, ".") || !strcmp(namelist[i]->d_name, "..")) continue;

        namelen = strlen(namelist[i]->d_name);
        if((plen + namelen) >= filedirsz) goto quit;
        //strcpy(filedir + plen, namelist[i]->d_name);
        memcpy(filedir + plen, namelist[i]->d_name, namelen);
        filedir[plen + namelen] = 0;

        if(stat(filedir, &xstat) < 0) {
            printf("**** %s", filedir);
            STD_ERR;
        }
        if(S_ISDIR(xstat.st_mode)) {
            if(recursive_dir(filedir, filedirsz) < 0) goto quit;
        } else {
            add_files(filedir + 2, xstat.st_size, NULL);
        }
        free(namelist[i]);
    }
    ret = 0;

quit:
    for(; i < n; i++) free(namelist[i]);
    free(namelist);
#endif
    filedir[plen - 1] = 0;
    return(ret);
}



u8 *fdload(u8 *fname, int *fsize) {
    struct stat xstat;
    FILE    *fd;
    int     size;
    u8      *buff;

    if(!fname) return(NULL);
    printf("  %s\n", fname);
    fd = fopen(fname, "rb");
    if(!fd) return(NULL);
    fstat(fileno(fd), &xstat);
    size = xstat.st_size;
    buff = malloc(size + 1);
    if(buff) {
        fread(buff, 1, size, fd);
        buff[size] = 0;
    } else {
        size = 0;
    }
    fclose(fd);
    if(fsize) *fsize = size;
    return(buff);
}



void *calldll_alloc(u8 *dump, int dumpsz) {
    int     pagesz;
    void    *ret;

    if(!dump) return(NULL);
    if(dumpsz < 0) return(NULL);
    pagesz = (dumpsz + 4095) & (~4095); // useful for pages? mah

#ifdef WIN32
    ret = VirtualAlloc(
        NULL,
        pagesz,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);    // write for memcpy
#else
    ret = malloc(pagesz);
    mprotect(
        ret,
        pagesz,
        PROT_EXEC | PROT_WRITE);    // write for memcpy
#endif
    memcpy(ret, dump, dumpsz);
    return(ret);
}



#define MAX_DLLS        8
#define MAX_DLL_FUNCS   16
typedef struct {
    u8      *name;
    int     off;
    void    *addr;
} calldllfunc_t;
typedef struct {
    u8      *name;
    HMODULE hlib;
    u8      is_exe;
    u8      is_lib;
    u8      is_mem;
    calldllfunc_t   func[MAX_DLL_FUNCS];
} calldll_t;

int CMD_CallDLL_func(int cmd) {
    static  calldll_t   dll[MAX_DLLS] = {{NULL,NULL,0,0,0,{{NULL,0,NULL}}}};  // cache for multiple dlls/funcs

    static u8   fulldlldir[PATHSZ + 1]; // used only here so don't waste the stack
    HMODULE hlib = NULL;
    void    *args[MAX_ARGS];
    void    *funcaddr   = NULL;
    int     funcoff     = 0,
            argc,
            di,
            dj,
            i,
            n,
            ret;
    u8      ans[16],
            *dllname,
            *callconv,
            *funcname   = NULL,
            *p,
            *mypath     = NULL,
            is_exe      = 0,
            is_lib      = 0,    // alternative of is_dat
            is_mem      = 0;    // remember to replicate in calldll_t!

    if(cmd < 0) {   // useless
        memset(dll, 0, sizeof(dll));
        return(-1);
    }

    dllname     = STR(0);
    funcname    = STR(1);
    if(myisdigitstr(funcname)) {
        funcoff  = myatoi(funcname);
        funcname = NULL;
    }
    callconv    = STR(2);

    if(!strnicmp(dllname, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        is_mem = 1;
    } else {
        p = mystrrchrs(dllname, "\\/");
        if(p) dllname = p;
        p = strrchr(dllname, '.');
        if(p && !stricmp(p, ".exe")) is_exe = 1;    // compiling with "-Wl,--image-base=0x8000000" is not much useful
        if(p && (!stricmp(p, ".exe") || !stricmp(p, ".dll") || !stricmp(p, ".so"))) is_lib = 1; // the others are handled as raw functions
    }

    for(di = 0; di < MAX_DLLS; di++) {
        if(!dll[di].name) continue;
        if(stricmp(dllname, dll[di].name)) continue;
        hlib   = dll[di].hlib;
        is_exe = dll[di].is_exe;
        is_lib = dll[di].is_lib;
        is_mem = dll[di].is_mem;
        for(dj = 0; dj < MAX_DLL_FUNCS; dj++) {
            if(!dll[di].func[dj].addr) continue;
            if(funcname) {
                if(!dll[di].func[dj].name) continue;
                if(stricmp(funcname, dll[di].func[dj].name)) continue;
            } else {
                if(funcoff != dll[di].func[dj].off) continue;
            }
            funcaddr = dll[di].func[dj].addr;
            break;
        }
        break;
    }

    if(!hlib) {
        fgetz(ans, sizeof(ans), stdin,
            "\n"
            "- the script has requested to load a function from the dll\n"
            "  %s\n"
            "%s"
            "  do you want to continue (y/N)? ",
            dllname, is_exe ? "- also note that it's an executable so its working is not guarantee\n" : "");
        if(tolower(ans[0]) != 'y') myexit(-1);

        for(i = 0; ; i++) {
            switch(i) {
                case 0:  mypath = bms_folder;       break;
                case 1:  mypath = current_folder;   break;
                case 2:  mypath = file_folder;      break;
                case 3:  mypath = output_folder;    break;
                case 4:  mypath = exe_folder;       break;
                case 5:  mypath = ".";              break;
                default: mypath = NULL;             break;
            }
            if(!mypath) break;
            n = snprintf(fulldlldir, PATHSZ, "%s%c%s", mypath, PATHSLASH, dllname);
            if((n < 0) || (n >= PATHSZ)) {
                printf("\nError: dll name too long\n");
                myexit(-1);
            }
            if(is_lib) {
                hlib = LOADDLL(fulldlldir);
            } else if(is_mem) {
                hlib = calldll_alloc(   // needed for DEP!
                    memory_file[-get_memory_file(dllname)].data,
                    memory_file[-get_memory_file(dllname)].size);
#ifdef WIN32
                if(hlib && !memcmp(hlib, "MZ", 2)) {
                    hlib = (void *)MemoryLoadLibrary(dllname, (void *)hlib);
                    is_lib = 1;
                }
#endif
            } else {
                p = (void *)fdload(fulldlldir, &ret);
                if(p) {
                    hlib = calldll_alloc(p, ret);   // needed for DEP!
                    free(p);
                }
            }
            if(hlib) break;
        }
        if(!hlib) {
            printf("\nError: file %s has not been found or cannot be loaded\n", dllname);
            myexit(-1);
        }
        printf("- library %s loaded at address %p\n", dllname, hlib);

        for(di = 0; di < MAX_DLLS; di++) {
            if(!dll[di].hlib) break;
        }
        if(di >= MAX_DLLS) {
            printf("\nError: is not possible to use additional dlls or functions\n");
            myexit(-1);
        }
        dll[di].name   = mystrdup(dllname);
        dll[di].hlib   = hlib;
        dll[di].is_exe = is_exe;
        dll[di].is_lib = is_lib;
        dll[di].is_mem = is_mem;
    }
    if(!funcaddr) {
        if(funcname) {
            if(is_lib) {
#ifdef WIN32
                if(is_mem) {
                    funcaddr = (void *)MemoryGetProcAddress(hlib, funcname);
                } else
#endif
                funcaddr = GETFUNC(funcname);
                if(!funcaddr) {
                    quick_var_from_name_check(&funcname, NULL);
                    funcaddr = (void *)myatoi(funcname);
                    funcname = NULL;
                    funcoff  = (void *)funcaddr - (void *)hlib;
                }
            } else {
                printf("\nError: the input library is handled as raw data so can't have a function name\n");
                myexit(-1);
            }
        } else {
            funcaddr = (void *)((u8 *)(hlib) + funcoff);
        }
        /* maybe in future
#ifdef WIN32
        if(!funcaddr && funcname && is_mem) {
            p = mymangle(funcname);
            if(p) {
                funcaddr = (void *)MemoryGetProcAddress(hlib, p);
                free(p);
            }
        }
#endif
        */
        if(!funcaddr) {
            printf("\nError: function not found\n");
            myexit(-1);
        }
        printf("- function found at offset %p\n", funcaddr);

        for(dj = 0; dj < MAX_DLLS; dj++) {
            if(!dll[di].func[dj].addr) break;
        }
        if(dj >= MAX_DLL_FUNCS) {
            printf("\nError: is not possible to use additional dlls or functions\n");
            myexit(-1);
        }
        if(funcname) {
            dll[di].func[dj].name = mystrdup(funcname);
            dll[di].func[dj].off  = 0;
        } else {
            dll[di].func[dj].name = NULL;
            dll[di].func[dj].off  = funcoff;
        }
        dll[di].func[dj].addr = funcaddr;
    }

    argc = NUM(0);
    if(argc < 0) argc = 0;
    memset(&args, 0, sizeof(args));
    for(i = 0; i < argc; i++) { // wow, looks chaotic?
        n = CMD.var[4 + i];
        if(n < 0) {    // MEMORY_FILE
            n = -n;
            args[i] = (void *)memory_file[n].data + memory_file[n].pos;
        } else {
            if(var_is_a_string(n)) {
                args[i] = (void *)get_var(n);
            } else {
                if(CMD.num[4 + i]) {    // &var
                    args[i] = (void *)&variable[n].value32;
                } else {
                    args[i] = (void *)get_var32(n);
                }
            }
        }
    }

    // horrible? yes, but avoids asm work-arounds and works perfectly
    // note that the arguments of the function prototypes don't seem necessary
    // but I have decided to leave them for maximum compatibility
#define CALLDLL_FUNC(X) \
        switch(argc) { \
            case 0: { \
                __##X int (*function0_##X)(void) = (void *)funcaddr; \
                ret = function0_##X(); \
                break; } \
            case 1: { \
                __##X int (*function1_##X)(void*) = (void *)funcaddr; \
                ret = function1_##X(args[0]); \
                break; } \
            case 2: { \
                __##X int (*function2_##X)(void*,void*) = (void *)funcaddr; \
                ret = function2_##X(args[0], args[1]); \
                break; } \
            case 3: { \
                __##X int (*function3_##X)(void*,void*,void*) = (void *)funcaddr; \
                ret = function3_##X(args[0], args[1], args[2]); \
                break; } \
            case 4: { \
                __##X int (*function4_##X)(void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function4_##X(args[0], args[1], args[2], args[3]); \
                break; } \
            case 5: { \
                __##X int (*function5_##X)(void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function5_##X(args[0], args[1], args[2], args[3], args[4]); \
                break; } \
            case 6: { \
                __##X int (*function6_##X)(void*,void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function6_##X(args[0], args[1], args[2], args[3], args[4], args[5]); \
                break; } \
            case 7: { \
                __##X int (*function7_##X)(void*,void*,void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function7_##X(args[0], args[1], args[2], args[3], args[4], args[5], args[6]); \
                break; } \
            case 8: { \
                __##X int (*function8_##X)(void*,void*,void*,void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function8_##X(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); \
                break; } \
            case 9: { \
                __##X int (*function9_##X)(void*,void*,void*,void*,void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function9_##X(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]); \
                break; } \
            case 10: { \
                __##X int (*function10_##X)(void*,void*,void*,void*,void*,void*,void*,void*,void*,void*) = (void *)funcaddr; \
                ret = function10_##X(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]); \
                break; } \
            default: { \
                printf("\nError: this tool doesn't support all these arguments for the dll functions ("#X")\n"); \
                myexit(-1); \
            } \
        }
#define CALLDLL_FUNC2(X) \
        switch(argc) { \
            case 0:  ret = X##_call(funcaddr, argc); break; \
            case 1:  ret = X##_call(funcaddr, argc, args[0]); break; \
            case 2:  ret = X##_call(funcaddr, argc, args[0], args[1]); break; \
            case 3:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2]); break; \
            case 4:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3]); break; \
            case 5:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4]); break; \
            case 6:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4], args[5]); break; \
            case 7:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4], args[5], args[6]); break; \
            case 8:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); break; \
            case 9:  ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]); break; \
            case 10: ret = X##_call(funcaddr, argc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]); break; \
            default: { \
                printf("\nError: this tool doesn't support all these arguments for the dll functions ("#X")\n"); \
                myexit(-1); \
            } \
        }

    ret = 0;
    if(stristr(callconv, "stdcall") || stristr(callconv, "winapi")) {   // thiscall on VC++
        CALLDLL_FUNC(stdcall)
    } else if(stristr(callconv, "cdecl")) { // thiscall on gcc
        CALLDLL_FUNC(cdecl)
#if defined(i386) || defined(IA64)
    } else if(stristr(callconv, "thiscall")) {
        CALLDLL_FUNC2(thiscall)
    } else if(stristr(callconv, "fastcall") || stristr(callconv, "msfastcall")) {
#ifdef __fastcall
        CALLDLL_FUNC(fastcall)
#else
        CALLDLL_FUNC2(msfastcall)
#endif
    } else if(stristr(callconv, "borland") || stristr(callconv, "delphi") || stristr(callconv, "register")) {
        CALLDLL_FUNC2(borland)
    } else if(stristr(callconv, "watcom")) {
        CALLDLL_FUNC2(watcom)
    } else if(stristr(callconv, "pascal")) {
        CALLDLL_FUNC2(pascal)
    } else if(stristr(callconv, "safecall")) {
        CALLDLL_FUNC2(safecall)
    } else if(stristr(callconv, "syscall") || stristr(callconv, "OS/2")) {
        CALLDLL_FUNC2(syscall)
    } else if(stristr(callconv, "optlink") || stristr(callconv, "VisualAge")) {
        CALLDLL_FUNC2(optlink)
    } else if(stristr(callconv, "clarion") || stristr(callconv, "TopSpeed") || stristr(callconv, "JPI")) {
        CALLDLL_FUNC2(clarion)
#endif
    } else {
        printf("\nError: calling convention %s not supported\n", callconv);
        myexit(-1);
    }

    if(!variable[CMD.var[3]].constant) {
        add_var(CMD.var[3], NULL, NULL, ret, sizeof(int));
    }

    //CLOSEDLL; // never call it!
    return(0);
}



int CMD_ScanDir_func(int cmd) {
    static u8   filedir[PATHSZ + 1] = "";
    static int  total_files         = -1;
    static int  curr_file           = 0;
    static files_t *files           = NULL;
    int     i;
    u8      *path;

    path    = VAR(0);
    if(!path) return(-1);
    if(!filedir[0]) {
        //if(strcmp(path, ".")) {
            //printf("\nError: at the moment the ScanDir function accepts only the \".\" as scan path\n");
            //myexit(-1);
        //}
        mystrcpy(filedir, path, PATHSZ);
        recursive_dir(filedir, PATHSZ);
        files = add_files(NULL, 0, &total_files);
        curr_file = 0;
    }
    if(curr_file < total_files) {
        add_var(CMD.var[1], NULL, files[curr_file].name, 0, -1);
        add_var(CMD.var[2], NULL, NULL, files[curr_file].size, sizeof(int));
        curr_file++;
    } else {
        add_var(CMD.var[1], NULL, "", 0, -1);
        add_var(CMD.var[2], NULL, NULL, -1, sizeof(int));
        if(files) {
            for(i = 0; i < total_files; i++) {
                FREEZ(files[i].name)
            }
            FREEZ(files)
        }
        filedir[0] = 0;
        total_files = -1;
    }
    return(0);
}



int CMD_Put_func(int cmd) {
    int     fd,
            type;

    fd   = FILEZ(2);
    type = NUM(1);
    if(verbose < 0) printf(". %08x put     %-10s 0x%08x %d\n", (i32)myftell(fd), get_varname(CMD.var[0]), (i32)NUM(2), (i32)type);
    if(myfwx(fd, CMD.var[0], type) < 0) return(-1);
    return(0);
}



int CMD_PutDString_func(int cmd) {
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    int     fd,
            size,
            datasz;
    u8      *data;

    fd   = FILEZ(2);
    size = VAR32(1);
    if(size == -1) ALLOC_ERR;
    data   = VAR(0);
    //datasz = 0;
    //if(data) datasz = strlen(data);
    //if(datasz > size) datasz = size;
    datasz = VARSZ(0);
    if(size < datasz) datasz = size;

    // alternative method (simpler but uses full allocated buff)
    //myalloc(&buff, size, &buffsz);
    //memcpy(buff, data, datasz);
    //if(size > datasz) memset(buff + datasz, 0, size - datasz);
    //if(myfw(fd, buff, size) < 0) return(-1);

    if(verbose < 0) printf(". %08x putdstr %-10s \"%.*s\" %d\n", (i32)myftell(fd), get_varname(CMD.var[0]), (i32)datasz, data, (i32)datasz);
    if(myfw(fd, data, datasz) < 0) return(-1);
    if(size > datasz) { // fill with zeroes, I avoided to use myfputc(0x00, fd);
        size -= datasz;
        myalloc(&buff, size, &buffsz);
        memset(buff, 0, size);
        if(myfw(fd, buff, size) < 0) return(-1);
    }
    return(0);
}



int CMD_PutCT_func(int cmd) {
    int     fd;

    fd = FILEZ(3);
    //if(NUM(1) < 0) {
        // ok
    //} else {
        //printf("\nError: PutCT is supported only with String type\n");
        //myexit(-1);
    //}
    if(verbose < 0) printf(". %08x putct   %-10s \"%.*s\"\n", (i32)myftell(fd), get_varname(CMD.var[0]), (i32)VAR32(2), VAR(0));
    if(fputss(fd, VAR(0), VAR32(2), (NUM(1) == TYPE_UNICODE) ? 1 : 0, 0) < 0) return(-1);
    return(0);
}



// the rule is simple: start_bms is executed for EACH recursive command like do, for, if
int start_bms(int startcmd, int nop, int *ret_break) {
#define NEW_START_BMS(B,X,Y) \
    cmd = B(X, Y, ret_break); \
    if(cmd < 0) goto quit_error; \
    if(*ret_break) { \
        *ret_break = 0; \
        nop = 1; \
    }

    int     cmd,
            tmp;
    u8      *error  = NULL;

    if(startcmd < 0) {
        cmd = 0;    // needed because it's the beginning
    } else {
        cmd = startcmd;
    }
    if(verbose > 0) printf("             .start_bms start: %d %d %d\n", (i32)startcmd, (i32)nop, (i32)*ret_break);
    for(; CMD.type != CMD_NONE; cmd++) {
        //if(verbose && CMD.debug_line) printf("\n%08x %s%s\n", (i32)myftell(filenumber[0]), CMD.debug_line, nop ? " (SKIP)" : "");
        if((verbose > 0) && CMD.debug_line && !nop) {
            printf("\n%08x %s\n", filenumber[0].fd ? (i32)myftell(0) : 0, CMD.debug_line);
        }

        switch(CMD.type) {
            case CMD_For: {
                //if(nop) break;
                //if(verbose < 0) printf(".\n");  // useful
                NEW_START_BMS(start_bms, cmd + 1, nop)
                break;
            }
            case CMD_Next: {
                if(nop) goto quit;
                if(verbose < 0) printf(".\n");  // useful
                if(CMD_Next_func(cmd) < 0) goto quit_error;
                if(startcmd >= 0) cmd = startcmd - 1;   // due to "cmd++"
                break;
            }
            case CMD_ForTo: {
                if(nop) break;
                //if(verbose < 0) printf(".\n");  // useful
                if(check_condition(cmd) < 0) nop = 1;
                break;
            }
            case CMD_Get: {
                if(nop) break;
                if(CMD_Get_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_GetDString: {
                if(nop) break;
                if(CMD_GetDString_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_GoTo: {
                if(nop) break;
                if(CMD_GoTo_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_IDString: {
                if(nop) break;
                if(CMD_IDString_func(cmd) < 0) {
                    error = "the signature doesn't match";        
                    goto quit_error;
                }
                break;
            }
            case CMD_Log: {
                if(nop) break;
                if(CMD_Log_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_CLog: {
                if(nop) break;
                if(CMD_CLog_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Math: {
                if(nop) break;
                if(CMD_Math_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_SavePos: {
                if(nop) break;
                if(CMD_SavePos_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Set: {
                if(nop) break;
                if(CMD_Set_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_String: {
                if(nop) break;
                if(CMD_String_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_If: {
                //if(nop) break;
                tmp = 0;
                do {
                    if(!tmp && !check_condition(cmd)) {
                        NEW_START_BMS(start_bms, cmd + 1, nop)
                        tmp = 1;
                    } else {
                        NEW_START_BMS(start_bms, cmd + 1, 1)
                    }
                } while(CMD.type != CMD_EndIf);
                break;
            }
            case CMD_Elif: {
                if(nop) goto quit;
                goto quit;
                break;
            }
            case CMD_Else: {
                if(nop) goto quit;
                goto quit;
                break;
            }
            case CMD_EndIf: {
                if(nop) goto quit;
                goto quit;
                break;
            }
            case CMD_GetCT: {
                if(nop) break;
                if(CMD_GetCT_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ComType: {
                if(nop) break;
                if(CMD_ComType_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Open: {
                if(nop) break;
                if(CMD_Open_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ReverseShort: {
                if(nop) break;
                if(CMD_ReverseShort_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ReverseLong: {
                if(nop) break;
                if(CMD_ReverseLong_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ReverseLongLong: {
                if(nop) break;
                if(CMD_ReverseLongLong_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Endian: {
                if(nop) break;
                endian = NUM(0);
                break;
            }
            case CMD_FileXOR: {
                if(nop) break;
                if(CMD_FileXOR_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_FileRot13: {
                if(nop) break;
                if(CMD_FileRot13_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_FileCrypt: {
                if(nop) break;
                if(CMD_FileCrypt_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Break: {
                if(nop) break;  // like cleanexit, don't touch
                nop = 1;
                *ret_break = 1;
                break;
            }
            case CMD_GetVarChr: {
                if(nop) break;
                if(CMD_GetVarChr_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_PutVarChr: {
                if(nop) break;
                if(CMD_PutVarChr_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Append: {
                if(nop) break;
                append_mode = !append_mode;
                break;
            }
            case CMD_Encryption: {
                if(nop) break;
                if(CMD_Encryption_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_GetArray: {
                if(nop) break;
                if(CMD_GetArray_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_PutArray: {
                if(nop) break;
                if(CMD_PutArray_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_StartFunction: {
                //if(nop) break;
                NEW_START_BMS(CMD_Function_func, cmd, 1)
                break;
            }
            case CMD_CallFunction: {
                if(nop) break;
                if(verbose < 0) printf(".\n");  // useful
                NEW_START_BMS(CMD_Function_func, cmd, nop)
                break;
            }
            case CMD_EndFunction: {
                if(nop) goto quit;
                goto quit;
                break;
            }
            case CMD_Debug: {
                //if(nop) break;
                //verbose = !verbose;
                if(CMD_Debug_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Padding: {
                if(nop) break;
                if(CMD_Padding_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ScanDir: {
                if(nop) break;
                if(CMD_ScanDir_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_CallDLL: {
                if(nop) break;
                if(CMD_CallDLL_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Put: {
                if(nop) break;
                if(CMD_Put_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_PutDString: {
                if(nop) break;
                if(CMD_PutDString_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_PutCT: {
                if(nop) break;
                if(CMD_PutCT_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Strlen: {
                if(nop) break;
                if(CMD_Strlen_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_Do: {
                //if(nop) break;
                if(verbose < 0) printf(".\n");  // useful
                NEW_START_BMS(start_bms, cmd + 1, nop)
                break;
            }
            case CMD_While: {
                if(nop) goto quit;
                if(check_condition(cmd) < 0) goto quit;
                if(startcmd >= 0) cmd = startcmd - 1;     // due to "cmd++"
                break;
            }
            case CMD_Print: {
                if(nop) break;
                if(CMD_Print_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_FindLoc: {
                if(nop) break;
                if(CMD_FindLoc_func(cmd) < 0) {
                    error = "the searched string has not been found";
                    goto quit_error;
                }
                break;
            }
            case CMD_GetBits: {
                if(nop) break;
                if(CMD_GetBits_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_PutBits: {
                if(nop) break;
                if(CMD_PutBits_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_ImpType: {
                if(nop) break;
                if(CMD_ImpType_func(cmd) < 0) goto quit_error;
                break;
            }
            case CMD_CleanExit: {
                if(nop) break;  // don't touch
                error = "invoked the termination of the extraction (CleanExit)";
                goto quit_error;
                break;
            }
            case CMD_NOP: {
                if(nop) break;
                // no operation, do nothing
                break;
            }
            default: {
                printf("\nError: invalid command %d\n", (i32)CMD.type);
                myexit(-1);
                break;
            }
        }
    }
    return(-1); // CMD_NONE
quit_error:
    if(verbose > 0) printf("\nError: %s\n", error ? error : (u8 *)"something wrong during the extraction");
    //myexit(-1);
    return(-1);
quit:
    if(verbose > 0) printf("             .start_bms end: %d %d %d (ret %d)\n", (i32)startcmd, (i32)nop, (i32)*ret_break, (i32)cmd);
    return(cmd);
}



void set_quickbms_arg(u8 *quickbms_arg) {
    int     i,
            argc;
    u8      tmp[64],
            *argument[MAX_ARGS + 1] = { NULL };

    if(!quickbms_arg) return;
    argc = bms_line(NULL, quickbms_arg, argument, NULL);
    for(i = 0; i < argc; i++) {
        sprintf(tmp, "quickbms_arg%d", (i32)i + 1);
        add_var(0, tmp, ARG[i], 0, -1);
    }
}



// zlib + base64
u8 *type_decompress(u8 *str, int *ret_len) {
    int     len,
            tmp;
    i32     t32;
    u8      *ret;

    if(ret_len) *ret_len = 0;
    if(!str) goto quit;
    len = unbase64(str, -1, str, -1);   // use the same buffer
    if(len < 0) goto quit;  //return(str)
    tmp = 0;
    ret = NULL;
    t32 = tmp;
    len = unzip_dynamic(str, len, &ret, &t32);
    tmp = t32;
    if(len < 0) goto quit;  //return(str)
    if(ret_len) *ret_len = len;
    return(ret);
quit:
    printf("\nError: failed Set type decompression, recheck your script\n");
    myexit(-1);
    return(NULL);
}



int c_structs(u8 *argument[MAX_ARGS + 1], int argc) {
typedef struct {
    u8  *old;
    u8  *new;
} define_t;
    static u8       tmp[64] = "";
    static int      defines = 0;
    static define_t *define = NULL;

    int     i,
            type    = TYPE_NONE,
            array   = 0,
            put     = 0;
    u8      *p;

    if(argc <= 0) {
        ARG[0] = "NOP";
        goto quit;
    }

    while(
      !stricmp(ARG[0], "unsigned") ||
      !stricmp(ARG[0], "signed") ||
      !stricmp(ARG[0], "const") ||
      !stricmp(ARG[0], "static") ||
      !stricmp(ARG[0], "local") ||
      !stricmp(ARG[0], "global") ||
      !stricmp(ARG[0], "volatile")
    ) {
        for(i = 1; i <= argc; i++) {
            ARG[i - 1] = ARG[i];
        }
        argc--;
    }

    if(!stricmp(ARG[1], "int")) {
        for(i = 2; i <= argc; i++) {
            ARG[i - 1] = ARG[i];
        }
        argc--;
    }

    if(!stricmp(ARG[1], "*")) {
        for(i = 2; i <= argc; i++) {
            ARG[i - 1] = ARG[i];
        }
        argc--;
        array = -1;
    }

    if(!stricmp(ARG[0], "struct") || !stricmp(ARG[1], "struct")) {
        ARG[0] = "NOP";
        argc = 0;
        goto quit;
    }

    if(!stricmp(ARG[0], "#define") || !stricmp(ARG[0], "define")) {
        define = realloc(define, (defines + 1) * sizeof(define_t));
        define[defines].new = mystrdup(ARG[1]);
        define[defines].old = mystrdup(ARG[2]);
        defines++;
        ARG[0] = "NOP";
        argc = 0;
        goto quit;
    }

    if(!stricmp(ARG[0], "typedef")) {
        define = realloc(define, (defines + 1) * sizeof(define_t));
        define[defines].old = mystrdup(ARG[1]);
        define[defines].new = mystrdup(ARG[2]);
        defines++;
        ARG[0] = "NOP";
        argc = 0;
        goto quit;
    }

    for(i = 0; i < defines; i++) {
        if(!stricmp(ARG[0], define[i].new)) {
            ARG[0] = define[i].old;
            break;
        }
    }

    p = strchr(ARG[0], '*');
    if(p) {
        *p = 0;
        array = -1;
    }

    p = strchr(ARG[1], '*');
    if(p) {
        p++;
        for(i = 0;; i++) {
            ARG[1][i] = p[i];
            if(!p[i]) break;
        }
        array = -1;
    }

    p = strchr(ARG[1], ':');
    if(p) {
        *p++ = 0;
        array = atoi(p);
        ARG[0] = "bits";
    }

    p = strchr(ARG[1], '=');
    if(p) {
        put = 1;
        *p++ = 0;
        while(*p <= ' ') p++;
        for(i = 0;; i++) {
            ARG[1][i] = p[i];
            if(!p[i]) break;
        }
    }

    while(ARG[0][0] == '_') {
        p = ARG[0] + 1;
        for(i = 0;; i++) {
            ARG[0][i] = p[i];
            if(!p[i]) break;
        }
    }

    if(!strncmp(ARG[0], "LP", 2)) {          // LPVOID
        p = ARG[0] + 2;
        for(i = 0;; i++) {
            ARG[0][i] = p[i];
            if(!p[i]) break;
        }
        array = -1;
    } else if(!strncmp(ARG[0], "P", 1)) {    // PCHAR, PLONG
        p = ARG[0] + 1;
        for(i = 0;; i++) {
            ARG[0][i] = p[i];
            if(!p[i]) break;
        }
        array = -1;
    }

    p = strchr(ARG[1], '[');
    if(p) {
        *p++ = 0;
        array = myatoi(p);
    }

    if((argc >= 2) && !stricmp(ARG[2], "=")) {
        for(i = 3; i <= argc; i++) {
            ARG[i - 2] = ARG[i];
        }
        argc -= 2;
        put = 1;
    }

    if(
        !stricmp(ARG[0], "8") ||
        !stricmp(ARG[0], "8bit") ||
        !stricmp(ARG[0], "byte") ||
        !stricmp(ARG[0], "ubyte") ||
        !stricmp(ARG[0], "char") ||
        !stricmp(ARG[0], "cchar") ||
        !stricmp(ARG[0], "tchar") ||
        !stricmp(ARG[0], "uchar") ||
        !stricmp(ARG[0], "u_char") ||
        !stricmp(ARG[0], "uint8_t") ||
        !stricmp(ARG[0], "uint8") ||
        !stricmp(ARG[0], "int8_t") ||
        !stricmp(ARG[0], "int8") ||
        !stricmp(ARG[0], "u8") ||
        !stricmp(ARG[0], "i8") ||
        !stricmp(ARG[0], "si8") ||
        !stricmp(ARG[0], "ui8") ||
        !stricmp(ARG[0], "ch") ||
        !stricmp(ARG[0], "tch") ||
        !stricmp(ARG[0], "str") ||
        !stricmp(ARG[0], "sz") ||
        !stricmp(ARG[0], "ctstr") ||
        !stricmp(ARG[0], "tstr") ||
        !stricmp(ARG[0], "fchar")
    ) {
        type = TYPE_BYTE;
    } else if(
        !stricmp(ARG[0], "16") ||
        !stricmp(ARG[0], "16bit") ||
        !stricmp(ARG[0], "word") ||
        !stricmp(ARG[0], "short") ||
        !stricmp(ARG[0], "ushort") ||
        !stricmp(ARG[0], "u_short") ||
        !stricmp(ARG[0], "uint16_t") ||
        !stricmp(ARG[0], "uint16") ||
        !stricmp(ARG[0], "int16_t") ||
        !stricmp(ARG[0], "int16") ||
        !stricmp(ARG[0], "u16") ||
        !stricmp(ARG[0], "i16") ||
        !stricmp(ARG[0], "si16") ||
        !stricmp(ARG[0], "ui16") ||
        !stricmp(ARG[0], "fixed8") ||
        !stricmp(ARG[0], "float16") ||
        !stricmp(ARG[0], "wchar") ||
        !stricmp(ARG[0], "wchar_t") ||
        !stricmp(ARG[0], "wch") ||
        !stricmp(ARG[0], "wstr") ||
        !stricmp(ARG[0], "fshort")
    ) {
        type = TYPE_SHORT;
    } else if(
        !stricmp(ARG[0], "32") ||
        !stricmp(ARG[0], "32bit") ||
        !stricmp(ARG[0], "dword") ||
        !stricmp(ARG[0], "unsigned") ||
        !stricmp(ARG[0], "int") ||
        !stricmp(ARG[0], "uint") ||
        !stricmp(ARG[0], "u_int") ||
        !stricmp(ARG[0], "long") ||
        !stricmp(ARG[0], "u_long") ||
        !stricmp(ARG[0], "uint32_t") ||
        !stricmp(ARG[0], "uint32") ||
        !stricmp(ARG[0], "int32_t") ||
        !stricmp(ARG[0], "int32") ||
        !stricmp(ARG[0], "u32") ||
        !stricmp(ARG[0], "i32") ||
        !stricmp(ARG[0], "si32") ||
        !stricmp(ARG[0], "ui32") ||
        !stricmp(ARG[0], "fixed") ||
        !stricmp(ARG[0], "bool") ||
        !stricmp(ARG[0], "void") ||
        !stricmp(ARG[0], "handle") ||
        !stricmp(ARG[0], "flong")
    ) {
        type = TYPE_LONG;
    } else if(
        !stricmp(ARG[0], "64") ||
        !stricmp(ARG[0], "64bit") ||
        !stricmp(ARG[0], "longlong") ||
        !stricmp(ARG[0], "ulonglong") ||
        !stricmp(ARG[0], "u_longlong") ||
        !stricmp(ARG[0], "uint64_t") ||
        !stricmp(ARG[0], "uint64") ||
        !stricmp(ARG[0], "int64_t") ||
        !stricmp(ARG[0], "int64") ||
        !stricmp(ARG[0], "u64") ||
        !stricmp(ARG[0], "i64") ||
        !stricmp(ARG[0], "si64") ||
        !stricmp(ARG[0], "ui64") ||
        !stricmp(ARG[0], "void64")
    ) {
        type = TYPE_LONGLONG;
    } else if(
        !stricmp(ARG[0], "float")
    ) {
        type = TYPE_FLOAT;
    } else if(
        !stricmp(ARG[0], "double")
    ) {
        type = TYPE_DOUBLE;
    } else if(
        !stricmp(ARG[0], "encodedu32") ||
        !stricmp(ARG[0], "encoded")
    ) {
        type = TYPE_VARIABLE;
    } else if(
        !stricmp(ARG[0], "bits") ||
        !stricmp(ARG[0], "sb") ||
        !stricmp(ARG[0], "ub") ||
        !stricmp(ARG[0], "fb")
    ) {
        type = TYPE_BITS;
    } else {
        //return(argc);
        type = TYPE_LONG;
    }

    if(array < 0) {
        ARG[0] = put ? "put" : "get";
        // ARG[1] is ok
        ARG[2] = "string";
        argc = 2;
        goto quit;
    }

    if(array > 0) {
        if(type == TYPE_BITS) {
            ARG[0] = put ? "putbits" : "getbits";
            // ARG[1] is ok
            sprintf(tmp, "%u", (i32)array);
            ARG[2] = tmp;
            argc = 2;
            goto quit;
        }
        ARG[0] = put ? "putdstring" : "getdstring";
        // ARG[1] is ok
        switch(type) {
            case TYPE_BYTE:     sprintf(tmp, "%u", (i32)array * 1); break;
            case TYPE_SHORT:    sprintf(tmp, "%u", (i32)array * 2); break;
            case TYPE_LONG:     sprintf(tmp, "%u", (i32)array * 4); break;
            case TYPE_LONGLONG: sprintf(tmp, "%u", (i32)array * 8); break;
            case TYPE_FLOAT:    sprintf(tmp, "%u", (i32)array * 4); break;
            case TYPE_DOUBLE:   sprintf(tmp, "%u", (i32)array * 8); break;
            default:            sprintf(tmp, "%u", (i32)array * 4); break;
        }
        ARG[2] = tmp;
        argc = 2;
        goto quit;
    }

        ARG[0] = put ? "put" : "get";
        // ARG[1] is ok
        switch(type) {
            case TYPE_BYTE:     sprintf(tmp, "byte");       break;
            case TYPE_SHORT:    sprintf(tmp, "short");      break;
            case TYPE_LONG:     sprintf(tmp, "long");       break;
            case TYPE_LONGLONG: sprintf(tmp, "longlong");   break;
            case TYPE_FLOAT:    sprintf(tmp, "float");      break;
            case TYPE_DOUBLE:   sprintf(tmp, "double");     break;
            case TYPE_VARIABLE: sprintf(tmp, "variable");   break;
            default:            sprintf(tmp, "long");       break;
        }
        ARG[2] = tmp;
        argc = 2;
        goto quit;

quit:
    ARG[argc + 1] = "";
    return(argc);
}



int parse_bms(FILE *fds) {
    int     i,
            cmd,
            argc,
            c_structs_do;
    u8      *debug_line = NULL,
            *argument[MAX_ARGS + 1] = { NULL },
            *tmp;

    cmd = 0;
    for(;;) {       // do NOT use "continue;"!
        if(cmd >= MAX_CMDS) {
            printf("\nError: the BMS script uses more commands than how much supported by this tool\n");
            myexit(-1);
        }
        argc = bms_line(fds, NULL, argument, &debug_line);
        if(argc < 0) break; // means "end of file"
        if(!argc) continue; // means "no command", here is possible to use "continue"

        argc--; // remove command argument
        // remember that myatoi is used only for the file number, all the rest must be add_var

        c_structs_do = 1;
redo:
               if(!stricmp(ARG[0], "QuickBMSver")   && (argc >= 1)) {
            CMD.type   = CMD_NOP;
            if(calc_quickbms_version(ARG[1]) > quickbms_version) {
                printf("\n"
                    "Error: this script has been created for a newer version of QuickBMS (%s),\n"
                    "       you can download it from:\n"
                    "\n"
                    "         http://aluigi.org/quickbms\n"
                    "\n", ARG[1]);
                myexit(-1);
            }

        } else if(!stricmp(ARG[0], "CLog")          && (argc >= 4)) {
            CMD.type   = CMD_CLog;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // name
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // offset
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // compressed size
            CMD.var[3] = -1;                                    // offsetoffset
            CMD.var[4] = -1;                                    // resourcesizeoffset
            CMD.var[6] = -1;                                    // uncompressedsizeoffset
            if(argc >= 6) {
                CMD.var[5] = add_var(0, ARG[6], NULL, 0, -2);   // uncompressedsize
                CMD.num[7] = myatoifile(ARG[8]);                // filenumber
            } else {
                CMD.var[5] = add_var(0, ARG[4], NULL, 0, -2);   // uncompressedsize
                CMD.num[7] = myatoifile(ARG[5]);                // filenumber
            }

        } else if(
                 (!stricmp(ARG[0], "Do")            && (argc >= 0))
              || (!stricmp(ARG[0], "Loop")          && (argc >= 0))) {  // mex inifile (not BMS)
            CMD.type   = CMD_Do;

        } else if(!stricmp(ARG[0], "FindLoc")       && (argc >= 3)) {
            CMD.type   = CMD_FindLoc;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var
            CMD.num[1] = add_datatype(ARG[2]);                  // datatype
            CSTRING(2, ARG[3])                                  // text/number
            if(argc >= 4) {
                if(!ARG[4][0]) {    // a typical mistake that I do too!
                    CMD.num[3] = 0;
                    CMD.str[4] = mystrdup(ARG[4]);
                } else {
                    CMD.num[3] = myatoifile(ARG[4]);            // filenumber
                    CMD.str[4] = mystrdup(ARG[5]);              // optional/experimental: the value you want to return in case the string is not found
                }
            } else {
                CMD.num[3] = 0;                                 // filenumber
                CMD.str[4] = NULL;                              // optional/experimental: the value you want to return in case the string is not found
            }

        } else if(!stricmp(ARG[0], "FindFileID")    && (argc >= 2)) {   // mex inifile (not BMS)
            CMD.type   = CMD_FindLoc;
            CMD.var[0] = add_var(0, ARG[2], NULL, 0, -2);       // var
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.str[2] = mystrdup(ARG[1]);                      // text/number
            CMD.num[3] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "For")           && (argc >= 0)) {
            if(argc >= 3) {
                CMD.type   = CMD_Math;
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // VarName
                CMD.num[1] = ARG[2][0];                         // operation
                CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);   // Var/Number
                cmd++;
            }

            CMD.type   = CMD_For;   // yes, no arguments, this is the new way

            if(argc >= 5) {
                cmd++;
                CMD.type   = CMD_ForTo;
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // T
                                                                // = T_value (check later, it must be check_condition compatible)
                if(!stricmp(ARG[4], "To")) {                    // To
                    CMD.str[1] = mystrdup("<=");
                } else {
                    CMD.str[1] = mystrdup(ARG[4]);
                }
                CMD.var[2] = add_var(0, ARG[5], NULL, 0, -2);   // To_value
                //CMD.var[3] = add_var(0, ARG[3], NULL, 0, -2);  // T_value (not used)
            }

        } else if(!stricmp(ARG[0], "Get")           && (argc >= 2)) {
            CMD.type   = CMD_Get;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype(ARG[2]);                  // type
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber
            if(CMD.num[1] == TYPE_BITS) {
                CMD.type   = CMD_GetBits;
                //CMD.var[0] is ok
                CMD.var[1] = myatoi(ARG[2]);
            }

        } else if(!stricmp(ARG[0], "GetBits")       && (argc >= 2)) {
            CMD.type   = CMD_GetBits;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // bits
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "PutBits")       && (argc >= 2)) {
            CMD.type   = CMD_PutBits;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // bits
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "Put")           && (argc >= 2)) {   // write mode
            CMD.type   = CMD_Put;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype(ARG[2]);                  // type
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber
            if(CMD.num[1] == TYPE_BITS) {
                CMD.type   = CMD_PutBits;
                //CMD.var[0] is ok
                CMD.var[1] = myatoi(ARG[2]);
            }

        } else if(!stricmp(ARG[0], "GetLong")       && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Get;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype("Long");                  // type
            CMD.num[2] = myatoifile(ARG[2]);                    // filenumber

        } else if(!stricmp(ARG[0], "GetInt")        && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Get;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype("Int");                   // type
            CMD.num[2] = myatoifile(ARG[2]);                    // filenumber

        } else if(!stricmp(ARG[0], "GetByte")       && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Get;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype("Byte");                  // type
            CMD.num[2] = myatoifile(ARG[2]);                    // filenumber

        } else if(!stricmp(ARG[0], "GetString")     && (argc >= 2)) {   // mex inifile (not BMS)
            CMD.type   = CMD_GetDString;
            CMD.var[0] = add_var(0, ARG[2], NULL, 0, -2);       // varname
            CMD.var[1] = add_var(0, ARG[1], NULL, 0, -2);       // NumberOfCharacters
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "GetNullString") && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Get;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.num[1] = add_datatype("String");                // type
            CMD.num[2] = myatoifile(ARG[2]);                    // filenumber

        } else if(!stricmp(ARG[0], "GetDString")    && (argc >= 2)) {
            CMD.type   = CMD_GetDString;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // NumberOfCharacters
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "PutDString")    && (argc >= 2)) {   // write mode
            CMD.type   = CMD_PutDString;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // varname
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // NumberOfCharacters
            CMD.num[2] = myatoifile(ARG[3]);                    // filenumber

        } else if(!stricmp(ARG[0], "GoTo")          && (argc >= 1)) {
            CMD.type   = CMD_GoTo;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // pos
            CMD.num[1] = myatoifile(ARG[2]);                    // file
            CMD.num[2] = SEEK_SET;
            if(argc >= 3) {
                     if(stristr(ARG[3], "SET")) CMD.num[2] = SEEK_SET;
                else if(stristr(ARG[3], "CUR")) CMD.num[2] = SEEK_CUR;
                else if(stristr(ARG[3], "END")) CMD.num[2] = SEEK_END;
            }

        } else if(
                  (!stricmp(ARG[0], "IDString")     && (argc >= 1))
               || (!stricmp(ARG[0], "ID")           && (argc >= 1))) {  // mex inifile (not BMS)
            CMD.type   = CMD_IDString;
            if(argc == 1) {
                CMD.num[0] = 0;
                CSTRING(1, ARG[1])                              // string
            } else {
                CMD.num[0] = myatoifile(ARG[1]);                // filenumber
                if(CMD.num[0] == MAX_FILES) {                   // simple work-around to avoid the different syntax of idstring
                    CSTRING(1, ARG[1])                          // string
                    CMD.num[0] = myatoifile(ARG[2]);
                } else {
                    CSTRING(1, ARG[2])                          // string
                    // CMD.num[0] = myatoifile(ARG[1]); // already set
                }
            }

        } else if(!strnicmp(ARG[0], "ID=", 3)       && (argc >= 0)) {   // mex inifile (not BMS)
            CMD.type   = CMD_IDString;
            CMD.num[0] = 0;
            CMD.str[1] = mystrdup(ARG[0] + 3);                  // bytes

        } else if(!stricmp(ARG[0], "ImpType")       && (argc >= 1)) {
            CMD.type   = CMD_ImpType;
            CMD.str[0] = mystrdup(ARG[1]);                      // type

        } else if(!stricmp(ARG[0], "Log")           && (argc >= 3)) {
            CMD.type   = CMD_Log;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // name
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // offset
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // size
            CMD.var[3] = -1;                                    // offsetoffset
            CMD.var[4] = -1;                                    // resourcesizeoffset
            if(argc >= 5) {
                CMD.num[5] = myatoifile(ARG[6]);                // filenumber
            } else {
                CMD.num[5] = myatoifile(ARG[4]);                // filenumber
            }

        } else if(!stricmp(ARG[0], "ExtractFile")   && (argc >= 0)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Log;
            CMD.var[0] = add_var(0, "FILENAME", NULL, 0, -2);   //  name
            CMD.var[1] = add_var(0, "FILEOFF",  NULL, 0,  0);   // offset
            CMD.var[2] = add_var(0, "FILESIZE", NULL, 0, -2);   // size
            CMD.var[3] = -1;                                    // offsetoffset
            CMD.var[4] = -1;                                    // resourcesizeoffset
            CMD.num[5] = myatoifile(ARG[6]);                    // filenumber

        } else if(!stricmp(ARG[0], "Math")          && (argc >= 3)) {
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            //CMD.num[1] = ARG[2][0];                             // op
            CMD.num[1] = 0; // yeah, a bit lame but supports everything in every position
            for(tmp = ARG[2]; *tmp; tmp++) {
                if(tolower(*tmp) == 'u') {          // unsigned
                    CMD.num[2] = 1;
                //} else if(tolower(*tmp) == 'i') {   // signed (default)
                    //CMD.num[2] = 0;
                } else if(!CMD.num[1]) {            // operator
                    CMD.num[1] = tolower(*tmp);
                }
            }
            if(!stricmp(ARG[2], "long")) CMD.num[1] = '=';      // a stupid error that can happen
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // var2

        } else if(!stricmp(ARG[0], "Add")           && (argc >= 3)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '+';                                   // op (skip specifier!)
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // var2

        } else if(!stricmp(ARG[0], "Subst")         && (argc >= 3)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '-';                                   // op (skip specifier!)
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // var2

        } else if(!stricmp(ARG[0], "Multiply")      && (argc >= 5)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Set;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // Var/Number
            cmd++;
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '*';                                   // op
            CMD.var[2] = add_var(0, ARG[5], NULL, 0, -2);       // var2

        } else if(!stricmp(ARG[0], "Divide")        && (argc >= 5)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Set;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // Var/Number
            cmd++;
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '/';                                   // op
            CMD.var[2] = add_var(0, ARG[5], NULL, 0, -2);       // var2

        } else if(!stricmp(ARG[0], "Up")            && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '+';                                   // op (skip specifier!)
            CMD.var[2] = add_var(0, "1", NULL, 0, -2);          // var2

        } else if(!stricmp(ARG[0], "Down")          && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Math;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var1
            CMD.num[1] = '-';                                   // op (skip specifier!)
            CMD.var[2] = add_var(0, "1", NULL, 0, -2);          // var2

        } else if(!stricmp(ARG[0], "Next")          && (argc >= 0)) {
            CMD.type   = CMD_Next;
            if(!argc) {
                CMD.var[0] = -1;
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // VarName
            }

        //} else if(!stricmp(ARG[0], "Continue")      && (argc >= 0)) {
            //CMD.type   = CMD_Continue;

        } else if(!stricmp(ARG[0], "Open")          && (argc >= 2)) {
            CMD.type   = CMD_Open;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // Folder/Specifier
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // Filename/Extension
            CMD.num[2] = myatoifile(ARG[3]);                    // File (default is 0, the same file)
            CMD.var[3] = add_var(0, ARG[4], NULL, 0, -2);       // optional/experimental: this var will be 1 if exists otherwise 0

        } else if(!stricmp(ARG[0], "SavePos")       && (argc >= 1)) {
            CMD.type   = CMD_SavePos;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName
            CMD.num[1] = myatoifile(ARG[2]);                    // File

        } else if(!stricmp(ARG[0], "Set")           && (argc >= 2)) {
            CMD.type   = CMD_Set;
            //CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);      // VarName
            if(!strnicmp(ARG[1], MEMORY_FNAME, MEMORY_FNAMESZ)) {
                CMD.var[0] = get_memory_file(ARG[1]);
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);
            }
            if(argc == 2) {
                CMD.num[1] = add_datatype("String");            // datatype
                //CMD.var[2] = add_var(0, ARG[2], NULL, 0, -2);  // Var/Number
                tmp = ARG[2];
            } else {
                if(ARG[2][0] == '=') {
                    CMD.num[1] = add_datatype("String");
                } else if(!stricmp(ARG[2], "strlen")) { // I'm crazy
                    CMD.type   = CMD_Strlen;
                    CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // dest var
                    CMD.var[1] = add_var(0, ARG[3], NULL, 0, -2);   // string
                } else {
                    CMD.num[1] = add_datatype(ARG[2]);           // datatype
                }
                //CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);  // Var/Number
                tmp = ARG[3];
            }
            if(CMD.num[1] == TYPE_BINARY) {
                CSTRING(2, tmp)
            } else if(CMD.num[1] == TYPE_COMPRESSED) {
                CMD.num[1] = TYPE_BINARY;
                CMD.str[2] = type_decompress(tmp, &CMD.num[2]);
            } else {
                CMD.var[2] = add_var(0, tmp, NULL, 0, -2);
            }

        } else if(!stricmp(ARG[0], "SETFILECNT")    && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Set;
            CMD.var[0] = add_var(0, "FILECNT", NULL, 0, -2);    // VarName
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.var[2] = add_var(0, ARG[1], NULL, 0, -2);       // Var/Number

        } else if(!stricmp(ARG[0], "SETBYTESREAD")  && (argc >= 1)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Set;
            CMD.var[0] = add_var(0, "BYTESREAD", NULL, 0, -2);  // VarName
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.var[2] = add_var(0, ARG[1], NULL, 0, -2);       // Var/Number

        } else if(!stricmp(ARG[0], "While")         && (argc >= 3)) {
            CMD.type   = CMD_While;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // Varname
            CMD.str[1] = mystrdup(ARG[2]);                      // Criterium
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // VarName2

        } else if(!stricmp(ARG[0], "EndLoop")       && (argc >= 2)) {   // mex inifile (not BMS)
            CMD.type   = CMD_While;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // Varname
            CMD.str[1] = mystrdup("!=");                        // Criterium
            CMD.var[2] = add_var(0, ARG[2], NULL, 0, -2);       // VarName2

        } else if(!stricmp(ARG[0], "String")        && (argc >= 3)) {
            CMD.type   = CMD_String;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName1
            CMD.num[1] = ARG[2][0]; /* NO tolower! */           // op
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // VarName2
            CMD.num[0] = argc - 3;
            for(i = 4; i <= argc; i++) {
                //if(!strnicmp(ARG[i], MEMORY_FNAME, MEMORY_FNAMESZ)) {
                    //CMD.var[i - 1] = get_memory_file(ARG[i]);
                //} else {
                    CMD.var[i - 1] = add_var(0, ARG[i], NULL, 0, -2);
                //}
            }

        } else if(!stricmp(ARG[0], "CleanExit")     && (argc >= 0)) {
            CMD.type   = CMD_CleanExit;

        } else if(!stricmp(ARG[0], "Exit")          && (argc >= 0)) {
            CMD.type   = CMD_CleanExit;

        } else if(!stricmp(ARG[0], "Case")          && (argc >= 2)) {   // mex inifile (not BMS)
            CMD.type   = CMD_If;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName1
            CMD.str[1] = mystrdup("=");                         // Criterium
            CMD.var[2] = add_var(0, ARG[2], NULL, 0, -2);       // VarName2
            cmd++;
            CMD.type   = CMD_EndIf;

        } else if(!stricmp(ARG[0], "If")            && (argc >= 3)) {
            CMD.type   = CMD_If;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName1
            CMD.str[1] = mystrdup(ARG[2]);                      // Criterium
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // VarName2

        } else if((!stricmp(ARG[0], "Elif") || !stricmp(ARG[0], "ElseIf")) && (argc >= 3)) {   // copy as above!
            CMD.type   = CMD_Elif;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // VarName1
            CMD.str[1] = mystrdup(ARG[2]);                      // Criterium
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // VarName2

        } else if(!stricmp(ARG[0], "Else")          && (argc >= 0)) {
            CMD.type   = CMD_Else;
            if((argc >= 4) && !stricmp(ARG[1], "If")) {         // copy as above!
                CMD.type   = CMD_Elif;
                CMD.var[0] = add_var(0, ARG[2], NULL, 0, -2);   // VarName1
                CMD.str[1] = mystrdup(ARG[3]);                  // Criterium
                CMD.var[2] = add_var(0, ARG[4], NULL, 0, -2);   // VarName2
            }

        } else if(!stricmp(ARG[0], "EndIf")         && (argc >= 0)) {
            CMD.type   = CMD_EndIf;

        } else if(!stricmp(ARG[0], "GetCT")         && (argc >= 3)) {
            CMD.type   = CMD_GetCT;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // variable
            CMD.num[1] = add_datatype(ARG[2]);                  // datatype
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // character
            CMD.num[3] = myatoifile(ARG[4]);                    // filenumber

        } else if(!stricmp(ARG[0], "PutCT")         && (argc >= 3)) {   // write mode
            CMD.type   = CMD_PutCT;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // variable
            CMD.num[1] = add_datatype(ARG[2]);                  // datatype
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // character
            CMD.num[3] = myatoifile(ARG[4]);                    // filenumber

        } else if(!stricmp(ARG[0], "ComType")       && (argc >= 1)) {
            CMD.type   = CMD_ComType;
            CMD.str[0] = mystrdup(ARG[1]);                      // ComType
            CSTRING(1, ARG[2])                                  // optional dictionary

        } else if(
                 (!stricmp(ARG[0], "ReverseShort")  && (argc >= 1))
              || (!stricmp(ARG[0], "FlipShort")     && (argc >= 1))) {  // mex inifile (not BMS)
            CMD.type   = CMD_ReverseShort;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // variable

        } else if(
                 (!stricmp(ARG[0], "ReverseLong")   && (argc >= 1))
              || (!stricmp(ARG[0], "FlipLong")      && (argc >= 1))) {  // mex inifile (not BMS)
            CMD.type   = CMD_ReverseLong;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // variable

        } else if(
                 (!stricmp(ARG[0], "ReverseLongLong")   && (argc >= 1))
              || (!stricmp(ARG[0], "FlipLongLong")      && (argc >= 1))) {  // mex inifile (not BMS)
            CMD.type   = CMD_ReverseLongLong;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // variable

        } else if(!stricmp(ARG[0], "PROMPTUSER")    && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "EVENTS")        && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "SEPPATH")       && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "NOFILENAMES")   && (argc >= 0)) {   // mex inifile (not BMS)
            CMD.type   = CMD_Set;
            CMD.var[0] = add_var(0, "FILENAME", NULL, 0, -2);   // VarName
            CMD.num[1] = add_datatype("String");                // datatype
            CMD.var[2] = add_var(0, "", NULL, 0, -2);           // Var/Number

        } else if(!stricmp(ARG[0], "WriteLong")     && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "StrCReplace")   && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "StrEResizeC")   && (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "SeperateHeader")&& (argc >= 0)) {   // mex inifile (not BMS)
            // do nothing, this command is useless
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "Endian")        && (argc >= 1)) {
            CMD.type   = CMD_Endian;
            if(!stricmp(ARG[1], "little") || !stricmp(ARG[1], "intel") || !stricmp(ARG[1], "1234")) {
                CMD.num[0] = MYLITTLE_ENDIAN;
            } else if(!stricmp(ARG[1], "big") || !stricmp(ARG[1], "network") || !stricmp(ARG[1], "4321")) {
                CMD.num[0] = MYBIG_ENDIAN;
            } else {
                printf("\nError: invalid endian value %s\n", ARG[1]);
            }

        } else if(!stricmp(ARG[0], "FileXOR")       && (argc >= 1)) {
            CMD.type   = CMD_FileXOR;
            CMD.num[0] = 0; // used to contain the size of str[0], improves the performances
            if(myisdigit(ARG[1][0]) || (ARG[1][0] == '\\')) {
                NUMS2BYTES(ARG[1], CMD.num[1], CMD.str[0], CMD.num[0])
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // string
            }
            CMD.num[2] = 0;                                     // reset pos
            if(argc == 1) {
                CMD.var[3] = add_var(0, "-1", NULL, 0, -2);     // current offset
                CMD.num[4] = 0;
            } else {
                CMD.var[3] = add_var(0, ARG[2], NULL, 0, -2);   // first position offset (used only for Log and multiple bytes in rare occasions)
                CMD.num[4] = myatoifile(ARG[3]);                // filenumber (not implemented)
            }

        } else if(!strnicmp(ARG[0], "FileRot", 7)   && (argc >= 1)) {
            CMD.type   = CMD_FileRot13;
            CMD.num[0] = 0; // used to contain the size of str[0], improves the performances
            if(myisdigit(ARG[1][0]) || (ARG[1][0] == '\\')) {
                NUMS2BYTES(ARG[1], CMD.num[1], CMD.str[0], CMD.num[0])
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // string
            }
            CMD.num[2] = 0;                                     // reset pos
            if(argc == 1) {
                CMD.var[3] = add_var(0, "-1", NULL, 0, -2);     // current offset
                CMD.num[4] = 0;
            } else {
                CMD.var[3] = add_var(0, ARG[2], NULL, 0, -2);   // first position offset (used only for Log and multiple bytes in rare occasions)
                CMD.num[4] = myatoifile(ARG[3]);                // filenumber (not implemented)
            }

        } else if(!stricmp(ARG[0], "FileCrypt")     && (argc >= 1)) {
            CMD.type   = CMD_FileCrypt;
            CMD.num[0] = 0; // used to contain the size of str[0], improves the performances
            if(myisdigit(ARG[1][0]) || (ARG[1][0] == '\\')) {
                NUMS2BYTES(ARG[1], CMD.num[1], CMD.str[0], CMD.num[0])
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // string
            }
            CMD.num[2] = 0;                                     // reset pos
            if(argc == 1) {
                CMD.var[3] = add_var(0, "-1", NULL, 0, -2);     // current offset
                CMD.num[4] = 0;
            } else {
                CMD.var[3] = add_var(0, ARG[2], NULL, 0, -2);   // first position offset (used only for Log and multiple bytes in rare occasions)
                CMD.num[4] = myatoifile(ARG[3]);                // filenumber (not implemented)
            }

        } else if(!stricmp(ARG[0], "Break")         && (argc >= 0)) {
            CMD.type   = CMD_Break;

        } else if(!stricmp(ARG[0], "Strlen")        && (argc >= 2)) {
            CMD.type   = CMD_Strlen;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // dest var
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // string

        } else if(!stricmp(ARG[0], "GetVarChr")     && (argc >= 3)) {
            CMD.type   = CMD_GetVarChr;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // dst byte
            if(!strnicmp(ARG[2], MEMORY_FNAME, MEMORY_FNAMESZ)) {
                CMD.var[1] = get_memory_file(ARG[2]);
            } else {
                CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);   // src var
            }
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // offset
            if(argc == 3) {
                CMD.num[3] = add_datatype("byte");
            } else {
                CMD.num[3] = add_datatype(ARG[4]);
            }

        } else if(!stricmp(ARG[0], "PutVarChr")     && (argc >= 3)) {
            CMD.type   = CMD_PutVarChr;
            if(!strnicmp(ARG[1], MEMORY_FNAME, MEMORY_FNAMESZ)) {
                CMD.var[0] = get_memory_file(ARG[1]);
            } else {
                CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);   // dst var
            }
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // offset
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // src byte
            if(argc == 3) {
                CMD.num[3] = add_datatype("byte");
            } else {
                CMD.num[3] = add_datatype(ARG[4]);
            }

        } else if(!stricmp(ARG[0], "Debug")         && (argc >= 0)) {
            CMD.type   = CMD_Debug;
            CMD.num[0] = myatoifile(ARG[1]);                    // type of verbosity

        } else if(!stricmp(ARG[0], "Padding")       && (argc >= 1)) {
            CMD.type   = CMD_Padding;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // padding size
            CMD.num[1] = myatoifile(ARG[2]);                    // filenumber

        } else if(!stricmp(ARG[0], "Append")        && (argc >= 0)) {
            CMD.type   = CMD_Append;

        } else if(!stricmp(ARG[0], "Encryption")    && (argc >= 2)) {
            CMD.type   = CMD_Encryption;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // type
            if(!stricmp(ARG[2], "?")) {
                printf("\n"
                    "Error: seems that the script you are using needs that you specify a fixed\n"
                    "       %s key at line %d for using it, so edit the script source code\n"
                    "       adding this needed value, examples:\n"
                    "         encryption %s \"mykey\"\n"
                    "         encryption %s \"\\x6d\\x79\\x6b\\x65\\x79\"\n"
                    "\n", ARG[1], (i32)bms_line_number, ARG[1], ARG[1]);
                myexit(-1);
            }
            CSTRING(1, ARG[2])                                  // key
            CSTRING(2, ARG[3])                                  // ivec
            CMD.num[3] = myatoi(ARG[4]);                        // decrypt/encrypt
            if(argc >= 5) {
                CMD.var[4] = add_var(0, ARG[5], NULL, 0, -2);   // keylen
            }

        } else if(!stricmp(ARG[0], "Print")         && (argc >= 1)) {
            CMD.type   = CMD_Print;
            CSTRING(0, ARG[1])                                  // message

        } else if(!stricmp(ARG[0], "GetArray")      && (argc >= 3)) {
            CMD.type   = CMD_GetArray;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // var
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // array number
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // number/string

        } else if(!stricmp(ARG[0], "PutArray")      && (argc >= 3)) {
            CMD.type   = CMD_PutArray;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // array number
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // number/string
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // var

        } else if(!stricmp(ARG[0], "StartFunction") && (argc >= 1)) {
            CMD.type   = CMD_StartFunction;
            CMD.str[0] = mystrdup(ARG[1]);

        } else if(!stricmp(ARG[0], "CallFunction")  && (argc >= 1)) {
            CMD.type   = CMD_CallFunction;
            CMD.str[0] = mystrdup(ARG[1]);
            CMD.num[1] = myatoi(ARG[2]);

        } else if(!stricmp(ARG[0], "EndFunction")   && (argc >= 0)) {
            CMD.type   = CMD_EndFunction;
            //CMD.str[0] = mystrdup(ARG[1]);

        } else if(!stricmp(ARG[0], "ScanDir")       && (argc >= 3)) {
            CMD.type   = CMD_ScanDir;
            CMD.var[0] = add_var(0, ARG[1], NULL, 0, -2);       // path to scan
            CMD.var[1] = add_var(0, ARG[2], NULL, 0, -2);       // filename
            CMD.var[2] = add_var(0, ARG[3], NULL, 0, -2);       // filesize
            if(ARG[4] && !filter_files) filter_files = mystrdup(ARG[4]);

        } else if(!stricmp(ARG[0], "CallDLL")       && (argc >= 3)) {
            CMD.type   = CMD_CallDLL;
            CMD.str[0] = mystrdup(ARG[1]);                      // name of the dll
            CMD.str[1] = mystrdup(ARG[2]);                      // name of the function or relative offset
            CMD.str[2] = mystrdup(ARG[3]);                      // stdcall/cdecl
            CMD.var[3] = add_var(0, ARG[4], NULL, 0, -2);       // return value
            CMD.num[0] = argc - 4;                              // number of arguments
            for(i = 5; i <= argc; i++) {
                CMD.num[i - 1] = 0;                             // &var disabled
                if(!strnicmp(ARG[i], MEMORY_FNAME, MEMORY_FNAMESZ)) {
                    CMD.var[i - 1] = get_memory_file(ARG[i]);
                } else {
                    if((ARG[i][0] == '&') || (ARG[i][0] == '*')) {
                        CMD.num[i - 1] = 1;                     // &var enabled
                        CMD.var[i - 1] = add_var(0, ARG[i] + 1, NULL, 0, -2);
                    } else {
                        CMD.var[i - 1] = add_var(0, ARG[i], NULL, 0, -2);
                    }
                }
            }

        } else if(!stricmp(ARG[0], "Game") || !stricmp(ARG[0], "Archive")
               || !strnicmp(ARG[0], "Game ", 5)
               || !strnicmp(ARG[0], "Game:", 5)
               || !strnicmp(ARG[0], "Archive", 7)
               || !strnicmp(ARG[0], "Archive:", 8)
               || strstr(ARG[0], "-------")
               || strstr(ARG[0], "=-=-=-=")
               || stristr(ARG[0], "<bms")
               || stristr(ARG[0], "<bms>")
               || stristr(ARG[0], "</bms>")) {
            CMD.type   = CMD_NOP;

        } else if(!stricmp(ARG[0], "NOP")) {
            CMD.type   = CMD_NOP;

        } else {
            if(c_structs_do) {
                argc = c_structs(argument, argc);
                c_structs_do = 0;
                goto redo;
            }

            printf("\nError: invalid command \"%s\" or arguments %d at line %d\n", ARG[0], (i32)argc, (i32)bms_line_number);
            myexit(-1);
        }

        if(CMD.type == CMD_NONE) {
            printf("\nError: there is an error in this tool because there is no command type\n");
            myexit(-1);
        }
        CMD.debug_line = debug_line;
        cmd++;
    }
    for(variables = 0; variable[variables].name; variables++);
    if(!cmd) {
        printf("\nError: the input BMS script is empty\n");
        myexit(-1);
    }
    return(0);
}



int myisalnum(int chr) {
    if((chr >= '0') && (chr <= '9')) return(1);
    if((chr >= 'a') && (chr <= 'z')) return(1);
    if((chr >= 'A') && (chr <= 'Z')) return(1);
    if(chr == '-') return(1);   // negative number
    //if(chr == '+') return(1);   // positive number
    return(0);
}



int myisdigitstr(u8 *str) { // only a quick version
    int     i;

    if(!str) return(0);
    if(!myisdigit(str[0])) return(0);
    for(i = 1; str[i]; i++) {
        if(i >= NUMBERSZ) return(0);    // avoid to waste time with long strings
        if(!strchr("0123456789abcdefABCDEFx$", str[i])) return(0);
    }
    return(1);
}



int myisdigit(int chr) {
    if((chr >= '0') && (chr <= '9')) return(1); // this is enough because hex start ever with 0x
    if(chr == '-') return(1);   // negative number
    //if(chr == '+') return(1);   // positive number
    //if(chr == '$') return(1);   // delphi/vb hex
    return(0);
}



int myatoifile(u8 *str) {   // for quick usage
    int     fdnum;

    if(str && !strnicmp(str, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        fdnum = get_memory_file(str);
    } else if(str && !strnicmp(str, "ARRAY", 5)) {
        fdnum = myatoi(str + 5);
    } else {
        if(!str || !str[0]) return(0);  // default is file number 0
        if(!myisdechex_string(str)) return(MAX_FILES);  // the syntax of idstring sux!
        fdnum = myatoi(str);
    }
    //if((fdnum <= 0) || (fdnum > MAX_FILES)) {
    if((fdnum < -MAX_FILES) || (fdnum > MAX_FILES)) {
        printf("\nError: invalid FILE number (%d)\n", (i32)fdnum);
        myexit(-1);
    }
    return(fdnum);
}



u8 *myitoa(int num) {
    static const u8 table[] = "0123456789abcdef";
    static u8       dstx[MULTISTATIC][3 + NUMBERSZ + 1] = {{""}};
    static int      dsty = 0;
    u8      tmp[NUMBERSZ + 1],  // needed because hex numbers are inverted, I have already done various tests and this is the fastest!
            *p,                 // even faster than using directly dst as output
            *t,
            *dst;
    u_int   unum;

    dst = (u8 *)dstx[dsty++ % MULTISTATIC];

    if(!num) {  // quick way, 0 is used enough often... ok it's probably useless
        dst[0] = '0';
        dst[1] = 0;
        return(dst);
    }

    p = dst;
    if(num < 0) {
        num = -num;
        *p++ = '-';
    }
    unum = num; // needed for the sign... many troubles

    //if((unum >= 0) && (unum <= 9)) {  // quick solution for numbers under 10, so uses only one char, (unum >= 0) avoids problems with 0x80000000
        //*p++ = table[unum];
        //*p   = 0;
        //return(dst);
    //}
    t = tmp + (NUMBERSZ - 1);   // the -1 is needed (old tests)
    *t = 0;
    t--;
    if(decimal_notation) {
        do {   // "unum" MUST be handled at the end of the cycle! example: 0
            *t = table[unum % (u_int)10];
            unum = unum / (u_int)10;
            if(!unum) break;
            t--;
        } while(t >= tmp);
    } else {
        *p++ = '0'; // hex notation is better for debugging
        *p++ = 'x';
        do {   // "unum" MUST be handled at the end of the cycle! example: 0
            *t = table[unum & 15];
            unum = unum >> (u_int)4;
            if(!unum) break;
            t--;
        } while(t >= tmp);
    }
    strcpy(p, t);

    //sprintf(dst, "%d", (i32)unum);  // old "one-instruction-only" solution, mine is better
    return(dst);
}



void mex_default_init(int file_only) {
    if(!file_only) EXTRCNT_idx   = add_var(0, "EXTRCNT", NULL, 0, sizeof(int));   // used by MultiEx as fixed variable
    BytesRead_idx = add_var(0, "BytesRead", NULL, 0, sizeof(int));   // used by MultiEx as fixed variable
    NotEOF_idx    = add_var(0, "NotEOF",    NULL, 1, sizeof(int));   // used by MultiEx as fixed variable
}



void bms_init(int reinit) {
    int     i,
            j;

        bms_line_number     = 0;
        extracted_files     = 0;
        reimported_files    = 0;
        endian              = MYLITTLE_ENDIAN;
        //force_overwrite     = 0;
        variables           = 0;
        compression_type    = COMP_ZLIB;
        file_xor_pos        = NULL;
        file_xor_size       = 0;
        file_rot13_pos      = NULL;
        file_rot13_size     = 0;
        file_crypt_pos      = NULL;
        file_crypt_size     = 0;
        comtype_dictionary_len = 0;
        comtype_scan        = 0;
        encrypt_mode        = 0;
        append_mode         = 0;
        temporary_file_used = 0;
        mex_default         = 0;
        file_xor            = NULL;
        file_rot13          = NULL;
        file_crypt          = NULL;
        comtype_dictionary  = NULL;
        //EXTRCNT_idx         = 0;
        //BytesRead_idx       = 0;
        //NotEOF_idx          = 0;

    if(mex_default) {
        mex_default_init(0);
    }
    CMD_Encryption_func(-1);

    // input folder only: in case someone writes bad scripts
    //do NOT enable//
    /*for(i = 0; i < MAX_VARS; i++) {
        if(variable[i].name)  variable[i].name[0]  = 0;
        if(variable[i].value) variable[i].value[0] = 0;
        variable[i].value32 = 0;
    }*/
    // input folder only: enough useful
    for(i = 0; i < MAX_FILES; i++) {
        memory_file[i].pos  = 0;
        memory_file[i].size = 0;
    }

    if(reinit) return;

    // not done in reinit because they contain allocated stuff
    memset(filenumber,  0, sizeof(filenumber));
    variable = variable_main;
    memset(variable,    0, sizeof(variable_main));
    memset(command,     0, sizeof(command));
    memset(memory_file, 0, sizeof(memory_file));
    memset(array,       0, sizeof(array));
    for(i = 0; i < MAX_CMDS; i++) {
        for(j = 0; j < MAX_ARGS; j++) {
            command[i].var[j] = -0x7fffff;  // helps a bit to identify errors in this tool, DO NOT MODIFY IT! NEVER! (it's used in places like check_condition)
            command[i].num[j] = -0x7fffff;  // helps a bit to identify errors in this tool
            // do NOT touch command[i].str[j]
        }
    }
    CMD_CallDLL_func(-1);

    getcwd(current_folder, PATHSZ);
    quickbms_version = calc_quickbms_version(VER);
}



void bms_finish(void) { // totally useless function, except in write mode for closing the files
    int     i,
            j;
    u8      ans[16];

    for(i = 0; i < MAX_FILES; i++) {
        if(filenumber[i].fd) fclose(filenumber[i].fd);
        FREEZ(filenumber[i].fullname)
        FREEZ(filenumber[i].basename)
    }
    memset(filenumber, 0, sizeof(filenumber));
    variable = variable_main;
    for(i = 0; i < MAX_VARS; i++) {
        FREEZ(variable[i].name)
        FREEZ(variable[i].value)
    }
    memset(variable, 0, sizeof(variable_main));
    for(i = 0; i < MAX_CMDS; i++) {
        FREEZ(command[i].debug_line)
        for(j = 0; j < MAX_ARGS; j++) {
            FREEZ(command[i].str[j])
        }
    }
    memset(command, 0, sizeof(command));
    for(i = 0; i < MAX_FILES; i++) {
        FREEZ(memory_file[i].data)
    }
    memset(memory_file, 0, sizeof(memory_file));
    for(i = 0; i < MAX_ARRAYS; i++) {
        for(j = 0; j < array[i].elements; j++) {
            FREEZ(array[i].str[j])
        }
    }
    memset(array, 0, sizeof(array));
    dumpa(0, NULL, -1, -1, -1);
    //unzip(0, NULL, 0, NULL, 0);
    bms_line(NULL, NULL, NULL, NULL);
    if(temporary_file_used) {
        fgetz(ans, sizeof(ans), stdin,
            "\n- a temporary file was created, do you want to delete it (y/N): ");
        if(tolower(ans[0]) == 'y') {
            unlink(TEMPORARY_FILE);
        }
    }
}



int bms_line(FILE *fd, u8 *input_line, u8 **argument, u8 **debug_line) {
#define ARGS_DELIMITER  " \t" ",()"
    static  int wide_comment = 0;
    static  u8  crlf[2] = {0,0};    // used only for bms_line_number!
    static  int buffsz  = 0;
    static  u8  *buff   = NULL;
    static  u8  tmpchars[MAX_ARGS][NUMBERSZ + 1] = {""};
    int     i,
            j,
            c;
    u8      tmp[1 + 1],
            *line,
            *p,
            *s;

    if(!argument) {
        FREEZ(buff)
        buffsz = 0;
        memset(&crlf, 0, sizeof(crlf));
        return(-1);
    }

    if(!bms_line_number) wide_comment = 0;

    //if(!input_line) return(0); NEVER
    do {
        bms_line_number++;
        for(i = 0;;) {
            if(fd) {
                c = fgetc(fd);
            } else {
                c = *input_line++;
                if(!c) c = -1;  // a buffer ends with 0
            }
            if(!c) continue;    // unicode blah, !i is used to handle only the first bytes 
            if((bms_line_number <= 1) && !i && ((c == 0xef) || (c == 0xbb) || (c == 0xbf) || (c == 0xfe) || (c == 0xff))) continue;
            if(c < 0) {
                if(!i) {    // end of file
                    bms_line_number = 0;
                    return(-1);
                }
                break;
            }
            if((c == '\n') || (c == '\r')) {
                if(!i) {    // used only for bms_line_number!
                    if(
                        (!crlf[0])
                     || ((crlf[0] == '\n') && (c == '\n'))
                     || ((crlf[0] == '\r') && (c == '\r'))
                    // || ((crlf[1] == '\r') && (crlf[0] == '\n') && (c == '\r'))
                     || ((crlf[1] == '\n') && (crlf[0] == '\r') && (c == '\n'))
                    ) {
                        bms_line_number++;
                    }
                    crlf[1] = crlf[0];
                    crlf[0] = c;
                    continue;
                }
                crlf[1] = 0;
                crlf[0] = c;
                break;
            }
            if(i >= buffsz) {
                buffsz += STRINGSZ;
                buff = realloc(buff, buffsz + 1);
                if(!buff) STD_ERR;
            }
            buff[i] = c;
            i++;
        }
        if(!buff) buff = malloc(1);
        buff[i] = 0;

        for(p = buff; *p && (*p != '\n') && (*p != '\r'); p++);
        *p = 0;

        for(p--; (p >= buff) && strchr(ARGS_DELIMITER ";", *p); p--);
        p[1] = 0;

        for(p = buff; *p && strchr(ARGS_DELIMITER "}", *p); p++);   // '}' is for C maniacs like me
        line = p;
        if((line[0] == '/') && (line[1] == '*')) {
            wide_comment = 1;
            break;
        }
        if((line[0] == '*') && (line[1] == '/')) {
            if(wide_comment) break;
        }
        if(!myisalnum(line[0])) line[0] = 0;  // so we avoids both invalid chars and comments like # ; // and so on
    } while(!line[0]);

    if(debug_line) {
        *debug_line = malloc(32 + strlen(line) + 1);
        sprintf(*debug_line, "%-3d %s", (i32)bms_line_number, line);
        if(verbose > 0) printf("READLINE %s\n", *debug_line);
    }

    for(i = 0; i < MAX_ARGS; i++) { // reset all
        argument[i] = NULL;
    }

    if(wide_comment) {
        p = strstr(line, "*/");
        if(!p) {
            line[0] = 0;
        } else {
            p += 2;
            for(j = 0;; j++) {
                line[j] = p[j];
                if(!p[j]) break;
            }
            wide_comment = 0;
        }
    }

    for(i = 0;;) {
        if(i >= MAX_ARGS) {
            printf("\nError: the BMS script uses more arguments than how much supported by this tool\n");
            myexit(-1);
        }
        for(p = line; *p && strchr(ARGS_DELIMITER, *p); p++);
        if(!*p) break;
        line = p;

        if((line[0] == '/') && (line[1] == '/')) break;
        if((line[0] == '/') && (line[1] == '*')) {
            wide_comment = 1;
            p = strstr(line + 2, "*/");
            if(!p) {
                break;
            } else {
                p += 2;
                for(j = 0;; j++) {
                    line[j] = p[j];
                    if(!p[j]) break;
                }
                wide_comment = 0;
            }
        }
        if(*line == '#') break;
        if(*line == ';') break;
        if(*line == '\'') {     // C char like 'A' or '\x41'
            line++;
            cstring(line, tmp, 1, &c);
            for(p = line + c; *p; p++) {
                if((p[0] == '\\') && (p[1] == '\'')) {
                    p++;
                    continue;
                }
                if(*p == '\'') break;
            }
            sprintf(tmpchars[i], "0x%02x", tmp[0]);
            argument[i] = tmpchars[i];
        } else if(*line == '\"') {  // string
            line++;
            s = line;
            for(p = line; *p; p++) {
                if((p[0] == '\\') && (p[1] == '\"')) {
                    p++;
                    *s++ = *p;
                    continue;
                }
                if(*p == '\"') break;
                *s++ = *p;
            }
            if(s != p) *s = 0;
            argument[i] = line;
        } else {
            for(p = line; *p; p++) {
                if(strchr(ARGS_DELIMITER, *p)) break;
            }
            argument[i] = line;
        }
        //if(p == line) break;  // this must be ignored otherwise "" is not handled
        i++;

        if(!*p) break;
        *p = 0;
        line = p + 1;
    }
    argument[i] = NULL;
    return(i);
}



int cstring(u8 *input, u8 *output, int maxchars, int *inlen) {
    i32     n,
            len;
    u8      *p,
            *o;

    if(!input || !output) {
        if(inlen) *inlen = 0;
        return(0);
    }

    p = input;
    o = output;
    while(*p) {
        if(maxchars >= 0) {
            if((o - output) >= maxchars) break;
        }
        if(*p == '\\') {
            p++;
            switch(*p) {
                case 0:  return(-1); break;
                //case '0':  n = '\0'; break;
                case 'a':  n = '\a'; break;
                case 'b':  n = '\b'; break;
                case 'e':  n = '\e'; break;
                case 'f':  n = '\f'; break;
                case 'n':  n = '\n'; break;
                case 'r':  n = '\r'; break;
                case 't':  n = '\t'; break;
                case 'v':  n = '\v'; break;
                case '\"': n = '\"'; break;
                case '\'': n = '\''; break;
                case '\\': n = '\\'; break;
                case '?':  n = '\?'; break;
                case '.':  n = '.';  break;
                case ' ':  n = ' ';  break;
                case 'x': {
                    //n = readbase(p + 1, 16, &len);
                    //if(len <= 0) return(-1);
                    if(sscanf(p + 1, "%02x%n", &n, &len) != 1) return(-1);
                    if(len > 2) len = 2;
                    p += len;
                    } break;
                default: {
                    //n = readbase(p, 8, &len);
                    //if(len <= 0) return(-1);
                    if(sscanf(p, "%3o%n", &n, &len) != 1) return(-1);
                    if(len > 3) len = 3;
                    p += (len - 1); // work-around for the subsequent p++;
                    } break;
            }
            *o++ = n;
        } else {
            *o++ = *p;
        }
        p++;
    }
    *o = 0;
    len = o - output;
    if(inlen) *inlen = p - input;
    return(len);
}



// if datalen is negative then it will return 0 if encryption is enabled or -1 if disabled
int perform_encryption(u8 *data, int datalen) {
#define ENCRYPT_BLOCKS(X,Y) { \
            tmp = datalen / X; \
            for(i = 0; i < tmp; i++) { \
                Y; \
                data += X; \
            } \
        }

#ifndef DISABLE_OPENSSL
    EVP_MD_CTX  *tmpctx;
    u8      digest[EVP_MAX_MD_SIZE],
            digest_hex[(EVP_MAX_MD_SIZE * 2) + 1];
#endif
    u_int   crc = 0;
    int     i   = 0;
    i32     tmp = 0;

    // if(datalen <= 0) NEVER ENABLE THIS because it's needed
    // if(!data)        NEVER

    if(wincrypt_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) datalen = wincrypt_decrypt(wincrypt_ctx, data, datalen);
        else              datalen = wincrypt_encrypt(wincrypt_ctx, data, datalen);

#ifndef DISABLE_OPENSSL
    } else if(evp_ctx) {
        if(datalen < 0) return(0);
        tmp = datalen;
        if(reimport) {
            i = evp_ctx->encrypt;
            evp_ctx->encrypt = encrypt_mode;
        }
        EVP_CipherUpdate(evp_ctx, data, &tmp, data, datalen);
        if(reimport) evp_ctx->encrypt = i;
        //EVP_CipherFinal(evp_ctx, data + datalen, &tmp);   // it causes tons of problems
        //datalen += tmp;

    } else if(evpmd_ctx) {  // probably I seem crazy for all these operations... but it's perfect!
        if(datalen < 0) return(0);
        tmpctx = calloc(1, sizeof(EVP_MD_CTX));
        if(!tmpctx) STD_ERR;
        EVP_DigestUpdate(evpmd_ctx, data, datalen);
        EVP_MD_CTX_copy_ex(tmpctx, evpmd_ctx);
        EVP_DigestFinal(evpmd_ctx, digest, &tmp);
        free(evpmd_ctx);
        evpmd_ctx = tmpctx;
        add_var(0, "QUICKBMS_HASH", digest, 0, tmp);
        byte2hex(digest, tmp, digest_hex, sizeof(digest_hex));
        add_var(0, "QUICKBMS_HEXHASH", digest_hex, 0, -1);

    } else if(blowfish_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, BF_decrypt((void *)data, blowfish_ctx))
        else              ENCRYPT_BLOCKS(8, BF_encrypt((void *)data, blowfish_ctx))

    } else if(aes_ctr_ctx) {
        if(datalen < 0) return(0);
        AES_ctr128_encrypt(data, data, datalen, &aes_ctr_ctx->ctx, aes_ctr_ctx->ivec, aes_ctr_ctx->ecount, &aes_ctr_ctx->num);
#endif
#ifndef DISABLE_MCRYPT
    } else if(mcrypt_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) mdecrypt_generic(mcrypt_ctx, data, datalen);
        else              mcrypt_generic(mcrypt_ctx, data, datalen);
#endif
#ifndef DISABLE_TOMCRYPT
    } else if(tomcrypt_ctx) {
        if(datalen < 0) return(0);
        if(tomcrypt_ctx->hash) {
            tomcrypt_doit(tomcrypt_ctx, NULL, data, datalen, digest, EVP_MAX_MD_SIZE, &tmp);
            if(tmp >= 0) {
                add_var(0, "QUICKBMS_HASH", digest, 0, tmp);
                byte2hex(digest, tmp, digest_hex, sizeof(digest_hex));
                add_var(0, "QUICKBMS_HEXHASH", digest_hex, 0, -1);
            }
        } else {
            tomcrypt_doit(tomcrypt_ctx, NULL, data, datalen, data, datalen, NULL);
        }
#endif

    } else if(tea_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, tea_crypt(tea_ctx, TEA_DECRYPT, data, data))
        else              ENCRYPT_BLOCKS(8, tea_crypt(tea_ctx, TEA_ENCRYPT, data, data))

    } else if(xtea_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, xtea_crypt_ecb(xtea_ctx, XTEA_DECRYPT, data, data))
        else              ENCRYPT_BLOCKS(8, xtea_crypt_ecb(xtea_ctx, XTEA_ENCRYPT, data, data))

    } else if(xxtea_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) xxtea_crypt(xxtea_ctx, XXTEA_DECRYPT, data, datalen);
        else              xxtea_crypt(xxtea_ctx, XXTEA_ENCRYPT, data, datalen);

    } else if(swap_ctx) {
        if(datalen < 0) return(0);
        swap_crypt(swap_ctx, data, datalen);

    } else if(math_ctx) {
        if(datalen < 0) return(0);
        math_crypt(math_ctx, data, datalen);

    } else if(xor_ctx) {
        if(datalen < 0) return(0);
        xor_crypt(xor_ctx, data, datalen);

    } else if(rot_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) rot_decrypt(rot_ctx, data, datalen);
        else              rot_encrypt(rot_ctx, data, datalen);

    } else if(rotate_ctx) {
        if(datalen < 0) return(0);
        rotate_crypt(rotate_ctx, data, datalen, encrypt_mode);

    } else if(inc_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) inc_crypt(inc_ctx, data, datalen, 0);
        else              inc_crypt(inc_ctx, data, datalen, 1);

    } else if(charset_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) charset_decrypt(charset_ctx, data, datalen);
        else              charset_encrypt(charset_ctx, data, datalen);

    } else if(charset2_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) charset_encrypt(charset2_ctx, data, datalen); // yes, it's encrypted first
        else              charset_decrypt(charset2_ctx, data, datalen); // and decrypted

    } else if(twofish_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, do_twofish_decrypt(twofish_ctx, data, data))
        else              ENCRYPT_BLOCKS(16, do_twofish_encrypt(twofish_ctx, data, data))

    } else if(seed_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, do_seed_decrypt(seed_ctx, data, data))
        else              ENCRYPT_BLOCKS(16, do_seed_encrypt(seed_ctx, data, data))

    } else if(serpent_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, serpent_decrypt_internal(serpent_ctx, (void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(16, serpent_encrypt_internal(serpent_ctx, (void *)data, (void *)data))

    } else if(ice_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, ice_key_decrypt(ice_ctx, (void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(8, ice_key_encrypt(ice_ctx, (void *)data, (void *)data))

    } else if(rotor_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) RTR_d_region(rotor_ctx, data, datalen, TRUE);
        else              RTR_e_region(rotor_ctx, data, datalen, TRUE);

    } else if(ssc_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ssc_decrypt(ssc_ctx->key, ssc_ctx->keysz, data, datalen);
        else              ssc_encrypt(ssc_ctx->key, ssc_ctx->keysz, data, datalen);

    } else if(cunprot_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) datalen = cunprot_decrypt(cunprot_ctx, data, datalen);
        else              datalen = cunprot_encrypt(cunprot_ctx, data, datalen);

    } else if(zipcrypto_ctx) { // the 12 bytes header must be removed by the user
        if(datalen < 0) return(0);
        if(!encrypt_mode) zipcrypto_decrypt(zipcrypto_ctx, (void *)get_crc_table(), data, datalen);
        else              zipcrypto_encrypt(zipcrypto_ctx, (void *)get_crc_table(), data, datalen);
        if(zipcrypto_ctx[3]) {  // yeah this is valid only for the decryption
            if(datalen < 12) {
                datalen = 0;
            } else {
                datalen -= 12;
                memmove(data, data + 12, datalen);
            }
        }

    } else if(threeway_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) threeway_decrypt(threeway_ctx, data, datalen);
        else              threeway_encrypt(threeway_ctx, data, datalen);

    } else if(skipjack_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, skipjack_decrypt(skipjack_ctx, data, data))
        else              ENCRYPT_BLOCKS(8, skipjack_encrypt(skipjack_ctx, data, data))

    } else if(anubis_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, ANUBISdecrypt(anubis_ctx, data, data))
        else              ENCRYPT_BLOCKS(16, ANUBISencrypt(anubis_ctx, data, data))

    } else if(aria_ctx) {
        if(datalen < 0) return(0);
        ENCRYPT_BLOCKS(16, ARIA_Crypt(data, aria_ctx->Nr, aria_ctx->rk, data))

    } else if(crypton_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, crypton_decrypt((void *)data, (void *)data, crypton_ctx))
        else              ENCRYPT_BLOCKS(16, crypton_encrypt((void *)data, (void *)data, crypton_ctx))

    } else if(frog_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, frog_decrypt((void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(16, frog_encrypt((void *)data, (void *)data))

    } else if(gost_ctx) {
        if(datalen < 0) return(0);
        if(!gost_ctx->type) {
            if(!encrypt_mode) ENCRYPT_BLOCKS(8, gostdecrypt((void *)data, (void *)data, gost_ctx->key))
            else              ENCRYPT_BLOCKS(8, gostcrypt((void *)data, (void *)data, gost_ctx->key))
        } else if(gost_ctx->type == 1) {
            gostofb((void *)data, (void *)data, datalen, gost_ctx->iv, gost_ctx->key);
        } else if(gost_ctx->type == 2) {
            if(!encrypt_mode) ENCRYPT_BLOCKS(8, gostcfbdecrypt((void *)data, (void *)data, datalen, gost_ctx->iv, gost_ctx->key))
            else              ENCRYPT_BLOCKS(8, gostcfbencrypt((void *)data, (void *)data, datalen, gost_ctx->iv, gost_ctx->key))
        }

    } else if(lucifer_ctx) {
        if(datalen < 0) return(0);
        ENCRYPT_BLOCKS(16, lucifer(data))

    } else if(kirk_ctx >= 0) {
        if(datalen < 0) return(0);
        switch(kirk_ctx) {
            case 0:  kirk_CMD0(data, data, datalen, 0); break;
            case 1:  kirk_CMD1(data, data, datalen, 0); break;
            case 4:  kirk_CMD4(data, data, datalen);    break;
            case 7:  kirk_CMD7(data, data, datalen);    break;
            case 10: kirk_CMD10(data, datalen);         break;
            case 11: kirk_CMD11(data, data, datalen);   break;
            case 14: kirk_CMD14(data, datalen);         break;
            default: break;
        }

    } else if(mars_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, mars_decrypt((void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(16, mars_encrypt((void *)data, (void *)data))

    } else if(misty1_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, misty1_decrypt_block(misty1_ctx, (void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(8, misty1_encrypt_block(misty1_ctx, (void *)data, (void *)data))

    } else if(noekeon_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(16, NOEKEONdecrypt(noekeon_ctx, (void *)data, (void *)data))
        else              ENCRYPT_BLOCKS(16, NOEKEONencrypt(noekeon_ctx, (void *)data, (void *)data))

    } else if(seal_ctx) {
        if(datalen < 0) return(0);
        seal_encrypt(seal_ctx, (void *)data, datalen);

    } else if(safer_ctx) {
        if(datalen < 0) return(0);
        if(!encrypt_mode) ENCRYPT_BLOCKS(8, Safer_Decrypt_Block((void *)data, (void *)safer_ctx, (void *)data))
        else              ENCRYPT_BLOCKS(8, Safer_Encrypt_Block((void *)data, (void *)safer_ctx, (void *)data))

    } else if(crc_ctx) {
        if(datalen < 0) return(0);
        crc = calc_crc(crc_ctx, data, datalen);
        add_var(0, "QUICKBMS_CRC", NULL, crc, sizeof(u_int));

    } else {
        if(datalen < 0) return(-1);
    }
    //return(0);  // don't return datalen because they are almost all block cipher encryptions and so it's all padded/aligned
    return(datalen);    // from version 0.3.11 I return datalen, only if I'm 100% sure that it's correct
}



int dumpa_memory_file(memory_file_t *memfile, u8 **ret_data, int size, int *ret_size) {
    u8      *data;

    data = *ret_data;
    if(size == -1) ALLOC_ERR;
    if(append_mode) {
        memfile->pos   = memfile->size;
        memfile->size += size;
    } else {
        memfile->pos   = 0;
        memfile->size  = size;
    }
    memfile->bitchr = 0;    // reset the bit stuff
    memfile->bitpos = 0;
    memfile->bitoff = 0;

    // the following are the new instructions for using less memory
    if(ret_size && !memfile->data && data) {
        memfile->data = data;   // direct assignment
        *ret_data = NULL;       // set to NULL, do NOT free!
        *ret_size = 0;
        goto quit;
    }

    if((u_int)memfile->size > (u_int)memfile->maxsize) {
        memfile->maxsize = memfile->size;
        if(memfile->maxsize == -1) ALLOC_ERR;
        memfile->data = realloc(memfile->data, memfile->maxsize + 1);
        if(!memfile->data) STD_ERR;
    } else if(!memfile->data && !memfile->maxsize) {    // avoids some rare problems in some rare cases
        memfile->data = realloc(memfile->data, memfile->maxsize + 1);
        if(!memfile->data) STD_ERR;
    }
    if(memfile->data) memcpy(memfile->data + memfile->pos, data, size);
quit:
    if(memfile->data) memfile->data[memfile->pos + size] = 0;  // not needed, it's for a possible future usage or something else
    return(size);
}



u8 *rename_invalid(u8 *old_name) {
    static u8   new_name[PATHSZ + 1];

    if(!old_name) old_name = "noname";
    fgetz(new_name, PATHSZ, stdin,
        "\n"
        "- it's not possible to create that file due to its filename or related\n"
        "  incompatibilities (for example already exists a folder with that name), so\n"
        "  now you must choose a new filename for saving it.\n"
        "  - old: %s\n"
        "  - new: ", old_name);
    return(new_name);
}



int perform_compression(u8 *in, int zsize, u8 **ret_out, int size, int *outsize) {
    int     tmp1,
            tmp2,
            tmp3;
    i32     t32 = 0;
    u8      *out,
            *p;

    out = *ret_out;
    switch(compression_type) {
        case COMP_ZLIB: {
            size = unzip_zlib(in, zsize, out, size, 0);
            break;
        }
        case COMP_DEFLATE: {
            size = unzip_deflate(in, zsize, out, size, 0);
            break;
        }
        case COMP_LZO1:
        case COMP_LZO1A:
        case COMP_LZO1B:
        case COMP_LZO1C:
        case COMP_LZO1F:
        case COMP_LZO1X:
        case COMP_LZO1Y:
        case COMP_LZO1Z:
        case COMP_LZO2A: {
            size = unlzo(in, zsize, out, size, compression_type);
            break;
        }
        case COMP_LZSS: {
            size = unlzss(in, zsize, out, size);
            break;
        }
        case COMP_LZX: {
            size = unlzx(in, zsize, out, size);
            break;
        }
        case COMP_GZIP: {
            t32 = *outsize;
            size = ungzip(in, zsize, &out, &t32); // outsize and NOT size because must be reallocated
            *outsize = t32;
            break;
        }
        case COMP_EXPLODE: {
            size = unexplode(in, zsize, out, size);
            break;
        }
        case COMP_LZMA: {
            t32 = *outsize;
            size = unlzma(in, zsize, &out, size, LZMA_FLAGS_NONE, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZMA_86HEAD: {
            t32 = *outsize;
            size = unlzma(in, zsize, &out, size, LZMA_FLAGS_86_HEADER, &t32); // contains the uncompressed size
            *outsize = t32;
            break;
        }
        case COMP_LZMA_86DEC: {
            t32 = *outsize;
            size = unlzma(in, zsize, &out, size, LZMA_FLAGS_86_DECODER, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZMA_86DECHEAD: {
            t32 = *outsize;
            size = unlzma(in, zsize, &out, size, LZMA_FLAGS_86_DECODER | LZMA_FLAGS_86_HEADER, &t32); // contains the uncompressed size
            *outsize = t32;
            break;
        }
        case COMP_LZMA_EFS: {
            t32 = *outsize;
            size = unlzma(in, zsize, &out, size, LZMA_FLAGS_EFS, &t32);
            *outsize = t32;
            break;
        }
        case COMP_BZIP2: {
            size = unbzip2(in, zsize, out, size);
            break;
        }
        case COMP_XMEMLZX: {
            size = unxmemlzx(in, zsize, out, size);
            break;
        }
        case COMP_HEX: {
            size = unhex(in, zsize, out, size);
            break;
        }
        case COMP_BASE64: {
            size = unbase64(in, zsize, out, size);
            break;
        }
        case COMP_UUENCODE: {
            size = uudecode(in, zsize, out, size, 0);
            break;
        }
        case COMP_XXENCODE: {
            size = uudecode(in, zsize, out, size, 1);
            break;
        }
        case COMP_ASCII85: {
            size = unascii85(in, zsize, out, size);
            break;
        }
        case COMP_YENC: {
            size = unyenc(in, zsize, out, size);
            break;
        }
        case COMP_UNLZW: {
            size = unlzw(out, size, in, zsize);
            break;
        }
        case COMP_UNLZWX: {
            size = unlzwx(out, size, in, zsize);
            break;
        }
        //case COMP_CAB: {
            //size = unmspack_cab(in, zsize, out, size);
            //break;
        //}
        //case COMP_CHM: {
            //size = unmspack_chm(in, zsize, out, size);
            //break;
        //}
        //case COMP_SZDD: {
            //size = unmspack_szdd(in, zsize, out, size);
            //break;
        //}
        case COMP_LZXCAB: {
            size = unmslzx(in, zsize, out, size, 21, 0);
            break;
        }
        case COMP_LZXCHM: {
            size = unmslzx(in, zsize, out, size, 16, 2);
            break;
        }
        case COMP_RLEW: {
            size = unrlew(in, zsize, out, size);
            break;
        }
        case COMP_LZJB: {
            size = lzjb_decompress(in, out, zsize, size);
            break;
        }
        case COMP_SFL_BLOCK: {
            size = expand_block(in, out, zsize, size);
            break;
        }
        case COMP_SFL_RLE: {
            size = expand_rle(in, out, zsize, size);
            break;
        }
        case COMP_SFL_NULLS: {
            size = expand_nulls(in, out, zsize, size);
            break;
        }
        case COMP_SFL_BITS: {
            size = expand_bits(in, out, zsize, size);
            break;
        }
        case COMP_LZMA2: {
            t32 = *outsize;
            size = unlzma2(in, zsize, &out, size, LZMA_FLAGS_NONE, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZMA2_86HEAD: {
            t32 = *outsize;
            size = unlzma2(in, zsize, &out, size, LZMA_FLAGS_86_HEADER, &t32); // contains the uncompressed size
            *outsize = t32;
            break;
        }
        case COMP_LZMA2_86DEC: {
            t32 = *outsize;
            size = unlzma2(in, zsize, &out, size, LZMA_FLAGS_86_DECODER, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZMA2_86DECHEAD: {
            t32 = *outsize;
            size = unlzma2(in, zsize, &out, size, LZMA_FLAGS_86_DECODER | LZMA_FLAGS_86_HEADER, &t32); // contains the uncompressed size
            *outsize = t32;
            break;
        }
        case COMP_NRV2b:
        case COMP_NRV2d:
        case COMP_NRV2e: {
            size = unucl(in, zsize, out, size, compression_type);
            break;
        }
        case COMP_HUFFBOH: {
            size = huffboh_unpack_mem2mem(in, zsize, out, size);
            break;
        }
        case COMP_UNCOMPRESS: {
            size = uncompress_lzw(in, zsize, out, size, -1);
            break;
        }
        case COMP_DMC: {
            size = undmc(in, zsize, out, size);
            break;
        }
        case COMP_LZH: {
            size = unlzh(in, zsize, out, size);
            break;
        }
        case COMP_LZARI: {
            size = unlzari(in, zsize, out, size);
            break;
        }
        case COMP_TONY: {
            size = decompressTony(in, zsize, out, size);
            break;
        }
        case COMP_RLE7: {
            size = decompressRLE7(in, zsize, out, size);
            break;
        }
        case COMP_RLE0: {
            size = decompressRLE0(in, zsize, out, size);
            break;
        }
        case COMP_RLE: {
            //size = rle_decode(out, in, zsize);
            size = unrle(out, in, zsize);
            break;
        }
        case COMP_RLEA: {
            size = another_rle(in, zsize, out, size);
            break;
        }
        case COMP_BPE: {
            size = bpe_expand(in, zsize, out, size);
            break;
        }
        case COMP_QUICKLZ: {
            size = unquicklz(in, zsize, out, size);
            break;
        }
        case COMP_Q3HUFF: {
            size = unq3huff(in, zsize, out, size);
            break;
        }
        case COMP_UNMENG: {
            size = unmeng(in, zsize, out, size);
            break;
        }
        case COMP_LZ2K: {
            unlz2k_init();
            size = unlz2k(in, out, zsize, size);
            break;
        }
        case COMP_DARKSECTOR: {
            size = undarksector(in, zsize, out, size, 1);
            break;
        }
        case COMP_MSZH: {
            size = mszh_decomp(in, zsize, out, size);
            break;
        }
        case COMP_UN49G: {
            un49g_init();
            size = un49g(out, in);
            break;
        }
        case COMP_UNTHANDOR: {
            size = unthandor(in, zsize, out, size);
            break;
        }
        case COMP_DOOMHUFF: {
            size = doomhuff(in, zsize, out, size);
            break;
        }
        case COMP_APLIB: {
            size = aP_depack_safe(in, zsize, out, size);
            break;
        }
        case COMP_TZARLZSS: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the tzar_lzss decompression requires the setting of the dictionary in\n"
                    "       field comtype with the name of the variable containing the type of\n"
                    "       tzar decompression (from 0xa1 to 0xc5), like:\n"
                    "         comtype tzar_lzss MYVAR\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tzar_lzss_init();
            t32 = size;
            tzar_lzss(in, zsize, out, &t32,    // it's so horrible because the last argument is dynamic
                get_var32(get_var_from_name(comtype_dictionary, comtype_dictionary_len)));
            size = t32;
            break;
        }
        case COMP_LZF: {
            size = lzf_decompress(in, zsize, out, size);
            break;
        }
        case COMP_CLZ77: {
            size = CLZ77_Decode(out, size, in, zsize);
            break;
        }
        case COMP_LZRW1: {
            size = lzrw1_decompress(in, out, zsize, size);
            break;
        }
        case COMP_DHUFF: {
            size = undhuff(in, zsize, out, size);
            break;
        }
        case COMP_FIN: {
            size = unfin(in, zsize, out, size);
            break;
        }
        case COMP_LZAH: {
            size = de_lzah(in, zsize, out, size);
            break;
        }
        case COMP_LZH12: {
            size = de_lzh(in, zsize, out, size, 12);
            break;
        }
        case COMP_LZH13: {
            size = de_lzh(in, zsize, out, size, 13);
            break;
        }
#ifdef WIN32   // the library is not by default in linux and it's too big to attach in quickbms
        case COMP_GRZIP: {
            size = GRZip_DecompressBlock(in, zsize, out);
            break;
        }
#endif
        case COMP_CKRLE: {
            size = CK_RLE_decompress(in, zsize, out, size);
            break;
        }
        case COMP_QUAD: {
            size = unquad(in, zsize, out, size);
            break;
        }
        case COMP_BALZ: {
            size = unbalz(in, zsize, out, size);
            break;
        }
        // it's a zlib with the adding of inflateBack9 which is not default
        case COMP_DEFLATE64: {
            size = inflate64(in, zsize, out, size);
            break;
        }
        case COMP_SHRINK: {
            size = unshrink(in, zsize, out, size);
            break;
        }
        case COMP_PPMDI: {
            size = unppmdi(in, zsize, out, size);    // PKWARE specifics
            break;
        }
        case COMP_MULTIBASE: {
            size = multi_base_decoder(  // the usage of comtype_dictionary_len avoids wasting 2 vars
                comtype_dictionary_len & 0xff, (comtype_dictionary_len >> 8) & 0xff,
                in, zsize, out, size,
                comtype_dictionary);
            break;
        }
        case COMP_BRIEFLZ: {
            size = blz_depack(in, out, size);   // no zsize
            break;
        }
        case COMP_PAQ6: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PAQ6 decompression requires the setting of the dictionary in\n"
                    "       field comtype with the name of the variable containing the level of\n"
                    "       compression (from 0 to 9), like:\n"
                    "         comtype paq6 MYVAR\n"
                    "         comtype paq6 3 # default level\n");
                //myexit(-1);
                size = -1;
                break;
            }
            size = unpaq6(in, zsize, out, size,
                get_var32(get_var_from_name(comtype_dictionary, comtype_dictionary_len)));
            break;
        }
        case COMP_SHCODEC: {
            size = sh_DecodeBlock(in, out, zsize);
            break;
        }
        case COMP_HSTEST1: {
            size = hstest_hs_unpack(out, in, zsize);
            break;
        }
        case COMP_HSTEST2: {
            size = hstest_unpackc(out, in, zsize);
            break;
        }
        case COMP_SIXPACK: {
            size = unsixpack(in, zsize, out, size);
            break;
        }
        case COMP_ASHFORD: {
            size = unashford(in, zsize, out, size);
            break;
        }
#ifdef WIN32    // the alternative is using the compiled code directly
        case COMP_JCALG: {
            size = JCALG1_Decompress_Small(in, out);
            break;
        }
#endif
        case COMP_JAM: {
            size = unjam(in, zsize, out, size);
            break;
        }
        case COMP_LZHLIB: {
            size = unlzhlib(in, zsize, out, size);
            break;
        }
        case COMP_SRANK: {
            size = unsrank(in, zsize, out, size);
            break;
        }
        case COMP_ZZIP: {
            if(size >= zsize) { // zzip is horrible to use in this way
                memcpy(out, in, zsize);
                size = ZzUncompressBlock(out);
            } else {
                size = -1;
            }
            break;
        }
        case COMP_SCPACK: {
            size = strexpand(out, in, size, (unsigned char **)comtype_dictionary);
            break;
        }
        case COMP_RLE3: {
            size = rl3_decode(in, zsize, out, size);
            break;
        }
        case COMP_BPE2: {
            size = unbpe2(in, zsize, out, size);
            break;
        }
        case COMP_BCL_HUF: {
            Huffman_Uncompress(in, out, zsize, size);
            break;
        }
        case COMP_BCL_LZ: {
            LZ_Uncompress(in, out, zsize);
            break;
        }
        case COMP_BCL_RICE: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the BCL_RICE decompression requires the setting of the dictionary in\n"
                    "       field comtype with the name of the variable containing the type of\n"
                    "       compression (from 1 to 8, read rice.h), like:\n"
                    "         comtype bcl_rice 1\n");
                //myexit(-1);
                size = -1;
                break;
            }
            Rice_Uncompress(in, out, zsize, size,
                get_var32(get_var_from_name(comtype_dictionary, comtype_dictionary_len)));
            break;
        }
        case COMP_BCL_RLE: {
            size = RLE_Uncompress(in, zsize, out, size);
            break;
        }
        case COMP_BCL_SF: {
            SF_Uncompress(in, out, zsize, size);
            break;
        }
        case COMP_SCZ: {
            t32 = size;
            if(Scz_Decompress_Buffer2Buffer(in, zsize, (void *)&p, &t32) && (t32 <= size)) {
                size = t32;
                memcpy(out, p, size);
                free(p);
            } else {
                size = -1;
            }
            break;
        }
        case COMP_SZIP: {
            t32 = size;
            SZ_BufftoBuffDecompress(out, &t32, in, zsize, NULL);
            size = t32;
            break;
        }
        case COMP_PPMDI_RAW: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PPMDi decompression requires the setting of the dictionary field\n"
                    "       in comtype specifying SaSize, MaxOrder and Method, like:\n"
                    "         comtype ppmdi_raw \"10 4 0\"\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tmp1 = tmp2 = tmp3 = 0;
            //sscanf(comtype_dictionary, "%d %d %d", &tmp1, &tmp2, &tmp3);
            get_parameter_numbers(comtype_dictionary, 3, &tmp1, &tmp2, &tmp3);
            size = unppmdi_raw(in, zsize, out, size, tmp1, tmp2, tmp3);
            break;
        }
        case COMP_PPMDG: {
            size = unppmdg(in, zsize, out, size);
            break;
        }
        case COMP_PPMDG_RAW: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PPMdG decompression requires the setting of the dictionary field\n"
                    "       in comtype specifying SaSize and MaxOrder, like:\n"
                    "         comtype ppmdg_raw \"10 4\"\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tmp1 = tmp2 = 0;
            //sscanf(comtype_dictionary, "%d %d", &tmp1, &tmp2);
            get_parameter_numbers(comtype_dictionary, 2, &tmp1, &tmp2);
            size = unppmdg_raw(in, zsize, out, size, tmp1, tmp2);
            break;
        }
        case COMP_PPMDJ: {
            size = unppmdj(in, zsize, out, size);
            break;
        }
        case COMP_PPMDJ_RAW: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PPMdJ decompression requires the setting of the dictionary field\n"
                    "       in comtype specifying SaSize, MaxOrder and CutOff, like:\n"
                    "         comtype ppmdj_raw \"10 4 0\"\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tmp1 = tmp2 = tmp3 = 0;
            //sscanf(comtype_dictionary, "%d %d %d", &tmp1, &tmp2, &tmp3);
            get_parameter_numbers(comtype_dictionary, 3, &tmp1, &tmp2, &tmp3);
            size = unppmdj_raw(in, zsize, out, size, tmp1, tmp2, tmp3);
            break;
        }
        case COMP_SR3C: {
            size = unsr3c(in, zsize, out, size);
            break;
        }
        case COMP_HUFFMANLIB: {
            t32 = size;
            if(!huffman_decode_memory(in, zsize, &p, &t32) && (t32 <= size)) {
                size = t32;
                memcpy(out, p, size);
                free(p);
            } else {
                size = -1;
            }
            break;
        }
        case COMP_SFASTPACKER: {
            size = SFUnpack(in, zsize, out, size, 0);
            break;
        }
        case COMP_SFASTPACKER2: {
            size = SFUnpack(in, zsize, out, size, 1);   // smart mode only
            break;
        }
        case COMP_DK2: {
            undk2_init();
            size = undk2(out, in, 0);
            break;
        }
        case COMP_LZ77WII: {
            t32 = *outsize;
            size = unlz77wii(in, zsize, &out, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZ77WII_RAW10: {
            size = unlz77wii_raw10(in, zsize, out, size);
            break;
        }
        case COMP_DARKSTONE: {
            size = undarkstone(in, zsize, out, size);
            break;
        }
        case COMP_SFL_BLOCK_CHUNKED: {
            size = sfl_block_chunked(in, zsize, out, size);
            break;
        }
        case COMP_YUKE_BPE: {
            size = yuke_bpe(in, zsize, out, size, 1);
            break;
        }
        case COMP_STALKER_LZA: {
            stalker_lza_init();
            t32 = size;
            stalker_lza(in, zsize, &p, &t32);  // size is filled by the function
            size = t32;
            if(/*(tmp1 >= 0) &&*/ (size > 0)) {
                myalloc(&out, size, outsize);
                memcpy(out, p, size);
                free(p);
            } else {
                size = -1;
            }
            break;
        }
        case COMP_PRS_8ING: {
            size = prs_8ing_uncomp(out, size, in, zsize);
            break;
        }
        case COMP_PUYO_CNX: {
            size = puyo_cnx_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_CXLZ: {
            size = puyo_cxlz_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_LZ00: {
            size = puyo_lz00_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_LZ01: {
            size = puyo_lz01_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_LZSS: {
            size = puyo_lzss_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_ONZ: {
            size = puyo_onz_unpack(in, zsize, out, size);
            break;
        }
        case COMP_PUYO_PRS: {
            size = puyo_prs_unpack(in, zsize, out, size);
            break;
        }
        //case COMP_PUYO_PVZ: {
            //size = puyo_pvz_unpack(in, zsize, out, size);
            //break;
        //}
        case COMP_FALCOM: {
            size = falcom_DecodeData(out, size, in, zsize);
            break;
        }
        case COMP_CPK: {
            size = CPK_uncompress(in, zsize, out, size);
            break;
        }
        case COMP_BZIP2_FILE: {
            t32 = *outsize;
            size = unbzip2_file(in, zsize, &out, &t32);
            *outsize = t32;
            break;
        }
        case COMP_LZ77WII_RAW11: {
            size = unlz77wii_raw11(in, zsize, out, size);
            break;
        }
        case COMP_LZ77WII_RAW30: {
            size = unlz77wii_raw30(in, zsize, out, size);
            break;
        }
        case COMP_LZ77WII_RAW20: {
            size = unlz77wii_raw20(in, zsize, out, size);
            break;
        }
        case COMP_PGLZ: {
            size = pglz_decompress(in, zsize, out, size);
            break;
        }
        case COMP_SLZ: {
            size = UnPackSLZ(in, zsize, out, size);
            break;
        }
        case COMP_SLZ_01: {
            size = slz_triace(in, zsize, out, size, 1);
            break;
        }
        case COMP_SLZ_02: {
            size = slz_triace(in, zsize, out, size, 2);
            break;
        }
        case COMP_LZHL: {
            size = unlzhl(in, zsize, out, size);
            break;
        }
        case COMP_D3101: {
            size = d3101(in, zsize, out, size);
            break;
        }
        case COMP_SQUEEZE: {
            size = unsqueeze(in, zsize, out, size);
            break;
        }
        case COMP_LZRW3: {
            size = unlzrw3(in, zsize, out, size);
            break;
        }
        QUICK_COMP_UNPACK(ahuff,    ahuff_ExpandMemory)
        QUICK_COMP_UNPACK(arith,    arith_ExpandMemory)
        QUICK_COMP_UNPACK(arith1,   arith1_ExpandMemory)
        QUICK_COMP_UNPACK(arith1e,  arith1e_ExpandMemory)
        QUICK_COMP_UNPACK(arithn,   arithn_ExpandMemory)
        QUICK_COMP_UNPACK(compand,  compand_ExpandMemory)
        QUICK_COMP_UNPACK(huff,     huff_ExpandMemory)
        QUICK_COMP_UNPACK(lzss,     lzss_ExpandMemory)
        QUICK_COMP_UNPACK(lzw12,    lzw12_ExpandMemory)
        QUICK_COMP_UNPACK(lzw15v,   lzw15v_ExpandMemory)
        QUICK_COMP_UNPACK(silence,  silence_ExpandMemory)
        case COMP_RDC: {
            size = rdc_decompress(in, zsize, out);
            break;
        }
        case COMP_ILZR: {
            size = ilzr_expand(in, zsize, out, size);
            break;
        }
        case COMP_DMC2: {
            size = dmc2_uncompress(in, zsize, out, size);
            break;
        }
        QUICK_COMP_UNPACK(diffcomp, diffcomp)
        case COMP_LZR: {
            size = LZRDecompress(out, size, in, in + zsize);
            break;
        }
        case COMP_LZS: {
            size = unlzs(in, zsize, out, size, 0);
            break;
        }
        case COMP_LZS_BIG: {
            size = unlzs(in, zsize, out, size, 1);
            break;
        }
        case COMP_COPY: {
            size = uncopy(in, zsize, out, size);
            break;
        }
        case COMP_MOHLZSS: {
            size = moh_lzss(in, zsize, out, size);
            break;
        }
        case COMP_MOHRLE: {
            size = moh_rle(in, zsize, out, size);
            break;
        }
        case COMP_YAZ0: {
            size = decodeYaz0(in, zsize, out, size);
            break;
        }
        case COMP_BYTE2HEX: {
            size = byte2hex(in, zsize, out, size);
            break;
        }
        case COMP_UN434A: {
            un434a_init();
            size = un434a(in, out);
            break;
        }
        case COMP_UNZIP_DYNAMIC: {
            t32 = *outsize;
            size = unzip_dynamic(in, zsize, &out, &t32);
            *outsize = t32;
            break;
        }
        case COMP_GZPACK: {
            size = gz_unpack(in, zsize, out, size);
            break;
        }
        case COMP_ZLIB_NOERROR: {
            size = unzip_zlib(in, zsize, out, size, 1);
            break;
        }
        case COMP_DEFLATE_NOERROR: {
            size = unzip_deflate(in, zsize, out, size, 1);
            break;
        }
        case COMP_PPMDH: {
            size = unppmdh(in, zsize, out, size);
            break;
        }
        case COMP_PPMDH_RAW: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PPMdH decompression requires the setting of the dictionary field\n"
                    "       in comtype specifying SaSize and MaxOrder, like:\n"
                    "         comtype ppmdh_raw \"10 4\"\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tmp1 = tmp2 = 0;
            //sscanf(comtype_dictionary, "%d %d", &tmp1, &tmp2);
            get_parameter_numbers(comtype_dictionary, 2, &tmp1, &tmp2);
            size = unppmdh_raw(in, zsize, out, size, tmp1, tmp2);
            break;
        }
        case COMP_RNC: {
            size = rnc_unpack(in, out, 0);
            break;
        }
        case COMP_RNC_RAW: {
            size = rnc_unpack(in, out, size);
            break;
        }
        case COMP_FITD: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the PAK_explode decompression requires the setting of the dictionary\n"
                    "       field in comtype specifying info5, like:\n"
                    "         get info5 byte\n"
                    "         comtype ppmdh_raw info5\n");
                //myexit(-1);
                size = -1;
                break;
            }
            tmp1 = 0;
            get_parameter_numbers(comtype_dictionary, 1, &tmp1);
            PAK_explode(in, out, zsize, size, tmp1);    // no return value
            break;
        }
        case COMP_KENS_Nemesis: {
            size = KENS_Nemesis(in, zsize, out, size);
            break;
        }
        case COMP_KENS_Kosinski: {
            size = KENS_Kosinski(in, zsize, out, size, 0);
            break;
        }
        case COMP_KENS_Kosinski_moduled: {
            size = KENS_Kosinski(in, zsize, out, size, 1);
            break;
        }
        case COMP_KENS_Enigma: {
            size = KENS_Enigma(in, zsize, out, size);
            break;
        }
        case COMP_KENS_Saxman: {
            size = KENS_Saxman(in, zsize, out, size);
            break;
        }
        case COMP_DRAGONBALLZ: {
            size = undragonballz(in, zsize, out);
            break;
        }
        case COMP_NITROSDK: {
            size = nitroDecompress(in, zsize, out, 1);
            break;
        }
        /* compressions */
        case COMP_ZLIB_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_rfc1950(in, zsize, out, size);
            break;
        }
        case COMP_DEFLATE_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_deflate(in, zsize, out, size);
            break;
        }
        case COMP_LZO1_COMPRESS:
        case COMP_LZO1X_COMPRESS:
        case COMP_LZO2A_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = lzo_compress(in, zsize, out, size, compression_type);
            break;
        }
        case COMP_XMEMLZX_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = xmem_compress(in, zsize, out, size);
            break;
        }
        case COMP_BZIP2_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = bzip2_compress(in, zsize, out, size);
            break;
        }
        case COMP_GZIP_COMPRESS: {
            size = 20 + MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = gzip_compress(in, zsize, out, size);
            break;
        }
        case COMP_LZSS_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = lzss_compress(in, zsize, out, size);
            break;
        }
        case COMP_SFL_BLOCK_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = compress_block(in, out, zsize);
            break;
        }
        case COMP_SFL_RLE_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = compress_rle(in, out, zsize);
            break;
        }
        case COMP_SFL_NULLS_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = compress_nulls(in, out, zsize);
            break;
        }
        case COMP_SFL_BITS_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = compress_bits(in, out, zsize);
            break;
        }
        case COMP_LZF_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = lzf_compress(in, zsize, out, size);
            break;
        }
        case COMP_BRIEFLZ_COMPRESS: {
            size = blz_max_packed_size(size);
            myalloc(&out, size, outsize);
            p = malloc(blz_workmem_size(zsize));
            size = blz_pack(in, out, zsize, p);
            free(p);
            break;
        }
#ifdef WIN32    // the alternative is using the compiled code directly
        case COMP_JCALG_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = JCALG1_Compress(in, zsize, out, 1024 * 1024, &JCALG1_AllocFunc, &JCALG1_DeallocFunc, &JCALG1_CallbackFunc, 0);
            break;
        }
#endif
        case COMP_BCL_HUF_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = Huffman_Compress(in, out, zsize);
            break;
        }
        case COMP_BCL_LZ_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = LZ_Compress(in, out, zsize);
            break;
        }
        case COMP_BCL_RICE_COMPRESS: {
            if(!comtype_dictionary) {
                printf("\n"
                    "Error: the BCL_RICE decompression requires the setting of the dictionary in\n"
                    "       field comtype with the name of the variable containing the type of\n"
                    "       compression (from 1 to 8, read rice.h), like:\n"
                    "         comtype bcl_rice 1\n");
                //myexit(-1);
                size = -1;
                break;
            }
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = Rice_Compress(in, out, zsize,
                get_var32(get_var_from_name(comtype_dictionary, comtype_dictionary_len)));
            break;
        }
        case COMP_BCL_RLE_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = RLE_Compress(in, zsize, out, size);
            break;
        }
        case COMP_BCL_SF_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = SF_Compress(in, out, zsize);
            break;
        }
        case COMP_SZIP_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            t32 = *outsize;
            SZ_BufftoBuffCompress(out, &t32, in, zsize, NULL);
            *outsize = t32;
            break;
        }
        case COMP_HUFFMANLIB_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            t32 = size;
            if(!huffman_encode_memory(in, zsize, &p, &t32)) {
                size = t32;
                myalloc(&out, size, outsize);
                memcpy(out, p, size);
                free(p);
            } else {
                size = -1;
            }
            break;
        }
        case COMP_LZMA_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_lzma(in, zsize, out, size, LZMA_FLAGS_NONE);
            break;
        }
        case COMP_LZMA_86HEAD_COMPRESS: {
            size = 8 + MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_lzma(in, zsize, out, size, LZMA_FLAGS_86_HEADER);
            break;
        }
        case COMP_LZMA_86DEC_COMPRESS: {
            size = 1 + MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_lzma(in, zsize, out, size, LZMA_FLAGS_86_DECODER);
            break;
        }
        case COMP_LZMA_86DECHEAD_COMPRESS: {
            size = 1 + 8 + MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_lzma(in, zsize, out, size, LZMA_FLAGS_86_DECODER | LZMA_FLAGS_86_HEADER);
            break;
        }
        case COMP_LZMA_EFS_COMPRESS: {
            size = 4 + MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = advancecomp_lzma(in, zsize, out, size, LZMA_FLAGS_EFS);
            break;
        }
        case COMP_FALCOM_COMPRESS: {
            size = MAXZIPLEN(size);
            myalloc(&out, size, outsize);
            size = falcom_EncodeData(out, size, in, zsize);
            break;
        }
        default: {
            printf("\nError: unsupported compression type %d\n", (i32)compression_type);
            break;
        }
    }
    *ret_out = out;
    return(size);
}



// log to file happens only here
int dumpa_direct_copy(int fdnum, FILE *fd, u8 *out, int size) {
    static int  tmpsz   = 0;
    static u8   *tmp    = NULL;
    int     t,
            len;

    if(out) {
        // normal buffer copy
        len = fwrite(out, 1, size, fd);
    } else {
        // direct copy
        if(!tmp) {
            tmpsz = 1024 * 1024; // 1 megabyte
            tmp = malloc(tmpsz);
            if(!tmp) STD_ERR;
        }

        for(len = 0; len < size; len += t) {
            t = tmpsz;
            if((size - len) < t) t = size - len;
            t = myfr(fdnum, tmp, t);
            if(t <= 0) break;
            t = fwrite(tmp, 1, t, fd);
            if(t <= 0) break;
        }
    }
    return(len);
}



inline void dumpa_state(int *quickbms_compression, int *quickbms_encryption, int zsize, int size) {
    // notes:
    // encryption uses only the output buffer: memory = file_size
    // compression uses both input and output: memory = file_size * 2 (at least)
    // otherwise no memory is used

    //if(quickbms_compression) {
        *quickbms_compression = 0;
        if((zsize > 0) && (size > 0)) *quickbms_compression = 1;
    //}
    //if(quickbms_encryption) {
        *quickbms_encryption = 0;
        if(!perform_encryption(NULL, -1)) *quickbms_encryption = 1;
    //}
}



int dumpa(int fdnum, u8 *fname, int offset, int size, int zsize) {
    static  u8  tmpname[PATHSZ + 32 + 1] = "";  // 32 includes the dynamic extension
    static  int insize  = 0,    // ONLY as total allocated input size
                outsize = 0;    // ONLY as total allocated output size
    static  u8  *in     = NULL,
                *out    = NULL;

    process_file_t  *procfile   = NULL;
    socket_file_t   *sockfile   = NULL;
    memory_file_t   *memfile    = NULL;
    FILE    *fd;
    int     len,
            oldoff,
            filetmp     = 0,
            direct_copy = 0,
            quickbms_compression = 0,
            quickbms_encryption  = 0,
            old_zsize,
            old_size,
            old_compression_type;
    u8      tmpbuff[64],
            ans[16],
            *p,
            *ext;

    if(!fname /*&& (offset < 0)*/ && (size < 0) && (zsize < 0)) {   // all must be invalid
        FREEZ(in)
        FREEZ(out)
        insize  = 0;
        outsize = 0;
        return(-1);
    }

    // the following is a set of filename cleaning instructions to avoid that files or data with special names are not saved
    if(fname) {
        sockfile = socket_open(fname);
        if(!sockfile) {
        procfile = process_open(fname);
        if(!procfile) {
            if(fname[1] == ':') fname += 2;
            for(p = fname; *p && (*p != '\n') && (*p != '\r'); p++) {
                if(strchr("?%*:|\"<>", *p)) {    // invalid filename chars not supported by the most used file systems
                    *p = '_';
                }
            }
            *p = 0;
            for(p--; (p >= fname) && ((*p == ' ') || (*p == '.')); p--) *p = 0;   // remove final spaces and dots
        }
        }
    }

    if(!fname || !fname[0]) {
        fname = tmpname;
        if(input_total_files <= 1) {    // extension added by sign_ext
            snprintf(fname, PATHSZ, "%08x.dat", (i32)extracted_files);
        } else {
            snprintf(fname, PATHSZ, "%s%c%08x.dat", filenumber[0].basename, PATHSLASH, (i32)extracted_files);
        }
    }

    // handling of the output filename
    if(sockfile) {
        // do nothing

    } else if(procfile) {
        // do nothing

    } else if(!strnicmp(fname, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        memfile = &memory_file[-get_memory_file(fname)];    // yes, remember that it must be negative of negative
        if(verbose > 0) printf("- create a memory file from offset %08x of %u bytes\n", (i32)offset, (i32)size);

    } else if(!stricmp(fname, TEMPORARY_FILE)) {
        temporary_file_used = 1;    // global for final unlink
        filetmp = 1;
        if(verbose > 0) printf("- create a temporary file from offset %08x of %u bytes\n", (i32)offset, (i32)size);

    } else {
        if(filter_files && (check_wildcard(fname, filter_files) < 0)) goto quit;
        if(!reimport) printf("  %08x %-10u %s\n", (i32)offset, (i32)size, fname);
        if(listfd) {
            fprintf(listfd, "  %08x %-10u %s\n", (i32)offset, (i32)size, fname);
            fflush(listfd);
        }
    }

    if(list_only && !memfile && !sockfile && !procfile && !filetmp) {
        // do nothing
    } else if((fname[strlen(fname) - 1] == '\\') || (fname[strlen(fname) - 1] == '/')) {    // folder
        // do nothing
    } else if(reimport && !memfile && !sockfile && !procfile) {
        if(fname == tmpname) {
            quick_simple_tmpname_scanner(fname, PATHSZ);
        }
        fd = fopen(fname, "rb");
        if(fd) {
            oldoff = myftell(fdnum);
            myfseek(fdnum, offset, SEEK_SET);
            dumpa_state(&quickbms_compression, &quickbms_encryption, zsize, size);

            old_zsize = zsize;
            old_size  = size;

            fseek(fd, 0, SEEK_END);
            size = ftell(fd);
            fseek(fd, 0, SEEK_SET);

            zsize = size;
            myalloc(&out, size,  &outsize); // will be allocated by perform_compression
            if(quickbms_compression) {
                myalloc(&in,  zsize, &insize);
                zsize = fread(in, 1, zsize, fd);
                old_compression_type = compression_type;
                switch(compression_type) {
                    #define QUICK_COMP_COMPRESS(X) \
                        case X: compression_type = X##_COMPRESS; break;
                    case COMP_NONE:             compression_type = COMP_COPY;               break;
                    case COMP_COPY:             compression_type = COMP_COPY;               break;
                    case COMP_NOP:              compression_type = COMP_COPY;               break;
                    case COMP_ZLIB_NOERROR:     compression_type = COMP_ZLIB_COMPRESS;      break;
                    case COMP_UNZIP_DYNAMIC:    compression_type = COMP_ZLIB_COMPRESS;      break;  // ???
                    case COMP_DEFLATE_NOERROR:  compression_type = COMP_DEFLATE_COMPRESS;   break;
                    QUICK_COMP_COMPRESS(COMP_ZLIB)
                    QUICK_COMP_COMPRESS(COMP_DEFLATE)
                    QUICK_COMP_COMPRESS(COMP_LZO1)
                    QUICK_COMP_COMPRESS(COMP_LZO1X)
                    QUICK_COMP_COMPRESS(COMP_LZO2A)
                    QUICK_COMP_COMPRESS(COMP_XMEMLZX)
                    QUICK_COMP_COMPRESS(COMP_BZIP2)
                    QUICK_COMP_COMPRESS(COMP_GZIP)
                    QUICK_COMP_COMPRESS(COMP_LZSS)
                    QUICK_COMP_COMPRESS(COMP_SFL_BLOCK)
                    QUICK_COMP_COMPRESS(COMP_SFL_RLE)
                    QUICK_COMP_COMPRESS(COMP_SFL_NULLS)
                    QUICK_COMP_COMPRESS(COMP_SFL_BITS)
                    QUICK_COMP_COMPRESS(COMP_LZF)
                    QUICK_COMP_COMPRESS(COMP_BRIEFLZ)
                    QUICK_COMP_COMPRESS(COMP_JCALG)
                    QUICK_COMP_COMPRESS(COMP_BCL_HUF)
                    QUICK_COMP_COMPRESS(COMP_BCL_LZ)
                    QUICK_COMP_COMPRESS(COMP_BCL_RICE)
                    QUICK_COMP_COMPRESS(COMP_BCL_RLE)
                    QUICK_COMP_COMPRESS(COMP_BCL_SF)
                    QUICK_COMP_COMPRESS(COMP_SZIP)
                    QUICK_COMP_COMPRESS(COMP_HUFFMANLIB)
                    QUICK_COMP_COMPRESS(COMP_LZMA)
                    QUICK_COMP_COMPRESS(COMP_LZMA_86HEAD)
                    QUICK_COMP_COMPRESS(COMP_LZMA_86DEC)
                    QUICK_COMP_COMPRESS(COMP_LZMA_86DECHEAD)
                    QUICK_COMP_COMPRESS(COMP_LZMA_EFS)
                    QUICK_COMP_COMPRESS(COMP_FALCOM)
                    default: {
                        if(compression_type < COMP_NOP) { // if it's already a compression algorithm, continue
                            printf("\nError: unsupported compression %d in reimport mode\n", (i32)compression_type);
                            myexit(-1);
                        }
                        break;
                    }
                }
                size = perform_compression(in, zsize, &out, size, &outsize);
                compression_type = old_compression_type;
                if(size < 0) {
                    printf("\n"
                        "Error: there is an error with the decompression\n"
                        "       the returned output size is negative (%d)\n", (i32)size);
                    myexit(-1);
                }
            } else {
                old_zsize = old_size;   // avoid boring "if" during the check of the size
                size = fread(out, 1, size, fd);
            }
            fclose(fd);

            // mainly for block ciphers, but also for cleaning the data
            // size and old_zsize are correct, check the next comment
            if(size < old_zsize) {
                myalloc(&out, old_zsize,  &outsize);
                memset(out + size, 0, old_zsize - size);
                size = old_zsize;
            }
            encrypt_mode = !encrypt_mode;
            size = perform_encryption(out, size);
            encrypt_mode = !encrypt_mode;
            if(size == -1) {
                printf("\nError: the encryption failed\n");
                myexit(-1);
            }

            // yes, size and old_zsize because it's the opposite of the extraction
            if(size > old_zsize) {
                printf("\n"
                    "Error: file \"%s\"\n"
                    "       the reimport option acts as a reimporter and so you cannot reinsert a\n"
                    "       file if it's bigger than the original otherwise it will overwrite the\n"
                    "       rest of the archive:\n"
                    "         new size: %d\n"
                    "         old size: %d\n"
                    "\n",
                    fname,
                    (i32)size,
                    (i32)old_zsize);

                printf("- do you want to skip this file? (y/N)\n  ");
                fgetz(ans, sizeof(ans), stdin, NULL);
                if(tolower(ans[0]) != 'y') {
                    if(!strnicmp(ans, "force", 5)) {
                        // force the writing of the file
                        old_zsize = size;
                    } else {
                        printf(
                            "       now it's suggested to restore the backup of the original archive\n"
                            "       because the current one could have been corrupted due to the\n"
                            "       incomplete operation\n");
                        myexit(-1);
                    }
                }
            }
            // separated to allow the "force" writing
            if(size <= old_zsize) {
                len = myfw(fdnum, out, size);
                if(len != size) {
                    printf("\nError: impossible to write the file on the disk, check your space\n");
                    myexit(-1);
                }
                printf("< %08x %-10u %s\n", (i32)offset, (i32)size, fname);
                reimported_files++;

                /* not needed at the moment, maybe in future but keep in mind the notes in quickbms.txt!
                myfseek(fdnum, reimport_zsize_offset, SEEK_SET);
                fputxx(fdnum, size, 4);     // zsize->size must be swapped!
                myfseek(fdnum, reimport_size_offset, SEEK_SET);
                fputxx(fdnum, zsize, 4);    // zsize->size must be swapped!
                */
            }

            myfseek(fdnum, oldoff, SEEK_SET);
        }

    } else if(memfile && !size && !zsize && !fdnum) {
        // memory file initialization: log MEMORY_FILE 0 0
        dumpa_memory_file(memfile, &out, size, &outsize);
        return(0);

    } else {
        if(!void_dump && !memfile && !sockfile && !procfile) {
            // the following is not so good for fname ""
            // because will ask the confirmation 2 times in some occasions
            fname = create_dir(fname);
            if(check_overwrite(fname, 0) < 0) goto quit;
        }

        oldoff = myftell(fdnum);
        myfseek(fdnum, offset, SEEK_SET);
        dumpa_state(&quickbms_compression, &quickbms_encryption, zsize, size);

        // direct_copy saves memory with normal files
        if(!memfile && !sockfile && !procfile && !quickbms_encryption && !quickbms_compression) {
#ifdef ENABLE_DIRECT_COPY
            direct_copy = 1;
#endif
        }
        if(!direct_copy) {
            //if(size == -1) ALLOC_ERR;
            myalloc(&out, size, &outsize);      // + 1 is NOT necessary
            if(quickbms_compression) { // remember that the (size == zsize) check is NOT valid so can't be used in a "generic" way!
                //if(zsize == -1) ALLOC_ERR;
                myalloc(&in, zsize, &insize);   // + 1 is NOT necessary
                myfr(fdnum, in, zsize);
                zsize = perform_encryption(in, zsize);
                if(zsize == -1) {
                    printf("\nError: the encryption failed\n");
                    myexit(-1);
                }

                size = perform_compression(in, zsize, &out, size, &outsize);

                if(comtype_scan && (size <= 0)) {  // both invalid and empty
                    myfseek(fdnum, oldoff, SEEK_SET);   // important, NEVER forget it!
                    goto quit;
                }
                if(size < 0) {
                    printf("\n"
                        "Error: there is an error with the decompression\n"
                        "       the returned output size is negative (%d)\n", (i32)size);
                    myexit(-1);
                }
                if(size > outsize) {    // "limit" possible overflows with some unsafe algorithms (like sflcomp)
                    printf("\n"
                        "Error: the uncompressed data (%d) is bigger than the allocated buffer (%d)\n", (i32)size, (i32)outsize);
                    myexit(-1);
                }
                // do NOT add checks which verify if the unpacked size is like the expected one, I prefer the compatibility
            } else {
                myfr(fdnum, out, size);
                size = perform_encryption(out, size);
                if(size == -1) {
                    printf("\nError: the encryption failed\n");
                    myexit(-1);
                }
            }
        }

        len = size;
        if(sockfile) {
            len = socket_write(sockfile, out, size);

        } else if(procfile) {
            len = process_write(procfile, out, size);

        } else if(memfile) {
            len = dumpa_memory_file(memfile, &out, size, &outsize);

        } else if(!void_dump) {
            if(fname == tmpname) {  // the length of the extension is fixed in the database
                if(direct_copy) {   // unfortunately will not catch the tga files in this way, that's the only price
                    len = size;     // but note that not all the tga files use the TRUEVISION-XFILE ending!
                    if(len > sizeof(tmpbuff)) len = sizeof(tmpbuff);
                    myfr(fdnum, tmpbuff, len);
                    myfseek(fdnum, offset, SEEK_SET);
                    ext = sign_ext(tmpbuff, len);
                } else {
                    ext = sign_ext(out, size);
                }
                strcpy(strrchr(fname, '.') + 1, ext);
                if(check_overwrite(fname, 0) < 0) goto quit;
                // check_overwrite is used before processing the file for performance reasons
                // because would be useless to extract a 2gb file that is already extracted
                // that's why this function is not called below but only here and in the main
                // part of the function above
            }
            for(;;) {
                if(append_mode) {
                    fd = fopen(fname, "ab");
                } else {
                    fd = fopen(fname, "wb");
                }
                //if(!fd) STD_ERR;
                if(fd) break;
                fname = rename_invalid(fname);
            }
            len = dumpa_direct_copy(
                fdnum, fd,
                direct_copy ? NULL : out,
                size);
            fclose(fd);
        }
        if(len != size) {
            printf("\nError: impossible to write the file on the disk, check your space\n");
            myexit(-1);
        }

        myfseek(fdnum, oldoff, SEEK_SET);
    }
    if(!memfile) {
        extracted_files++;
        if(mex_default) {
            add_var(EXTRCNT_idx, NULL, NULL, extracted_files, sizeof(int));
        }
    }
quit:
    return(0);
}



int check_wildcard(u8 *fname, u8 *wildcard) {
    u8      *f,
            *w,
            *a;

    if(!fname) return(-1);
    if(!wildcard) return(-1);
    f = fname;
    w = wildcard;
    a = NULL;
    while(*f || *w) {
        if(!*w && !a) return(-1);
        if(*w == '?') {
            if(!*f) break;
            w++;
            f++;
        } else if(*w == '*') {
            w++;
            a = w;
        } else {
            if(!*f) break;
            if(tolower(*f) != tolower(*w)) {
                if(!a) return(-1);
                f++;
                w = a;
            } else {
                f++;
                w++;
            }
        }
    }
    if(*f || *w) return(-1);
    return(0);
}



u8 *create_dir(u8 *fname) {
    u8      *p,
            *l;

    if(!fname) return(NULL);
    p = strchr(fname, ':'); // unused
    if(p) {
        *p = '_';
        fname = p + 1;
    }
    for(p = fname; *p && strchr("\\/. \t:", *p); p++) *p = '_';
    fname = p;

    for(p = fname; ; p = l + 1) {
        for(l = p; *l && (*l != '\\') && (*l != '/'); l++);
        if(!*l) break;
        *l = 0;

        if(!strcmp(p, "..")) {
            p[0] = '_';
            p[1] = '_';
        }

        make_dir(fname);
        *l = PATHSLASH;
    }
    return(fname);
}



int check_overwrite(u8 *fname, int check_if_present_only) {
    FILE    *fd;
    u8      ans[16];

    if(force_overwrite) return(0);
    if(!fname) return(0);
    fd = fopen(fname, "rb");
    if(!fd) return(0);
    fclose(fd);
    if(check_if_present_only) return(-1);
    printf("- the file \"%s\" already exists\n  do you want to overwrite it (y/N/all)? ", fname);
    if(append_mode) printf("\n"
        "  (remember that you are in append mode so be sure that the output folder was\n"
        "  empty otherwise the new data will be appended to the existent files!) ");
    fgetz(ans, sizeof(ans), stdin, NULL);
    if(tolower(ans[0]) == 'y') return(0);
    if(tolower(ans[0]) == 'a') {
        force_overwrite = 1;
        return(0);
    }
    return(-1);
}



void myalloc(u8 **data, QUICKBMS_int wantsize, QUICKBMS_int *currsize) {
    int     ows;        // original wantsize
    u8      *old_data;  // allocate it at any cost

    if(wantsize < 0) {
        printf("\nError: the requested amount of bytes to allocate is negative (%d)\n", (i32)wantsize);
        myexit(-1);
    }
    if(!wantsize) return;

    ows = wantsize;
    wantsize += MYALLOC_ZEROES;                 // another "not bad as fault-safe and fast alloc solution" (good for padding and strange things like some games and XMemDecompress)
    wantsize = (wantsize + 4095) & (~4095);     // not bad as fault-safe and fast alloc solution: padding (4096 is usually the default size of a memory page)
    if((wantsize < 0) || (wantsize < ows)) {    // due to integer rounding
        printf("\nError: the requested amount of bytes to allocate is negative/too big (%d)\n", (i32)wantsize);
        myexit(-1);
        //wantsize = ows;   // remember memset MYALLOC_ZEROES
    }

    if(wantsize <= *currsize) {
        if(*currsize > 0) goto quit;
    }

    old_data = *data;
    *data = realloc(*data, wantsize);
    if(!*data) {
        if(old_data) free(old_data);
        *data = malloc(wantsize);
        if(!*data) {
            printf("- try allocating %u bytes\n", (i32)wantsize);
            STD_ERR;
        }
    }
    *currsize = wantsize - MYALLOC_ZEROES;      // obviously
quit:
    memset((*data) + ows, 0, MYALLOC_ZEROES);   // ows is the original wantsize, useful in some cases like XMemDecompress
}



int getxx(u8 *tmp, int bytes) {
    u_int   num;
    int     i;

    if(!tmp) return(0);
    num = 0;
    for(i = 0; i < bytes; i++) {
        if(endian == MYLITTLE_ENDIAN) {
            num |= ((u_int)tmp[i] << (u_int)(i << (u_int)3));
        } else {
            num |= ((u_int)tmp[i] << (u_int)((bytes - (u_int)1 - i) << (u_int)3));
        }
    }
    return(num);
}



int putxx(u8 *data, u_int num, int bytes) {
    int     i;

    if(!data) return(0);
    for(i = 0; i < bytes; i++) {
        if(endian == MYLITTLE_ENDIAN) {
            data[i] = num >> (i << (u_int)3);
        } else {
            data[i] = num >> ((bytes - (u_int)1 - i) << (u_int)3);
        }
    }
    return(bytes);
}



u8 *fgetss(int fdnum, int chr, int unicode, int line) {  // reads a chr terminated string, at the moment unicode is referred to the 16bit unicode
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    int     i,
            c,
            unicnt  = -1,
            except  = 0;

    if(chr < 0) {
        chr = -chr;
        except = 1;
    }
    // if(!fd) do nothing, modify myfgetc
    for(i = 0;;) {
        c = myfgetc(fdnum);
        if(c < 0) {
            if(!i) return(NULL);    // return a NULL if EOF... this is for compatibility with old versions of quickbms although it's not so right
            break;
        }
        if(line && !i) {
            if((c == '\r') || (c == '\n')) continue;
        }
        if(unicode) {
            unicnt++;
            if(endian == MYLITTLE_ENDIAN) {
                if(unicnt & 1) continue;
            } else {
                if(!(unicnt & 1)) continue;
            }
        }
        if(except) {
            if(c != chr) break;
        } else {
            if(c == chr) break;
        }
        if(i >= buffsz) {
            buffsz += STRINGSZ;
            buff = realloc(buff, buffsz + 1);
            if(!buff) STD_ERR;
        }
        buff[i] = c;
        i++;
    }
    if(unicode) {
        if(endian == MYLITTLE_ENDIAN) c = myfgetc(fdnum);  // needed for reaching the real end of the unicode string (16 bit)
    }
    //if(c < 0) return(NULL);
    if(!buff) buff = malloc(1); // remember, anything returned by this function MUST be allocated
    buff[i] = 0;
    if(line) {
        for(i = 0; buff[i]; i++) {  // buff has been nulled
            if((buff[i] == '\r') || (buff[i] == '\n')) buff[i] = 0;
        }
    }
    return(buff);
}



int fputss(int fdnum, u8 *data, int chr, int unicode, int line) {  // writes a chr terminated string, at the moment unicode is referred to the 16bit unicode
    int     i,
            c,
            unicnt  = -1;

    if(!data) data = "";
    // if(!fd) do nothing, modify myfputc
    for(i = 0;;) {
        if(unicode) {
            unicnt++;
            if(
                ((endian == MYLITTLE_ENDIAN) && (unicnt & 1))
             || ((endian != MYLITTLE_ENDIAN) && !(unicnt & 1))) {
                c = myfputc(0x00, fdnum);
                if(c < 0) return(-1);
                continue;
            }
        }
        if(line) {
            if(data[i] == 0x00) break;
            if(data[i] == '\r') break;
            if(data[i] == '\n') break;
        }
        if((chr < 0) && (data[i] == 0x00)) break;
        c = myfputc(data[i], fdnum);
        if(c < 0) return(-1);
        if(c == chr) break;
        i++;
    }
    if(unicode) {
        if(endian == MYLITTLE_ENDIAN) c = myfputc(0x00, fdnum);
    }
    if(line) {
        if(myfputc('\r', fdnum) < 0) return(-1);
        if(myfputc('\n', fdnum) < 0) return(-1);
    }
    return(i);
}



int myfgetc(int fdnum) {
    int     c;
    u8      buff[1];

    c = myfr(fdnum, buff, 1);
    if(c < 0) return(c);
    return(buff[0]);
}



int myfputc(int c, int fdnum) {
    int     ret;
    u8      buff[1];

    buff[0] = c;
    ret = myfw(fdnum, buff, 1);
    if(ret < 0) return(ret);
    return(c);
}



int fgetxx(int fdnum, int bytes) {
    int     ret;
    u8      tmp[bytes];

    // if(!fd) do nothing, modify myfr
    myfr(fdnum, tmp, bytes);
    ret = getxx(tmp, bytes);
    if(endian_killer) { // reverse endianess
        endian = (endian == MYLITTLE_ENDIAN) ? MYBIG_ENDIAN : MYLITTLE_ENDIAN;
        myfseek(fdnum, -bytes, SEEK_CUR);
        fputxx(fdnum, ret, bytes);
        endian = (endian == MYLITTLE_ENDIAN) ? MYBIG_ENDIAN : MYLITTLE_ENDIAN;
    }
    return(ret);
}



int fputxx(int fdnum, int num, int bytes) {
    u8      tmp[bytes];

    // if(!fd) do nothing, modify mywr
    putxx(tmp, num, bytes);
    return(myfw(fdnum, tmp, bytes));
}



int myfilesize(int fdnum) {
    struct stat xstat;

    if(fdnum < 0) {
        return(memory_file[-fdnum].size);
    }
    CHECK_FILENUM
    if(filenumber[fdnum].sd) return(((u_int)(-1)) >> 1);    // 0x7fffffff...
    if(filenumber[fdnum].pd) return(((process_file_t *)filenumber[fdnum].pd)->size);
    fstat(fileno(filenumber[fdnum].fd), &xstat);
    return(xstat.st_size);
}



int delimit(u8 *str) {
    u8      *p;

    if(!str) return(-1);
    for(p = str; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - str);
}



int unreal_index(int fdnum) {
    int     result = 0;
    u8      b0,
            b1,
            b2,
            b3,
            b4;

    b0 = fgetxx(fdnum, 1);
    if(b0 & 0x40) {
        b1 = fgetxx(fdnum, 1);
        if(b1 & 0x80) {
            b2 = fgetxx(fdnum, 1);
            if(b2 & 0x80) {
                b3 = fgetxx(fdnum, 1);
                if(b3 & 0x80) {
                    b4 = fgetxx(fdnum, 1);
                    result = b4;
                }
                result = (result << 7) | (b3 & 0x7f);
            }
            result = (result << 7) | (b2 & 0x7f);
        }
        result = (result << 7) | (b1 & 0x7f);
    }
    result = (result << 6) | (b0 & 0x3f);
    if(b0 & 0x80) result = -result;
    return(result);
}



int make_unreal_index(int number, u8 *index_num) {
    int     len  = 0,
            sign = 0;

    if(number < 0) {
        number = -number;
        sign = -1;
    }

    len++;
    index_num[0] = (number & 0x3f);
    number >>= 6;
    if(number) {
        len++;
        index_num[0] += 0x40;
        index_num[1] = (number & 0x7f);
        number >>= 7;
        if(number) {
            len++;
            index_num[1] += 0x80;
            index_num[2] = (number & 0x7f);
            number >>= 7;
            if(number) {
                len++;
                index_num[2] += 0x80;
                index_num[3] = (number & 0x7f);
                number >>= 7;
                if(number) {
                    len++;
                    index_num[3] += 0x80;
                    index_num[4] = number;
                }
            }
        }
    }
    if(sign) index_num[0] += 0x80;
    return(len);
}




u8 *myfrx(int fdnum, int type, int *ret_num, int *error) {
    long double tmp_longdouble;
    double  tmp_double;
    float   tmp_float;
    u64     tmp64;
    int     retn    = 0;
    u8      tmp[16],
            c,
            *ret    = NULL;

    *error = 0;
    switch(type) {
        case TYPE_LONGLONG:     retn = fgetxx(fdnum, 8);            break;
        case TYPE_LONG:         retn = fgetxx(fdnum, 4);            break;
        case TYPE_SHORT:        retn = fgetxx(fdnum, 2);            break;
        case TYPE_BYTE:         retn = fgetxx(fdnum, 1);            break;
        case TYPE_THREEBYTE:    retn = fgetxx(fdnum, 3);            break;
        case TYPE_ASIZE:        retn = myfilesize(fdnum);           break;
        case TYPE_STRING: {
            ret  = fgetss(fdnum, 0,    0, 0);
            if(!ret) *error = 1;    // this damn error stuff is needed for compatibility with the old quickbms
            break;                  // and located here doesn't affect the performances
        }
        case TYPE_LINE: {
            ret  = fgetss(fdnum, '\n', 0, 1);
            if(!ret) *error = 1;
            delimit(ret);
            break;
        }
        case TYPE_FILENAME: {
            ret  = filenumber[fdnum].filename;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_BASENAME: {
            ret  = filenumber[fdnum].basename;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_FULLNAME: {
            ret  = filenumber[fdnum].fullname;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_EXTENSION: {
            ret  = filenumber[fdnum].fileext;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_CURRENT_FOLDER: {
            ret  = current_folder;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_FILE_FOLDER: {
            ret  = file_folder;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_INOUT_FOLDER: {
            ret  = output_folder;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_BMS_FOLDER: {
            ret  = bms_folder;
            if(!ret) *error = 1;
            break;
        }
        case TYPE_UNICODE: {
            ret  = fgetss(fdnum, 0,    1, 0);
            if(!ret) *error = 1;
            break;
        }
        case TYPE_FLOAT: {
            // use fgetxx instead of myfr for handling the endianess
            retn = fgetxx(fdnum, 4);
            //tmp_float = *(float *)((void *)(&retn));
            tmp_float = 0;
            memcpy(&tmp_float, &retn, 4);
            retn = (int)tmp_float;
            break;
        }
        case TYPE_DOUBLE: {
            // use fgetxx instead of myfr for handling the endianess
            tmp64 = fgetxx(fdnum, 8);
            //tmp_double = *(double *)((void *)(&tmp64));
            tmp_double = 0;
            memcpy(&tmp_double, &tmp64, 8);
            retn = (int)tmp_double;
            break;
        }
        case TYPE_LONGDOUBLE: {
            //myfr(fdnum, tmp, 12); // I want to handle also the endianess
            for(c = 0; c < 12; c++) {
                if(endian == MYLITTLE_ENDIAN) {
                    myfr(fdnum, tmp + c, 1);
                } else {
                    myfr(fdnum, tmp + 11 - c, 1);
                }
            }
            //tmp_longdouble = *(long double *)tmp;
            tmp_longdouble = 0;
            memcpy(&tmp_longdouble, tmp, sizeof(tmp_longdouble));
            retn = (int)tmp_longdouble;
            break;
        }
        case TYPE_VARIABLE: {
            do {
                c = fgetxx(fdnum, 1);
                retn = (retn << 7) | (c & 0x7f);
            } while(c & 0x80);
            break;
        }
        case TYPE_VARIABLE2: {
            retn = unreal_index(fdnum);
            break;
        }
        case TYPE_VARIANT: {
            retn = fgetxx(fdnum, 2);
            myfr(fdnum, tmp, 6);
            switch(retn) {
                case 0:  type = TYPE_NONE;      break;
                case 1:  type = TYPE_NONE;      break;
                case 2:  type = TYPE_SHORT;     break;
                case 3:  type = TYPE_LONG;      break;
                case 4:  type = TYPE_FLOAT;     break;  // float
                case 5:  type = TYPE_DOUBLE;    break;  // double
                case 6:  type = TYPE_LONGLONG;  break;
                case 7:  type = TYPE_LONGLONG;  break;
                case 8:  type = TYPE_UNICODE;   break;
                case 9:  type = TYPE_LONG;      break;
                case 10: type = TYPE_LONG;      break;
                case 11: type = TYPE_SHORT;     break;
                case 12: type = TYPE_VARIANT;   break;
                case 17: type = TYPE_BYTE;      break;
                default: type = TYPE_LONG;      break;  // ???
            }
            return(myfrx(fdnum, type, ret_num, error));
            break;
        }
        case TYPE_NONE: retn = 0;   break;
        default: {
            printf("\nError: invalid datatype %d\n", (i32)type);
            myexit(-1);
            break;
        }
    }
    *ret_num = retn;
    //if(!ISNUMTYPE(type) && !ret) *error = 1;  // bad, decrease a lot the performances
    return(ret);
}



int put_type_variable(int fdnum, u_int num) {
    int     i   = 0;
    u8      tmp[32];

    do {
        tmp[i++] = num & 0x7f;
        num >>= 7;
    } while(num);

    for(--i; i >= 0; i--) {
        if(i) tmp[i] |= 0x80;
        if(myfw(fdnum, &tmp[i], 1) < 0) return(-1);
    }
    return(0);
}



int myfwx(int fdnum, int varn, int type) {
    long double tmp_longdouble;
    double  tmp_double;
    float   tmp_float;
    u64     tmp64;
    int     retn    = 0;
    u8      tmp[16],
            c;

    switch(type) {
        case TYPE_LONGLONG:     retn = fputxx(fdnum, get_var32(varn), 8);   break;
        case TYPE_LONG:         retn = fputxx(fdnum, get_var32(varn), 4);   break;
        case TYPE_SHORT:        retn = fputxx(fdnum, get_var32(varn), 2);   break;
        case TYPE_BYTE:         retn = fputxx(fdnum, get_var32(varn), 1);   break;
        case TYPE_THREEBYTE:    retn = fputxx(fdnum, get_var32(varn), 3);   break;
        case TYPE_ASIZE:        retn = fputxx(fdnum, myfilesize(fdnum), 4); break;
        case TYPE_STRING: { // NULL delimited string
            retn = fputss(fdnum, get_var(varn), 0, 0, 0);
            break;
        }
        case TYPE_LINE: {
            retn = fputss(fdnum, get_var(varn), -1, 0, 1);
            break;
        }
        case TYPE_FILENAME: {
            retn = fputss(fdnum, filenumber[fdnum].filename, -1, 0, 0);
            break;
        }
        case TYPE_BASENAME: {
            retn = fputss(fdnum, filenumber[fdnum].basename, -1, 0, 0);
            break;
        }
        case TYPE_FULLNAME: {
            retn = fputss(fdnum, filenumber[fdnum].fullname, -1, 0, 0);
            break;
        }
        case TYPE_EXTENSION: {
            retn = fputss(fdnum, filenumber[fdnum].fileext, -1, 0, 0);
            break;
        }
        case TYPE_CURRENT_FOLDER: {
            retn = fputss(fdnum, current_folder, -1, 0, 0);
            break;
        }
        case TYPE_FILE_FOLDER: {
            retn = fputss(fdnum, file_folder, -1, 0, 0);
            break;
        }
        case TYPE_INOUT_FOLDER: {
            retn = fputss(fdnum, output_folder, -1, 0, 0);
            break;
        }
        case TYPE_BMS_FOLDER: {
            retn = fputss(fdnum, bms_folder, -1, 0, 0);
            break;
        }
        case TYPE_UNICODE: {    // NULL delimited
            retn = fputss(fdnum, get_var(varn), 0, 1, 0);
            break;
        }
        case TYPE_FLOAT: {
            retn = get_var32(varn);
            tmp_float = (float)retn;
            //retn = *(int *)((void *)(&tmp_float));
            retn = 0;
            memcpy(&retn, &tmp_float, 4);
            retn = fputxx(fdnum, retn, 4);
            break;
        }
        case TYPE_DOUBLE: {
            retn = get_var32(varn);
            tmp_double = (double)retn;
            //tmp64 = *(u64 *)((void *)(&tmp_double));
            tmp64 = 0;
            memcpy(&tmp64, &tmp_double, 8);
            retn = fputxx(fdnum, tmp64, 8);
            break;
        }
        case TYPE_LONGDOUBLE: {
            retn = get_var32(varn);
            tmp_longdouble = (long double)retn;
            memcpy(tmp, (void *)&tmp_longdouble, sizeof(tmp_longdouble));
            for(c = 0; c < 12; c++) {
                if(endian == MYLITTLE_ENDIAN) {
                    myfw(fdnum, tmp + c, 1);
                } else {
                    myfw(fdnum, tmp + 11 - c, 1);
                }
            }
            retn = 0;
            break;
        }
        case TYPE_VARIABLE:     retn = put_type_variable(fdnum, get_var32(varn));   break;
        case TYPE_VARIABLE2: {
            c = make_unreal_index(get_var32(varn), tmp);
            retn = myfw(fdnum, tmp, c);
            break;
        }
        //case TYPE_VARIANT:    // unsupported
        case TYPE_NONE: retn = 0;   break;
        default: {
            printf("\nError: invalid or unsupported datatype %d\n", (i32)type);
            myexit(-1);
            break;
        }
    }
    return(retn);
}



void bytesread_eof(int fdnum, int len) {
    int     oldoff  = 0;

    if(!fdnum) {
        oldoff = get_var32(BytesRead_idx);
        add_var(BytesRead_idx, NULL, NULL, oldoff + len, sizeof(int));
        if(myftell(fdnum) >= myfilesize(fdnum)) {
        //if(myfeof(fdnum)) {   // feof doesn't work
            add_var(NotEOF_idx, NULL, NULL, 0, sizeof(int));
        }
    }
}



void post_fseek_actions(int fdnum, int diff_offset) {
    if(file_xor_size)   (*file_xor_pos)   += diff_offset;
    if(file_rot13_size) (*file_rot13_pos) += diff_offset;
    if(file_crypt_size) (*file_crypt_pos) += diff_offset;
    if(mex_default) bytesread_eof(fdnum, diff_offset);
}



void post_fread_actions(int fdnum, u8 *data, int len) {
    int     i;

    // fdnum is used only for bytesread_eof so ignore it
    //if(!data) not needed here
    if(file_xor_size) {
        for(i = 0; i < len; i++) {
            data[i] ^= file_xor[(*file_xor_pos) % file_xor_size];
            (*file_xor_pos)++;
        }
    }
    if(file_rot13_size) {
        for(i = 0; i < len; i++) {
            data[i] += file_rot13[(*file_rot13_pos) % file_rot13_size];
            (*file_rot13_pos)++;
        }
    }
    if(file_crypt_size) {
        perform_encryption(data, len);
    }
    if(mex_default) bytesread_eof(fdnum, len);
}



u_int myftell(int fdnum) {
    if(fdnum < 0) {
        return(memory_file[-fdnum].pos);
    }
    CHECK_FILENUM
    if(filenumber[fdnum].sd) return(((socket_file_t  *)filenumber[fdnum].sd)->pos);
    if(filenumber[fdnum].pd) return(((process_file_t *)filenumber[fdnum].pd)->pos);
    return(ftell(filenumber[fdnum].fd));
}



int myfeof(int fdnum) {
    memory_file_t   *memfile    = NULL;
    int     ret = 0;

    if(fdnum < 0) {
        memfile = &memory_file[-fdnum];
        if(memfile->pos >= memfile->size) {
            ret = 1;
        }
    } else {
        CHECK_FILENUM
        if(filenumber[fdnum].sd) return(0);
        if(filenumber[fdnum].pd) return(0);
        ret = feof(filenumber[fdnum].fd);
    }
    return(ret);
}



int myfseek(int fdnum, u_int offset, int type) {
    memory_file_t   *memfile    = NULL;
    u_int   oldoff;
    int     i,
            err = 0;
    u8      tmp[1];

    oldoff = myftell(fdnum);
    if(fdnum < 0) {
        memfile = &memory_file[-fdnum];
        switch(type) {
            case SEEK_SET: memfile->pos = offset;                   break;
            case SEEK_CUR: memfile->pos += offset;                  break;
            case SEEK_END: memfile->pos = memfile->size + offset;   break;
            default: break;
        }
        if(memfile->pos < 0) memfile->pos = 0;
        if((memfile->pos < 0) || (memfile->pos > memfile->size)) {
            err = -1;
        }
    } else {
        CHECK_FILENUM
        if(filenumber[fdnum].sd) {
            for(i = 0; i < offset; i++) {
                if(socket_read(filenumber[fdnum].sd, tmp, 1) < 0) {
                    err = -1;
                    break;
                }
            }
        } else if(filenumber[fdnum].pd) {
            switch(type) {
                case SEEK_SET: ((process_file_t *)filenumber[fdnum].pd)->pos = offset;                   break;
                case SEEK_CUR: ((process_file_t *)filenumber[fdnum].pd)->pos += offset;                  break;
                case SEEK_END: ((process_file_t *)filenumber[fdnum].pd)->pos = ((process_file_t *)filenumber[fdnum].pd)->size + offset;   break;
                default: break;
            }
        } else {
            if(type == SEEK_SET) {
                err = fseek(filenumber[fdnum].fd, offset, type);
            } else {    // signed
                err = fseek(filenumber[fdnum].fd, (int)offset, type);
            }
        }
    }
    if(err) {
        printf("\nError: the offset 0x%08x in the file %d can't be reached\n", (i32)offset, (i32)fdnum);
        myexit(-1);
    }
    post_fseek_actions(fdnum, myftell(fdnum) - oldoff);
    return(0);
}



int myfr(int fdnum, u8 *data, int size) {
    memory_file_t   *memfile    = NULL;
    int     len,
            quit_if_diff    = 1;

    // if(!data) not necessary
    if(size < 0) {
        size = BUFFSZ;
        quit_if_diff = 0;
    }
    if(fdnum < 0) {
        memfile = &memory_file[-fdnum];
        if(!memfile->data) {
            fdnum = -fdnum;
            if(fdnum == 1) {
                printf("\nError: in this script MEMORY_FILE has not been used/declared yet\n");
            } else {
                printf("\nError: in this script MEMORY_FILE%d has not been used/declared yet\n", (i32)fdnum);
            }
            myexit(-1);
        }
        len = size;
        if((memfile->pos + size) > memfile->size) {
            len = memfile->size - memfile->pos;
        }
        memcpy(data, memfile->data + memfile->pos, len);
        memfile->pos += len;
    } else {
        CHECK_FILENUM
        if(filenumber[fdnum].sd) {
            len = socket_read(filenumber[fdnum].sd, data, size);
        } else if(filenumber[fdnum].pd) {
            len = process_read(filenumber[fdnum].pd, data, size);
        } else {
            len = fread(data, 1, size, filenumber[fdnum].fd);
            if(write_mode) {
                /*
                  in "r+b" mode the offsets are not synchronized so happens horrible things like:
                  - read 7 bytes, write 7 bytes... from offset 0 instead of 7
                  - file of 12 bytes, read 7, read 4, write 7... fails because can't increase size
                  the following lame solution works perfectly and solves the problem
                */
                fseek(filenumber[fdnum].fd, ftell(filenumber[fdnum].fd), SEEK_SET);
            }
        }
    }
    if((len != size) && quit_if_diff) {
        printf("\n"
            "Error: incomplete input file number %d, can't read %u bytes.\n"
            "       anyway don't worry, it's possible that the BMS script has been written\n"
            "       to exit in this way if it's reached the end of the archive so check it\n"
            "       or contact its author or verify that all the files have been extracted\n"
            "\n", (i32)fdnum, (i32)(size - len));
        myexit(-1);
    }
    post_fread_actions(fdnum, data, len);
    return(len);
}



/*
    all the write operations are performed here
    and only here
*/
int myfw(int fdnum, u8 *data, int size) {
    memory_file_t   *memfile    = NULL;
    int     len;

    // if(!data) not necessary
    if(size < 0) {
        printf("\n"
            "Error: problems with input file number %d, can't write negative size.\n"
            "\n", (i32)fdnum);
        myexit(-1);
    }
    post_fread_actions(-1, data, size);
    if(fdnum < 0) {
        memfile = &memory_file[-fdnum];
        if(!memfile->data) {
            fdnum = -fdnum;
            if(fdnum == 1) {
                printf("\nError: in this script MEMORY_FILE has not been used/declared yet\n");
            } else {
                printf("\nError: in this script MEMORY_FILE%d has not been used/declared yet\n", (i32)fdnum);
            }
            myexit(-1);
        }
        len = size;
        if((memfile->pos + size) > memfile->size) {
            memfile->size = memfile->pos + size;
            myalloc(&memfile->data, memfile->size, &memfile->maxsize);
        }
        memcpy(memfile->data + memfile->pos, data, len);
        memfile->pos += len;
    } else {
        CHECK_FILENUM
        if(filenumber[fdnum].sd) {
            len = socket_write(filenumber[fdnum].sd, data, size);
        } else if(filenumber[fdnum].pd) {
            len = process_write(filenumber[fdnum].pd, data, size);
        } else {
            len = fwrite(data, 1, size, filenumber[fdnum].fd);
            fflush(filenumber[fdnum].fd);
        }
    }
    if(len != size) {
        printf("\n"
            "Error: problems with input file number %d, can't write %u bytes.\n"
            "%s"
            "\n", (i32)fdnum, (i32)(size - len),
            write_mode ? "" : "       you MUST use the -w option for enabling the file writing mode\n");
        myexit(-1);
    }
    return(len);
}



void myhelp(u8 *argv0) {
    printf("\n"
        "Usage: %s [options] <script.BMS> <input_archive/folder> <output_folder>\n"
        "\n"
        "Options:\n"
        "-l     list the files without extracting them, you can use . as output folder\n"
        "-f W   filter the files to extract using the W wildcard, example -f \"*.mp3\"\n"
        "       example: quickbms -f \"*.mp3\" script.bms archive.dat output_folder\n"
        "-F W   as above but works only with the files in the input folder (if used)\n"
        "       example: quickbms -F \"*.dat\" script.bms input_folder output_folder\n"
        "-o     if the output files already exist this option will overwrite them\n"
        "       automatically without asking the user's confirmation\n"
        "-r     experimental reimport option that should work with many archives:\n"
        "         quickbms script.bms archive.pak output_folder\n"
        "         modify the needed files in output_folder and maybe remove the others\n"
        "         quickbms -w -r script.bms archive.pak output_folder\n"
        "\n"
        "Advanced options:\n"
        "-d     automatically creates an additional output folder with the name of the\n"
        "       input file processed without extension\n"
        "-E     experimental option for automatically reversing the endianess of any\n"
        "       memory file simply reading it field by field\n"
        "-c     quick list of the basic BMS commands and some notes about this tool\n"
        "\n"
        "Debug and experimental options:\n"
        "-v     verbose debug informations, useful for verifying possible errors\n"
        "-V     alternative verbose output, useful for programmers\n"
        "-L F   dump the offset/size/name of the files inside the file F\n"
        "-x     use the hexadecimal notation in myitoa (debug)\n"
        "-0     no extraction of files, useful for testing a script without using space\n"
        "-R     needed for the programs that act as interface for QuickBMS\n"
        "-a S   pass arguments to the input script like quickbms_arg1, 2, 3 and so on\n"
        "\n"
        "Features and security activation options\n"
        "-w     enable the write mode required to write physical input files with Put*\n"
        "-n     enable the usage of network sockets\n"
        "-p     enable the usage of processes\n"
        "\n"
        "Examples:\n"
        "  quickbms c:\\zip.bms c:\\myfile.zip \"c:\\new folder\"\n"
        "  quickbms -l -f \"*.txt\" zip.bms myfile.zip .\n"
        "  quickbms -F \"*.bff\" c:\\nfsshift.bms c:\\Shift\\Pakfiles c:\\output\n"
        "\n", argv0);
}



void quick_bms_list(void) {
    fputs("\n"
        "quick reference list of the BMS commands:\n"
        "\n"
        " CLog <filename> <offset> <compressed_size> <uncompressed_size> [file]\n"
        "    extract the file at give offset decompressing its content\n"
        "\n"
        " Do\n"
        " ...\n"
        " While <variable> <condition> <variable>\n"
        "    perform a loop which ends when the condition is no longer valid\n"
        "\n"
        " FindLoc <variable> <type> <string> [file] [ret_if_err]\n"
        "    if the string is found put its offset in the variable\n"
        "    by default if FindLoc doesn't find the string it terminates the script\n"
        "    while if ret_if_err is specified (for example -1 or \"\") it will be put in\n"
        "    variable instead of terminating\n"
        "\n"
        " For [variable] = [value] [To] [variable]\n"
        " ...\n"
        " Next [variable]\n"
        "    classical for(;;) loop, Next simply increments the value of the variable\n"
        "    the arguments are optionals for using this For like an endless loop and\n"
        "    To can be substituited with any condition like != == < <= > >= and so on\n"
        "\n"
        " Break\n"
        "    quit a loop (experimental)\n"
        "\n"
        " Get <variable> <type> [file]\n"
        "    read a number (8, 16, 32 bits) or a string\n"
        "\n"
        " GetDString <variable> <length> [file]\n"
        "    read a string of the specified length\n"
        "\n"
        " GoTo <offset> [file]\n"
        "    reach the specified offset, if it's negative it goes from the end\n"
        "\n"
        " IDString [file] <string>\n"
        "    check if the data in the file matches the given string\n"
        "\n"
        " Log <filename> <offset> <size> [file]\n"
        "    extract the file at the given offset with that size\n"
        "\n"
        " Math <variable> <operator> <variable>\n"
        "    perform a mathematical operation on the first variable, available op:\n"
        "    + * / - ^ & | % ! ~ << >> r (rot right) l (rot left) s (bit s) w (byte s)\n"
        "\n"
        " Open <folder> <filename> <file>\n"
        "    open a new file and assign the given file number\n"
        "\n"
        " SavePos <variable> [file]\n"
        "    save the current offset in the variable\n"
        "\n"
        " Set <variable> [type] <variable>\n"
        "    assign the content of the second variable to the first one, type ignored\n"
        "\n"
        " String <variable> <operator> <variable>\n"
        "    perform an append/removing/xor operation on the first variable\n"
        "\n"
        " CleanExit\n"
        "    terminate the extraction\n"
        "\n"
        " If <variable> <criterium> <variable>\n"
        " ...\n"
        " Else / Elif / Else If\n"
        " ...\n"
        " EndIf\n"
        "    classical if(...) { ... } else if { ... } else { ... }\n"
        "\n"
        " GetCT <variable> <type> <character> [file]\n"
        "    read a string (type is useless) delimited by the given character\n"
        "\n"
        " ComType <type> [dictionary]\n"
        "    specify the type of compression to use in CLog: quickbms.txt for the list\n"
        "\n"
        " ReverseLong <variable>\n"
        "    invert the order/endianess of the variable\n"
        "\n"
        " Endian <type>\n"
        "    choose between little and big endian order of the read numbers\n"
        "\n"
        " FileXOR <string_of_numbers> [offset]\n"
        "    xor the read data with the sequence of numbers in the given string\n"
        "\n"
        " FileRot13 <string_of_numbers> [offset]\n"
        "    add/substract the read data with the sequence of numbers in the string\n"
        "\n"
        " Strlen <variable> <variable>\n"
        "    put the length of the second variable in the first one\n"
        "\n"
        " GetVarChr <variable> <variable> <offset> [type]\n"
        "    put the byte at the given offset of the second variable in the first one\n"
        "\n"
        " PutVarChr <variable> <offset> <variable> [type]\n"
        "    put the byte in the second variable in the first one at the given offset\n"
        "\n"
        " Padding <number> [file]\n"
        "    adjust the current offset of the file using the specified number (size of\n"
        "    padding), note that at the moment the padding is performed only when\n"
        "    this command is called and not automatically after each file reading\n"
        "\n"
        " Append\n"
        "    enable/disable the writing of the data at the end of the files with *Log\n"
        "\n"
        " Encryption <algorithm> <key> [ivec] [mode] [keylen]\n"
        "    enable that type of decryption: quickbms.txt for the list\n"
        "\n"
        " Print \"message\"\n"
        "    display a message, you can display the content of the variables simply\n"
        "    specifying their name between '%' like: Print \"my offset is %OFFSET%\"\n"
        "\n"
        " GetArray <variable> <array_num> <index>\n"
        "    get the value stored at the index position of array_num\n"
        "\n"
        " PutArray <array_num> <index> <variable>\n"
        "    store the variable at the index position of array_num\n"
        "\n"
        " StartFunction NAME\n"
        " ...\n"
        " EndFunction\n"
        " CallFunction NAME\n"
        "    experimental functions for recursive archives\n"
        "\n"
        "Refer to quickbms.txt for the rest of the commands and their details!\n"
        "\n"
        "NOTES:\n"
        "- a variable and a fixed number are the same thing internally in the tool\n"
        "  because all the data is handled as strings with the consequent pros\n"
        "  (incredibly versatile) and cons (slowness with some types of scripts)\n"
        "- everything is case insensitive (ABC is like abc) except the content of\n"
        "  strings and variables (excluded some operations like in String)\n"
        "- the [file] field is optional, if not specified it's 0 so the main file\n"
        "- also the final ';' char of the original BMS language is optional\n"
        "- example of <string_of_numbers>: \"0x123 123 456 -12 -0x7f\" or 0xff or \"\"\n"
        "- both hexadecimal (0x) and decimal numbers are supported, negatives included\n"
        "- all the mathematical operations are performed using signed 32 bit numbers\n"
        "- available types of data: long (32 bits), short (16), byte (8), string\n"
        "- all the fixed strings are handled in C syntax like \"\\x12\\x34\\\\hello\\\"bye\\0\"\n"
        "- do not use variable names which start with a number like 123MYVAR or -MYVAR\n"
        "- if you use the file MEMORY_FILE will be used a special memory buffer, create\n"
        "  it with CLog or Log and use it normally like any other file\n"
        "- is possible to use multiple memory files: MEMORY_FILE, MEMORY_FILE2,\n"
        "  MEMORY_FILE3, MEMORY_FILE4 and so on\n"
        "- use TEMPORARY_FILE for creating a file with this exact name also in -l mode\n"
        "\n"
        "informations about the original BMS scripting language and original examples:\n"
        "  http://wiki.xentax.com/index.php/BMS\n"
        "  http://multiex.xentax.com/complete_scripts.txt\n"
        "\n"
        "check the source code of this tool for the additional enhancements implemented\n"
        "by me (like support for xor, rot13, lzo, lzss, zlib/deflate and so on) or send\n"
        "me a mail because various features are not documented yet or just watch the\n"
        "examples provided on the project's homepage which cover ALL the enhancements:\n"
        "  http://aluigi.org/papers.htm#quickbms\n"
        "\n"
        "the tool supports also the \"multiex inifile\" commands in case of need.\n"
        "\n", stdout);
}



int calc_quickbms_version(u8 *version) {
    int     n,
            len,
            ret,
            seq;
    u8      *p;

    if(!version) return(0);
    ret = 0;
    seq = 24;
    for(p = version; *p; p += len) {
        if(*p == '.') {
            seq -= 8;
            if(seq < 0) break;
            len = 1;
        } else if(((*p >= 'a') && (*p <= 'z')) || ((*p >= 'A') && (*p <= 'Z'))) {
            ret += *p;
            len = 1;
        } else {
            n = readbase(p, 10, &len);
            if(len <= 0) break;
            ret += n << seq;
        }
    }
    return(ret);
}



void alloc_err(const char *fname, int line, const char *func) {
    printf("\n- error in %s line %d: %s()\n", fname, (i32)line, func);
    printf("Error: tentative of allocating -1 bytes\n");
    myexit(-2);
}



void std_err(const char *fname, int line, const char *func) {
    printf("\n- error in %s line %d: %s()\n", fname, (i32)line, func);
    perror("Error");
    myexit(-2);
}



void winerr(void) {
#ifdef WIN32
    u8      *message = NULL;

    FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      0,
      (char *)&message,
      0,
      NULL);

    if(message) {
        printf("\nError: %s\n", message);
        LocalFree(message);
    } else {
        printf("\nError: unknown Windows error\n");
    }
    myexit(-1);
#else
    STD_ERR;
#endif
}



void myexit(int ret) {
    if(!ret && quick_gui_exit) exit(ret);   // as below
#ifdef WIN32
    u8      ans[16];

    if(GetWindowLong(mywnd, GWL_WNDPROC)) {
        fgetz(ans, sizeof(ans), stdin,
            "\nPress RETURN to quit");
    }
#endif
    if(ret == -1) {
        printf("\n"
            "Note that if both the scripts and your files are correct then it's possible\n"
            "that the script needs a newer version of QuickBMS, in which case download it:\n"
            "\n"
            "  http://aluigi.org/quickbms\n"
            "\n");
    }
    exit(ret);  // as above
}


