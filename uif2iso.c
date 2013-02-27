/*
    Copyright 2007,2008 Luigi Auriemma

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

    http://www.gnu.org/licenses/gpl.txt
*/

#define _LARGE_FILES        // if it's not supported the tool will work
#define __USE_LARGEFILE64   // without support for large files
#define __USE_FILE_OFFSET64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS   64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <openssl/des.h>

#ifdef WIN32
    #include <windows.h>
    HWND    mywnd;
    char *get_file(void);
    char *put_file(void);
#else
    #define stricmp strcasecmp
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef int32_t     i32;
typedef uint32_t    u32;
typedef int64_t     i64;
typedef uint64_t    u64;



#define VER         "0.1.4"
#define BBIS_SIGN   0x73696262
#define BLHR_SIGN   0x72686c62
#define BSDR_SIGN   0x72647362
#define BLMS_SIGN   0x736d6c62
#define BLSS_SIGN   0x73736c62
#define OUT_ISO     0
#define OUT_NRG     1
#define OUT_CUE     2

#define PRINTF64(x) (u32)(((x) >> 32) & 0xffffffff), (u32)((x) & 0xffffffff)    // I64x, llx? blah
#if defined(_LARGE_FILES)
    #if defined(__APPLE__)
        #define fseek   fseeko
        #define ftell   ftello
    #else
        #define off_t   off64_t
        #define fopen   fopen64
        #define fseek   fseeko64
        #define ftell   ftello64
    #endif
#endif



#pragma pack(2)

typedef struct {
    u8      id[4];
    u32     size;
} nrg_chunk_t;

typedef struct {
    u32     sign;       // blhr
    u32     size;       // size of the data plus ver and num
    u32     ver;        // ignored
    u32     num;        // number of blhr_data structures
} blhr_t;

typedef struct {
    u64     offset;     // input offset
    u32     zsize;      // block size
    u32     sector;     // where to place the output
    u32     size;       // size in sectors!
    u32     type;       // type
} blhr_data_t;

typedef struct {
    u32     sign;       // bbis
    u32     bbis_size;  // ignored, probably the size of the structure
    u16     ver;        // version, 1
    u16     image_type; // 8 for ISO, 9 for mixed
    u16     unknown1;   // ???
    u16     padding;    // ignored
    u32     sectors;    // number of sectors of the ISO
    u32     sectorsz;   // CD use sectors and this is the size of them (chunks)
    u32     unknown2;   // almost ignored
    u64     blhr;       // where is located the blhr header
    u32     blhrbbissz; // total size of the blhr and bbis headers
    u8      hash[16];   // hash, used with passwords
    u32     unknown3;   // ignored
    u32     unknown4;   // ignored
} bbis_t;

#pragma pack()



u8 *path2fname(u8 *path);
u8 *frames2time(u64 num);
void nrg2cue(FILE *fd, u64 nrgoff, u8 *fileo);
void magiciso_is_invalid(FILE *fd, u64 nrgoff, u8 *fileo);
void nrg_truncate(u8 *fileo, int secsz);
u8 *blhr_unzip(FILE *fd, z_stream *z, DES_key_schedule *ctx, u32 zsize, u32 unzsize);
u8 *change_ext(u8 *fname, u8 *ext);
FILE *open_file(u8 *fname, int write);
int blms2cue(FILE *fd, u8 *fname, u8 *blms, int blms_len);
void uif_crypt_key(u8 *key, u8 *pwd);
void uif_crypt(DES_key_schedule *ctx, u8 *data, int size);
u8 *show_hash(u8 *hash);
void myalloc(u8 **data, unsigned wantsize, unsigned *currsize);
void myfr(FILE *fd, void *data, unsigned size);
void myfw(FILE *fd, void *data, unsigned size);
int unzip(z_stream *z, u8 *in, u32 insz, u8 *out, u32 outsz);
void l2n_blhr(blhr_t *p);
void l2n_blhr_data(blhr_data_t *p);
void l2n_bbis(bbis_t *p);
void l2n_16(u16 *num);  // from little endian to number
void l2n_32(u32 *num);
void l2n_64(u64 *num);
void b2n_16(u16 *num);  // from big endian to number
void b2n_32(u32 *num);
void b2n_64(u64 *num);
int getxx(u8 *data, u64 *ret, int bits, int intnet);
int putxx(u8 *data, u64 num, int bits, int intnet);
void std_err(void);
int fgetz(u8 *data, int size, FILE *fd);
void myexit(void);



int     endian;



int main(int argc, char *argv[]) {
    DES_key_schedule    *ctx;
    z_stream    z;
    blhr_data_t *blhr_data;
    blhr_t  blhr,
            blms,       // both blms and blss have a structure very similar to blhr so I have decided
            blss;       // to use the same type for avoiding to create other functions
    bbis_t  bbis;
    FILE    *fdi,
            *fdo,
            *fdcue;
    u64     tot,
            file_size;
    u32     i,
            insz,
            outsz;
    int     outtype     = OUT_ISO;
    u8      ans[130],   // password is max 31 chars
            pwdkey[32], // password is max 31 chars
            tmphash[16],
            *filei,
            *fileo,
            *filec,
            *in,
            *out,
            *p,
            *blms_data  = NULL,
            *blss_data  = NULL,
            *outext;

    setbuf(stdout, NULL);

    fputs("\n"
        "UIF2ISO "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    endian = 1;                         // big endian
    if(*(char *)&endian) endian = 0;    // little endian

#ifdef WIN32
    mywnd = GetForegroundWindow();
    if(GetWindowLong(mywnd, GWL_WNDPROC)) {
        p = argv[1];
        argv = malloc(sizeof(char *) * 3);
        if(argc < 2) {
            argv[1] = get_file();
        } else {
            argv[1] = p;
        }
        argv[2] = put_file();
        argc = 3;
    }
#endif

    if(argc < 3) {
        printf("\n"
            "Usage: %s <input.UIF> <output>\n"
            "\n"
            "The output ISO,NRG,CUE/BIN extension is automatically choosed by the tool\n"
            "\n", argv[0]);
        myexit();
    }

    ctx   = NULL;
    filei = argv[1];
    fileo = argv[2];

    fdi = open_file(filei, 0);

    z.zalloc = (alloc_func)0;
    z.zfree  = (free_func)0;
    z.opaque = (voidpf)0;
    if(inflateInit2(&z, 15)) {
        printf("\nError: zlib initialization error\n");
        myexit();
    }

    fseek(fdi, 0, SEEK_END);
    file_size = ftell(fdi);
    if(fseek(fdi, file_size - sizeof(bbis), SEEK_SET)) {
        if(((file_size - sizeof(bbis)) > 0x7fffffff) && ((file_size - sizeof(bbis)) < file_size)) printf("  an error here means that your exe has no full LARGE_FILES 64 bit support!\n");
        std_err();
    }
    myfr(fdi, &bbis, sizeof(bbis));
redo_bbis:
    l2n_bbis(&bbis);
    if(bbis.sign != BBIS_SIGN) {
        printf("\nError: wrong bbis signature (%08x)\n", bbis.sign);
        myexit();
    }
    if(ctx) bbis.blhr += sizeof(bbis) + 8;

    printf("\n"
        "  file size    %08x%08x\n"
        "  version      %hu\n"
        "  image type   %hu\n"
        "  padding      %hu\n"
        "  sectors      %u\n"
        "  sectors size %u\n"
        "  blhr offset  %08x%08x\n"
        "  blhr size    %u\n"
        "  hash         %s\n",
        PRINTF64(file_size),
        bbis.ver,
        bbis.image_type,
        bbis.padding,
        bbis.sectors,
        bbis.sectorsz,
        PRINTF64(bbis.blhr),
        bbis.blhrbbissz,
        show_hash(bbis.hash));
    //printf(
    //    "  bbis size    %08x\n"
    //    "  unknown      %08x %08x %08x\n",
    //    bbis.bbis_size, bbis.unknown2, bbis.unknown3, bbis.unknown4);

    if(fseek(fdi, bbis.blhr, SEEK_SET)) std_err();
    myfr(fdi, &blhr, sizeof(blhr));
    l2n_blhr(&blhr);
    if(blhr.sign != BLHR_SIGN) {
        if(blhr.sign == BSDR_SIGN) {
            printf("- the input file is protected by password, insert it: ");
            fgetz(ans, sizeof(ans), stdin);
            if(strlen(ans) > 31) ans[31] = 0;

            uif_crypt_key(pwdkey, ans);
            printf("- DES password: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                pwdkey[0], pwdkey[1], pwdkey[2], pwdkey[3],
                pwdkey[4], pwdkey[5], pwdkey[6], pwdkey[7]);
            if(!ctx) {
                ctx = malloc(sizeof(DES_key_schedule));
                if(!ctx) std_err();
            }
            DES_set_key((void *)pwdkey, ctx);

            if(blhr.size != sizeof(bbis)) {
                printf("- Alert: the size of the bbis struct and the one specified by bsdr don't match\n");
            }
            fseek(fdi, -8, SEEK_CUR);
            memcpy(tmphash, bbis.hash, sizeof(bbis.hash));
            myfr(fdi, &bbis, sizeof(bbis));
            uif_crypt(ctx, (void *)&bbis, sizeof(bbis));
            memcpy(bbis.hash, tmphash, sizeof(bbis.hash));
            goto redo_bbis;
        } else {
            printf("\nError: wrong blhr signature (%08x)\n", blhr.sign);
        }
        myexit();
    }

    blhr_data = (void *)blhr_unzip(fdi, &z, ctx, blhr.size - 8, sizeof(blhr_data_t) * blhr.num);

    if(bbis.image_type == 8) {
        // nothing to do
    } else if(bbis.image_type == 9) {
        printf("- raw or mixed type image\n");

        myfr(fdi, &blms, sizeof(blms));
        l2n_blhr(&blms);
        if(blms.sign != BLMS_SIGN) {
            printf("- Alert: wrong blms signature (%08x)\n", blms.sign);
        } else {
            blms_data = blhr_unzip(fdi, &z, ctx, blms.size - 8, blms.num);

            myfr(fdi, &blss, sizeof(blss));
            if(fseek(fdi, 4, SEEK_CUR)) std_err();  // additional data to skip
            l2n_blhr(&blss);
            if(blss.sign != BLSS_SIGN) {
                printf("- Alert: wrong blss signature (%08x)\n", blss.sign);
            } else {
                if(blss.num) {
                    outtype = OUT_CUE;
                    blss_data = blhr_unzip(fdi, &z, ctx, blss.size - 12, blss.num);
                } else {
                    outtype = OUT_NRG;
                }
            }
        }
    } else {
        printf("- Alert: this type of image (%hu) is not supported by this tool, I try as ISO\n", bbis.image_type);
    }

    in   = out   = NULL;
    insz = outsz = 0;
    tot  = 0;

    switch(outtype) {
        case OUT_ISO: {
            printf("- ISO output image format\n");
            outext = ".iso";
            break;
        }
        case OUT_NRG: {
            printf("- NRG (Nero v2) output image format\n");
            outext = ".nrg";
            break;
        }
        case OUT_CUE: {
            printf("- BIN/CUE output image format\n");
            outext = ".bin";
            break;
        }
        default: break;
    }
    fileo = change_ext(fileo, outext);
    fdo = open_file(fileo, 1);

    if(outtype == OUT_CUE) {
        printf(
            "- generate the CUE file\n"
            "  this data is located also in blss but I prefer to generate it from scratch\n");
        filec = change_ext(fileo, ".cue");
        fdcue = open_file(filec, 1);
        if(blms2cue(fdcue, path2fname(fileo), blms_data, blms.num) < 0) {
            myfw(fdcue, blss_data, blss.num);
        } else {
            if(blss_data) {
                printf("- the following is the original CUE file which was included in the UIF:\n\n");
                fwrite(blss_data, 1, blss.num, stdout);
                printf("\n");
            }
        }
        fclose(fdcue);
    }

    printf("- start unpacking:\n");
    for(i = 0; i < blhr.num; i++) {
        l2n_blhr_data(&blhr_data[i]);

        printf("  %03d%%\r", (i * 100) / blhr.num);

        #ifdef VERBOSE
        printf("\n"
            "offset        %08x%08x\n"
            "input size    %08x\n"
            "output sector %08x\n"
            "sectors       %08x\n",
            PRINTF64(blhr_data[i].offset),
            blhr_data[i].zsize,
            blhr_data[i].sector,
            blhr_data[i].size);
        #endif

        myalloc(&in, blhr_data[i].zsize, &insz);

        if(blhr_data[i].zsize) {
            if(fseek(fdi, blhr_data[i].offset, SEEK_SET)) std_err();
            myfr(fdi, in, blhr_data[i].zsize);
            uif_crypt(ctx, in, blhr_data[i].zsize);
        }

        blhr_data[i].size *= bbis.sectorsz;
        myalloc(&out, blhr_data[i].size, &outsz);

        switch(blhr_data[i].type) {
            case 1: {   // non compressed
                if(blhr_data[i].zsize > blhr_data[i].size) {
                    printf("\nError: input size is bigger than output\n");
                    myexit();
                }
                memcpy(out, in, blhr_data[i].zsize);
                memset(out + blhr_data[i].zsize, 0, blhr_data[i].size - blhr_data[i].zsize); // needed?
                break;
            }
            case 3: {   // multi byte
                memset(out, 0, blhr_data[i].size);
                break;
            }
            case 5: {   // compressed
                unzip(&z, in, blhr_data[i].zsize, out, blhr_data[i].size);
                break;
            }
            default: {
                printf("\nError: unknown type (%d)\n", blhr_data[i].type);
                myexit();
            }
        }

        if(fseek(fdo, (u64)blhr_data[i].sector * (u64)bbis.sectorsz, SEEK_SET)) std_err();
        myfw(fdo, out, blhr_data[i].size);
        tot += blhr_data[i].size;
    }

    printf("  100%%\n"
        "- 0x%08x%08x bytes written\n", PRINTF64(tot));

    inflateEnd(&z);
    fclose(fdi);
    fclose(fdo);

    if(outtype == OUT_NRG) {
        nrg_truncate(fileo, bbis.sectorsz * 2); // max 1 sector plus another one if NER5 is not in the last one
        printf(
            "\n"
            "  Please keep in mind that MagicISO creates INVALID NRG files which not only\n"
            "  are unreadable by the various burners/mounters/converters for this type of\n"
            "  image but also by the same Nero which owns the original NRG format, so if the\n"
            "  output NRG file doesn't work is enough normal.\n"
            "\n"
            "  This is the reason why this tool has created an additional CUE file which can\n"
            "  be used in case the NRG one doesn't work. If you are trying to mount the CUE\n"
            "  file but it gives errors or you see no data try to enable all the emulation\n"
            "  options of your mounting program and it will work perfectly.\n"
            "\n");
    }

    printf("- finished\n");
    myexit();
    return(0);
}



#ifdef WIN32
char *get_file(void) {
    OPENFILENAME    ofn;
    static char     filename[4096];
    static const char   filter[] =
                    "UIF file\0"    "*.uif\0"
                    "(*.*)\0"       "*.*\0"
                    "\0"            "\0";

    filename[0] = 0;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize     = sizeof(ofn);
    ofn.lpstrFilter     = filter;
    ofn.nFilterIndex    = 1;
    ofn.lpstrFile       = filename;
    ofn.nMaxFile        = sizeof(filename);
    ofn.lpstrTitle      = "Select the input UIF file to convert";
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;

    printf("- %s\n", ofn.lpstrTitle);
    if(!GetOpenFileName(&ofn)) exit(1);
    return(filename);
}

char *put_file(void) {
    OPENFILENAME    ofn;
    static char     filename[4096 + 10];
    static const char   filter[] =
                    "image file\0"  "*.iso;*.nrg;*.bin;*.cue\0"
                    "(*.*)\0"       "*.*\0"
                    "\0"            "\0";

    filename[0] = 0;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize     = sizeof(ofn);
    ofn.lpstrFilter     = filter;
    ofn.nFilterIndex    = 1;
    ofn.lpstrFile       = filename;
    ofn.nMaxFile        = sizeof(filename);
    ofn.lpstrTitle      = "Choose the name of the output file to create (the extension is automatic)";
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;

    printf("- %s\n", ofn.lpstrTitle);
    if(!GetSaveFileName(&ofn)) exit(1);
    return(filename);
}
#endif



u8 *path2fname(u8 *path) {
    u8      *p;

    p = strrchr(path, '\\');
    if(!p) p = strrchr(path, '/');
    if(p) return(p + 1);
    return(path);
}



u8 *frames2time(u64 num) {
    int     mm,
            ss,
            ff;
    static u8   ret_time[32];

    num /= 2352;    // default sector size
    ff = num % 75;
    ss = (num / 75) % 60;
    mm = (num / 75) / 60;
    sprintf(ret_time, "%02d:%02d:%02d", mm, ss, ff);
    return(ret_time);
}



void nrg2cue(FILE *fd, u64 nrgoff, u8 *fileo) {
    nrg_chunk_t chunk;
    FILE    *fdcue,
            *fdcdt;
    u64     index0,
            index1,
            index2;
    u32     sectsz,
            mode;
    int     i,
            numsz,
            track,
            firstindex = 1;
    u8      *filec,
            *filecdt,
            *buff,
            *p,
            *l;

    if(fseek(fd, nrgoff, SEEK_SET)) {
        printf("- Alert: wrong NRG header offset\n");
        return;
    }

    printf("- generate the CUE file\n");
    filec = change_ext(fileo, ".cue");
    fdcue = open_file(filec, 1);
    fprintf(fdcue, "FILE \"%s\" BINARY\r\n", path2fname(fileo));

    track = 1;
    for(;;) {   // get tracks and do more things
        myfr(fd, &chunk, sizeof(chunk));
        b2n_32(&chunk.size);
        if(!memcmp(chunk.id, "NER5", 4) || !memcmp(chunk.id, "NERO", 4)) break;
        if(!memcmp(chunk.id, "DAOX", 4) || !memcmp(chunk.id, "DAOI", 4)) {
            if(chunk.size >= 22) {
                buff = malloc(chunk.size);
                if(!buff) std_err();
                myfr(fd, buff, chunk.size);

                numsz = (!memcmp(chunk.id, "DAOX", 4)) ? 8 : 4;

                p = buff + 22;
                l = buff + chunk.size - (4 + 4 + (numsz * 3));
                for(i = 0; p <= l; i++) {
                    p += 10;
                    sectsz = *(u32 *)p; p += 4;
                    b2n_32(&sectsz);
                    mode   = p[0];      p += 4;
                    p += getxx(p, &index0, numsz << 3, 1);
                    p += getxx(p, &index1, numsz << 3, 1);
                    p += getxx(p, &index2, numsz << 3, 1);
                    #ifdef VERBOSE
                    printf("  %08x %02x %08x%08x %08x%08x %08x%08x\n", sectsz, mode, PRINTF64(index0), PRINTF64(index1), PRINTF64(index2));
                    #endif
                    switch(mode) {
                        // case 2: yes, this is data mode 2 BUT the CUE will give an error if you use this mode!
                        case 3: fprintf(fdcue, "    TRACK %02d MODE2/%u\r\n", track, sectsz); break;
                        case 7: fprintf(fdcue, "    TRACK %02d AUDIO\r\n",    track);         break;
                        case 0:
                        default:fprintf(fdcue, "    TRACK %02d MODE1/%u\r\n", track, sectsz); break;
                    }
                    if(firstindex) {
                        fprintf(fdcue, "        INDEX 00 00:00:00\r\n");
                        firstindex = 0;
                    } else if(index1 > index0) {
                        fprintf(fdcue, "        INDEX 00 %s\r\n", frames2time(index0));
                    }
                    fprintf(fdcue, "        INDEX 01 %s\r\n", frames2time(index1));
                    track++;
                }

                free(buff);
                continue;
            }
        }
        if(!memcmp(chunk.id, "ETN2", 4) || !memcmp(chunk.id, "ETNF", 4)) {
            if(chunk.size >= 22) {
                buff = malloc(chunk.size);
                if(!buff) std_err();
                myfr(fd, buff, chunk.size);

                numsz = (!memcmp(chunk.id, "ETN2", 4)) ? 8 : 4;

                sectsz = 2352;  // right???
                p = buff;
                l = buff + chunk.size - ((numsz * 2) + 4 + 4 + 4);
                for(i = 0; p <= l; i++) {
                    p += getxx(p, &index1, numsz << 3, 1);
                    p += getxx(p, &index2, numsz << 3, 1);
                    mode   = p[0];      p += 4;
                    p += 4 + 4;
                    #ifdef VERBOSE
                    printf("  %02x %08x%08x %08x%08x\n", mode, PRINTF64(index1), PRINTF64(index2));
                    #endif
                    switch(mode) {
                        case 3: fprintf(fdcue, "    TRACK %02d MODE2/%u\r\n", track, sectsz); break;
                        case 7: fprintf(fdcue, "    TRACK %02d AUDIO\r\n",    track);         break;
                        case 0:
                        default:fprintf(fdcue, "    TRACK %02d MODE1/%u\r\n", track, sectsz); break;
                    }
                    if(!i) fprintf(fdcue, "        INDEX 00 00:00:00\r\n");
                    fprintf(fdcue, "        INDEX 01 %s\r\n", frames2time(index1));
                    track++;
                }

                free(buff);
                continue;
            }
        }
        if(!memcmp(chunk.id, "CDTX", 4)) {
            buff = malloc(chunk.size);
            if(!buff) std_err();
            myfr(fd, buff, chunk.size);

            filecdt = change_ext(fileo, ".cdt");
            fdcdt = open_file(filecdt, 1);
            myfw(fdcdt, buff, chunk.size);
            fclose(fdcdt);

            fprintf(fdcue, "CDTEXTFILE \"%s\"\r\n", path2fname(filecdt));
            free(buff);
            continue;
        }
        if(fseek(fd, chunk.size, SEEK_CUR)) break;
    }
    fclose(fdcue);
}



void magiciso_is_invalid(FILE *fd, u64 nrgoff, u8 *fileo) {
    nrg_chunk_t chunk;
    u64     index2;
    int     numsz,
            track;
    u8      tracks, // can't be more than 8bit
            *buff;

    if(fseek(fd, nrgoff, SEEK_SET)) {
        printf("- Alert: wrong NRG header offset\n");
        return;
    }

    track = 1;
    tracks = 1;
    for(;;) {   // get tracks and do more things
        myfr(fd, &chunk, sizeof(chunk));
        b2n_32(&chunk.size);
        if(!memcmp(chunk.id, "NER5", 4) || !memcmp(chunk.id, "NERO", 4)) break;
        if(!memcmp(chunk.id, "DAOX", 4) || !memcmp(chunk.id, "DAOI", 4)) {
            if(chunk.size >= 22) {
                buff = malloc(chunk.size);
                if(!buff) std_err();
                myfr(fd, buff, chunk.size);

                tracks = (buff[21] - buff[20]) + 1;
                numsz = (!memcmp(chunk.id, "DAOX", 4)) ? 8 : 4;
                getxx(buff + chunk.size - numsz, &index2, numsz << 3, 1);
                if(index2 > nrgoff) {
                    putxx(buff + chunk.size - numsz, nrgoff, numsz << 3, 1);
                    printf("- correcting last DAO index2\n");
                    fseek(fd, -numsz, SEEK_CUR);
                    myfw(fd, buff + chunk.size - numsz, numsz);
                    fflush(fd); // you can't imagine how much required is this fflush...
                }

                free(buff);
                continue;   // skip the fseek chunk.size stuff made at each cycle
            }
        }
        if(!memcmp(chunk.id, "SINF", 4)) {  // usually located after DAO
            if(chunk.size >= 4) {
                if(fseek(fd, 3, SEEK_CUR)) break;
                printf("- correcting SINF to %u tracks\n", tracks);
                myfw(fd, &tracks, 1);
                fflush(fd); // you can't imagine how much required is this fflush...
                fseek(fd, -4, SEEK_CUR);    // restore
            }
        }
        if(fseek(fd, chunk.size, SEEK_CUR)) break;
    }
}



void nrg_truncate(u8 *fileo, int secsz) {
    FILE    *fd;
    u64     truncsize,
            realsize,
            nrgoff;
    int     truncseek;
    u8      *buff,
            *p;

    fd = fopen(fileo, "r+b");
    if(!fd) return;

    fflush(fd);
    fseek(fd, 0, SEEK_END);
    realsize = ftell(fd);

    if(!fseek(fd, -secsz, SEEK_END)) {
        buff = malloc(secsz);
        if(!buff) std_err();
        myfr(fd, buff, secsz);
        for(p = buff + secsz - 12; p >= buff; p--) {
            if(!memcmp(p, "NER5", 4)) {
                nrgoff = *(u64 *)(p + 4);
                p += 12;
                break;
            }
            if(!memcmp(p, "NERO", 4)) {
                nrgoff = *(u32 *)(p + 4);
                p += 8;
                break;
            }
        }
        if(p >= buff) {
            truncseek = -(secsz - (p - buff));

            b2n_64(&nrgoff);
            magiciso_is_invalid(fd, nrgoff, fileo);
            nrg2cue(fd, nrgoff, fileo);

            fseek(fd, truncseek, SEEK_END);
            fflush(fd);
            truncsize = ftell(fd);
            if(realsize != truncsize) {
                printf("- found NRG end of file at offset 0x%08x%08x\n", PRINTF64(truncsize));
                ftruncate(fileno(fd), truncsize);   // trick to spawn errors or warnings if there is no large file support
                fflush(fd);
                fclose(fd);

                fd = fopen(fileo, "rb");    // verify if the truncation was correct
                if(!fd) return;
                fseek(fd, 0, SEEK_END);
                realsize = ftell(fd);
                if(realsize < truncsize) {
                    printf("\n"
                        "Error: the truncated file is smaller than how much I requested\n"
                        "       is possible that ftruncate() doesn't support large files\n"
                        "       Please contact me reporting also the sizeo of the UIF and your platform\n");
                } else if(realsize != truncsize) {
                    printf("- Alert: seems that the file has not been truncated to the correct NRG size\n");
                }
            }
        }
        free(buff);
    }
    fclose(fd);
}



u8 *blhr_unzip(FILE *fd, z_stream *z, DES_key_schedule *ctx, u32 zsize, u32 unzsize) {
    static int  insz = 0;
    static u8   *in  = NULL;
    u8          *data;

    myalloc(&in, zsize, &insz);
    myfr(fd, in, zsize);
    if(ctx) uif_crypt(ctx, in, zsize);
    data = malloc(unzsize);
    if(!data) std_err();
    unzip(z, in, zsize, (void *)data, unzsize);
    return(data);
}



u8 *change_ext(u8 *fname, u8 *ext) {
    u8      *p;

    p = malloc(strlen(fname) + strlen(ext) + 1);
    if(!p) std_err();
    strcpy(p, fname);
    fname = p;
    p = strrchr(fname, '.');
    if(!p || (p && (strlen(p) != 4))) p = fname + strlen(fname);
    strcpy(p, ext);
    return(fname);
}



FILE *open_file(u8 *fname, int write) {
    FILE    *fd;
    u8      ans[16];

    if(write) {
        printf("- create %s\n", fname);
        fd = fopen(fname, "rb");
        if(fd) {
            fclose(fd);
            printf("- the output file already exists, do you want to overwrite it (y/N)? ");
            fgetz(ans, sizeof(ans), stdin);
            if((ans[0] != 'y') && (ans[0] != 'Y')) myexit();
        }
        fd = fopen(fname, "wb");
        if(!fd) std_err();
    } else {
        printf("- open %s\n", fname);
        fd = fopen(fname, "rb");
        if(!fd) std_err();
    }
    return(fd);
}



int blms2cue(FILE *fd, u8 *fname, u8 *blms, int blms_len) {
    u32     bin,
            cue,
            type;
    int     track,
            mode,
            tot;
    u8      mm,
            ss,
            ff,
            *p;

    if(blms_len < 0x40) return(-1);

    bin = *(u32 *)(blms + 0x04);
    l2n_32(&bin);
    if(bin > blms_len) return(-1);

    cue = *(u32 *)(blms + 0x10);
    l2n_32(&cue);
    if(cue > blms_len) return(-1);

    p = blms + 0x40;
    if(bin) {
        p = blms + bin;
        printf("- BIN name stored in the UIF file: %s\n", p);
        p += strlen(p) + 1;
    }
    if(cue) {
        p = blms + cue;
        printf("- CUE name stored in the UIF file: %s\n", p);
        p += strlen(p) + 1;
    }

    fprintf(fd, "FILE \"%s\" BINARY\r\n", fname);

    for(tot = 0; (p - blms) < blms_len; p += 68) {
        if(p[3] & 0xa0) continue;
        track = p[3];
        mode  = p[11];
        mm    = p[8];
        ss    = p[9] - 2;   // these are the 2 seconds located at the beginning of the NRG file
        ff    = p[10];
        type = *(u32 *)(p + 24);
        l2n_32(&type);
        switch(p[1]) {
            case 0x10:
            case 0x12: {
                fprintf(fd, "    TRACK %02d AUDIO\r\n", track);
                } break;
            case 0x14:
            default: {
                fprintf(fd, "    TRACK %02d MODE%d/%d\r\n", track, mode, type);
                } break;
        }
        fprintf(fd, "        INDEX %02d %02d:%02d:%02d\r\n", 1, mm, ss, ff);
        tot++;
    }

    return(tot);
}



void uif_crypt_key(u8 *key, u8 *pwd) {
    i64     *k,
            a,
            b;
    int     i;

    strncpy(key, pwd, 32);
    k = (i64 *)key;

    for(i = 1; i < 4; i++) {
        if(!endian) {   // this solution is required for little/big endian compatibility and speed
            k[0] += k[i];
            continue;
        }
        a = k[0];
        b = k[i];
        l2n_64(&a);
        l2n_64(&b);
        a += b;
        l2n_64(&a);
        k[0] = a;
    }
}



void uif_crypt(DES_key_schedule *ctx, u8 *data, int size) {
    u8      *p,
            *l;

    if(!ctx) return;
    l = data + size - (size & 7);
    for(p = data; p < l; p += 8) {
        DES_ecb_encrypt((void *)p, (void *)p, ctx, DES_DECRYPT);
    }
}



u8 *show_hash(u8 *hash) {
    int     i;
    static u8   vis[33];
    static const char hex[16] = "0123456789abcdef";
    u8      *p;

    p = vis;
    for(i = 0; i < 16; i++) {
        *p++ = hex[hash[i] >> 4];
        *p++ = hex[hash[i] & 15];
    }
    *p = 0;

    return(vis);
}



void myalloc(u8 **data, unsigned wantsize, unsigned *currsize) {
    if(wantsize <= *currsize) return;
    *data = realloc(*data, wantsize);
    if(!*data) std_err();
    *currsize = wantsize;
}



void myfr(FILE *fd, void *data, unsigned size) {
    if(fread(data, 1, size, fd) == size) return;
    printf("\nError: incomplete input file, can't read %u bytes\n", size);
    myexit();
}



void myfw(FILE *fd, void *data, unsigned size) {
    if(fwrite(data, 1, size, fd) == size) return;
    printf("\nError: problems during the writing of the output file\n");
    myexit();
}



int unzip(z_stream *z, u8 *in, u32 insz, u8 *out, u32 outsz) {
    inflateReset(z);

    z->next_in   = in;
    z->avail_in  = insz;
    z->next_out  = out;
    z->avail_out = outsz;
    if(inflate(z, Z_SYNC_FLUSH) != Z_STREAM_END) {
        printf("\nError: the compressed input is wrong or incomplete\n");
        myexit();
    }
    return(z->total_out);
}



void l2n_blhr(blhr_t *p) {
    if(!endian) return;
    l2n_32(&p->sign);
    l2n_32(&p->size);
    l2n_32(&p->ver);
    l2n_32(&p->num);
}



void l2n_blhr_data(blhr_data_t *p) {
    if(!endian) return;
    l2n_64(&p->offset);
    l2n_32(&p->zsize);
    l2n_32(&p->sector);
    l2n_32(&p->size);
    l2n_32(&p->type);
}



void l2n_bbis(bbis_t *p) {
    if(!endian) return;
    l2n_32(&p->sign);
    l2n_32(&p->bbis_size);
    l2n_16(&p->ver);
    l2n_16(&p->image_type);
    l2n_16(&p->unknown1);
    l2n_16(&p->padding);
    l2n_32(&p->sectors);
    l2n_32(&p->sectorsz);
    l2n_32(&p->unknown2);
    l2n_64(&p->blhr);
    l2n_32(&p->blhrbbissz);
    l2n_32(&p->unknown3);
    l2n_32(&p->unknown4);
}



void l2n_16(u16 *num) {
    u16     tmp;

    if(!endian) return;

    tmp = *num;
    *num = ((tmp & 0xff00) >> 8) |
           ((tmp & 0x00ff) << 8);
}



void l2n_32(u32 *num) {
    u32     tmp;

    if(!endian) return;

    tmp = *num;
    *num = ((tmp & 0xff000000) >> 24) |
           ((tmp & 0x00ff0000) >>  8) |
           ((tmp & 0x0000ff00) <<  8) |
           ((tmp & 0x000000ff) << 24);
}



void l2n_64(u64 *num) {
    u64     tmp;

    if(!endian) return;

    tmp = *num;
    *num = (u64)((u64)(tmp & (u64)0xff00000000000000ULL) >> (u64)56) |
           (u64)((u64)(tmp & (u64)0x00ff000000000000ULL) >> (u64)40) |
           (u64)((u64)(tmp & (u64)0x0000ff0000000000ULL) >> (u64)24) |
           (u64)((u64)(tmp & (u64)0x000000ff00000000ULL) >> (u64)8)  |
           (u64)((u64)(tmp & (u64)0x00000000ff000000ULL) << (u64)8)  |
           (u64)((u64)(tmp & (u64)0x0000000000ff0000ULL) << (u64)24) |
           (u64)((u64)(tmp & (u64)0x000000000000ff00ULL) << (u64)40) |
           (u64)((u64)(tmp & (u64)0x00000000000000ffULL) << (u64)56);
}



void b2n_16(u16 *num) {
    u16     tmp;

    if(endian) return;

    tmp = *num;
    *num = ((tmp & 0xff00) >> 8) |
           ((tmp & 0x00ff) << 8);
}



void b2n_32(u32 *num) {
    u32     tmp;

    if(endian) return;

    tmp = *num;
    *num = ((tmp & 0xff000000) >> 24) |
           ((tmp & 0x00ff0000) >>  8) |
           ((tmp & 0x0000ff00) <<  8) |
           ((tmp & 0x000000ff) << 24);
}



void b2n_64(u64 *num) {
    u64     tmp;

    if(endian) return;

    tmp = *num;
    *num = (u64)((u64)(tmp & (u64)0xff00000000000000ULL) >> (u64)56) |
           (u64)((u64)(tmp & (u64)0x00ff000000000000ULL) >> (u64)40) |
           (u64)((u64)(tmp & (u64)0x0000ff0000000000ULL) >> (u64)24) |
           (u64)((u64)(tmp & (u64)0x000000ff00000000ULL) >> (u64)8)  |
           (u64)((u64)(tmp & (u64)0x00000000ff000000ULL) << (u64)8)  |
           (u64)((u64)(tmp & (u64)0x0000000000ff0000ULL) << (u64)24) |
           (u64)((u64)(tmp & (u64)0x000000000000ff00ULL) << (u64)40) |
           (u64)((u64)(tmp & (u64)0x00000000000000ffULL) << (u64)56);
}



int getxx(u8 *data, u64 *ret, int bits, int intnet) {
    u64     num;
    int     i,
            bytes;

    num = 0;
    bytes = bits >> 3;
    for(i = 0; i < bytes; i++) {
        if(!intnet) {   // intel/little endian
            num |= (data[i] << (i << 3));
        } else {        // network/big endian
            num |= (data[i] << ((bytes - 1 - i) << 3));
        }
    }
    *ret = num;
    return(bytes);
}



int putxx(u8 *data, u64 num, int bits, int intnet) {
    int     i,
            bytes;

    bytes = bits >> 3;
    for(i = 0; i < bytes; i++) {
        if(!intnet) {
            data[i] = (num >> (i << 3)) & 0xff;
        } else {
            data[i] = (num >> ((bytes - 1 - i) << 3)) & 0xff;
        }
    }
    return(bytes);
}



void std_err(void) {
    perror("\nError");
    myexit();
}



int fgetz(u8 *data, int size, FILE *fd) {
    u8      *p;

    fflush(fd);
    if(!fgets(data, size, fd)) {
        data[0] = 0;
        return(0);
    }
    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



void myexit(void) {
#ifdef WIN32
    u8      ans[8];

    if(GetWindowLong(mywnd, GWL_WNDPROC)) {
        printf("\nPress RETURN to quit");
        fgetz(ans, sizeof(ans), stdin);
    }
#endif
    exit(1);
}


