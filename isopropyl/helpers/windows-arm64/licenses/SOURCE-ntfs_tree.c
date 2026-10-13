/* SPDX-License-Identifier: GPL-2.0-or-later
 * Device-free NTFS directory/file population using upstream libntfs-3g.
 * The image must be a regular file; paths are UTF-8 and never shell text.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <locale.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#include "ntfs-3g/volume.h"
#include "ntfs-3g/dir.h"
#include "ntfs-3g/attrib.h"
#include "ntfs-3g/inode.h"
#include "ntfs-3g/unistr.h"

static int valid(const char *p) {
    if (!*p || *p=='/' || *p=='\\' || strchr(p,':')) return 0;
    const char *q=p;
    while (*q) {
        const char *end=strchr(q,'/'); size_t n=end?(size_t)(end-q):strlen(q);
        if (!n || (n==1&&q[0]=='.') || (n==2&&q[0]=='.'&&q[1]=='.')) return 0;
        if (!end) break; q=end+1;
    }
    return 1;
}
int main(int argc,char **argv) {
    if (argc<4 || !valid(argv[3])) return 2;
    struct stat image;
    if (stat(argv[1],&image) || !S_ISREG(image.st_mode)) return 2;
    ntfs_set_locale();
    int reading=!strcmp(argv[2],"read"), directory=!strcmp(argv[2],"mkdir");
    if (!reading && !directory && strcmp(argv[2],"write")) return 2;
    ntfs_volume *vol=ntfs_mount(argv[1],reading?NTFS_MNT_RDONLY:NTFS_MNT_EXCLUSIVE);
    if (!vol) { perror("open private NTFS image"); return 3; }
    ntfs_inode *inode=NULL,*parent=NULL; ntfs_attr *attr=NULL; FILE *input=NULL;
    int result=4; const char *stage="open inode"; char *copy=NULL; ntfschar *name=NULL; unsigned char *buffer=NULL;
    if (reading) inode=ntfs_pathname_to_inode(vol,NULL,argv[3]);
    else {
        if (ntfs_pathname_to_inode(vol,NULL,argv[3])) goto done; /* never replace */
        copy=strdup(argv[3]); if (!copy) goto done;
        char *leaf=strrchr(copy,'/');
        if (leaf) { *leaf++=0; parent=ntfs_pathname_to_inode(vol,NULL,copy); }
        else { leaf=copy; parent=ntfs_pathname_to_inode(vol,NULL,"/"); }
        if (!parent) goto done;
        int length=ntfs_mbstoucs(leaf,&name);
        if (length<=0 || length>255) goto done;
        stage="create inode";inode=ntfs_create(parent,const_cpu_to_le32(0),name,(u8)length,directory?S_IFDIR:S_IFREG);
    }
    if (!inode) goto done;
    if (directory) { result=0; goto done; }
    stage="open data attribute";attr=ntfs_attr_open(inode,AT_DATA,AT_UNNAMED,0);
    if (!attr && !reading) {
        if (ntfs_attr_add(inode,AT_DATA,AT_UNNAMED,0,NULL,0)) goto done;
        attr=ntfs_attr_open(inode,AT_DATA,AT_UNNAMED,0);
    }
    if (!attr) goto done;
    buffer=malloc(1024*1024); if (!buffer) goto done;
    s64 offset=0;
    if (reading) {
#ifdef _WIN32
        _setmode(_fileno(stdout),_O_BINARY);
#endif
        while (offset<attr->data_size) {
            s64 wanted=attr->data_size-offset; if (wanted>1024*1024) wanted=1024*1024;
            s64 count=ntfs_attr_pread(attr,offset,wanted,buffer);
            if (count<=0 || fwrite(buffer,1,(size_t)count,stdout)!=(size_t)count) goto done;
            offset+=count;
        }
        if (fflush(stdout)) goto done;
    } else {
        if (argc!=5) goto done;
        stage="open source";input=fopen(argv[4],"rb"); if (!input) goto done;
        struct stat src; if (fstat(fileno(input),&src) || !S_ISREG(src.st_mode)) goto done;
        stage="allocate data";if (ntfs_attr_truncate(attr,src.st_size)) goto done;
        size_t count;
        while ((count=fread(buffer,1,1024*1024,input))) {
            size_t written=0;
            while (written<count) {
                stage="write data";s64 n=ntfs_attr_pwrite(attr,offset+(s64)written,(s64)(count-written),buffer+written);
                if (n<=0) goto done; written+=(size_t)n;
            }
            offset+=(s64)count;
        }
        if (ferror(input) || offset!=src.st_size) goto done;
    }
    result=0;
done:
    if (input) fclose(input); if (attr) ntfs_attr_close(attr);
    if (inode) { if (parent?ntfs_inode_close_in_dir(inode,parent):ntfs_inode_close(inode)) { stage="close inode";result=4; } }
    if (parent) ntfs_inode_close(parent);
    free(name); free(copy); free(buffer);
    if (ntfs_umount(vol,FALSE)) { stage="close volume";result=4; }
    if (result) { fprintf(stderr,"Private NTFS operation failed at %s\n",stage);perror("private NTFS tree operation"); }
    return result;
}
