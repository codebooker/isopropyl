/* SPDX-License-Identifier: GPL-2.0-or-later
 * libntfs-3g backend restricted to regular private image files. Deliberately
 * excludes physical disk handles and every device-control operation.
 */
#include "config.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include "types.h"
struct ntfs_device;
#include "device.h"
#include "device_io.h"
#define FD(dev) (*(int *)(dev)->d_private)
static int device_namespace(const char *name) {
    if (!name) return 1;
    /* Win32 normalizes slash direction and namespace names are case-insensitive. */
    if ((name[0]=='\\' || name[0]=='/') && (name[1]=='\\' || name[1]=='/')) {
        if (name[2]=='.' && (name[3]=='\\' || name[3]=='/')) return 1;
        if (name[2]=='?' && (name[3]=='\\' || name[3]=='/')) {
            /* Extended ordinary drive file paths remain valid for long names. */
            return !(((name[4]>='A' && name[4]<='Z') || (name[4]>='a' && name[4]<='z')) && name[5]==':' && (name[6]=='\\' || name[6]=='/'));
        }
    }
    return 0;
}
static int image_open(struct ntfs_device *dev,int flags) {
    struct stat status;int fd;
    if (NDevOpen(dev)) { errno=EBUSY;return -1; }
    if (device_namespace(dev->d_name)) {errno=EINVAL;return -1;}
    if (_sopen_s(&fd,dev->d_name,flags|_O_BINARY,_SH_DENYRW,_S_IREAD|_S_IWRITE)) return -1;
    if (fstat(fd,&status) || !S_ISREG(status.st_mode)) { _close(fd);errno=EINVAL;return -1; }
    dev->d_private=malloc(sizeof(int));
    if (!dev->d_private) {_close(fd);errno=ENOMEM;return -1;}
    FD(dev)=fd;NDevSetOpen(dev);
    if ((flags&O_RDWR)!=O_RDWR) NDevSetReadOnly(dev);
    return 0;
}
static int image_sync(struct ntfs_device *dev) {
    if (NDevReadOnly(dev)) return 0;
    if (_commit(FD(dev))) return -1;
    NDevClearDirty(dev);return 0;
}
static int image_close(struct ntfs_device *dev) {
    if (!NDevOpen(dev)) {errno=EBADF;return -1;}
    if (NDevDirty(dev) && image_sync(dev)) return -1;
    if (_close(FD(dev))) return -1;
    free(dev->d_private);dev->d_private=NULL;NDevClearOpen(dev);return 0;
}
static s64 image_seek(struct ntfs_device *dev,s64 offset,int whence) {return _lseeki64(FD(dev),offset,whence);}
static s64 image_read(struct ntfs_device *dev,void *buf,s64 count) {
    if (count<0) {errno=EINVAL;return -1;}
    return _read(FD(dev),buf,(unsigned int)(count>INT_MAX?INT_MAX:count));
}
static s64 image_write(struct ntfs_device *dev,const void *buf,s64 count) {
    if (NDevReadOnly(dev)) {errno=EROFS;return -1;}
    if (count<0) {errno=EINVAL;return -1;}
    NDevSetDirty(dev);return _write(FD(dev),buf,(unsigned int)(count>INT_MAX?INT_MAX:count));
}
static s64 image_pread(struct ntfs_device *dev,void *buf,s64 count,s64 offset) {
    if (image_seek(dev,offset,SEEK_SET)!=offset) return -1;
    return image_read(dev,buf,count);
}
static s64 image_pwrite(struct ntfs_device *dev,const void *buf,s64 count,s64 offset) {
    if (image_seek(dev,offset,SEEK_SET)!=offset) return -1;
    return image_write(dev,buf,count);
}
static int image_stat(struct ntfs_device *dev,struct stat *buf) {return fstat(FD(dev),buf);}
static int image_ioctl(struct ntfs_device *dev,unsigned long request,void *argument) {
    (void)dev;(void)request;(void)argument;errno=ENOTSUP;return -1;
}
int ntfs_win32_set_sparse(int fd) {(void)fd;errno=ENOTSUP;return -1;}
int ntfs_win32_ftruncate(int fd,s64 size) {return _chsize_s(fd,size)?-1:0;}
int ntfs_device_win32_ftruncate(struct ntfs_device *dev,s64 size) {return ntfs_win32_ftruncate(FD(dev),size);}
struct ntfs_device_operations ntfs_device_win32_io_ops={image_open,image_close,image_seek,image_read,image_write,image_pread,image_pwrite,image_sync,image_stat,image_ioctl};
