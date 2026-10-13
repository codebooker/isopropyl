/* SPDX-License-Identifier: GPL-2.0-or-later
 * libntfs-3g's optional POSIX name-to-SID mapping has no Windows equivalent.
 * Native image construction uses NTFS security descriptors, never this map.
 */
#ifndef ISOPROPYL_WIN_POSIX_ACCOUNTS_H
#define ISOPROPYL_WIN_POSIX_ACCOUNTS_H
#include <errno.h>
#include <stdlib.h>
#define random rand
#define srandom srand
int ffs(int value);
#ifndef S_IFLNK
#define S_IFLNK 0120000
#define S_ISLNK(m) (((m)&0170000)==S_IFLNK)
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_ISUID
#define S_ISUID 04000
#define S_ISGID 02000
#endif
#ifndef S_ISVTX
#define S_ISVTX 01000
#endif
#ifndef major
#define major(d) ((unsigned int)(d)>>8)
#define minor(d) ((unsigned int)(d)&255)
#define makedev(major_number, minor_number) (((unsigned int)(major_number)<<8)|((unsigned int)(minor_number)&255))
#endif
typedef unsigned int uid_t;
typedef unsigned int gid_t;
static int getuid(void) { return 0; }
static int geteuid(void) { return 0; }
static int getgid(void) { return 0; }
static int getegid(void) { return 0; }
static int fork(void) { errno=ENOSYS; return -1; }
static int setsid(void) { errno=ENOSYS; return -1; }
struct passwd { unsigned int pw_uid; unsigned int pw_gid; char *pw_name; };
struct group { unsigned int gr_gid; char **gr_mem; };
static struct passwd *getpwnam(const char *name) { (void)name; errno=ENOTSUP; return 0; }
static struct group *getgrnam(const char *name) { (void)name; errno=ENOTSUP; return 0; }
static struct passwd *getpwuid(unsigned int id) { (void)id; errno=ENOTSUP; return 0; }
static struct group *getgrgid(unsigned int id) { (void)id; errno=ENOTSUP; return 0; }
#endif
