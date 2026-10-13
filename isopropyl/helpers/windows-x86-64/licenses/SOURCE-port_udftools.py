#!/usr/bin/env python3
"""Make pinned udftools mkudffs a portable, regular-image-only helper."""
from pathlib import Path
import sys
root=Path(sys.argv[1])
for name in ['main.c','mkudffs.c','options.c']:
 p=root/'mkudffs'/name;s=p.read_text()
 for header in ['sys/ioctl.h','linux/fs.h','linux/fd.h','sys/sysmacros.h','linux/hdreg.h','linux/cdrom.h']:
  s=s.replace('#include <'+header+'>','')
 if name=='main.c':
  s=s.replace('int main(int argc, char *argv[])', '#ifdef _WIN32\n#define main isopropyl_main\n#endif\nint main(int argc, char *argv[])')
  s += '\n#ifdef _WIN32\n#undef main\nint wmain(int argc,wchar_t **wide_argv) {\n    char **argv=calloc((size_t)argc+1,sizeof(char *));\n    if (!argv) return 1;\n    for(int i=0;i<argc;i++) {\n        int count=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide_argv[i],-1,NULL,0,NULL,NULL);\n        if(!count || !(argv[i]=malloc((size_t)count))) return 1;\n        if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide_argv[i],-1,argv[i],count,NULL,NULL)) return 1;\n    }\n    int result=isopropyl_main(argc,argv);\n    for(int i=0;i<argc;i++) free(argv[i]);free(argv);return result;\n}\n#endif\n'
  start=s.index('static int is_whole_disk(');end=s.index('static int write_func(',start)
  s=s[:start]+'''static int is_whole_disk(int fd) { struct stat st; return fstat(fd,&st)==0 && S_ISREG(st.st_mode) ? 1 : -1; }
static int is_removable_disk(int fd) { (void)fd; return -1; }

'''+s[end:]
  start=s.index('\tif (fcntl(0, F_GETFL)');end=s.index('\n\tappname =',start)
  s=s[:start]+s[end:]
  # Existing images only. No device paths, missing files, or image creation.
  start=s.index('\tif (fd < 0)\n');end=s.index('\n\tif (fd >= 0)',start)
  s=s[:start]+'''\t{ struct stat image_stat;
      if (fd < 0 || fstat(fd,&image_stat)!=0 || !S_ISREG(image_stat.st_mode)) {
        fprintf(stderr,"mkudffs: ISOpropyl helper requires an existing regular image\\n"); exit(1);
      }
    }
'''+s[end:]
 elif name=='options.c':
  start=s.index('\t/* Autodetect media type */');end=s.index('\n\tswitch (media)',start)
  s=s[:start]+'\tif (media == MEDIA_TYPE_NONE) media = MEDIA_TYPE_HD;\n'+s[end:]
 elif name=='mkudffs.c':
  s=s.replace('if (gettimeofday(&tv, NULL) != 0 || tv.tv_sec == (time_t)-1 || (tm = localtime(&tv.tv_sec)) == NULL', 'time_t udf_seconds;\n\tif (gettimeofday(&tv, NULL) != 0 || tv.tv_sec == (time_t)-1 || (udf_seconds = (time_t)tv.tv_sec, (tm = localtime(&udf_seconds))) == NULL')
  s=s.replace('\tstruct hd_geometry geometry;','')
  start=s.index('\tif (fd >= 0 && fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)');end=s.index('\n\t{',s.index('\n\telse',start))
  s=s[:start]+s[end:]
  # macOS exposes timezone as a function, so derive UDF offset via strftime.
  s=s.replace('\t\taltzone = timezone - 3600;\n\t\tif (daylight)\n\t\t\tts.typeAndTimezone = cpu_to_le16(((-altzone/60) & 0x0FFF) | 0x1000);\n\t\telse\n\t\t\tts.typeAndTimezone = cpu_to_le16(((-timezone/60) & 0x0FFF) | 0x1000);','''        { char zone[16]; int hours=0, minutes=0, sign=1;
          if (strftime(zone,sizeof(zone),"%z",tm) == 5) {
            sign=zone[0]=='-' ? -1 : 1; hours=(zone[1]-'0')*10+zone[2]-'0'; minutes=(zone[3]-'0')*10+zone[4]-'0';
          }
          ts.typeAndTimezone=cpu_to_le16(((sign*(hours*60+minutes)) & 0x0FFF) | 0x1000);
        }''')
 p.write_text(s)
(root/'include'/'isopropyl_windows.h').write_text(r'''#ifndef ISOPROPYL_UDF_WINDOWS_H
#define ISOPROPYL_UDF_WINDOWS_H
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#ifndef S_ISREG
#define S_ISREG(m) (((m)&_S_IFMT)==_S_IFREG)
#endif
struct isopropyl_udf_timeval { long long tv_sec; long tv_usec; };
static int isopropyl_udf_gettimeofday(struct isopropyl_udf_timeval *tv,void *unused) {
  FILETIME ft;ULARGE_INTEGER ticks; (void)unused;
  GetSystemTimeAsFileTime(&ft);ticks.LowPart=ft.dwLowDateTime;ticks.HighPart=ft.dwHighDateTime;
  tv->tv_sec=(long long)(ticks.QuadPart/10000000ULL)-11644473600LL;
  tv->tv_usec=(long)((ticks.QuadPart%10000000ULL)/10);return 0;
}
#define timeval isopropyl_udf_timeval
#define gettimeofday isopropyl_udf_gettimeofday
#define off_t __int64
#define stat _stat64
#define fstat _fstat64
#define lseek _lseeki64
#define fsync _commit
static int isopropyl_utf8_open(const char *path,int flags,...) {
  int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);
  if(!count) { errno=EINVAL;return -1; }
  wchar_t *wide=malloc((size_t)count*sizeof(wchar_t));
  if(!wide) { errno=ENOMEM;return -1; }
  MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,count);
  int result=_wopen(wide,flags|_O_BINARY);free(wide);return result;
}
#define open isopropyl_utf8_open
#endif
#endif
''')
p=root/'include/config.h'
p.write_text('#define PACKAGE_NAME "udftools"\n#define PACKAGE_VERSION "2.3"\n#define _FILE_OFFSET_BITS 64\n#include "isopropyl_windows.h"\n')
