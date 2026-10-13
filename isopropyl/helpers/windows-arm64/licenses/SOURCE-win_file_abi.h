/* SPDX-License-Identifier: GPL-2.0-or-later
 * Use UCRT's explicitly sized 64-bit file metadata ABI. MinGW's old-name
 * struct stat can retain 32-bit off_t when Windows headers precede config.h,
 * while fstat is redirected to a 64-bit function. That corrupts the stack.
 */
#ifndef ISOPROPYL_WIN_FILE_ABI_H
#define ISOPROPYL_WIN_FILE_ABI_H
#ifdef _WIN32
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/stat.h>
#include <stddef.h>
_Static_assert(sizeof(struct _stat64)==56, "UCRT file metadata ABI must be 64-bit");
_Static_assert(offsetof(struct _stat64,st_size)==24, "UCRT file-size field ABI mismatch");
/* util.c enables MinGW alarm after some headers; the force include must
 * keep this existing CRT declaration available regardless of include order. */
extern unsigned int __cdecl alarm(unsigned int seconds);
#undef stat
#undef fstat
#undef stat64
#undef fstat64
#undef lstat
#undef lstat64
#define stat _stat64
#define fstat _fstat64
#define stat64 _stat64
#define fstat64 _fstat64
#define lstat _stat64
#define lstat64 _stat64
#endif
#endif
