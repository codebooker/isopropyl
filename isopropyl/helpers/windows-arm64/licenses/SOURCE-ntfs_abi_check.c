#include "config.h"
#include <stddef.h>
/* This include order is used by libntfs-3g/mft.c and must preserve packing. */
#include "ntfs-3g/compat.h"
#include "ntfs-3g/layout.h"
_Static_assert(sizeof(MFT_RECORD)==48,"MFT record must be packed");
_Static_assert(offsetof(MFT_RECORD,attrs_offset)==20,"MFT attrs offset ABI");
_Static_assert(offsetof(MFT_RECORD,bytes_in_use)==24,"MFT bytes-in-use ABI");
_Static_assert(offsetof(MFT_RECORD,bytes_allocated)==28,"MFT allocated bytes ABI");
_Static_assert(sizeof(MFT_RECORD_FLAGS)==2,"MFT flags ABI");
_Static_assert(sizeof(ATTR_FLAGS)==2,"Attribute flags ABI");
_Static_assert(sizeof(RESIDENT_ATTR_FLAGS)==1,"Resident flags ABI");
_Static_assert(sizeof(NTFS_BOOT_SECTOR)==512,"Boot sector ABI");
