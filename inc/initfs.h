/* initfs.h - parse multiboot2 module named "initfs" and unpack cpio newc into VFS */
#pragma once

#include <stdint.h>

/* Scan multiboot2 tags for a module with name `module_name`.
   If found, unpack cpio newc archive from the module into the VFS.
   Returns 0 on success, negative on error, 1 if module not found. */
int initfs_process_multiboot_module(uint32_t multiboot_magic, uint64_t multiboot_info, const char *module_name);


