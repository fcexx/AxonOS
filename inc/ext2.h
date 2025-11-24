#ifndef INC_EXT2_H
#define INC_EXT2_H

#include <stdint.h>

/* Minimal ext2 on-disk structures needed for a reader */

/* Superblock (at offset 1024 bytes) */
struct ext2_super_block {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size; /* block size = 1024 << s_log_block_size */
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    /* We don't need the rest for a minimal reader */
};

/* Inode on-disk (only fields we use) */
struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15]; /* pointers to blocks */
    /* rest omitted */
};

/* Directory entry (version 2) */
struct ext2_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    /* name follows */
};

/* File types (file_type in dir entry) */
#define EXT2_FT_UNKNOWN  0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR      2

/* Magic */
#define EXT2_SUPER_MAGIC 0xEF53

/* Public API: mount from memory image, list root, read file */
int ext2_mount_from_memory(void *image, size_t size);
void ext2_ls_root(void);
int ext2_read_file_root(const char *name, void *out_buf, size_t buf_size);

#endif /* INC_EXT2_H */
