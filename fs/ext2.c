#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../inc/heap.h"
#include "../inc/ext2.h"
#include "../inc/fs.h"

/* Minimal ext2 runtime structures */
struct ext2_mount {
    void *image;
    size_t size;
    struct ext2_super_block sb;
    uint32_t block_size;
    uint32_t inodes_per_group;
    uint32_t inode_size;
    uint32_t bg_inode_table; /* first group's inode table block */
};

struct ext2_file_handle {
    uint32_t inode_no;
    struct ext2_inode inode;
};

static struct fs_driver ext2_driver;
static struct fs_driver_ops ext2_ops;
static struct ext2_mount *g_mount = NULL;

static inline void *ext2_block_ptr(struct ext2_mount *m, uint32_t block_no) {
    if (!m || !m->image) return NULL;
    uint64_t off = (uint64_t)block_no * m->block_size;
    if (off + m->block_size > m->size) return NULL;
    return (uint8_t*)m->image + off;
}

int ext2_mount_from_memory(void *image, size_t size) {
    if (!image || size < 2048) return -1;
    struct ext2_super_block *sb = (struct ext2_super_block*)((uint8_t*)image + 1024);
    if (sb->s_magic != EXT2_SUPER_MAGIC) return -1;
    struct ext2_mount *m = (struct ext2_mount*)kmalloc(sizeof(struct ext2_mount));
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    m->image = image;
    m->size = size;
    memcpy(&m->sb, sb, sizeof(*sb));
    m->block_size = 1024u << sb->s_log_block_size;
    m->inodes_per_group = sb->s_inodes_per_group;
    m->inode_size = (sb->s_rev_level == 0) ? 128 : 128; /* minimal: assume 128 */
    /* Read first group descriptor to get inode table */
    uint8_t *gd_table;
    if (m->block_size == 1024) gd_table = (uint8_t*)image + 2048;
    else gd_table = (uint8_t*)image + m->block_size; /* block 1 */
    /* group descriptor: bg_inode_table at offset 8 (little endian) */
    uint32_t bg_inode_table = *(uint32_t*)(gd_table + 8);
    m->bg_inode_table = bg_inode_table;
    g_mount = m;
    /* attach mount to driver data if driver registered */
    ext2_driver.driver_data = (void*)g_mount;
    return 0;
}

static int ext2_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file; /* create not supported */
    return -1; /* not handled */
}

static int ext2_open(const char *path, struct fs_file **out_file) {
    if (!g_mount) return -1; /* not handled if not mounted */
    if (!path || path[0] != '/') return -1; /* not handled */
    /* Mount namespace: handle only under /ext2 path */
    if (strncmp(path, "/ext2", 5) != 0 || (path[5] != '\0' && path[5] != '/')) {
        return -1; /* not our path */
    }
    const char *name = (path[5] == '\0') ? "" : (path + 6);
    uint32_t inode_no = 2; /* root */
    if (name[0] == '\0') {
        /* open root directory as a file handle */
    } else {
        /* search root directory for name */
        /* read root inode */
        uint32_t inode_idx = inode_no - 1;
        uint64_t inode_table_off = (uint64_t)g_mount->bg_inode_table * g_mount->block_size;
        uint8_t *inode_ptr = (uint8_t*)g_mount->image + inode_table_off + inode_idx * g_mount->inode_size;
        struct ext2_inode root_inode;
        memcpy(&root_inode, inode_ptr, sizeof(root_inode));
        /* iterate direct blocks */
        for (int b = 0; b < 12; b++) {
            uint32_t block = root_inode.i_block[b];
            if (block == 0) continue;
            uint8_t *blk = ext2_block_ptr(g_mount, block);
            if (!blk) continue;
            uint32_t off = 0;
            while (off < g_mount->block_size) {
                struct ext2_dir_entry *de = (struct ext2_dir_entry*)(blk + off);
                if (de->inode == 0) break;
                char namebuf[256];
                int nlen = de->name_len;
                if (nlen > 255) nlen = 255;
                memcpy(namebuf, blk + off + sizeof(*de), nlen);
                namebuf[nlen] = '\0';
                if (strcmp(namebuf, name) == 0) {
                    inode_no = de->inode;
                    goto found_inode;
                }
                if (de->rec_len == 0) break;
                off += de->rec_len;
            }
        }
        return -1; /* not handled/not found under ext2 root */
found_inode: ;
    }
    /* load inode */
    uint32_t inode_idx = inode_no - 1;
    uint64_t inode_table_off = (uint64_t)g_mount->bg_inode_table * g_mount->block_size;
    uint8_t *inode_ptr = (uint8_t*)g_mount->image + inode_table_off + inode_idx * g_mount->inode_size;
    struct ext2_inode inode;
    memcpy(&inode, inode_ptr, sizeof(inode));
    struct fs_file *f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -4;
    memset(f, 0, sizeof(*f));
    /* copy path */
    size_t plen = strlen(path) + 1;
    char *pp = (char*)kmalloc(plen);
    memcpy(pp, path, plen);
    f->path = pp;
    f->size = inode.i_size;
    f->fs_private = ext2_driver.driver_data; /* mount pointer */
    f->type = (inode.i_mode & 0x4000) ? FS_TYPE_DIR : FS_TYPE_REG;
    struct ext2_file_handle *fh = (struct ext2_file_handle*)kmalloc(sizeof(*fh));
    fh->inode_no = inode_no;
    memcpy(&fh->inode, &inode, sizeof(inode));
    f->driver_private = fh;
    *out_file = f;
    return 0;
}

static ssize_t ext2_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !g_mount) return -1;
    struct ext2_file_handle *fh = (struct ext2_file_handle*)file->driver_private;
    struct ext2_inode *inode = &fh->inode;
    if (offset >= inode->i_size) return 0;
    if (offset + size > inode->i_size) size = inode->i_size - offset;
    size_t to_read = size;
    size_t read = 0;
    uint32_t block_size = g_mount->block_size;
    uint32_t first_block = offset / block_size;
    uint32_t block_offset = offset % block_size;
    uint32_t ptrs_per_block = block_size / 4;
    while (to_read > 0) {
        uint32_t block_no = 0;
        if (first_block < 12) {
            block_no = inode->i_block[first_block];
        } else if (first_block < 12 + ptrs_per_block) {
            /* single indirect */
            uint32_t indirect_block = inode->i_block[12];
            if (indirect_block == 0) return read;
            uint8_t *ind_blk = ext2_block_ptr(g_mount, indirect_block);
            if (!ind_blk) return read;
            uint32_t idx = first_block - 12;
            uint32_t *arr = (uint32_t*)ind_blk;
            block_no = arr[idx];
        } else {
            /* double/triple indirect not supported */
            return read;
        }
        if (block_no == 0) return read;
        uint8_t *blk = ext2_block_ptr(g_mount, block_no);
        if (!blk) return read;
        size_t can = block_size - block_offset;
        size_t now = can < to_read ? can : to_read;
        memcpy((uint8_t*)buf + read, blk + block_offset, now);
        read += now;
        to_read -= now;
        first_block++;
        block_offset = 0;
    }
    return (ssize_t)read;
}

static void ext2_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

/* Register driver; mount must be provided later via ext2_mount_from_memory */
int ext2_register(void) {
    ext2_ops.name = "ext2";
    ext2_ops.create = ext2_create;
    ext2_ops.open = ext2_open;
    ext2_ops.read = ext2_read;
    ext2_ops.write = NULL;
    ext2_ops.release = ext2_release;
    ext2_driver.ops = &ext2_ops;
    ext2_driver.driver_data = (void*)g_mount;
    return fs_register_driver(&ext2_driver);
}

int ext2_unregister(void) {
    return fs_unregister_driver(&ext2_driver);
}
