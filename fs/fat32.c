#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <heap.h>
#include <fs.h>
#include <ext2.h>
#include <fat32.h>
#include <disk.h>
#include <stat.h>
#include <axonos.h>
#include <ramfs.h>
#include <vga.h>

/* Disable local debug prints in this file */
#ifdef kprintf
#undef kprintf
#endif
#define kprintf(...) do {} while(0)

/* fat32.c uses utf16le_to_utf8() before its definition; keep an explicit prototype
   to avoid implicit declaration UB on x86_64. */
static int utf16le_to_utf8(const uint16_t *in, int inlen, char *out, int outcap);

/* local helper: strip matching leading/trailing quotes from a string in-place */
static void strip_matching_quotes_local(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len >= 2) {
        char first = s[0];
        char last = s[len - 1];
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            memmove(s, s + 1, len - 2);
            s[len - 2] = '\0';
        }
    }
}

/* Minimal read-only FAT32 implementation supporting:
   - mount from a block device (partition or raw)
   - short (8.3) name lookup and directory listing
   - reading files (cluster chain via FAT)
   This is intentionally simple and readable; no LFN support and no write support.
*/

struct fat32_mount {
    int device_id;
    uint32_t partition_lba; /* LBA of boot sector (0 for raw) */
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t num_fats;
    uint32_t sectors_per_fat;
    uint32_t root_cluster;
    uint64_t total_sectors;
    uint32_t first_fat_sector;
    uint32_t first_data_sector;
};

struct fat32_file_handle {
    struct fat32_mount *m;
    uint32_t start_cluster;
    uint32_t size;
    uint32_t cur_cluster;
};

static struct fs_driver fat32_driver;
static struct fs_driver_ops fat32_ops;
static struct fat32_mount *g_fat = NULL;

/* helpers */
static int read_sector(int device_id, uint32_t lba, void *buf) {
    return disk_read_sectors(device_id, lba, buf, 1);
}

static int read_sectors(int device_id, uint32_t lba, void *buf, uint32_t count) {
    return disk_read_sectors(device_id, lba, buf, count);
}

static uint32_t cluster_to_lba(struct fat32_mount *m, uint32_t cluster) {
    if (cluster < 2) return 0;
    return (uint32_t)(m->first_data_sector + (uint64_t)(cluster - 2) * m->sectors_per_cluster);
}

static uint32_t bytes_per_cluster_512(const struct fat32_mount *m) {
    /* fat32_parse_boot enforces bytes_per_sector==512 */
    return (uint32_t)m->sectors_per_cluster * 512u;
}

/* Read FAT entry (32-bit) */
static uint32_t fat32_read_fat_entry(struct fat32_mount *m, uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;
    /* Our block layer uses 512-byte sectors; support only BPB bytes_per_sector==512. */
    uint32_t fat_sector = m->first_fat_sector + (fat_offset / 512u);
    uint32_t ent_offset = fat_offset % 512u;
    uint8_t buf[512];
    if (read_sector(m->device_id, fat_sector, buf) != 0) return 0x0FFFFFFF;
    uint32_t val = *(uint32_t*)(buf + ent_offset);
    return val & 0x0FFFFFFF;
}

static int is_pow2_u32(uint32_t v) { return v && ((v & (v - 1)) == 0); }

/* LFN checksum (FAT spec): computed from 11-byte short name entry. */
static uint8_t fat32_lfn_checksum(const uint8_t shortname11[11]) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; i++) {
        sum = (uint8_t)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + shortname11[i]);
    }
    return sum;
}

/* parse boot sector at given LBA; return 0 on success */
static int fat32_parse_boot(struct fat32_mount *m, uint32_t lba) {
    uint8_t buf[512];
    if (read_sector(m->device_id, lba, buf) != 0) return -1;
    /* basic checks */
    if (buf[510] != 0x55 || buf[511] != 0xAA) return -1;
    uint16_t bytes_per_sector = *(uint16_t*)(buf + 11);
    uint8_t sectors_per_cluster = *(uint8_t*)(buf + 13);
    uint16_t reserved = *(uint16_t*)(buf + 14);
    uint8_t num_fats = *(uint8_t*)(buf + 16);
    uint32_t total_sectors32 = *(uint32_t*)(buf + 32);
    uint32_t sectors_per_fat32 = *(uint32_t*)(buf + 36);
    uint32_t root_cluster = *(uint32_t*)(buf + 44);
    /* We only support 512-byte sectors (matches disk_read_sectors contract).
       Reject invalid values to avoid buffer overruns / OOB FAT reads. */
    if (bytes_per_sector != 512) return -1;
    if (sectors_per_cluster == 0 || sectors_per_cluster > 128) return -1;
    if (!is_pow2_u32((uint32_t)sectors_per_cluster)) return -1;
    if (reserved == 0 || num_fats == 0 || sectors_per_fat32 == 0) return -1;
    m->bytes_per_sector = bytes_per_sector;
    m->sectors_per_cluster = sectors_per_cluster;
    m->reserved_sectors = reserved;
    m->num_fats = num_fats;
    m->sectors_per_fat = sectors_per_fat32;
    m->root_cluster = root_cluster ? root_cluster : 2;
    m->total_sectors = total_sectors32 ? total_sectors32 : (*(uint16_t*)(buf + 19));
    m->first_fat_sector = m->partition_lba + m->reserved_sectors;
    m->first_data_sector = (uint32_t)(m->partition_lba + m->reserved_sectors + (uint64_t)m->num_fats * m->sectors_per_fat);
    if (m->root_cluster < 2) return -1;
    return 0;
}

/* try mount boot sector at lba; return 0 on success */
int fat32_mount_from_device(int device_id) {
    /* allow remounting the same device; but prevent multiple different mounts */
    if (g_fat) {
        if (g_fat->device_id == device_id) return 0;
        return -1; /* already mounted from another device */
    }
    struct fat32_mount *m = (struct fat32_mount*)kmalloc(sizeof(*m));
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    m->device_id = device_id;
    m->partition_lba = 0;
    kprintf("fat32: probing device %d at LBA 0\n", device_id);
    if (fat32_parse_boot(m, 0) == 0) {
        kprintf("fat32: found BPB at LBA 0 on device %d\n", device_id);
        g_fat = m;
        fat32_driver.driver_data = (void*)g_fat;
        kprintf("FAT32: mounted from device %d (LBA 0) - ready for manual mount\n", device_id);
        return 0;
    } else {
        kprintf("fat32: no valid BPB at LBA 0 on device %d\n", device_id);
    }
    /* maybe MBR with partition table: read sector 0 and check partition entries */
    uint8_t buf[512];
    if (read_sector(device_id, 0, buf) != 0) { kfree(m); return -1; }
    if (buf[510] != 0x55 || buf[511] != 0xAA) { kfree(m); return -1; }
    kprintf("fat32: read MBR on device %d, scanning partitions\n", device_id);
    /* partition table at offset 446, 4 entries of 16 bytes */
    for (int i = 0; i < 4; i++) {
        uint8_t *pe = buf + 446 + i * 16;
        uint8_t part_type = pe[4];
        uint32_t start_lba = *(uint32_t*)(pe + 8);
        uint32_t part_sectors = *(uint32_t*)(pe + 12);
        if (start_lba == 0 || part_sectors == 0) continue;
        kprintf("fat32: checking partition %d type=0x%02x start=%u sectors=%u\n", i, part_type, start_lba, part_sectors);
        /* Try to parse boot sector at partition start regardless of reported type */
        m->partition_lba = start_lba;
        if (fat32_parse_boot(m, m->partition_lba) == 0) {
            kprintf("fat32: found BPB at partition %d start %u on device %d\n", i, start_lba, device_id);
            g_fat = m;
            fat32_driver.driver_data = (void*)g_fat;
            kprintf("FAT32: mounted from device %d (partition %d) - ready for manual mount\n", device_id, i);
            return 0;
        } else {
            kprintf("fat32: no valid BPB at partition %d start %u\n", i, start_lba);
        }
    }
    kfree(m);
    return -1;
}

/* public probe wrapper */
int fat32_probe_and_mount(int device_id) {
    return fat32_mount_from_device(device_id);
}

/* open: handle paths under /fat */
/* forward declarations for helpers implemented later in this file */
static int fat32_find_entry_in_dir(struct fat32_mount *m, uint32_t dir_cluster, const char *name,
                                   uint32_t *out_start_cluster, uint32_t *out_size, int *out_is_dir);
static int fat32_resolve_parent_cluster(struct fat32_mount *m, const char *path, uint32_t *out_parent_cluster, char *out_basename, size_t blen);

static int fat32_open(const char *path, struct fs_file **out_file) {
    kprintf("fat32: open called for path='%s'\n", path ? path : "(null)");
    if (!g_fat) return -1;
    if (!path || path[0] != '/') return -1;
    /* Determine mount prefix so driver can be mounted at arbitrary path (e.g., /mnt/c) */
    char mount_prefix[128];
    if (fs_get_matching_mount_prefix(path, mount_prefix, sizeof(mount_prefix)) != 0) {
        /* fallback: treat whole path as under mount */
        mount_prefix[0] = '\0';
    }
    size_t mp_len = strlen(mount_prefix);
    kprintf("fat32: mount_prefix='%s' mp_len=%u\n", mount_prefix, (unsigned)mp_len);
    const char *name = path;
    if (mp_len > 0) {
        if (strncmp(path, mount_prefix, mp_len) == 0) {
            name = path + mp_len;
        } else {
            kprintf("fat32: path '%s' does not start with mount_prefix '%s'\n", path, mount_prefix);
            return -1;
        }
    }
    if (*name == '\0' || strcmp(name, "/") == 0) {
        /* open root directory */
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(*f));
        if (!f) return -1;
        memset(f,0,sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        memcpy(pp, path, plen);
        f->path = pp;
        f->size = 0;
        f->fs_private = &fat32_driver;
        f->type = FS_TYPE_DIR;
        f->driver_private = NULL;
        *out_file = f;
        return 0;
    }
    /* Support nested paths: resolve parent directory cluster and search there for the entry */
    /* Skip leading '/' */
    if (name[0] == '/') name++;
    char tmp[512];
    size_t nl = strlen(name);
    if (nl >= sizeof(tmp)) return -1;
    memcpy(tmp, name, nl+1);
    /* strip trailing '/' if any */
    if (nl > 1 && tmp[nl-1] == '/') tmp[nl-1] = '\0';
    /* resolve parent cluster and basename */
    char basename[256];
    uint32_t parent_cluster = g_fat->root_cluster;
    if (fat32_resolve_parent_cluster(g_fat, name, &parent_cluster, basename, sizeof(basename)) != 0) {
        /* If resolve failed but name may be single component, use name as basename */
        /* Try single-component fallback */
        if (strlen(name) >= sizeof(basename)) return -1;
        strcpy(basename, name[0] == '/' ? name+1 : name);
        parent_cluster = g_fat->root_cluster;
    }
    /* search basename in parent_cluster */
    uint32_t found_start = 0;
    uint32_t found_size = 0;
    int found_is_dir = 0;
    if (fat32_find_entry_in_dir(g_fat, parent_cluster, basename, &found_start, &found_size, &found_is_dir) == 0) {
        struct fs_file *f = (struct fs_file*)kmalloc(sizeof(*f));
        if (!f) return -1;
        memset(f,0,sizeof(*f));
        size_t plen = strlen(path) + 1;
        char *pp = (char*)kmalloc(plen);
        if (!pp) { kfree(f); return -1; }
        memcpy(pp, path, plen);
        f->path = pp;
        f->size = found_size;
        f->fs_private = &fat32_driver;
        f->type = found_is_dir ? FS_TYPE_DIR : FS_TYPE_REG;
        struct fat32_file_handle *fh = (struct fat32_file_handle*)kmalloc(sizeof(*fh));
        if (!fh) { kfree((void*)f->path); kfree(f); return -1; }
        memset(fh,0,sizeof(*fh));
        fh->m = g_fat;
        fh->start_cluster = found_start;
        fh->size = found_size;
        fh->cur_cluster = found_start;
        f->driver_private = fh;
        *out_file = f;
        return 0;
    }
    return -1;
}

static ssize_t fat32_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    kprintf("fat32: read called path='%s' size=%u off=%u\n", file && file->path ? file->path : "(null)", (unsigned)size, (unsigned)offset);
    if (!file) return -1;
    struct fat32_file_handle *fh = NULL;
    if (file->driver_private) fh = (struct fat32_file_handle*)file->driver_private;
    struct fat32_mount *m = fh ? fh->m : g_fat;
    if (!m) return -1;
    /* If regular file, read clusters */
    if (file->type != FS_TYPE_DIR) {
        if (!fh) return -1;
        /* invalid/empty start cluster -> treat as empty file */
        if (fh->start_cluster < 2 || fh->size == 0) return 0;
        if ((size_t)offset >= fh->size) return 0;
        if (offset + size > fh->size) size = fh->size - offset;
        uint32_t bytes_per_cluster = bytes_per_cluster_512(m);
        if (bytes_per_cluster == 0) return -1;
        uint32_t cluster = fh->start_cluster;
        uint32_t seek_clusters = (uint32_t)(offset / bytes_per_cluster);
        uint32_t off_in_cluster = (uint32_t)(offset % bytes_per_cluster);
        uint32_t c = cluster;
        for (uint32_t i = 0; i < seek_clusters; i++) {
            uint32_t nxt = fat32_read_fat_entry(m, c);
            if (nxt >= 0x0FFFFFF8) { return 0; }
            c = nxt;
        }
        cluster = c;
        uint8_t *tmp = (uint8_t*)kmalloc(bytes_per_cluster);
        if (!tmp) return -1;
        size_t toread = size;
        size_t written = 0;
        while (toread > 0) {
            uint32_t lba = cluster_to_lba(m, cluster);
            if (lba == 0) { kfree(tmp); return -1; }
            if (read_sectors(m->device_id, lba, tmp, m->sectors_per_cluster) != 0) { kfree(tmp); return -1; }
            size_t can = bytes_per_cluster - off_in_cluster;
            size_t now = can < toread ? can : toread;
            memcpy((uint8_t*)buf + written, tmp + off_in_cluster, now);
            written += now;
            toread -= now;
            off_in_cluster = 0;
            if (toread == 0) break;
            uint32_t nxt = fat32_read_fat_entry(m, cluster);
            if (nxt >= 0x0FFFFFF8) break;
            cluster = nxt;
        }
        kfree(tmp);
        return (ssize_t)written;
    }

    /* Directory read: produce ext2_dir_entry stream (must respect offset/EOF). */
    uint32_t cluster = (fh && fh->start_cluster) ? fh->start_cluster : m->root_cluster;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(m);
    uint8_t *tmp = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!tmp) return -1;
    size_t pos = 0;      /* total bytes "virtually" produced so far */
    size_t written = 0;  /* bytes actually copied into buf */
    uint32_t c = cluster;
    while (1) {
        uint32_t lba = cluster_to_lba(m, c);
        if (read_sectors(m->device_id, lba, tmp, m->sectors_per_cluster) != 0) break;
        /* LFN handling: collect LFN entries that precede a short entry.
           LFN entries have attribute 0x0F and a sequence number (1..n), with last entry flagged 0x40.
        */
        /* temp storage for LFN parts as UTF-16LE code units (max 20 parts * 13 u16) */
        uint16_t lfn_u16[20][13];
        int lfn_u16_len[20];
        memset(lfn_u16_len, 0, sizeof(lfn_u16_len));
        memset(lfn_u16, 0, sizeof(lfn_u16));
        int lfn_present = 0;
        int lfn_count = 0;
        uint8_t lfn_ck = 0;
        int lfn_ck_valid = 0;
        for (uint32_t off = 0; off + 32 <= bytes_per_cluster; off += 32) {
            uint8_t first = tmp[off];
            if (first == 0x00) { goto dir_done; } /* end */
            if (first == 0xE5) { lfn_present = 0; lfn_count = 0; continue; } /* deleted */
            uint8_t attr = tmp[off + 11];
            if (attr == 0x0F) {
                /* LFN entry */
                uint8_t seq = tmp[off] & 0x1F;
                if (seq == 0 || seq > 20) { lfn_present = 0; lfn_count = 0; continue; }
                uint8_t ck = tmp[off + 13];
                if (!lfn_ck_valid) { lfn_ck = ck; lfn_ck_valid = 1; }
                else if (lfn_ck != ck) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
                /* extract up to 13 UTF-16LE code units from name1/name2/name3 into lfn_u16[seq-1] */
                int p = 0;
                lfn_u16_len[seq-1] = 0;
                /* name1: offsets 1..10 (5 UTF-16) */
                for (int i = 0; i < 5; i++) {
                    uint16_t ch = *(uint16_t*)(tmp + off + 1 + i*2);
                    if (ch == 0x0000 || ch == 0xFFFF) break;
                    if (p < 13) lfn_u16[seq-1][p++] = ch;
                }
                /* name2: offsets 14..25 (6 UTF-16) */
                for (int i = 0; i < 6; i++) {
                    uint16_t ch = *(uint16_t*)(tmp + off + 14 + i*2);
                    if (ch == 0x0000 || ch == 0xFFFF) break;
                    if (p < 13) lfn_u16[seq-1][p++] = ch;
                }
                /* name3: offsets 28..31 (2 UTF-16) */
                for (int i = 0; i < 2; i++) {
                    uint16_t ch = *(uint16_t*)(tmp + off + 28 + i*2);
                    if (ch == 0x0000 || ch == 0xFFFF) break;
                    if (p < 13) lfn_u16[seq-1][p++] = ch;
                }
                lfn_u16_len[seq-1] = p;
                lfn_present = 1;
                if (tmp[off] & 0x40) {
                    /* last LFN entry indicates total count */
                    lfn_count = seq;
                }
                continue;
            }
            /* short entry: assemble name from LFN if present, otherwise fall back to 8.3 */
            /* dynamically allocate name buffers to avoid fixed-stack overflows.
               Cap to a reasonable upper bound to avoid unbounded allocations. */
            size_t namebuf_cap = 512;
            if (bytes_per_cluster > namebuf_cap) namebuf_cap = bytes_per_cluster;
            if (namebuf_cap > 4096) namebuf_cap = 4096;
            char *namebuf = (char*)kmalloc(namebuf_cap);
            if (!namebuf) { kfree(buf); return -1; }
            if (lfn_present && lfn_count > 0 && lfn_ck_valid) {
                uint8_t short_ck = fat32_lfn_checksum(tmp + off);
                if (short_ck != lfn_ck) {
                    lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
                }
            }
            int pos = 0;
            if (lfn_present && lfn_count > 0) {
                /* assemble from lfn_u16 parts [0 .. lfn_count-1] converting UTF-16LE -> UTF-8 */
                for (int si = 0; si < lfn_count; si++) {
                    if (lfn_u16_len[si] <= 0) continue;
                    char tmputf[128];
                    int conv = utf16le_to_utf8(lfn_u16[si], lfn_u16_len[si], tmputf, (int)sizeof(tmputf));
                    if (conv > 0) {
                        for (int k = 0; k < conv && pos < (int)namebuf_cap - 1; k++) namebuf[pos++] = tmputf[k];
                    }
                }
                namebuf[pos] = '\0';
            } else {
                /* No LFN — fallback to legacy 8.3 (better than hiding files). */
                for (int i = 0; i < 8; i++) {
                    char ch = (char)tmp[off + i];
                    if (ch != ' ' && pos < (int)namebuf_cap - 1) namebuf[pos++] = ch;
                }
                if (tmp[off + 8] != ' ') {
                    if (pos < (int)namebuf_cap - 1) namebuf[pos++] = '.';
                    for (int i = 0; i < 3; i++) {
                        char ch = (char)tmp[off + 8 + i];
                        if (ch != ' ' && pos < (int)namebuf_cap - 1) namebuf[pos++] = ch;
                    }
                }
                namebuf[pos] = '\0';
            }
            size_t namelen = strlen(namebuf);
            size_t rec_len = 8 + namelen;

            /* Apply offset/size slicing over the generated ext2_dir_entry stream */
            if (pos + rec_len <= offset) {
                pos += rec_len;
                lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
                continue;
            }
            if (written >= size) goto dir_done;
            size_t entry_off = 0;
            if (offset > pos) entry_off = offset - pos;
            size_t tmpent_cap = 8 + namebuf_cap;
            uint8_t *tmpent = (uint8_t*)kmalloc(tmpent_cap);
            if (!tmpent) { kfree(namebuf); kfree(buf); return -1; }
            if (rec_len > tmpent_cap) {
                /* name too long for our entry buffer; skip */
                kfree(tmpent);
                pos += rec_len;
                lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
                kfree(namebuf);
                continue;
            }
            struct ext2_dir_entry de;
            de.inode = 1; /* non-zero pseudo-inode so VFS treats entry as present */
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = (tmp[off + 11] & 0x10) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
            /* debug: report directory entry discovered */
            kprintf("fat32: readdir found name='%s' type=%d lba=%u off=%u\n", namebuf, de.file_type, lba, off);
            memcpy(tmpent, &de, 8);
            if (namelen > 0) memcpy(tmpent + 8, namebuf, namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy((uint8_t*)buf + written, tmpent + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
            /* reset LFN state */
            lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
            kfree(tmpent);
            kfree(namebuf);
        }
        uint32_t nxt = fat32_read_fat_entry(m, c);
        if (nxt >= 0x0FFFFFF8 || nxt == 0) break;
        c = nxt;
    }
dir_done:
    kfree(tmp);
    return (ssize_t)written;
}

static void fat32_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

static int fat32_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st) return -1;
    memset(st,0,sizeof(*st));
    st->st_mode = (file->type == FS_TYPE_DIR) ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    st->st_size = (off_t)file->size;
    st->st_nlink = 1;
    return 0;
}

/* Write FAT entry */
static int fat32_write_fat_entry(struct fat32_mount *m, uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 4;
    /* Our block layer uses 512-byte sectors; support only BPB bytes_per_sector==512. */
    uint32_t fat_sector = m->first_fat_sector + (fat_offset / 512u);
    uint32_t ent_offset = fat_offset % 512u;
    uint8_t buf[512];
    if (read_sector(m->device_id, fat_sector, buf) != 0) return -1;
    uint32_t *p = (uint32_t*)(buf + ent_offset);
    *p = (*p & 0xF0000000u) | (value & 0x0FFFFFFFu);
    if (disk_write_sectors(m->device_id, fat_sector, buf, 1) != 0) return -1;
    /* mirror to other FAT copies if present */
    for (uint8_t fi = 1; fi < m->num_fats; fi++) {
        uint32_t s2 = m->first_fat_sector + (uint32_t)fi * m->sectors_per_fat + (fat_offset / 512u);
        if (disk_write_sectors(m->device_id, s2, buf, 1) != 0) return -1;
    }
    return 0;
}

/* find free cluster starting from 2 */
static uint32_t fat32_find_free_cluster(struct fat32_mount *m) {
    uint32_t total_data_sectors = (uint32_t)(m->total_sectors - (m->first_data_sector - m->partition_lba));
    uint32_t total_clusters = total_data_sectors / m->sectors_per_cluster;
    if (total_clusters < 2) return 0;
    for (uint32_t c = 2; c < total_clusters + 2; c++) {
        uint32_t v = fat32_read_fat_entry(m, c);
        if (v == 0) return c;
    }
    return 0;
}

/* allocate n clusters and return first cluster (0 on failure) */
static uint32_t fat32_alloc_clusters(struct fat32_mount *m, uint32_t n) {
    if (n == 0) return 0;
    uint32_t first = 0;
    uint32_t prev = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t freec = fat32_find_free_cluster(m);
        if (freec == 0) {
            /* allocation failure: mark allocated ones as 0 (naive) */
            return 0;
        }
        if (first == 0) first = freec;
        if (prev != 0) {
            if (fat32_write_fat_entry(m, prev, freec) != 0) return 0;
        }
        prev = freec;
        /* mark this cluster as allocated temporarily (EOC) */
        if (fat32_write_fat_entry(m, freec, 0x0FFFFFFF) != 0) return 0;
    }
    return first;
}

/* debug: print hex + ascii for first 'len' bytes of sector starting at lba */
static void fat32_hexdump_sector(int device_id, uint32_t lba, size_t len) {
    size_t want = (len + 511) & ~511;
    uint8_t *buf = (uint8_t*)kmalloc(want);
    if (!buf) return;
    if (read_sectors(device_id, lba, buf, (uint32_t)(want / 512)) != 0) { kfree(buf); return; }
    size_t printed = 0;
    while (printed < len) {
        char line[128];
        int lp = snprintf(line, sizeof(line), "%04x: ", (unsigned int)printed);
        for (int i = 0; i < 16 && printed + i < len; i++) {
            lp += snprintf(line + lp, sizeof(line) - lp, "%02x ", buf[printed + i]);
        }
        lp += snprintf(line + lp, sizeof(line) - lp, " ");
        for (int i = 0; i < 16 && printed + i < len; i++) {
            unsigned char ch = buf[printed + i];
            line[lp++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
        }
        line[lp++] = '\n';
        line[lp] = '\0';
        kprintf("%s", line);
        printed += 16;
    }
    kfree(buf);
}

/* Convert path basename to 11-byte 8.3 name (uppercase, space padded) */
static void fat32_make_shortname(const char *name, uint8_t out[11]) {
    /* simple: split at last '.' */
    memset(out, ' ', 11);
    const char *dot = strrchr(name, '.');
    size_t namelen = dot ? (size_t)(dot - name) : strlen(name);
    size_t extlen = dot ? strlen(dot+1) : 0;
    size_t p = 0;
    for (size_t i = 0; i < namelen && p < 8; i++) {
        char c = name[i];
        if (c >= 'a' && c <= 'z') c = c - 32;
        out[p++] = (uint8_t)c;
    }
    p = 8;
    for (size_t i = 0; i < extlen && i < 3; i++) {
        char c = dot[1 + i];
        if (c >= 'a' && c <= 'z') c = c - 32;
        out[p++] = (uint8_t)c;
    }
}

/* compute checksum for 11-byte short name (FAT spec) */
static uint8_t fat32_shortname_checksum(const uint8_t *name11) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; i++) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + name11[i];
    }
    return sum;
}

/* Convert UTF-8 string to UTF-16LE code units (in-place into uint16_t array).
   Returns number of u16 units written, or -1 on error. Supports surrogate pairs. */
static int utf8_to_utf16le(const char *s, uint16_t *out, size_t outcap) {
    if (!s || !out) return -1;
    size_t oi = 0;
    const unsigned char *p = (const unsigned char*)s;
    while (*p) {
        uint32_t codepoint = 0;
        if (*p < 0x80) { codepoint = *p++; }
        else if ((*p & 0xE0) == 0xC0) {
            if ((p[1] & 0xC0) != 0x80) return -1;
            codepoint = ((*p & 0x1F) << 6) | (p[1] & 0x3F);
            p += 2;
        } else if ((*p & 0xF0) == 0xE0) {
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return -1;
            codepoint = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            p += 3;
        } else if ((*p & 0xF8) == 0xF0) {
            if ((p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return -1;
            codepoint = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            p += 4;
        } else return -1;
        if (codepoint <= 0xFFFF) {
            if (oi + 1 > outcap) return -1;
            out[oi++] = (uint16_t)codepoint;
        } else {
            if (oi + 2 > outcap) return -1;
            codepoint -= 0x10000;
            out[oi++] = (uint16_t)(0xD800 | ((codepoint >> 10) & 0x3FF));
            out[oi++] = (uint16_t)(0xDC00 | (codepoint & 0x3FF));
        }
    }
    return (int)oi;
}

/* Convert UTF-16LE array (in) of length inlen to UTF-8 bytes in out (outcap).
   Returns number of bytes written, or -1 on error. */
static int utf16le_to_utf8(const uint16_t *in, int inlen, char *out, int outcap) {
    if (!in || !out) return -1;
    int op = 0;
    for (int i = 0; i < inlen; i++) {
        uint32_t code = (uint32_t)in[i];
        if (code == 0xFFFF || code == 0x0000) break;
        /* handle surrogate pairs */
        if (code >= 0xD800 && code <= 0xDBFF) {
            if (i + 1 >= inlen) return -1;
            uint32_t low = (uint32_t)in[i+1];
            if (low < 0xDC00 || low > 0xDFFF) return -1;
            code = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
            i++;
        }
        if (code <= 0x7F) {
            if (op + 1 >= outcap) return -1;
            out[op++] = (char)code;
        } else if (code <= 0x7FF) {
            if (op + 2 >= outcap) return -1;
            out[op++] = (char)(0xC0 | ((code >> 6) & 0x1F));
            out[op++] = (char)(0x80 | (code & 0x3F));
        } else if (code <= 0xFFFF) {
            if (op + 3 >= outcap) return -1;
            out[op++] = (char)(0xE0 | ((code >> 12) & 0x0F));
            out[op++] = (char)(0x80 | ((code >> 6) & 0x3F));
            out[op++] = (char)(0x80 | (code & 0x3F));
        } else {
            if (op + 4 >= outcap) return -1;
            out[op++] = (char)(0xF0 | ((code >> 18) & 0x07));
            out[op++] = (char)(0x80 | ((code >> 12) & 0x3F));
            out[op++] = (char)(0x80 | ((code >> 6) & 0x3F));
            out[op++] = (char)(0x80 | (code & 0x3F));
        }
    }
    if (op >= outcap) return -1;
    out[op] = '\0';
    return op;
}

/* write LFN entries into directory buffer at offset 'off' using UTF-16LE array u16[] len 'ulen'.
   seq_count = number of LFN entries (ceiling(ulen/13)). short_checksum is checksum for 11-byte short name.
*/
static void fat32_write_lfn_entries_to_buf(uint8_t *dirbuf, uint32_t off, const uint16_t *u16, int ulen, int seq_count, uint8_t short_checksum) {
    /* write entries so that the entry nearest to the short entry contains seq == seq_count (last) */
    for (int i = 0; i < seq_count; i++) {
        /* place part i at entry index (seq_count - 1 - i) so that entry with seq==seq_count ends up just before short entry */
        int entry_index = seq_count - 1 - i;
        uint32_t entry_off = off + (uint32_t)entry_index * 32;
        /* zero the entry (clear to 0) */
        for (int k = 0; k < 32; k++) dirbuf[entry_off + k] = 0x00;
        int part_index = i; /* which part this entry contains (0..seq_count-1) */
        uint8_t seqnum = (uint8_t)(part_index + 1);
        if (part_index + 1 == seq_count) seqnum |= 0x40; /* last LFN entry flag on highest-seq */
        dirbuf[entry_off + 0] = seqnum;
        /* fill name1 (5 u16) */
        for (int j = 0; j < 5; j++) {
            int idx = part_index * 13 + j;
            uint16_t val;
            if (idx < ulen) val = u16[idx];
            else if (idx == ulen) val = 0x0000;
            else val = 0xFFFF;
            memcpy(dirbuf + entry_off + 1 + j*2, &val, 2);
        }
        dirbuf[entry_off + 11] = 0x0F;
        dirbuf[entry_off + 12] = 0;
        dirbuf[entry_off + 13] = short_checksum;
        /* ensure cluster fields in LFN entry are zero */
        dirbuf[entry_off + 20] = dirbuf[entry_off + 21] = 0;
        dirbuf[entry_off + 26] = dirbuf[entry_off + 27] = 0;
        /* name2 (6 u16) */
        for (int j = 0; j < 6; j++) {
            int idx = part_index * 13 + 5 + j;
            uint16_t val;
            if (idx < ulen) val = u16[idx];
            else if (idx == ulen) val = 0x0000;
            else val = 0xFFFF;
            memcpy(dirbuf + entry_off + 14 + j*2, &val, 2);
        }
        /* name3 (2 u16) */
        for (int j = 0; j < 2; j++) {
            int idx = part_index * 13 + 11 + j;
            uint16_t val;
            if (idx < ulen) val = u16[idx];
            else if (idx == ulen) val = 0x0000;
            else val = 0xFFFF;
            memcpy(dirbuf + entry_off + 28 + j*2, &val, 2);
        }
    }
}

/* Find a directory entry with given name inside directory starting at dir_cluster.
   Returns 0 on success and fills out_start_cluster/out_size/out_is_dir, -1 if not found or error. */
static int fat32_find_entry_in_dir(struct fat32_mount *m, uint32_t dir_cluster, const char *name,
                                   uint32_t *out_start_cluster, uint32_t *out_size, int *out_is_dir) {
    if (!m || !name) return -1;
    uint32_t cluster = dir_cluster;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(m);
    uint8_t *buf = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!buf) return -1;
    /* prepare lowercase target */
    char target[512];
    size_t tn = strlen(name);
    if (tn >= sizeof(target)) { kfree(buf); return -1; }
    for (size_t i = 0; i < tn; i++) target[i] = (char)((name[i] >= 'A' && name[i] <= 'Z') ? (name[i] + 32) : name[i]);
    target[tn] = '\0';

    while (1) {
        uint32_t lba = cluster_to_lba(m, cluster);
        if (read_sectors(m->device_id, lba, buf, m->sectors_per_cluster) != 0) break;
        uint16_t lfn_u16[20][13];
        int lfn_u16_len[20];
        memset(lfn_u16_len, 0, sizeof(lfn_u16_len));
        memset(lfn_u16, 0, sizeof(lfn_u16));
        int lfn_present = 0, lfn_count = 0;
        uint8_t lfn_ck = 0;
        int lfn_ck_valid = 0;
        for (uint32_t off = 0; off + 32 <= bytes_per_cluster; off += 32) {
            uint8_t first = buf[off];
            if (first == 0x00) { kfree(buf); return -1; }
            if (first == 0xE5) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
            uint8_t attr = buf[off + 11];
            if (attr == 0x0F) {
                uint8_t seq = buf[off] & 0x1F;
                if (seq == 0 || seq > 20) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
                /* checksum must be consistent across this LFN sequence */
                uint8_t ck = buf[off + 13];
                if (!lfn_ck_valid) { lfn_ck = ck; lfn_ck_valid = 1; }
                else if (lfn_ck != ck) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
                int p = 0;
                lfn_u16_len[seq-1] = 0;
                for (int i = 0; i < 5; i++) { uint16_t ch = *(uint16_t*)(buf + off + 1 + i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++] = ch; }
                for (int i = 0; i < 6; i++) { uint16_t ch = *(uint16_t*)(buf + off + 14 + i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++] = ch; }
                for (int i = 0; i < 2; i++) { uint16_t ch = *(uint16_t*)(buf + off + 28 + i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++] = ch; }
                lfn_u16_len[seq-1] = p;
                lfn_present = 1;
                if (buf[off] & 0x40) lfn_count = (int)(buf[off] & 0x1F);
                continue;
            }
            /* assemble name into dynamically allocated buffer to avoid stack overflow */
            size_t namebuf_cap = 512;
            if (bytes_per_cluster > namebuf_cap) namebuf_cap = bytes_per_cluster;
            if (namebuf_cap > 4096) namebuf_cap = 4096;
            char *namebuf = (char*)kmalloc(namebuf_cap);
            if (!namebuf) { kfree(buf); return -1; }
            if (lfn_present && lfn_count > 0 && lfn_ck_valid) {
                uint8_t short_ck = fat32_lfn_checksum(buf + off);
                if (short_ck != lfn_ck) {
                    lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
                }
            }
            int pos = 0;
            if (lfn_present && lfn_count > 0) {
                /* IMPORTANT: seq=1 is the last part of name; build from highest seq down to 1. */
                for (int si = 0; si < lfn_count; si++) {
                    if (lfn_u16_len[si] <= 0) continue;
                    char tmputf[128];
                    int conv = utf16le_to_utf8(lfn_u16[si], lfn_u16_len[si], tmputf, sizeof(tmputf));
                    if (conv > 0) {
                        for (int k = 0; k < conv && pos < (int)namebuf_cap - 1; k++) namebuf[pos++] = tmputf[k];
                    }
                }
                namebuf[pos] = '\0';
            } else {
                for (int i = 0; i < 8 && pos < (int)namebuf_cap - 1; i++) {
                    char ch = buf[off + i];
                    if (ch != ' ') namebuf[pos++] = (char)((ch >= 'a' && ch <= 'z') ? ch - 32 : ch);
                }
                if (buf[off + 8] != ' ' && pos < (int)namebuf_cap - 1) {
                    namebuf[pos++] = '.';
                    for (int i = 0; i < 3 && pos < (int)namebuf_cap - 1; i++) {
                        char ch = buf[off + 8 + i];
                        if (ch != ' ') namebuf[pos++] = (char)((ch >= 'a' && ch <= 'z') ? ch - 32 : ch);
                    }
                }
                namebuf[pos] = '\0';
            }
            /* lowercase for compare */
            size_t lower_cap = namebuf_cap;
            char *lower_namebuf = (char*)kmalloc(lower_cap);
            if (!lower_namebuf) { kfree(namebuf); kfree(buf); return -1; }
            size_t nb_len = strlen(namebuf);
            if (nb_len >= lower_cap) nb_len = lower_cap - 1;
            for (size_t i = 0; i < nb_len; i++) {
                char c = namebuf[i];
                lower_namebuf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
            }
            lower_namebuf[nb_len] = '\0';
            if (strcmp(lower_namebuf, target) == 0) {
                uint16_t high = *(uint16_t*)(buf + off + 20);
                uint16_t low = *(uint16_t*)(buf + off + 26);
                uint32_t start_cluster = ((uint32_t)high << 16) | (uint32_t)low;
                uint32_t size = *(uint32_t*)(buf + off + 28);
                int is_dir = (buf[off + 11] & 0x10) ? 1 : 0;
                /* Basic sanity: regular files/dirs should not have start_cluster < 2 unless empty. */
                if (start_cluster < 2 && size != 0) { kfree(lower_namebuf); kfree(namebuf); kfree(buf); return -1; }
                if (out_start_cluster) *out_start_cluster = start_cluster;
                if (out_size) *out_size = size;
                if (out_is_dir) *out_is_dir = is_dir;
                kfree(lower_namebuf);
                kfree(namebuf);
                kfree(buf);
                return 0;
            }
            kfree(lower_namebuf);
            kfree(namebuf);
            lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
        }
        uint32_t nxt = fat32_read_fat_entry(m, cluster);
        if (nxt >= 0x0FFFFFF8 || nxt == 0) break;
        cluster = nxt;
    }
    kfree(buf);
    return -1;
}

/* Resolve parent directory cluster and basename for given path under mount.
   path should be relative to mount (leading '/' optional). Returns 0 on success. */
static int fat32_resolve_parent_cluster(struct fat32_mount *m, const char *path, uint32_t *out_parent_cluster, char *out_basename, size_t blen) {
    if (!m || !path || !out_parent_cluster || !out_basename) return -1;
    char tmp[512];
    size_t plen = strlen(path);
    if (plen >= sizeof(tmp)) return -1;
    memcpy(tmp, path, plen+1);
    /* strip leading '/' */
    if (tmp[0] == '/') memmove(tmp, tmp+1, strlen(tmp));
    /* strip trailing slash */
    size_t tl = strlen(tmp);
    if (tl > 0 && tmp[tl-1] == '/') tmp[tl-1] = '\0';
    /* if empty -> parent is root and basename empty */
    if (tmp[0] == '\0') return -1;
    /* find last component */
    char *last = strrchr(tmp, '/');
    uint32_t parent = m->root_cluster;
    if (last) {
        *last = '\0';
        char *tok = strtok(tmp, "/");
        while (tok) {
            uint32_t found_start = 0;
            uint32_t found_size = 0;
            int found_is_dir = 0;
            if (fat32_find_entry_in_dir(m, parent, tok, &found_start, &found_size, &found_is_dir) != 0) return -1;
            if (!found_is_dir) return -1;
            parent = found_start;
            tok = strtok(NULL, "/");
        }
        char *bn = last + 1;
        if (strlen(bn) >= blen) return -1;
        strcpy(out_basename, bn);
    } else {
        /* single-component path under mount */
        if (strlen(tmp) >= blen) return -1;
        strcpy(out_basename, tmp);
        parent = m->root_cluster;
    }
    *out_parent_cluster = parent;
    return 0;
}

/* Check whether a name (UTF-8 ASCII) exists in root directory (LFN-aware, case-insensitive) */
static int fat32_name_exists(const char *name) {
    if (!g_fat || !name) return 0;
    uint32_t cluster = g_fat->root_cluster;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(g_fat);
    uint8_t *buf = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!buf) return 0;
    char target[512];
    size_t tn = strlen(name);
    for (size_t i=0;i<tn;i++) target[i] = (char)((name[i]>='a'&&name[i]<='z') ? (name[i]-32) : name[i]);
    target[tn] = '\0';
    while (1) {
        uint32_t lba = cluster_to_lba(g_fat, cluster);
        if (read_sectors(g_fat->device_id, lba, buf, g_fat->sectors_per_cluster) != 0) break;
        uint16_t lfn_u16[20][13];
        int lfn_u16_len[20];
        memset(lfn_u16_len, 0, sizeof(lfn_u16_len));
        memset(lfn_u16, 0, sizeof(lfn_u16));
        int lfn_present = 0, lfn_count = 0;
        uint8_t lfn_ck = 0;
        int lfn_ck_valid = 0;
        for (uint32_t off=0; off + 32 <= bytes_per_cluster; off += 32) {
            uint8_t first = buf[off];
            if (first == 0x00) { kfree(buf); return 0; }
            if (first == 0xE5) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
            uint8_t attr = buf[off + 11];
            if (attr == 0x0F) {
                uint8_t seq = buf[off] & 0x1F;
                if (seq == 0 || seq > 20) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
                uint8_t ck = buf[off + 13];
                if (!lfn_ck_valid) { lfn_ck = ck; lfn_ck_valid = 1; }
                else if (lfn_ck != ck) { lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0; continue; }
                int p=0;
                lfn_u16_len[seq-1] = 0;
                for (int i=0;i<5;i++){ uint16_t ch = *(uint16_t*)(buf+off+1+i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++]=ch; }
                for (int i=0;i<6;i++){ uint16_t ch = *(uint16_t*)(buf+off+14+i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++]=ch; }
                for (int i=0;i<2;i++){ uint16_t ch = *(uint16_t*)(buf+off+28+i*2); if (ch==0x0000||ch==0xFFFF) break; if (p<13) lfn_u16[seq-1][p++]=ch; }
                lfn_u16_len[seq-1] = p;
                lfn_present = 1;
                if (buf[off] & 0x40) lfn_count = (int)(buf[off] & 0x1F);
                continue;
            }
            /* short entry */
            char namebuf[512];
            if (lfn_present && lfn_count>0 && lfn_ck_valid) {
                uint8_t short_ck = fat32_lfn_checksum(buf + off);
                if (short_ck != lfn_ck) {
                    lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
                }
            }
            if (lfn_present && lfn_count>0) {
                int pos=0;
                for (int si=0; si<lfn_count; si++) {
                    if (lfn_u16_len[si] <= 0) continue;
                    char tmputf[64];
                    int conv = utf16le_to_utf8(lfn_u16[si], lfn_u16_len[si], tmputf, sizeof(tmputf));
                    if (conv > 0) {
                        for (int k=0;k<conv && pos < (int)sizeof(namebuf)-1;k++) namebuf[pos++]=tmputf[k];
                    }
                }
                namebuf[pos]=0;
            } else {
                int p2=0;
                for (int i=0;i<8;i++){ char ch = buf[off+i]; if (ch!=' ') namebuf[p2++]= (char)((ch>='a'&&ch<='z')?ch-32:ch); }
                if (buf[off+8] != ' ') { namebuf[p2++]='.'; for (int i=0;i<3;i++){ char ch=buf[off+8+i]; if (ch!=' ') namebuf[p2++]=(char)((ch>='a'&&ch<='z')?ch-32:ch); } }
                namebuf[p2]=0;
            }
            /* compare case-insensitive */
            if (strcmp(namebuf, target) == 0) { kfree(buf); return 1; }
            lfn_present = 0; lfn_count = 0; lfn_ck_valid = 0;
        }
        uint32_t nxt = fat32_read_fat_entry(g_fat, cluster);
        if (nxt >= 0x0FFFFFF8 || nxt == 0) break;
        cluster = nxt;
    }
    kfree(buf);
    return 0;
}
/* create file in root directory (short name only) */
static int fat32_create(const char *path, struct fs_file **out_file) {
    if (!g_fat) return -1;
    if (!path || path[0] != '/') return -1;
    /* Resolve parent directory and basename (path is absolute under mount) */
    char mount_prefix[128];
    if (fs_get_matching_mount_prefix(path, mount_prefix, sizeof(mount_prefix)) != 0) mount_prefix[0] = '\0';
    const char *name = path;
    if (mount_prefix[0] != '\0') {
        size_t mp_len = strlen(mount_prefix);
        if (strncmp(path, mount_prefix, mp_len) == 0) name = path + mp_len;
        else return -1;
    }
    char basename_raw[256];
    uint32_t parent_cluster = g_fat->root_cluster;
    if (fat32_resolve_parent_cluster(g_fat, name, &parent_cluster, basename_raw, sizeof(basename_raw)) != 0) {
        /* support creating directly under root if resolve failed */
        const char *p = strrchr(name, '/');
        const char *b = p ? p+1 : (name[0] == '/' ? name+1 : name);
        if (!b || !*b) return -1;
        if (strlen(b) >= sizeof(basename_raw)) return -1;
        strcpy(basename_raw, b);
        parent_cluster = g_fat->root_cluster;
    }
    /* Normalize basename: strip surrounding quotes if present */
    char cleanname[256];
    size_t bl_in = strlen(basename_raw);
    if (bl_in >= sizeof(cleanname)) bl_in = sizeof(cleanname) - 1;
    memcpy(cleanname, basename_raw, bl_in);
    cleanname[bl_in] = '\0';
    strip_matching_quotes_local(cleanname);
    /* Prevent duplicate filename in parent directory */
    uint32_t tmp_start = 0, tmp_size = 0; int tmp_is_dir = 0;
    if (fat32_find_entry_in_dir(g_fat, parent_cluster, cleanname, &tmp_start, &tmp_size, &tmp_is_dir) == 0) {
        kprintf("fat32: create failed: name exists %s\n", cleanname);
        return -1;
    }
    uint32_t cluster = parent_cluster;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(g_fat);
    uint8_t *buf = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!buf) return -1;
    uint8_t shortname[11];
    fat32_make_shortname(cleanname, shortname);
    kprintf("fat32: creating %s in dir cluster %u\n", cleanname, cluster);
    /* Always use LFN (no 8.3 support). Compute LFN entries needed (13 u16 per entry). */
    size_t bl = strlen(cleanname);
    int need_lfn = 1;
    int lfn_entries = (int)((bl + 12) / 13);

    /* Search for a sequence of free directory slots of length lfn_entries+1 (LFN entries + short entry) */
    while (1) {
        uint32_t lba = cluster_to_lba(g_fat, cluster);
        if (read_sectors(g_fat->device_id, lba, buf, g_fat->sectors_per_cluster) != 0) { kfree(buf); return -1; }
        uint32_t contiguous = 0;
        uint32_t found_off = 0;
        for (uint32_t off = 0; off + 32 <= bytes_per_cluster; off += 32) {
            uint8_t first = buf[off];
            if (first == 0x00 || first == 0xE5) {
                if (contiguous == 0) found_off = off;
                contiguous++;
                if ((int)contiguous >= lfn_entries + 1) break;
            } else {
                contiguous = 0;
            }
        }
        if ((int)contiguous >= lfn_entries + 1) {
            /* We have space at found_off for LFN entries (if any) followed by short entry */
            /* If LFN required, construct and write LFN entries in reverse order */
            if (need_lfn && lfn_entries > 0) {
                /* compute checksum for short name */
                uint8_t chk = fat32_shortname_checksum(shortname);
                /* convert UTF-8 basename to UTF-16LE units */
                int ucap = (int)(bl + 4); /* rough cap */
                uint16_t *u16 = (uint16_t*)kmalloc(sizeof(uint16_t) * ucap);
                if (!u16) { kfree(buf); return -1; }
                int ulen = utf8_to_utf16le(cleanname, u16, (size_t)ucap);
                if (ulen < 0) { kfree(u16); kfree(buf); return -1; }
                /* write LFN entries to buffer (they will be written to disk together with short entry) */
                fat32_write_lfn_entries_to_buf(buf, found_off, u16, ulen, lfn_entries, chk);
                kfree(u16);
            }
            /* write short entry after LFN entries (or at found_off if no LFN) */
            uint32_t short_off = found_off + lfn_entries * 32;
            memcpy(buf + short_off, shortname, 11);
            buf[short_off + 11] = 0x20; /* archive */
            memset(buf + short_off + 20, 0, 2);
            memset(buf + short_off + 26, 0, 2);
            memset(buf + short_off + 28, 0, 4);
            if (disk_write_sectors(g_fat->device_id, lba, buf, g_fat->sectors_per_cluster) != 0) { kfree(buf); kprintf("fat32: write failed when creating\n"); return -1; }
            /* build fs_file as before */
            struct fs_file *f = (struct fs_file*)kmalloc(sizeof(*f));
            if (!f) { kfree(buf); return -1; }
            memset(f,0,sizeof(*f));
            size_t plen = strlen(path) + 1;
            char *pp = (char*)kmalloc(plen);
            memcpy(pp, path, plen);
            f->path = pp;
            f->size = 0;
                f->fs_private = &fat32_driver;
            f->type = FS_TYPE_REG;
            struct fat32_file_handle *fh = (struct fat32_file_handle*)kmalloc(sizeof(*fh));
            memset(fh,0,sizeof(*fh));
            fh->m = g_fat;
            fh->start_cluster = 0;
            fh->size = 0;
            f->driver_private = fh;
            *out_file = f;
            kfree(buf);
            kprintf("fat32: created file %s (dir lba %u)\n", cleanname, lba);
            /* debug dump of directory sector */
            fat32_hexdump_sector(g_fat->device_id, lba, 256);
            return 0;
        }
        uint32_t next = fat32_read_fat_entry(g_fat, cluster);
        if (next >= 0x0FFFFFF8 || next == 0) break;
        cluster = next;
    }
    kfree(buf);
    return -1;
}

/* create directory in root (shortname only) */
static int fat32_mkdir(const char *path) {
    if (!g_fat) return -1;
    if (!path || path[0] != '/') return -1;
    /* resolve parent cluster and basename */
    char mount_prefix[128];
    if (fs_get_matching_mount_prefix(path, mount_prefix, sizeof(mount_prefix)) != 0) mount_prefix[0] = '\0';
    const char *name = path;
    if (mount_prefix[0] != '\0') {
        size_t mp_len = strlen(mount_prefix);
        if (strncmp(path, mount_prefix, mp_len) == 0) name = path + mp_len;
        else return -1;
    }
    const char *p = strrchr(name, '/');
    const char *basename = p ? p+1 : (name[0] == '/' ? name+1 : name);
    if (!basename || !*basename) return -1;
    /* normalize basename (strip quotes) */
    char cleanname[256];
    size_t bl_in = strlen(basename);
    if (bl_in >= sizeof(cleanname)) bl_in = sizeof(cleanname) - 1;
    memcpy(cleanname, basename, bl_in);
    cleanname[bl_in] = '\0';
    strip_matching_quotes_local(cleanname);
    /* prevent duplicate dir in parent */
    uint32_t parent_cluster = g_fat->root_cluster;
    char basename_raw[256];
    if (fat32_resolve_parent_cluster(g_fat, name, &parent_cluster, basename_raw, sizeof(basename_raw)) != 0) {
        /* fallback: treat as under root */
        parent_cluster = g_fat->root_cluster;
    }
    uint32_t tmp_start = 0, tmp_size = 0; int tmp_is_dir = 0;
    if (fat32_find_entry_in_dir(g_fat, parent_cluster, cleanname, &tmp_start, &tmp_size, &tmp_is_dir) == 0) return -1;
    /* Always create LFN for directories; shortname placeholder will be written but ignored. */
    uint8_t shortname[11];
    fat32_make_shortname(cleanname, shortname);
    size_t bl = strlen(cleanname);
    int lfn_entries = (int)((bl + 12) / 13);
    uint32_t cluster = parent_cluster;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(g_fat);
    uint8_t *buf = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!buf) return -1;
    while (1) {
        uint32_t lba = cluster_to_lba(g_fat, cluster);
        if (read_sectors(g_fat->device_id, lba, buf, g_fat->sectors_per_cluster) != 0) { kfree(buf); return -1; }
        for (uint32_t off = 0; off + 32 <= bytes_per_cluster; off += 32) {
            uint8_t first = buf[off];
            if (first == 0x00 || first == 0xE5) {
                /* allocate one cluster for new dir */
                uint32_t newc = fat32_alloc_clusters(g_fat, 1);
                if (newc == 0) { kfree(buf); return -1; }
                /* prepare LFN and short entry for new directory */
                uint8_t chk = fat32_shortname_checksum(shortname);
                /* convert name to UTF-16LE */
                uint16_t *u16 = (uint16_t*)kmalloc(sizeof(uint16_t) * (bl + 4));
                if (!u16) { kfree(buf); return -1; }
                int ulen = utf8_to_utf16le(basename, u16, bl + 4);
                if (ulen < 0) { kfree(u16); kfree(buf); return -1; }
                fat32_write_lfn_entries_to_buf(buf, off, u16, ulen, lfn_entries, chk);
                kfree(u16);
                /* short entry (placeholder) */
                uint32_t short_off = off + lfn_entries * 32;
                memcpy(buf + short_off, shortname, 11);
                buf[short_off + 11] = 0x10; /* directory attribute */
                uint16_t high = (uint16_t)((newc >> 16) & 0xFFFF);
                uint16_t low = (uint16_t)(newc & 0xFFFF);
                memcpy(buf + short_off + 20, &high, 2);
                memcpy(buf + short_off + 26, &low, 2);
                memset(buf + short_off + 28, 0, 4); /* size 0 */
                if (disk_write_sectors(g_fat->device_id, lba, buf, g_fat->sectors_per_cluster) != 0) { kfree(buf); return -1; }
                /* initialize new directory cluster with . and .. entries */
                uint8_t *clbuf = (uint8_t*)kmalloc(bytes_per_cluster);
                if (!clbuf) { kfree(buf); return -1; }
                memset(clbuf, 0, bytes_per_cluster);
                /* . entry */
                clbuf[0] = '.';
                for (int i=1;i<11;i++) clbuf[i] = ' ';
                clbuf[11] = 0x10;
                uint16_t new_high = (uint16_t)((newc >> 16) & 0xFFFF);
                uint16_t new_low = (uint16_t)(newc & 0xFFFF);
                memcpy(clbuf + 20, &new_high, 2);
                memcpy(clbuf + 26, &new_low, 2);
                /* .. entry */
                clbuf[32] = '.';
                clbuf[33] = '.';
                for (int i=34;i<44;i++) clbuf[i] = ' ';
                clbuf[44] = 0x10;
                uint16_t parent_high = (uint16_t)((parent_cluster >> 16) & 0xFFFF);
                uint16_t parent_low = (uint16_t)(parent_cluster & 0xFFFF);
                memcpy(clbuf + 52, &parent_high, 2);
                memcpy(clbuf + 58, &parent_low, 2);
                if (disk_write_sectors(g_fat->device_id, cluster_to_lba(g_fat, newc), clbuf, g_fat->sectors_per_cluster) != 0) { kfree(clbuf); kfree(buf); return -1; }
                kfree(clbuf);
                kfree(buf);
                return 0;
            }
        }
        uint32_t next = fat32_read_fat_entry(g_fat, cluster);
        if (next >= 0x0FFFFFF8 || next == 0) break;
        cluster = next;
    }
    kfree(buf);
    return -1;
}

/* write data to an open file (supports creating clusters) */
static ssize_t fat32_write(struct fs_file *file, const void *buf_in, size_t size, size_t offset) {
    if (!file || !file->driver_private) return -1;
    struct fat32_file_handle *fh = (struct fat32_file_handle*)file->driver_private;
    struct fat32_mount *m = fh->m;
    uint32_t bytes_per_cluster = bytes_per_cluster_512(m);
    /* calculate clusters needed for (offset+size) */
    uint32_t endpos = (uint32_t)(offset + size);
    uint32_t need_clusters = (endpos + bytes_per_cluster - 1) / bytes_per_cluster;
    /* ensure file has clusters allocated */
    if (fh->start_cluster == 0) {
        uint32_t first = fat32_alloc_clusters(m, need_clusters);
        if (first == 0) return -1;
        fh->start_cluster = first;
    } else {
        /* naive: do not extend existing chain if not enough, for simplicity support only overwrite within allocated size */
        /* Incomplete: scanning current chain length */
    }
    /* write data cluster by cluster */
    uint32_t cluster = fh->start_cluster;
    uint32_t skip_clusters = (uint32_t)(offset / bytes_per_cluster);
    uint32_t off_in_cluster = (uint32_t)(offset % bytes_per_cluster);
    /* advance to start cluster */
    for (uint32_t i=0;i<skip_clusters;i++) {
        uint32_t nxt = fat32_read_fat_entry(m, cluster);
        if (nxt >= 0x0FFFFFF8) { return -1; }
        cluster = nxt;
    }
    uint8_t *tmp = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!tmp) return -1;
    size_t remaining = size;
    size_t written = 0;
    while (remaining > 0) {
        uint32_t lba = cluster_to_lba(m, cluster);
        /* read cluster into tmp */
        if (read_sectors(m->device_id, lba, tmp, m->sectors_per_cluster) != 0) { kfree(tmp); return -1; }
        size_t can = bytes_per_cluster - off_in_cluster;
        size_t now = can < remaining ? can : remaining;
        memcpy(tmp + off_in_cluster, (const uint8_t*)buf_in + written, now);
        /* write back */
        if (disk_write_sectors(m->device_id, lba, tmp, m->sectors_per_cluster) != 0) { kfree(tmp); return -1; }
        written += now;
        remaining -= now;
        off_in_cluster = 0;
        if (remaining == 0) break;
        uint32_t nxt = fat32_read_fat_entry(m, cluster);
        if (nxt >= 0x0FFFFFF8) {
            /* need to allocate one more cluster */
            uint32_t newc = fat32_alloc_clusters(m, 1);
            if (newc == 0) { kfree(tmp); return -1; }
            if (fat32_write_fat_entry(m, cluster, newc) != 0) { kfree(tmp); return -1; }
            cluster = newc;
        } else {
            cluster = nxt;
        }
    }
    kfree(tmp);
    /* update file size in directory entry */
    fh->size = endpos > fh->size ? endpos : fh->size;
    file->size = fh->size;
    /* update directory entry in parent directory */
    /* build shortname from path and resolve parent cluster */
    const char *path = file->path;
    const char *basename = strrchr(path, '/');
    basename = basename ? basename+1 : path;
    /* determine mount-relative name for resolve helper */
    char mount_prefix[128];
    if (fs_get_matching_mount_prefix(path, mount_prefix, sizeof(mount_prefix)) != 0) mount_prefix[0] = '\0';
    const char *name = path;
    if (mount_prefix[0] != '\0') {
        size_t mp_len = strlen(mount_prefix);
        if (strncmp(path, mount_prefix, mp_len) == 0) name = path + mp_len;
    }
    uint32_t parent_cluster = m->root_cluster;
    char basename_raw[256];
    if (fat32_resolve_parent_cluster(m, name, &parent_cluster, basename_raw, sizeof(basename_raw)) != 0) {
        /* fallback to root */
        parent_cluster = m->root_cluster;
    }
    uint8_t sname[11];
    fat32_make_shortname(basename, sname);
    uint32_t c = parent_cluster;
    uint8_t *d = (uint8_t*)kmalloc(bytes_per_cluster);
    if (!d) return (ssize_t)written;
    while (1) {
        uint32_t lba = cluster_to_lba(m, c);
        if (read_sectors(m->device_id, lba, d, m->sectors_per_cluster) != 0) break;
        for (uint32_t off=0; off + 32 <= bytes_per_cluster; off += 32) {
            if (memcmp(d + off, sname, 11) == 0) {
                /* write start cluster high/low and size */
                uint16_t high = (uint16_t)((fh->start_cluster >> 16) & 0xFFFF);
                uint16_t low = (uint16_t)(fh->start_cluster & 0xFFFF);
                memcpy(d + off + 20, &high, 2);
                memcpy(d + off + 26, &low, 2);
                uint32_t sz = fh->size;
                memcpy(d + off + 28, &sz, 4);
                disk_write_sectors(m->device_id, lba, d, m->sectors_per_cluster);
                kfree(d);
                return (ssize_t)written;
            }
        }
        uint32_t nxt = fat32_read_fat_entry(m, c);
        if (nxt >= 0x0FFFFFF8 || nxt == 0) break;
        c = nxt;
    }
    kfree(d);
    return (ssize_t)written;
}

int fat32_register(void) {
    fat32_ops.name = "fat32";
    fat32_ops.create = fat32_create;
    fat32_ops.mkdir = fat32_mkdir;
    fat32_ops.open = fat32_open;
    fat32_ops.read = fat32_read;
    fat32_ops.write = fat32_write;
    fat32_ops.release = fat32_release;
    fat32_ops.chmod = NULL;
    fat32_driver.ops = &fat32_ops;
    fat32_driver.driver_data = NULL;
    kprintf("fat32: registering filesystem driver\n");
    int r = fs_register_driver(&fat32_driver);
    return r;
}

int fat32_unregister(void) {
    return fs_unregister_driver(&fat32_driver);
}

struct fs_driver *fat32_get_driver(void) {
    return &fat32_driver;
}

/* Cleanup mounted FAT state (called on umount) */
void fat32_unmount_cleanup(void) {
    if (!g_fat) return;
    kprintf("fat32: unmount cleanup for device %d\n", g_fat->device_id);
    kfree(g_fat);
    g_fat = NULL;
    fat32_driver.driver_data = NULL;
}


