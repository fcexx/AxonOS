#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fs.h>
#include <procfs.h>
#include <heap.h>
#include <ext2.h>
#include <stat.h>
#include <spinlock.h>
#include <thread.h>
#include <rtc.h>
#include <sysinfo.h>
#include <axonos.h>

struct procfs_handle {
	int kind; /* 1=root, 2=pid_dir, 3=pid_file, 4=symlink, 5=pid_fd_dir, 6=pid_fd_link, 7=plain, 8=proc_sys_dir, 9=proc_sys_file */
	int pid;
	int file_id; /* for pid_file: 0=cmdline, 1=stat; for sys files: ids; for pid_fd_link: fd number */
	size_t pos;
};

static struct fs_driver procfs_driver;
static struct fs_driver_ops procfs_ops;
static spinlock_t procfs_lock = { 0 };

static ssize_t procfs_show_cmdline(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = thread_get(pid);
    if (!t) return 0;
    size_t len = strlen(t->name);
    if (len > size) len = size;
    memcpy(buf, t->name, len);
    if (len < size) buf[len++] = '\n';
    return (ssize_t)len;
}

static ssize_t procfs_show_stat(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = thread_get(pid);
    if (!t) return 0;
    /* Simple key-value style */
    int written = snprintf(buf, size, "pid %d\nname %s\nstate %d\nppid %d\ncwd %s\n",
                           (int)t->tid, t->name, (int)t->state, (int)t->parent_tid, t->cwd);
    if (written < 0) return 0;
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_meminfo(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	/* Provide simple meminfo: MemTotal, MemFree */
	int mb = sysinfo_ram_mb();
	if (mb < 0) mb = 0;
	int written = snprintf(buf, size, "MemTotal: %d kB\nMemFree: %d kB\n", mb * 1024, 0);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

static ssize_t procfs_show_uptime(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	/* uptime in seconds since rtc_ticks / HZ approximation (HZ == 1000 assumed via rtc_ticks ms) */
	double secs = (double)rtc_ticks / 1000.0;
	int written = snprintf(buf, size, "%.2f\n", secs);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* CPU info */
static ssize_t procfs_show_cpuinfo(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	const char *model = sysinfo_cpu_name();
	int written = snprintf(buf, size,
		"processor\t: 0\n"
		"model name\t: %s\n"
		"cpu cores\t: %d\n",
		model ? model : "Unknown", 1);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Simple proc/sys storage: kernel.hostname */
static char proc_hostname[64] = OS_NAME;
static ssize_t procfs_show_hostname(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	size_t len = strlen(proc_hostname);
	if (len > size) len = size;
	memcpy(buf, proc_hostname, len);
	if (len < size) buf[len++] = '\n';
	return (ssize_t)len;
}

static ssize_t procfs_store_hostname(const char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return -1;
	/* copy up to capacity-1 and trim newline */
	size_t copy_len = size;
	if (copy_len >= sizeof(proc_hostname)) copy_len = sizeof(proc_hostname) - 1;
	memcpy(proc_hostname, buf, copy_len);
	proc_hostname[copy_len] = '\0';
	/* trim trailing newline */
	if (copy_len > 0 && proc_hostname[copy_len-1] == '\n') proc_hostname[copy_len-1] = '\0';
	return (ssize_t)size;
}

static ssize_t procfs_write(struct fs_file *file, const void *buf, size_t size, size_t offset) {
	if (!file || !file->driver_private || !buf) return -1;
	struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
	if (!h) return -1;
	/* only support writing to proc/sys/kernel/hostname (kind 9, file_id 20) */
	if (h->kind == 9 && h->file_id == 20) {
		/* permission: only root */
		thread_t *ct = thread_current();
		if (!ct || ct->euid != 0) return -1;
		/* accept whole buffer (ignore offset semantics for simplicity) */
		return procfs_store_hostname((const char*)buf, size, NULL);
	}
	return -1;
}

static int procfs_create(const char *path, struct fs_file **out_file) {
    (void)path; (void)out_file;
    return -1;
}

static int procfs_open(const char *path, struct fs_file **out_file) {
    if (!path || !out_file) return -1;
    if (!(strcmp(path, "/proc") == 0 || strncmp(path, "/proc/", 6) == 0)) return -1;
    int rc = -1;
    struct fs_file *f = NULL;
    char *pp = NULL;
    struct procfs_handle *h = NULL;

    /* allocate fs_file early */
    f = (struct fs_file*)kmalloc(sizeof(struct fs_file));
    if (!f) return -1;
    memset(f, 0, sizeof(*f));
    pp = (char*)kmalloc(strlen(path) + 1);
    if (!pp) { kfree(f); return -1; }
    memcpy(pp, path, strlen(path) + 1);
    f->path = pp;
    f->fs_private = procfs_driver.driver_data;

    /* prepare handle */
    h = (struct procfs_handle*)kmalloc(sizeof(struct procfs_handle));
    if (!h) { kfree(pp); kfree(f); return -1; }
    memset(h, 0, sizeof(*h));

    /* Determine type */
    if (strcmp(path, "/proc") == 0) {
        h->kind = 1; /* root */
        f->type = FS_TYPE_DIR;
        f->size = 0;
    } else {
		/* parse /proc/<id>[/name...] */
		const char *p = path + 6; /* after "/proc/" */
		const char *slash = strchr(p, '/');
		size_t first_len = slash ? (size_t)(slash - p) : strlen(p);
		if (first_len == 0) { kfree(h); kfree(pp); kfree(f); return -1; }
		/* handle 'self' */
		int pid = -1;
		if (first_len == 4 && strncmp(p, "self", 4) == 0) {
			thread_t *ct = thread_current();
			pid = ct ? (int)ct->tid : -1;
		} else {
			/* numeric pid? */
			char tmp[32];
			if (first_len >= sizeof(tmp)) { kfree(h); kfree(pp); kfree(f); return -1; }
			memcpy(tmp, p, first_len); tmp[first_len] = '\0';
			int ok = 1;
			for (size_t i = 0; i < first_len; i++) if (tmp[i] < '0' || tmp[i] > '9') { ok = 0; break; }
			if (ok) pid = atoi(tmp);
		}
		/* special subtree: /proc/sys/... */
		if (first_len == 3 && strncmp(p, "sys", 3) == 0) {
			if (!slash) {
				h->kind = 8; f->type = FS_TYPE_DIR; f->size = 0;
				f->driver_private = h;
				*out_file = f;
				return 0;
			} else {
				/* parse second component */
				const char *q = slash + 1;
				const char *slash2 = strchr(q, '/');
				size_t qlen = slash2 ? (size_t)(slash2 - q) : strlen(q);
				if (qlen == 0) { kfree(h); kfree(pp); kfree(f); return -1; }
				/* only 'kernel' namespace supported */
				if (qlen == 6 && strncmp(q, "kernel", 6) == 0) {
					if (!slash2) {
						/* /proc/sys/kernel */
						h->kind = 8; f->type = FS_TYPE_DIR; f->size = 0;
						f->driver_private = h;
						*out_file = f;
						return 0;
					} else {
						/* /proc/sys/kernel/<name> */
						const char *name = slash2 + 1;
						if (strncmp(name, "hostname", 8) == 0) {
							h->kind = 9; h->file_id = 20; f->type = FS_TYPE_REG;
							/* size = strlen + newline */
							f->size = strlen(proc_hostname) + 1;
							f->driver_private = h;
							*out_file = f;
							return 0;
						}
					}
				}
				kfree(h); kfree(pp); kfree(f); return -1;
			}
		}
		/* if path is exactly /proc/<something> and something is not a pid -> special files like /proc/meminfo or directories like sys/bus */
		if (!slash) {
			/* Could be pid dir or top-level file like meminfo/uptime */
			/* Check for meminfo/uptime */
			if (first_len == 7 && strncmp(p, "meminfo", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				/* size computed later on read */
				h->file_id = 10; /* meminfo */
				*out_file = f;
				return 0;
			}
			if (first_len == 6 && strncmp(p, "uptime", 6) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 11; /* uptime */
				*out_file = f;
				return 0;
			}
			if (first_len == 7 && strncmp(p, "cpuinfo", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 12; /* cpuinfo */
				*out_file = f;
				return 0;
			}
			if (first_len == 3 && strncmp(p, "sys", 3) == 0) {
				/* /proc/sys root directory */
				h->kind = 8; f->type = FS_TYPE_DIR; f->size = 0;
				*out_file = f;
				return 0;
			}
			if (pid < 0) { kfree(h); kfree(pp); kfree(f); return -1; }
			/* pid directory */
			h->kind = 2;
			h->pid = pid;
			f->type = FS_TYPE_DIR;
			f->size = 0;
		} else {
			/* deeper paths: could be /proc/<pid>/cmdline, /proc/<pid>/stat, /proc/<pid>/fd, /proc/<pid>/fd/<n> */
			const char *rest = slash + 1;
			if (pid < 0) { kfree(h); kfree(pp); kfree(f); return -1; }
			/* check for fd directory */
			if (strncmp(rest, "fd", 2) == 0 && (rest[2] == '\0' || rest[2] == '/')) {
				if (rest[2] == '\0') {
					h->kind = 5; h->pid = pid; f->type = FS_TYPE_DIR; f->size = 0;
				} else {
					/* /proc/<pid>/fd/<n> */
					const char *rest2 = rest + 3; /* after 'fd/' */
					if (!rest2) { kfree(h); kfree(pp); kfree(f); return -1; }
					/* parse fd number */
					char tmp[16];
					size_t l = strlen(rest2);
					if (l == 0 || l >= sizeof(tmp)) { kfree(h); kfree(pp); kfree(f); return -1; }
					memcpy(tmp, rest2, l); tmp[l] = '\0';
					int ok = 1;
					for (size_t i = 0; i < l; i++) if (tmp[i] < '0' || tmp[i] > '9') { ok = 0; break; }
					if (!ok) { kfree(h); kfree(pp); kfree(f); return -1; }
					int fdnum = atoi(tmp);
					h->kind = 6; h->pid = pid; h->file_id = fdnum;
					/* represent as symlink */
					f->type = FS_TYPE_REG;
					/* compute symlink size below */
					size_t cap = 512;
					char *tmpbuf = (char*)kmalloc(cap);
					if (tmpbuf) {
						/* build link target */
						thread_t *t = thread_get(pid);
						if (t && fdnum >= 0 && fdnum < THREAD_MAX_FD && t->fds[fdnum]) {
							const char *target = t->fds[fdnum]->path ? t->fds[fdnum]->path : "(anon)";
							size_t tlen = strlen(target);
							if (tlen >= cap) tlen = cap - 1;
							memcpy(tmpbuf, target, tlen);
							f->size = tlen;
						} else {
							const char *not = "(invalid)";
							size_t tlen = strlen(not);
							if (tlen >= cap) tlen = cap - 1;
							memcpy(tmpbuf, not, tlen);
							f->size = tlen;
						}
						kfree(tmpbuf);
					}
				}
			} else {
				/* other pid children: cmdline, stat */
			if (strncmp(rest, "cmdline", 7) == 0) {
					h->kind = 3; h->pid = pid; h->file_id = 0; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "stat", 4) == 0) {
					h->kind = 3; h->pid = pid; h->file_id = 1; f->type = FS_TYPE_REG;
				} else {
					kfree(h); kfree(pp); kfree(f); return -1;
				}
				/* compute size */
				size_t cap = 4096;
				char *tmpbuf = (char*)kmalloc(cap);
				if (tmpbuf) {
					ssize_t full = (h->file_id == 0) ? procfs_show_cmdline(tmpbuf, cap, (void*)(uintptr_t)h->pid)
													 : procfs_show_stat(tmpbuf, cap, (void*)(uintptr_t)h->pid);
					if (full > 0) f->size = (size_t)full;
					kfree(tmpbuf);
				}
			}
		}
    }

    f->driver_private = h;
    *out_file = f;
    return 0;
}

static ssize_t procfs_read(struct fs_file *file, void *buf, size_t size, size_t offset) {
    if (!file || !file->driver_private || !buf) return -1;
    struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
    if (!h) return -1;

    /* directory reading */
    if (h->kind == 1) {
        /* /proc root: list numeric pids as directories */
        /* include some top-level virtual files/directories before PIDs */
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        const char *top[] = { "meminfo", "cpuinfo", "uptime", "sys", "bus", "tty" };
        for (size_t ti = 0; ti < sizeof(top)/sizeof(top[0]); ti++) {
            const char *name = top[ti];
            size_t namelen = strlen(name);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
            uint8_t tmpent[256];
            if (rec_len <= sizeof(tmpent)) {
                for (size_t zi = 0; zi < sizeof(tmpent); zi++) tmpent[zi] = 0;
                struct ext2_dir_entry de;
                de.inode = (uint32_t)(1000 + (uint32_t)ti); /* pseudo inode */
                de.rec_len = (uint16_t)rec_len;
                de.name_len = (uint8_t)namelen;
                /* sys and bus are directories */
                de.file_type = (strcmp(name, "sys") == 0 || strcmp(name, "bus") == 0) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
                memcpy(tmpent, &de, 8);
                memcpy(tmpent + 8, name, namelen);
                size_t avail = size - written;
                size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                if (tocopy > avail) tocopy = avail;
                if (tocopy > 0) memcpy(out + written, tmpent + entry_off, tocopy);
                written += tocopy;
            }
            pos += rec_len;
        }
        int cnt = thread_get_count();
        for (int i = 0; i < cnt; i++) {
            thread_t *t = thread_get_by_index(i);
            if (!t) continue;
            char namebuf[32];
            int nlen = snprintf(namebuf, sizeof(namebuf), "%d", (int)t->tid);
            if (nlen <= 0) continue;
            size_t namelen = (size_t)nlen;
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) { pos += rec_len; continue; }
            struct ext2_dir_entry de;
            /* Ensure non-zero pseudo-inode: some userspace parsers stop at inode==0 */
            de.inode = (uint32_t)((uint32_t)(t->tid + 1) & 0xFFFFFFFFu);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, namebuf, namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

    if (h->kind == 2) {
        /* /proc/<pid> dir: entries cmdline and stat */
        const char *names[2] = { "cmdline", "stat" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        /* if pid has fd dir, include 'fd' as directory entry first */
        thread_t *ttmp = thread_get(h->pid);
        int include_fd = (ttmp != NULL);
        int start_idx = 0;
        if (include_fd) {
            /* add fd entry before others */
            const char *fname = "fd";
            size_t namelen = strlen(fname);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; }
            else {
                if (written < size) {
                    size_t entry_off = 0;
                    if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
                    uint8_t tmpent[512];
                    if (rec_len <= sizeof(tmpent)) {
                        for (size_t zi = 0; zi < sizeof(tmpent); zi++) tmpent[zi] = 0;
                        struct ext2_dir_entry de;
                        de.inode = 2;
                        de.rec_len = (uint16_t)rec_len;
                        de.name_len = (uint8_t)namelen;
                        de.file_type = EXT2_FT_DIR;
                        memcpy(tmpent, &de, 8);
                        memcpy(tmpent + 8, fname, namelen);
                        size_t avail = size - written;
                        size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
                        if (tocopy > avail) tocopy = avail;
                        if (tocopy > 0) memcpy(out + written, tmpent + entry_off, tocopy);
                        written += tocopy;
                    }
                }
            }
            pos += rec_len;
        }
        for (int idx = 0; idx < 2; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = 0;
            if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
            uint8_t tmp[512];
            if (rec_len > sizeof(tmp)) { pos += rec_len; continue; }
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(idx + 1);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_REG_FILE;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
            size_t avail = size - written;
            size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
            if (tocopy > avail) tocopy = avail;
            if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
            written += tocopy;
            pos += rec_len;
        }
        return (ssize_t)written;
    }

	/* /proc/sys directory listing */
	if (h->kind == 8) {
		/* only one namespace 'kernel' for now */
		const char *names[] = { "kernel" };
		size_t pos = 0;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int idx = 0; idx < 1; idx++) {
			size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
			if (written >= size) break;
			size_t entry_off = 0;
			if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
			uint8_t tmp[256];
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(2000 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
            for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
            memcpy(tmp, &de, 8);
            memcpy(tmp + 8, names[idx], namelen);
			size_t avail = size - written;
			size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
			if (tocopy > avail) tocopy = avail;
			if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
			written += tocopy;
			pos += rec_len;
		}
		return (ssize_t)written;
	}

    /* regular file */
    if (h->kind == 3) {
        ssize_t full = 0;
        size_t cap = 4096;
        if (cap < size + offset) cap = size + offset;
        if (cap > 65536) cap = 65536;
        char *tmp = (char*)kmalloc(cap);
        if (!tmp) return -1;
        if (h->file_id == 0) full = procfs_show_cmdline(tmp, cap, (void*)(uintptr_t)h->pid);
        else full = procfs_show_stat(tmp, cap, (void*)(uintptr_t)h->pid);
        if (full < 0) { kfree(tmp); return -1; }
        size_t len = (size_t)full;
        if ((size_t)offset >= len) { kfree(tmp); return 0; }
        size_t to_copy = len - (size_t)offset;
        if (to_copy > size) to_copy = size;
        memcpy(buf, tmp + offset, to_copy);
        kfree(tmp);
        return (ssize_t)to_copy;
    }

	/* pid fd directory listing */
	if (h->kind == 5) {
		thread_t *t = thread_get(h->pid);
		if (!t) return -1;
		size_t pos = 0;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int i = 0; i < THREAD_MAX_FD; i++) {
			char namebuf[16];
			int nlen = snprintf(namebuf, sizeof(namebuf), "%d", i);
			if (nlen <= 0) continue;
			size_t namelen = (size_t)nlen;
			size_t rec_len = 8 + namelen;
			rec_len = (rec_len + 3) & ~3u;
			if (pos + rec_len <= offset) { pos += rec_len; continue; }
			if (written >= size) break;
			size_t entry_off = 0;
			if ((size_t)offset > pos) entry_off = (size_t)offset - pos;
			uint8_t tmp[256];
			if (rec_len > sizeof(tmp)) { pos += rec_len; continue; }
			struct ext2_dir_entry de;
			de.inode = (uint32_t)(i + 1);
			de.rec_len = (uint16_t)rec_len;
			de.name_len = (uint8_t)namelen;
			de.file_type = (t->fds[i] ? EXT2_FT_REG_FILE : EXT2_FT_UNKNOWN);
			for (size_t zi = 0; zi < sizeof(tmp); zi++) tmp[zi] = 0;
			memcpy(tmp, &de, 8);
			memcpy(tmp + 8, namebuf, namelen);
			size_t avail = size - written;
			size_t tocopy = rec_len > entry_off ? rec_len - entry_off : 0;
			if (tocopy > avail) tocopy = avail;
			if (tocopy > 0) memcpy(out + written, tmp + entry_off, tocopy);
			written += tocopy;
			pos += rec_len;
		}
		return (ssize_t)written;
	}

	/* pid fd symlink target */
	if (h->kind == 6) {
		thread_t *t = thread_get(h->pid);
		if (!t) return 0;
		int fdnum = h->file_id;
		const char *target = "(invalid)";
		if (fdnum >= 0 && fdnum < THREAD_MAX_FD && t->fds[fdnum]) {
			if (t->fds[fdnum]->path) target = t->fds[fdnum]->path;
			else target = "(anon)";
		}
		size_t tlen = strlen(target);
		if ((size_t)offset >= tlen) return 0;
		size_t tocopy = tlen - (size_t)offset;
		if (tocopy > size) tocopy = size;
		memcpy(buf, target + offset, tocopy);
		return (ssize_t)tocopy;
	}

	/* top-level files like meminfo/uptime */
	if (h->kind == 7) {
		size_t cap = 4096;
		if (cap < size + offset) cap = size + offset;
		char *tmpbuf = (char*)kmalloc(cap);
		if (!tmpbuf) return -1;
		ssize_t full = 0;
		if (h->file_id == 10) full = procfs_show_meminfo(tmpbuf, cap, NULL);
		else if (h->file_id == 11) full = procfs_show_uptime(tmpbuf, cap, NULL);
		if (full < 0) { kfree(tmpbuf); return -1; }
		size_t len = (size_t)full;
		if ((size_t)offset >= len) { kfree(tmpbuf); return 0; }
		size_t tocopy = len - (size_t)offset;
		if (tocopy > size) tocopy = size;
		memcpy(buf, tmpbuf + offset, tocopy);
		kfree(tmpbuf);
		return (ssize_t)tocopy;
	}

	/* proc/sys files (hostname etc) */
	if (h->kind == 9) {
		/* only hostname supported (file_id == 20) */
		if (h->file_id == 20) {
			size_t tcap = 256;
			if (tcap < size + offset) tcap = size + offset;
			char *tmpbuf = (char*)kmalloc(tcap);
			if (!tmpbuf) return -1;
			ssize_t full = procfs_show_hostname(tmpbuf, tcap, NULL);
			if (full < 0) { kfree(tmpbuf); return -1; }
			size_t len = (size_t)full;
			if ((size_t)offset >= len) { kfree(tmpbuf); return 0; }
			size_t tocopy = len - (size_t)offset;
			if (tocopy > size) tocopy = size;
			memcpy(buf, tmpbuf + offset, tocopy);
			kfree(tmpbuf);
			return (ssize_t)tocopy;
		}
		return -1;
	}

    return -1;
}

static void procfs_release(struct fs_file *file) {
    if (!file) return;
    if (file->driver_private) kfree(file->driver_private);
    if (file->path) kfree((void*)file->path);
    kfree(file);
}

int procfs_fill_stat(struct fs_file *file, struct stat *st) {
    if (!file || !st || !file->driver_private) return -1;
    struct procfs_handle *h = (struct procfs_handle*)file->driver_private;
    if (!h) return -1;
    if (h->kind == 1 || h->kind == 2 || h->kind == 5 || h->kind == 8) {
        st->st_ino = 0;
        st->st_mode = S_IFDIR | 0555;
        st->st_nlink = 2;
    } else if (h->kind == 6) {
        /* fd links are symlinks */
        st->st_ino = 0;
        st->st_mode = S_IFLNK | 0777;
        st->st_nlink = 1;
        st->st_size = (off_t)file->size;
    } else {
        st->st_ino = 0;
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = (off_t)file->size;
    }
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_atime = st->st_mtime = st->st_ctime = (time_t)rtc_ticks;
    return 0;
}

int procfs_register(void) {
    procfs_ops.name = "procfs";
    procfs_ops.create = procfs_create;
    procfs_ops.open = procfs_open;
    procfs_ops.read = procfs_read;
    procfs_ops.write = procfs_write;
    procfs_ops.release = procfs_release;
    procfs_ops.chmod = NULL;
    procfs_driver.ops = &procfs_ops;
    procfs_driver.driver_data = NULL;
    procfs_lock.lock = 0;
    return fs_register_driver(&procfs_driver);
}

int procfs_unregister(void) {
    return fs_unregister_driver(&procfs_driver);
}

int procfs_mount(const char *path) {
    if (!path) return -1;
    return fs_mount(path, &procfs_driver);
}


