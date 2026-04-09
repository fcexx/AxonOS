#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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
#include <smp.h>
#include <usb.h>
#include <scsi.h>
#include <pci.h>
#include <devfs.h>
#include <vga.h>
#include <pit.h>
#include <loadavg.h>

struct procfs_handle {
	int kind; /* 1=root, 2=pid_dir, 3=pid_file, 4=symlink, 5=pid_fd_dir, 6=pid_fd_link, 7=plain, 8=proc_sys_dir, 9=proc_sys_file */
	int pid;
	int file_id; /* pid_file: 0=cmdline,1=stat,2=status,3=statm; sys/plain: ids; pid_fd_link: fd number */
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
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    size_t len = strlen(comm);
    if (len + 1 > size) len = (size > 0) ? (size - 1) : 0;
    memcpy(buf, comm, len);
    if (len < size) buf[len++] = '\0';
    return (ssize_t)len;
}

static char procfs_state_char(const thread_t *t) {
    if (!t) return 'Z';
    switch (t->state) {
        case THREAD_RUNNING:
        case THREAD_READY: return 'R';
        case THREAD_BLOCKED:
        case THREAD_SLEEPING: return 'S';
        case THREAD_TERMINATED: return 'Z';
        default: return 'S';
    }
}

static ssize_t procfs_show_stat(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = thread_get(pid);
    if (!t) return 0;
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    int ppid = (t->parent_tid >= 0) ? t->parent_tid : 0;
    int pgrp = (t->pgid >= 0) ? t->pgid : (int)t->tid;
    int sid = (t->sid >= 0) ? t->sid : pgrp;
    int tty_nr = 0;
    int tpgid = pgrp;
    int prio = 20 + t->nice;
    if (prio < 1) prio = 1;
    if (prio > 39) prio = 39;
    uint64_t now_ticks = timer_ticks;
    uint64_t hz = pit_get_frequency();
    if (hz == 0) hz = 1000;
    uint64_t elapsed_ticks = (now_ticks >= t->start_ticks) ? (now_ticks - t->start_ticks) : 0;
    /* /proc/<pid>/stat expects USER_HZ units (typically 100). */
    uint64_t utime = (elapsed_ticks * 100ull) / hz;
    uint64_t stime = 0;
    uint64_t starttime = (t->start_ticks * 100ull) / hz;
    int written = snprintf(
        buf, size,
        "%d (%s) %c %d %d %d %d %d "
        "%u %llu %llu %llu %llu %llu %llu %lld %lld "
        "%d %d %d %d %llu %llu %d\n",
        (int)t->tid, comm, procfs_state_char(t), ppid, pgrp, sid, tty_nr, tpgid,
        0u,                  /* flags */
        0ull, 0ull, 0ull, 0ull, /* minflt cminflt majflt cmajflt */
        (unsigned long long)utime,
        (unsigned long long)stime,
        0ll, 0ll,            /* cutime cstime */
        prio, t->nice,
        1,                   /* num_threads */
        0,                   /* itrealvalue */
        (unsigned long long)starttime,
        0ull,                /* vsize */
        0                    /* rss */
    );
    if (written < 0) return 0;
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_status(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = thread_get(pid);
    if (!t) return 0;
    char comm[sizeof(t->name)];
    memcpy(comm, t->name, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    int ppid = (t->parent_tid >= 0) ? t->parent_tid : 0;
    int pgrp = (t->pgid >= 0) ? t->pgid : (int)t->tid;
    int sid = (t->sid >= 0) ? t->sid : pgrp;
    int written = snprintf(
        buf, size,
        "Name:\t%s\n"
        "State:\t%c\n"
        "Pid:\t%d\n"
        "PPid:\t%d\n"
        "Uid:\t%u\t%u\t%u\t%u\n"
        "Gid:\t%u\t%u\t%u\t%u\n"
        "Threads:\t1\n"
        "NSpgid:\t%d\n"
        "NSsid:\t%d\n",
        comm, procfs_state_char(t), (int)t->tid, ppid,
        (unsigned)t->uid, (unsigned)t->euid, (unsigned)t->suid, (unsigned)t->euid,
        (unsigned)t->gid, (unsigned)t->egid, (unsigned)t->sgid, (unsigned)t->egid,
        pgrp, sid
    );
    if (written < 0) return 0;
    size_t w = (size_t)written;
    if (w > size) w = size;
    return (ssize_t)w;
}

static ssize_t procfs_show_statm(char *buf, size_t size, void *priv) {
    int pid = (int)(uintptr_t)priv;
    if (!buf || size == 0) return 0;
    thread_t *t = thread_get(pid);
    if (!t) return 0;
    (void)t;
    /* size resident shared text lib data dt (pages) */
    int written = snprintf(buf, size, "0 0 0 0 0 0 0\n");
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

/* Kernel snprintf has no floating-point; use fixed-point text. */
static void procfs_fmt_centiseconds(uint64_t ms_whole, char *out, size_t cap) {
	uint64_t sec = ms_whole / 1000ull;
	unsigned cent = (unsigned)((ms_whole % 1000ull) * 100ull / 1000ull);
	if (cent > 99u) cent = 99u;
	snprintf(out, cap, "%llu.%02u", (unsigned long long)sec, cent);
}

static void procfs_fmt_load_scaled(unsigned long scaled, char *out, size_t cap) {
	unsigned long whole = scaled / 65536ul;
	unsigned long cent = (scaled % 65536ul) * 100ul / 65536ul;
	if (cent > 99ul) cent = 99ul;
	snprintf(out, cap, "%lu.%02lu", whole, cent);
}

static ssize_t procfs_show_uptime(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	uint64_t ms = (uint64_t)pit_get_time_ms();
	char up[32];
	procfs_fmt_centiseconds(ms, up, sizeof(up));
	int written = snprintf(buf, size, "%s 0.00\n", up);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Linux /proc/loadavg — busybox uptime uses this for "load average" */
static ssize_t procfs_show_loadavg(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	unsigned long av[3];
	loadavg_get_user(av);
	char s1[24], s2[24], s3[24];
	procfs_fmt_load_scaled(av[0], s1, sizeof(s1));
	procfs_fmt_load_scaled(av[1], s2, sizeof(s2));
	procfs_fmt_load_scaled(av[2], s3, sizeof(s3));
	int run = thread_runnable_nonidle_count();
	if (run < 0)
		run = 0;
	int nthr = thread_get_count();
	if (nthr < 1)
		nthr = 1;
	int written = snprintf(buf, size, "%s %s %s %d/%d %d\n", s1, s2, s3, run, nthr, nthr);
	if (written < 0) return 0;
	size_t w = (size_t)written;
	if (w > size) w = size;
	return (ssize_t)w;
}

/* Minimal /proc/stat — nproc and some tools count cpu0..cpuN-1 lines */
static ssize_t procfs_show_kernel_stat(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	int n = smp_cpu_count();
	if (n < 1)
		n = 1;
	size_t w = 0;
	w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0,
			      "cpu  0 0 0 0 0 0 0 0 0 0\n");
	for (int i = 0; i < n && w < size; i++) {
		int wr = snprintf(buf + w, (w < size) ? (size - w) : 0,
				  "cpu%d 0 0 0 0 0 0 0 0 0 0\n", i);
		if (wr < 0)
			break;
		w += (size_t)wr;
	}
	w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0,
			      "intr 0\nctxt 0\nbtime 0\nprocesses %d\nprocs_running %d\nprocs_blocked 0\n",
			      thread_get_count(), thread_runnable_nonidle_count());
	if (w > size)
		w = size;
	return (ssize_t)w;
}

static ssize_t procfs_show_partitions(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	/* Linux-like /proc/partitions format (minimal). */
	size_t w = 0;
	w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0, "major minor  #blocks  name\n");
	int n = devfs_block_count();
	for (int i = 0; i < n; i++) {
		char name[64];
		int did = -1;
		uint32_t sectors = 0;
		if (devfs_block_get(i, name, sizeof(name), &did, &sectors) != 0) continue;
		/* Show both SATA-like sdX and legacy IDE-like hdN nodes. */
		int is_sd = (name[0] == 's' && name[1] == 'd');
		int is_hd = (name[0] == 'h' && name[1] == 'd');
		if (!is_sd && !is_hd) continue;
		/* blocks in 1K units like Linux: sectors * 512 / 1024 == sectors/2 */
		uint32_t blocks = sectors / 2;
		/* fake major/minor; enough for userland tools that just parse size+name */
		int major = is_hd ? 3 : 8;
		int minor = did >= 0 ? did * 16 : i * 16;
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
							   "%5d %5d %8u %s\n", major, minor, (unsigned)blocks, name);
		if (written < 0) break;
		w += (size_t)written;
		if (w >= size) { w = size; break; }
	}
	return (ssize_t)w;
}

/* Linux-like /proc/mounts backed by VFS mount table */
static ssize_t procfs_show_mounts(char *buf, size_t size, void *priv) {
    (void)priv;
    if (!buf || size == 0) return 0;
    size_t w = 0;
    int n = fs_mount_count();
    for (int i = 0; i < n; i++) {
        char mpath[64];
        char fstype[32];
        if (fs_mount_get(i, mpath, sizeof(mpath), fstype, sizeof(fstype)) != 0) continue;
        /* source mountpoint fstype options dump pass */
        int wr = snprintf(buf + w, (w < size) ? (size - w) : 0,
                          "%s %s %s rw,relatime 0 0\n",
                          fstype, mpath, fstype);
        if (wr < 0) break;
        w += (size_t)wr;
        if (w >= size) { w = size; break; }
    }
    return (ssize_t)w;
}

/* Linux-like /proc/scsi/scsi: Host, Channel, Id, Lun, Type, Vendor, Model, Rev */
static ssize_t procfs_show_scsi(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	size_t w = 0;
	int n = scsi_lun_count();
	for (int i = 0; i < n; i++) {
		char vendor[32], product[32], revision[16];
		uint32_t sectors;
		int disk_id;
		char dev_letter;
		if (scsi_lun_get_info(i, vendor, sizeof(vendor), product, sizeof(product),
		                      revision, sizeof(revision), &sectors, &disk_id, &dev_letter) != 0)
			continue;
		uint32_t size_mb = sectors / 2048;
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
			"Host: scsi Channel: 00 Id: %02d Lun: 00\n  Vendor: %-8s Model: %-16s Rev: %-4s\n  Type:   Direct-Access    ANSI SCSI revision: 05\n  /dev/sd%c: %u sectors (%u MiB)\n",
			disk_id, vendor, product, revision, dev_letter, (unsigned)sectors, size_mb);
		if (written < 0) break;
		w += (size_t)written;
		if (w >= size) { w = size; break; }
	}
	if (n == 0)
		w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0, "(no SCSI disks)\n");
	return (ssize_t)w;
}

/* /proc/pci — список PCI устройств (формат lspci-подобный) */
static ssize_t procfs_show_pci(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	size_t w = 0;
	pci_device_t *devs = pci_get_devices();
	int count = pci_get_device_count();
	for (int i = 0; i < count && w < size; i++) {
		pci_device_t *d = &devs[i];
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
			"%02x:%02x.%x %04x:%04x class %02x%02x%02x\n",
			d->bus, d->device, d->function,
			d->vendor_id, d->device_id,
			d->class_code, d->subclass, d->prog_if);
		if (written < 0) break;
		w += (size_t)written;
	}
	if (count == 0)
		w += (size_t)snprintf(buf + w, (w < size) ? (size - w) : 0, "(no PCI devices)\n");
	return (ssize_t)w;
}

/* CPU info */
static ssize_t procfs_show_cpuinfo(char *buf, size_t size, void *priv) {
	(void)priv;
	if (!buf || size == 0) return 0;
	int ncpu = smp_cpu_count();
	if (ncpu < 1)
		ncpu = 1;
	const char *model = sysinfo_cpu_name();
	size_t w = 0;
	for (int i = 0; i < ncpu && w < size; i++) {
		int written = snprintf(buf + w, (w < size) ? (size - w) : 0,
			"processor\t: %d\n"
			"model name\t: %s\n"
			"cpu cores\t: %d\n",
			i, model ? model : "Unknown", ncpu);
		if (written < 0)
			break;
		w += (size_t)written;
		if (w >= size) {
			w = size;
			break;
		}
		if (i + 1 < ncpu && w + 1 < size)
			buf[w++] = '\n';
	}
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
    char npath[512];
    strncpy(npath, path, sizeof(npath) - 1);
    npath[sizeof(npath) - 1] = '\0';
    size_t nlen = strlen(npath);
    while (nlen > 5 && npath[nlen - 1] == '/') {
        npath[nlen - 1] = '\0';
        nlen--;
    }
    path = npath;
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
				h->kind = 8; h->file_id = 0; f->type = FS_TYPE_DIR; f->size = 0;
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
						h->kind = 8; h->file_id = 1; f->type = FS_TYPE_DIR; f->size = 0;
						f->driver_private = h;
						*out_file = f;
						return 0;
					} else {
						/* /proc/sys/kernel/<name> */
						const char *name = slash2 + 1;
						if (strcmp(name, "hostname") == 0) {
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
		/* top-level file: /proc/partitions (file_id 13 — 12 is cpuinfo) */
		if (first_len == 10 && strncmp(p, "partitions", 10) == 0) {
			h->kind = 7;
			h->file_id = 13;
			f->type = FS_TYPE_REG;
			f->size = 4096; /* approximate */
			f->driver_private = h;
			*out_file = f;
			return 0;
		}
		/* /proc/scsi (directory) and /proc/scsi/scsi (file) */
		if (first_len == 4 && strncmp(p, "scsi", 4) == 0) {
			if (!slash) {
				h->kind = 13;
				f->type = FS_TYPE_DIR;
				f->size = 0;
				f->driver_private = h;
				*out_file = f;
				return 0;
			}
			if (strcmp(slash + 1, "scsi") == 0) {
				h->kind = 7;
				h->file_id = 40;
				f->type = FS_TYPE_REG;
				f->size = 4096;
				f->driver_private = h;
				*out_file = f;
				return 0;
			}
			kfree(h); kfree(pp); kfree(f); return -1;
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
			if (first_len == 3 && strncmp(p, "pci", 3) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 41; /* pci */
				*out_file = f;
				return 0;
			}
			if (first_len == 7 && strncmp(p, "loadavg", 7) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 14; /* loadavg */
				*out_file = f;
				return 0;
			}
            if (first_len == 6 && strncmp(p, "mounts", 6) == 0) {
                h->kind = 7; f->type = FS_TYPE_REG;
                f->size = 0;
                f->driver_private = h;
                h->file_id = 16; /* mounts */
                *out_file = f;
                return 0;
            }
			if (first_len == 4 && strncmp(p, "stat", 4) == 0) {
				h->kind = 7; f->type = FS_TYPE_REG;
				f->size = 0;
				f->driver_private = h;
				h->file_id = 15; /* kernel stat (cpu lines) */
				*out_file = f;
				return 0;
			}
			if (first_len == 3 && strncmp(p, "sys", 3) == 0) {
				/* /proc/sys root directory */
				h->kind = 8; h->file_id = 0; f->type = FS_TYPE_DIR; f->size = 0;
				*out_file = f;
				return 0;
			}
            if (first_len == 3 && strncmp(p, "tty", 3) == 0) {
                /* /proc/tty root directory (minimal) */
                h->kind = 12; f->type = FS_TYPE_DIR; f->size = 0;
                *out_file = f;
                return 0;
            }
            if (first_len == 3 && strncmp(p, "bus", 3) == 0) {
                /* /proc/bus root directory */
                h->kind = 10; f->type = FS_TYPE_DIR; f->size = 0;
                *out_file = f;
                return 0;
            }
            if (first_len == 3 && strncmp(p, "net", 3) == 0) {
                /* /proc/net — netstat, ss */
                h->kind = 14; f->type = FS_TYPE_DIR; f->size = 0;
                f->driver_private = h;
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
            /* /proc/bus/... */
            if (first_len == 3 && strncmp(p, "bus", 3) == 0) {
                if (strncmp(rest, "usb", 3) == 0 && (rest[3] == '\0' || rest[3] == '/')) {
                    if (rest[3] == '\0') {
                        h->kind = 11; f->type = FS_TYPE_DIR; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                    const char *rest2 = rest + 4; /* after usb/ */
                    if (strncmp(rest2, "devices", 7) == 0) {
                        h->kind = 7; h->file_id = 30; f->type = FS_TYPE_REG; f->size = 0;
                        f->driver_private = h;
                        *out_file = f;
                        return 0;
                    }
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
            /* /proc/tty/... */
            if (first_len == 3 && strncmp(p, "tty", 3) == 0) {
                if (strcmp(rest, "drivers") == 0) {
                    h->kind = 7; h->file_id = 31; f->type = FS_TYPE_REG; f->size = 0;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                if (*rest == '\0') {
                    h->kind = 12; f->type = FS_TYPE_DIR; f->size = 0;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
            /* /proc/net/{tcp,udp,...} */
            if (first_len == 3 && strncmp(p, "net", 3) == 0) {
                if (strchr(rest, '/')) { kfree(h); kfree(pp); kfree(f); return -1; }
                int fid = -1;
                if (strcmp(rest, "tcp") == 0) fid = 50;
                else if (strcmp(rest, "udp") == 0) fid = 51;
                else if (strcmp(rest, "tcp6") == 0) fid = 52;
                else if (strcmp(rest, "udp6") == 0) fid = 53;
                else if (strcmp(rest, "raw") == 0) fid = 54;
                else if (strcmp(rest, "raw6") == 0) fid = 55;
                else if (strcmp(rest, "unix") == 0) fid = 56;
                else if (strcmp(rest, "arp") == 0) fid = 57;
                else if (strcmp(rest, "dev") == 0) fid = 58;
                else if (strcmp(rest, "route") == 0) fid = 59;
                if (fid >= 0) {
                    h->kind = 7;
                    h->file_id = fid;
                    f->type = FS_TYPE_REG;
                    f->size = 65536;
                    f->driver_private = h;
                    *out_file = f;
                    return 0;
                }
                kfree(h); kfree(pp); kfree(f); return -1;
            }
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
				/* other pid children: cmdline, stat, status, statm */
			if (strncmp(rest, "cmdline", 7) == 0 && rest[7] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 0; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "stat", 4) == 0 && rest[4] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 1; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "status", 6) == 0 && rest[6] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 2; f->type = FS_TYPE_REG;
				} else if (strncmp(rest, "statm", 5) == 0 && rest[5] == '\0') {
					h->kind = 3; h->pid = pid; h->file_id = 3; f->type = FS_TYPE_REG;
				} else {
					kfree(h); kfree(pp); kfree(f); return -1;
				}
				/* compute size */
				size_t cap = 4096;
				char *tmpbuf = (char*)kmalloc(cap);
				if (tmpbuf) {
					ssize_t full = 0;
					if (h->file_id == 0) full = procfs_show_cmdline(tmpbuf, cap, (void*)(uintptr_t)h->pid);
					else if (h->file_id == 1) full = procfs_show_stat(tmpbuf, cap, (void*)(uintptr_t)h->pid);
					else if (h->file_id == 2) full = procfs_show_status(tmpbuf, cap, (void*)(uintptr_t)h->pid);
					else if (h->file_id == 3) full = procfs_show_statm(tmpbuf, cap, (void*)(uintptr_t)h->pid);
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
        const char *top[] = { "meminfo", "cpuinfo", "uptime", "loadavg", "mounts", "stat", "partitions", "sys", "bus", "tty", "net", "scsi" };
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
                /* sys, bus, tty, scsi are directories */
                de.file_type = (strcmp(name, "sys") == 0 || strcmp(name, "bus") == 0 || strcmp(name, "tty") == 0 || strcmp(name, "net") == 0 || strcmp(name, "scsi") == 0)
                               ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
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
        /* /proc/<pid> dir: entries cmdline/stat/status/statm */
        const char *names[4] = { "cmdline", "stat", "status", "statm" };
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
        for (int idx = 0; idx < 4; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
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
        const char *names_root[] = { "kernel" };
        const char *names_kernel[] = { "hostname" };
        const char *const *names = (h->file_id == 1) ? names_kernel : names_root;
        int ncount = 1;
		size_t pos = 0;
		size_t written = 0;
		uint8_t *out = (uint8_t*)buf;
		for (int idx = 0; idx < ncount; idx++) {
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
            de.file_type = (h->file_id == 1) ? EXT2_FT_REG_FILE : EXT2_FT_DIR;
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

    /* /proc/tty directory listing */
    if (h->kind == 12) {
        const char *names[] = { "drivers" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3100 + idx);
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

    /* /proc/net directory listing */
    if (h->kind == 14) {
        static const char *names[] = { "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "unix", "arp", "dev", "route" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t *)buf;
        for (size_t idx = 0; idx < sizeof(names) / sizeof(names[0]); idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) {
                pos += rec_len;
                continue;
            }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(4000u + (uint32_t)idx);
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

    /* /proc/bus directory listing */
    if (h->kind == 10) {
        const char *names[] = { "usb" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3000 + idx);
            de.rec_len = (uint16_t)rec_len;
            de.name_len = (uint8_t)namelen;
            de.file_type = EXT2_FT_DIR;
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

    /* /proc/bus/usb directory listing */
    if (h->kind == 13) {
        /* /proc/scsi: list file "scsi" */
        const char *names[] = { "scsi" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3200 + idx);
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
        }
        return (ssize_t)written;
    }
    if (h->kind == 11) {
        const char *names[] = { "devices" };
        size_t pos = 0;
        size_t written = 0;
        uint8_t *out = (uint8_t*)buf;
        for (int idx = 0; idx < 1; idx++) {
            size_t namelen = strlen(names[idx]);
            size_t rec_len = 8 + namelen;
            rec_len = (rec_len + 3) & ~3u;
            if (pos + rec_len <= offset) { pos += rec_len; continue; }
            if (written >= size) break;
            size_t entry_off = ((size_t)offset > pos) ? ((size_t)offset - pos) : 0;
            uint8_t tmp[128];
            memset(tmp, 0, sizeof(tmp));
            struct ext2_dir_entry de;
            de.inode = (uint32_t)(3010 + idx);
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

    /* regular file */
    if (h->kind == 3) {
        ssize_t full = 0;
        size_t cap = 4096;
        if (cap < size + offset) cap = size + offset;
        if (cap > 65536) cap = 65536;
        char *tmp = (char*)kmalloc(cap);
        if (!tmp) return -1;
        if (h->file_id == 0) full = procfs_show_cmdline(tmp, cap, (void*)(uintptr_t)h->pid);
        else if (h->file_id == 1) full = procfs_show_stat(tmp, cap, (void*)(uintptr_t)h->pid);
        else if (h->file_id == 2) full = procfs_show_status(tmp, cap, (void*)(uintptr_t)h->pid);
        else if (h->file_id == 3) full = procfs_show_statm(tmp, cap, (void*)(uintptr_t)h->pid);
        else full = -1;
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
		if (h->file_id >= 50 && h->file_id <= 56) cap = 65536;
		if (cap < size + offset) cap = size + offset;
		if (cap > 65536) cap = 65536;
		char *tmpbuf = (char*)kmalloc(cap);
		if (!tmpbuf) return -1;
		ssize_t full = 0;
		if (h->file_id == 10) full = procfs_show_meminfo(tmpbuf, cap, NULL);
		else if (h->file_id == 11) full = procfs_show_uptime(tmpbuf, cap, NULL);
		else if (h->file_id == 12) full = procfs_show_cpuinfo(tmpbuf, cap, NULL);
		else if (h->file_id == 13) full = procfs_show_partitions(tmpbuf, cap, NULL);
		else if (h->file_id == 14) full = procfs_show_loadavg(tmpbuf, cap, NULL);
		else if (h->file_id == 15) full = procfs_show_kernel_stat(tmpbuf, cap, NULL);
        else if (h->file_id == 16) full = procfs_show_mounts(tmpbuf, cap, NULL);
		else if (h->file_id == 40) full = procfs_show_scsi(tmpbuf, cap, NULL);
		else if (h->file_id == 41) full = procfs_show_pci(tmpbuf, cap, NULL);
        else if (h->file_id == 30) full = usb_proc_bus_devices_show(tmpbuf, cap, NULL);
        else if (h->file_id == 31) full = (ssize_t)snprintf(tmpbuf, cap, "pty_slave            /dev/tty\n");
        else if (h->file_id == 50) full = procfs_net_snap_tcp(tmpbuf, cap);
        else if (h->file_id == 51) full = procfs_net_snap_udp(tmpbuf, cap);
        else if (h->file_id == 52) full = procfs_net_snap_tcp6(tmpbuf, cap);
        else if (h->file_id == 53) full = procfs_net_snap_udp6(tmpbuf, cap);
        else if (h->file_id == 54) full = procfs_net_snap_raw(tmpbuf, cap);
        else if (h->file_id == 55) full = procfs_net_snap_raw6(tmpbuf, cap);
        else if (h->file_id == 56) full = procfs_net_snap_unix(tmpbuf, cap);
        else if (h->file_id == 57) full = procfs_net_snap_arp(tmpbuf, cap);
        else if (h->file_id == 58) full = procfs_net_snap_dev(tmpbuf, cap);
        else if (h->file_id == 59) full = procfs_net_snap_route(tmpbuf, cap);
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
    if (h->kind == 1 || h->kind == 2 || h->kind == 5 || h->kind == 8 || h->kind == 10 || h->kind == 11 || h->kind == 12 || h->kind == 13 || h->kind == 14) {
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


