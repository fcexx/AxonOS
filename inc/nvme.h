#pragma once

/* Probe PCI NVMe controllers and register discovered namespaces as block disks.
   Returns number of registered NVMe namespaces (>=0). */
int nvme_init(void);

