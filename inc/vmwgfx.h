/* VMware SVGA / SVGA-II: minimal 2D linear framebuffer (Linux-style pci driver hook) */
#ifndef VMWGFX_H
#define VMWGFX_H

#include <video.h>

int vmwgfx_driver_register(void);
int vmwgfx_kernel_init(void);
extern const video_ops_t vmwgfx_video_ops;

#endif /* VMWGFX_H */
