/* Cirrus video driver skeleton header */
#ifndef CIRRUS_H
#define CIRRUS_H

#include <video.h>

int cirrus_driver_register(void);
int cirrus_kernel_init(void);
extern const video_ops_t cirrus_video_ops;

#endif /* CIRRUS_H */


