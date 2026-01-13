/* Intel video driver skeleton header */
#ifndef INTEL_H
#define INTEL_H

#include <video.h>

int intel_driver_register(void);

/* driver ops exposed to registry */
extern const video_ops_t intel_video_ops;

#endif /* INTEL_H */


