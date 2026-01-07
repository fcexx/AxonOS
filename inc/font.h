#pragma once

#include <stdint.h>

struct font {
    int cwidth, cheight;
    uint8_t *font_data;
    uint32_t font_size;
};

void set_font(struct font *f);