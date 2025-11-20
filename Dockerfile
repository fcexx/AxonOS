FROM ubuntu:22.04

#docker build -t axonos
#docker run axonos

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Moscow

RUN echo 'grub-pc grub-pc/install_devices string /dev/sda' | debconf-set-selections && \
    echo 'grub-pc grub-pc/install_devices_empty boolean true' | debconf-set-selections && \
    echo 'keyboard-configuration keyboard-configuration/layoutcode string ru' | debconf-set-selections && \
    echo 'keyboard-configuration keyboard-configuration/variantcode string' | debconf-set-selections

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nasm \
    grub-pc-bin \
    grub-common \
    qemu-system-gui \
    xorriso \
    qemu-system-x86 \
    gcc-multilib \
    xorg \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY . .

CMD ["sh", "-c", "make"]