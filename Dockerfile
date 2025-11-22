FROM debian:stable-slim

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
    gcc-12 g++-12 gcc-12-multilib libc6-dev-i386 \
    xorg \
    git \
    make \
    && rm -rf /var/lib/apt/lists/* && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100

WORKDIR /workspace

COPY . .

CMD ["sh", "-c", "make"]