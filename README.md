<h1 align="center">🐊 Axon OS</h1>

<p align="center">
  <b>Minimal. Fast. Open.</b><br>
  A lightweight, experimental operating system written by a small team.<br>
  <i>Because simplicity is power.</i>
</p>

---

<p align="center">
  <a href="https://github.com/fcexx/AxonOS/stargazers">
    <img src="https://img.shields.io/github/stars/fcexx/AxonOS?style=for-the-badge&color=yellow" alt="Stars">
  </a>
  <a href="https://github.com/fcexx/AxonOS/network/members">
    <img src="https://img.shields.io/github/forks/fcexx/AxonOS?style=for-the-badge&color=orange" alt="Forks">
  </a>
  <a href="https://github.com/fcexx/AxonOS/commits/main">
    <img src="https://img.shields.io/github/last-commit/fcexx/AxonOS?style=for-the-badge&color=brightgreen" alt="Last Commit">
  </a>
  <a href="https://github.com/fcexx/AxonOS/issues">
    <img src="https://img.shields.io/github/issues/fcexx/AxonOS?style=for-the-badge&color=blue" alt="Issues">
  </a>
  <a href="https://github.com/fcexx/AxonOS/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/fcexx/AxonOS?style=for-the-badge&color=red" alt="License">
  </a>
</p>

---

### ✨ Features
- ⚙️ Custom kernel fully written in C
- 🧩 Low-level architecture: GDT, IDT, PIC, PIT, RTC, Paging
- 🧠 Dynamic heap allocator + virtual memory manager
- 🧵 Threading system with full context switching
- ⌨️ Hardware drivers: Keyboard, Serial, PCI, RTC, PIT
- 🌐 Experimental Intel E1000 network driver + basic ARP/ICMP stack
- 🖥 VGA text-mode UI with built-in apps (Snake, Tetris, Neofetch, Clock, System Info)
- 💻 Built-in Ring0 shell with core commands
- 📝 Integrated OSH interpreter (Axon Shell)
- 🏃 Task management & lightweight scheduler
- 🚀 Fast boot and clean modular codebase
- 🐍 Cross-platform build support (Linux / Windows via WSL)
- 🧩 Fully open-source — learn, modify, improve оно?

---

### ⚙️ Installation

#### 🐧 Linux / macOS
```bash
git clone https://github.com/fcexx/AxonOS.git
cd AxonOS
make clean && make && make run
```

#### 🪟 Windows (via WSL or MSYS2)
```bash
git clone https://github.com/fcexx/AxonOS.git
cd AxonOS
make clean && make && make run
```

#### 💡 Requirements
- `qemu`
- `make`
- `gcc`

---

### ⭐ Star Us!
If you like **Axon OS**, don’t forget to **⭐ star the repo** — it really helps visibility!  

<p align="center">
  ⭐⭐⭐⭐⭐  
  <br><i>“A tiny kernel with big ambitions.”</i>
</p>

---

<p align="center">
  © 2025 AxonOS Project — Made with 🖤 by the community
</p>
