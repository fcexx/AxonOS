#include <sysinfo.h>
#include <thread.h>
#include <stdint.h>
#include <axonos.h>
#include <apic_timer.h>

void neofetch_run(void) {
    const char *cpu = sysinfo_cpu_name();
    int ram = sysinfo_ram_mb();
    int threads = thread_get_count();
    const char *boot = sysinfo_pc_type() ? "BIOS / Multiboot" : "UEFI";
    
    // Get formatted uptime
    char uptime_str[32];
    apic_timer_format_uptime(uptime_str, sizeof(uptime_str));

    kprintf("\n");

    /* серый крокодил — построчно */
    kprintf("<(08)>                  .-._   _ _ _ _ _ _ _ _\n");
    kprintf("<(08)>         .-''-.__.-'00  '-' ' ' ' ' ' ' ' '-.\n");
    kprintf("<(08)>         '.___ '    .   .--_'-' '-' '-' _'-' '._\n");
    kprintf("<(08)>          V: V 'vv-'   '_   '.       .'  _..' '.'.\n");
    kprintf("<(08)>            '=.____.=_.--'   :_.__.__:_   '.   : :\n");
    kprintf("<(08)>                    (((____.-'        '-.  /   : :\n");
    kprintf("<(08)>          snd                         (((-'\\ .' /\n");
    kprintf("<(08)>                                    _____..'  .'\n");
    kprintf("<(08)>                                   '-._____.-'\n");

    /* инфа */
    kprintf("<(0f)>========================================\n");
    kprintf("<(0f)> <(0e)>OS:       <(0b)>%s version %s\n", OS_NAME, OS_VERSION);
    kprintf("<(0f)> <(0e)>Kernel:   <(0b)>Axon x86_64\n");
    kprintf("<(0f)> <(0e)>CPU:      <(0b)>%s\n", cpu ? cpu : "Unknown");

    if (ram >= 0)
        kprintf("<(0f)> <(0e)>RAM:      <(0b)>%d MB\n", ram);
    else
        kprintf("<(0f)> <(0e)>RAM:      <(0c)>Unknown\n");

    kprintf("<(0f)> <(0e)>Boot:     <(0b)>%s\n", boot);
    kprintf("<(0f)> <(0e)>Threads:  <(0b)>%d\n", threads);
    kprintf("<(0f)> <(0e)>Uptime:   <(0b)>%s\n", uptime_str);
    kprintf("<(0f)> <(0e)>Heap:     <(0b)>enabled\n");
    kprintf("<(0f)> <(0e)>Paging:   <(0b)>active\n");
    kprintf("<(0f)>========================================\n\n");
}