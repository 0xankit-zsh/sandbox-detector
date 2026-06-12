/**
 * Sandbox Detection Utility for Malware Analysis
 * 
 * Features:
 * - Virtualization detection (VMware, VirtualBox, Hyper-V, KVM, Xen)
 * - Registry artifact analysis
 * - BIOS validation and fingerprinting
 * - MAC address inspection
 * - Hardware-based heuristics (CPU, RAM, disk, uptime)
 * 
 * Compilation:
 *   gcc -o sandbox_detect sandbox_detect.c -lm
 * 
 * Usage:
 *   ./sandbox_detect [--verbose] [--json]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cpuid.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#endif

/* ==================== Configuration ==================== */

#define THRESHOLD_CPU_CORES        2
#define THRESHOLD_RAM_MB         1024
#define THRESHOLD_DISK_GB          40
#define THRESHOLD_UPTIME_MIN       10

/* Verbose output flag */
static bool verbose = false;
static bool json_output = false;

/* Detection result structure */
typedef struct {
    const char *name;
    bool detected;
    double confidence;
    char details[256];
} DetectionResult;

/* Detection results array */
static DetectionResult results[50];
static int result_count = 0;

/* ==================== Helper Functions ==================== */

void add_result(const char *name, bool detected, double confidence, const char *details) {
    if (result_count < 50) {
        results[result_count].name = name;
        results[result_count].detected = detected;
        results[result_count].confidence = confidence;
        strncpy(results[result_count].details, details, 255);
        results[result_count].details[255] = '\0';
        result_count++;
    }
}

void log_info(const char *msg) {
    if (verbose && !json_output) {
        printf("[INFO] %s\n", msg);
    }
}

void log_detection(const char *test, const char *indicator, double confidence) {
    if (!json_output) {
        printf("[DETECT] %s: %s (confidence: %.0f%%)\n", test, indicator, confidence * 100);
    }
}

/* ==================== CPU / Virtualization Detection ==================== */

/* Check CPUID hypervisor bit */
static bool check_hypervisor_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    
    /* Check for hypervisor presence bit (CPUID leaf 0x01, ECX bit 31) */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 31)) {
            add_result("CPUID Hypervisor Bit", true, 0.95, "Hypervisor present bit set");
            log_detection("CPUID", "Hypervisor present bit (ECX[31])", 0.95);
            return true;
        }
    }
    return false;
}

/* Get hypervisor signature using CPUID leaf 0x40000000 */
static const char* get_hypervisor_signature(void) {
    uint32_t eax, ebx, ecx, edx;
    char signature[13] = {0};
    
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        /* Signature is in EBX, ECX, EDX */
        memcpy(signature, &ebx, 4);
        memcpy(signature + 4, &ecx, 4);
        memcpy(signature + 8, &edx, 4);
        
        if (strlen(signature) > 0) {
            /* Check for known hypervisors */
            if (strcmp(signature, "VMwareVMware") == 0) return "VMware";
            if (strcmp(signature, "VBoxVBoxVBox") == 0) return "VirtualBox";
            if (strcmp(signature, "KVMKVMKVM") == 0) return "KVM";
            if (strcmp(signature, "XenVMMXenVMM") == 0) return "Xen";
            if (strcmp(signature, "Microsoft Hv") == 0) return "Hyper-V";
            if (strncmp(signature, "HVM", 3) == 0) return "Xen HVM";
            return signature;
        }
    }
    return NULL;
}

/* Red Pill timing-based detection (SIDT instruction) */
static bool redpill_timing(void) {
    unsigned long long time1, time2;
    unsigned char idtr[10] = {0};
    
    /* Store IDTR */
    __asm__ volatile("sidt %0" : "=m"(idtr));
    
    time1 = __rdtsc();
    
    /* Execute SIDT again */
    __asm__ volatile("sidt %0" : "=m"(idtr));
    
    time2 = __rdtsc();
    
    /* In some VMs, SIDT takes significantly longer */
    if (time2 - time1 > 100) {
        add_result("Red Pill Timing", true, 0.70, "SIDT timing anomaly detected");
        log_detection("Red Pill", "SIDT timing anomaly", 0.70);
        return true;
    }
    return false;
}

/* IN instruction timing check for VMware detection */
static bool vmware_in_timing(void) {
    unsigned long long start, end;
    unsigned short port_val;
    
    /* VMware backdoor I/O port */
    start = __rdtsc();
    __asm__ volatile("in %%dx, %%ax" : "=a"(port_val) : "d"(0x5658));
    end = __rdtsc();
    
    if (end - start > 50) {
        add_result("VMware I/O Timing", true, 0.75, "I/O port access timing anomaly");
        log_detection("VMware", "I/O port timing anomaly", 0.75);
        return true;
    }
    return false;
}

/* ==================== Registry Artifact Analysis ==================== */

#ifdef __linux__
/* Read a file and check for content pattern */
static bool check_file_content(const char *path, const char *pattern) {
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, pattern)) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}
#endif

/* Check for virtualization-related files */
static void check_registry_artifacts(void) {
    struct stat st;
    int detected_count = 0;
    char detected_list[256] = {0};
    
#ifdef __linux__
    /* Check for VMware artifacts */
    if (stat("/proc/scsi/scsi", &st) == 0) {
        if (check_file_content("/proc/scsi/scsi", "VMware")) {
            strcat(detected_list, "VMware SCSI, ");
            detected_count++;
        }
    }
    
    if (stat("/proc/scsi/scsi", &st) == 0) {
        if (check_file_content("/proc/scsi/scsi", "VBOX")) {
            strcat(detected_list, "VirtualBox SCSI, ");
            detected_count++;
        }
    }
    
    /* Check for VMware PCI devices */
    if (stat("/proc/bus/pci/devices", &st) == 0) {
        if (check_file_content("/proc/bus/pci/devices", "15ad")) {
            strcat(detected_list, "VMware PCI (15ad), ");
            detected_count++;
        }
    }
    
    /* Check for VirtualBox Guest Additions */
    if (stat("/opt/VBoxGuestAdditions", &st) == 0) {
        strcat(detected_list, "VirtualBox Guest Additions, ");
        detected_count++;
    }
    
    /* Check for VMware Tools */
    if (stat("/usr/lib/vmware-tools", &st) == 0 || stat("/usr/bin/vmware-user", &st) == 0) {
        strcat(detected_list, "VMware Tools, ");
        detected_count++;
    }
    
    /* Check for Hyper-V KVP daemon */
    if (stat("/usr/sbin/hv_kvp_daemon", &st) == 0) {
        strcat(detected_list, "Hyper-V KVP Daemon, ");
        detected_count++;
    }
    
    /* Check for QEMU artifacts */
    if (check_file_content("/proc/cpuinfo", "QEMU")) {
        strcat(detected_list, "QEMU CPU, ");
        detected_count++;
    }
    
    /* Check for Docker */
    if (stat("/.dockerenv", &st) == 0 || stat("/run/.containerenv", &st) == 0) {
        strcat(detected_list, "Container (Docker), ");
        detected_count++;
    }
#endif
    
    if (detected_count > 0) {
        /* Remove trailing comma and space */
        detected_list[strlen(detected_list) - 2] = '\0';
        double confidence = 0.70 + (detected_count * 0.05);
        if (confidence > 0.95) confidence = 0.95;
        add_result("Registry/File Artifacts", true, confidence, detected_list);
        log_detection("Artifacts", detected_list, confidence);
    } else {
        add_result("Registry/File Artifacts", false, 0.00, "No sandbox artifacts found");
    }
}

/* ==================== BIOS Validation ==================== */

static void check_bios(void) {
    char bios_info[256] = {0};
    int detection_flags = 0;
    
#ifdef __linux__
    /* Read DMI information for BIOS */
    if (stat("/sys/class/dmi/id/bios_vendor", &(struct stat){0}) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/bios_vendor", "r");
        if (fp) {
            char vendor[64] = {0};
            if (fgets(vendor, sizeof(vendor), fp)) {
                /* Remove newline */
                vendor[strcspn(vendor, "\n")] = 0;
                
                /* Check for virtualization BIOS vendors */
                if (strcasestr(vendor, "VMware") || strcasestr(vendor, "VirtualBox") ||
                    strcasestr(vendor, "QEMU") || strcasestr(vendor, "Bochs")) {
                    snprintf(bios_info, sizeof(bios_info), "Virtualized BIOS: %s", vendor);
                    detection_flags++;
                } else {
                    snprintf(bios_info, sizeof(bios_info), "BIOS Vendor: %s", vendor);
                }
            }
            fclose(fp);
        }
    }
    
    /* Check BIOS date */
    if (stat("/sys/class/dmi/id/bios_date", &(struct stat){0}) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/bios_date", "r");
        if (fp) {
            char date[32] = {0};
            if (fgets(date, sizeof(date), fp)) {
                date[strcspn(date, "\n")] = 0;
                
                /* Check if BIOS date is suspiciously new or old */
                int year = 0;
                if (sscanf(date, "%04d", &year) == 1) {
                    if (year > 2023 || year < 2000) {
                        strcat(bios_info, " | Suspicious BIOS date");
                        detection_flags++;
                    }
                }
            }
            fclose(fp);
        }
    }
    
    /* Check system vendor */
    if (stat("/sys/class/dmi/id/sys_vendor", &(struct stat){0}) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/sys_vendor", "r");
        if (fp) {
            char vendor[64] = {0};
            if (fgets(vendor, sizeof(vendor), fp)) {
                vendor[strcspn(vendor, "\n")] = 0;
                
                if (strcasestr(vendor, "VMware") || strcasestr(vendor, "VirtualBox") ||
                    strcasestr(vendor, "QEMU") || strcasestr(vendor, "Bochs") ||
                    strcasestr(vendor, "KVM") || strcasestr(vendor, "innotek")) {
                    snprintf(bios_info, sizeof(bios_info), "Virtualized System Vendor: %s", vendor);
                    detection_flags++;
                }
            }
            fclose(fp);
        }
    }
    
    /* Check product name */
    if (stat("/sys/class/dmi/id/product_name", &(struct stat){0}) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/product_name", "r");
        if (fp) {
            char product[64] = {0};
            if (fgets(product, sizeof(product), fp)) {
                product[strcspn(product, "\n")] = 0;
                
                if (strcasestr(product, "Virtual") || strcasestr(product, "VMware") ||
                    strcasestr(product, "KVM") || strcasestr(product, "QEMU") ||
                    strcasestr(product, "Bochs")) {
                    snprintf(bios_info, sizeof(bios_info), "Virtualized Product: %s", product);
                    detection_flags++;
                }
            }
            fclose(fp);
        }
    }
#endif
    
    if (detection_flags > 0) {
        double confidence = 0.75 + (detection_flags * 0.05);
        if (confidence > 0.95) confidence = 0.95;
        add_result("BIOS Validation", true, confidence, bios_info);
        log_detection("BIOS", bios_info, confidence);
    } else if (strlen(bios_info) > 0) {
        add_result("BIOS Validation", false, 0.05, bios_info);
    } else {
        add_result("BIOS Validation", false, 0.00, "BIOS information unavailable");
    }
}

/* ==================== MAC Address Inspection ==================== */

static void check_mac_addresses(void) {
    struct ifaddrs *ifaddr, *ifa;
    int if_count = 0;
    int suspicious_count = 0;
    char suspicious_macs[256] = {0};
    
    /* Known sandbox/virtualization MAC OUIs */
    const char *suspicious_ouis[] = {
        "00:05:69", /* VMware */
        "00:0C:29", /* VMware */
        "00:50:56", /* VMware */
        "00:1C:14", /* VMware */
        "00:0F:4B", /* Virtual Iron */
        "00:16:3E", /* Xen / Citrix */
        "08:00:27", /* VirtualBox */
        "52:54:00", /* QEMU / KVM */
        "00:15:5D", /* Hyper-V */
        "00:03:FF", /* Virtual PC */
        "00:1D:8E", /* KVM */
        "00:1E:37", /* KVM */
        "00:21:F6", /* KVM */
        "02:50:00", /* VirtualBox */
        "02:42:AC", /* Docker */
        "02:42:0A", /* Docker */ 
        NULL
    };
    
    if (getifaddrs(&ifaddr) == -1) {
        add_result("MAC Inspection", false, 0.00, "Failed to get network interfaces");
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
        if (sll->sll_halen != 6) continue;
        
        if_count++;
        
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
            sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
            sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
        
        /* Check against suspicious OUIs */
        for (int i = 0; suspicious_ouis[i] != NULL; i++) {
            if (strncasecmp(mac, suspicious_ouis[i], 8) == 0) {
                suspicious_count++;
                if (strlen(suspicious_macs) < 200) {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%s ", mac);
                    strcat(suspicious_macs, tmp);
                }
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    if (suspicious_count > 0) {
        double confidence = 0.70 + (suspicious_count * 0.10);
        if (confidence > 0.95) confidence = 0.95;
        add_result("MAC Inspection", true, confidence, suspicious_macs);
        log_detection("MAC Address", suspicious_macs, confidence);
    } else {
        char info[64];
        snprintf(info, sizeof(info), "%d interfaces, no known vendor OUIs", if_count);
        add_result("MAC Inspection", false, 0.00, info);
    }
}

/* ==================== Hardware-Based Heuristics ==================== */

static void check_hardware_heuristics(void) {
    int heuristic_score = 0;
    char details[512] = {0};
    int detail_pos = 0;
    
#ifdef __linux__
    /* CPU Core Count */
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < THRESHOLD_CPU_CORES) {
        heuristic_score++;
        detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
            "Low CPU cores: %ld ", num_cpus);
    }
    
    /* Memory Size */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long long total_ram_mb = (pages * page_size) / (1024 * 1024);
    if (total_ram_mb < THRESHOLD_RAM_MB) {
        heuristic_score++;
        detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
            "Low RAM: %lldMB ", total_ram_mb);
    }
    
    /* System Uptime */
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        long uptime_min = info.uptime / 60;
        if (uptime_min < THRESHOLD_UPTIME_MIN) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Low uptime: %ldmin ", uptime_min);
        }
    }
    
    /* Disk Size - Check root partition */
    struct statfs stat;
    if (statfs("/", &stat) == 0) {
        unsigned long long disk_gb = (stat.f_blocks * stat.f_bsize) / (1024ULL * 1024 * 1024);
        if (disk_gb < THRESHOLD_DISK_GB) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Small disk: %lluGB ", disk_gb);
        }
    }
    
    /* Check for common hostnames in sandboxes */
    const char *common_hostnames[] = {
        "sandbox", "malware", "analysis", "cuckoo", "windows",
        "win7", "win10", "winxp", "ubuntu", "debian"
    };
    
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        for (int i = 0; i < 10; i++) {
            if (strcasestr(hostname, common_hostnames[i])) {
                heuristic_score++;
                detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                    "Suspicious hostname: %s ", hostname);
                break;
            }
        }
    }
    
    /* Check for low number of processes */
    DIR *proc = opendir("/proc");
    if (proc) {
        int process_count = 0;
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                process_count++;
            }
        }
        closedir(proc);
        
        if (process_count < 50) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Low process count: %d ", process_count);
        }
    }
#endif
    
    if (heuristic_score > 0) {
        double confidence = 0.10 + (heuristic_score * 0.10);
        if (confidence > 0.90) confidence = 0.90;
        add_result("Hardware Heuristics", true, confidence, details);
        log_detection("Hardware", details, confidence);
    } else {
        add_result("Hardware Heuristics", false, 0.00, "No suspicious hardware patterns");
    }
}

/* ==================== Additional Checks ==================== */

/* Check for debugger presence */
static void check_debugger(void) {
#ifdef __linux__
    /* Check ptrace */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        add_result("Debugger Detection", true, 0.85, "ptrace indicates debugger/tracer");
        log_detection("Debugger", "ptrace detected", 0.85);
        return;
    }
#endif
    add_result("Debugger Detection", false, 0.00, "No debugger detected");
}

/* Check system uptime anomaly */
static void check_uptime_anomaly(void) {
#ifdef __linux__
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        if (info.uptime < 300) { /* Less than 5 minutes */
            add_result("Uptime Anomaly", true, 0.65, "System recently booted");
            log_detection("Uptime", "Fresh boot (<5 min)", 0.65);
            return;
        }
    }
#endif
    add_result("Uptime Anomaly", false, 0.00, "Normal uptime");
}

/* ==================== Main Function ==================== */

void print_results(void) {
    double total_score = 0.0;
    int max_weight = 0;
    
    if (json_output) {
        printf("{\n");
        printf("  \"timestamp\": %ld,\n", time(NULL));
        printf("  \"detections\": [\n");
        
        for (int i = 0; i < result_count; i++) {
            printf("    {\n");
            printf("      \"name\": \"%s\",\n", results[i].name);
            printf("      \"detected\": %s,\n", results[i].detected ? "true" : "false");
            printf("      \"confidence\": %.2f,\n", results[i].confidence);
            printf("      \"details\": \"%s\"\n", results[i].details);
            printf("    }%s\n", (i < result_count - 1) ? "," : "");
        }
        
        /* Calculate overall score */
        for (int i = 0; i < result_count; i++) {
            if (results[i].detected) {
                total_score += results[i].confidence;
                max_weight++;
            }
        }
        double overall = (max_weight > 0) ? (total_score / max_weight) : 0.0;
        
        printf("  ],\n");
        printf("  \"overall_sandbox_confidence\": %.2f\n", overall);
        printf("}\n");
    } else {
        printf("\n");
        printf("========================================\n");
        printf("   Sandbox Detection Results\n");
        printf("========================================\n\n");
        
        for (int i = 0; i < result_count; i++) {
            const char *status = results[i].detected ? "DETECTED" : "CLEAN";
            printf("[%s] %s\n", status, results[i].name);
            printf("      Confidence: %.0f%%\n", results[i].confidence * 100);
            printf("      Details: %s\n", results[i].details);
            printf("\n");
        }
        
        /* Calculate overall score */
        double total = 0.0;
        int detected_count = 0;
        for (int i = 0; i < result_count; i++) {
            if (results[i].detected) {
                total += results[i].confidence;
                detected_count++;
            }
        }
        double overall = (detected_count > 0) ? (total / detected_count) : 0.0;
        
        printf("========================================\n");
        printf("Overall Sandbox Detection Confidence: %.0f%%\n", overall * 100);
        printf("========================================\n");
        
        if (overall > 0.70) {
            printf("⚠️  HIGH PROBABILITY: System appears to be a sandbox/VM\n");
        } else if (overall > 0.40) {
            printf("⚠️  MEDIUM PROBABILITY: Some sandbox indicators present\n");
        } else if (overall > 0.10) {
            printf("✓  LOW PROBABILITY: Limited sandbox indicators\n");
        } else {
            printf("✓  NEGLIGIBLE: No significant sandbox indicators\n");
        }
    }
}

int main(int argc, char *argv[]) {
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Sandbox Detection Utility\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --verbose, -v    Enable verbose output\n");
            printf("  --json, -j       Output in JSON format\n");
            printf("  --help, -h       Show this help\n");
            return 0;
        }
    }
    
    log_info("Starting sandbox detection...");
    
    /* Run all detection modules */
    check_hypervisor_cpuid();
    
    const char *hv_sig = get_hypervisor_signature();
    if (hv_sig) {
        add_result("Hypervisor Signature", true, 0.95, hv_sig);
        log_detection("Hypervisor", hv_sig, 0.95);
    } else {
        add_result("Hypervisor Signature", false, 0.00, "No hypervisor signature");
    }
    
    redpill_timing();
    vmware_in_timing();
    check_registry_artifacts();
    check_bios();
    check_mac_addresses();
    check_hardware_heuristics();
    check_debugger();
    check_uptime_anomaly();
    
    print_results();
    
    return 0;
}
