#include "mac.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 참고 mac: (https://url.kr/wt71i2)
// 참고 ip: (https://kldp.org/node/4039)

Mac get_my_mac(const char *if_name)
{
    struct ifreq ifr;
    int socketd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketd < 0)
    {
        perror("socket");
        exit(-1);
    }
    strcpy(ifr.ifr_name, if_name);
    if(ioctl(socketd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(-1);
    }
    Mac res((uint8_t*)ifr.ifr_hwaddr.sa_data);
    return res;
};

Ip get_my_ip(const char *if_name)
{
    struct ifreq ifr;
    char buf[16];
	int socketd = socket(AF_INET, SOCK_DGRAM, 0);
    if(socketd < 0)
    {
        perror("socker");
        exit(-1);
    }
        
	strcpy(ifr.ifr_name, if_name);

	if (ioctl(socketd, SIOCGIFADDR, &ifr) < 0) 
    {
        perror("ioctl");
		exit(-1);
	}
    Ip res(inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, buf, sizeof(struct sockaddr)));
	return res;
}
