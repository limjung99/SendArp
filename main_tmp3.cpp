#include <cstdio>
#include <pcap.h>
#include <string>
#include <fstream>
#include <iostream>
#include <stdint.h>
#include <vector>
#include <sstream>
#include <ifaddrs.h>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;

struct pcap_pkthdr* header;
const u_char* packet;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void sendArp(string smac,string dmac,string sip,string tmac,string tip,pcap_t *handle,u_int16_t type){
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

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


}

vector<pair<string,string>> senderNtarget;
string my_mac_addr;
string my_ip_addr;
map<string,string> ipNmac;


int main(int argc, char* argv[]) {
	if (argc <4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    
	for(int i=2;i<argc-1;i+=2){
		string sender_ip(argv[i]);
		string target_ip(argv[i+1]);
		senderNtarget.push_back({sender_ip,target_ip});
	}
    //나의 mac주소 구하기  
	string interface(dev);
	string my_mac_filpath = "/sys/class/net/"+interface+"/address";
	ifstream ifs(my_mac_filpath);
	ifs>>my_mac_addr;
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
    /*-----------------------------------------------------------------*/
    ifstream fin;
    fin.open("/proc/net/arp");
    while(!fin.eof()){
        string str;
        getline(fin,str);
        string word;
        cout<<str<<endl;
        /* stringstream sstream(str);
        while(getline(sstream,word,' ')){
            cout<<word<<endl;
        } */

    }
	pcap_close(handle);
}
