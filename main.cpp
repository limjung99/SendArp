#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <stdint.h>
#include <iomanip>
#define BUFFSIZE 4096
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
}

class Arpspoofer{
	private:
		vector<Ip> senders_ip;
		vector<Ip> targets_ip;
		map<string,string> ip_mac_pair;
		int sender_counter=0; /*네트워크에 존재하는 Sender*/
		Mac mymac;
		Ip myip;
	public:
		Arpspoofer(Mac mac,Ip ip){
			mymac = mac;
			myip = ip;
		};
		void addIp(string type,Ip ip){
			if(type=="sender"){
				senders_ip.push_back(ip);
				sender_counter++;
			}
			else{
				targets_ip.push_back(ip);
			}
		}
		void sendArpPacket(string srcMac,string dstMac,string srcIp,string targetMac,string targetIp,pcap_t *handle,uint16_t type){
			//sender and target mac address resolving (arp protocol을 이용해서 sender와 target의 mac을 알아온다)
			EthArpPacket packet;
			packet.eth_.dmac_ = Mac(dstMac); 
			packet.eth_.smac_ = Mac(srcMac); 
			packet.eth_.type_ = htons(EthHdr::Arp);
			packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet.arp_.pro_ = htons(EthHdr::Ip4);
			packet.arp_.hln_ = Mac::SIZE;
			packet.arp_.pln_ = Ip::SIZE;
			packet.arp_.op_ = htons(type);
			packet.arp_.smac_ = Mac(srcMac); 
			packet.arp_.sip_ = htonl(Ip(srcIp)); 
			packet.arp_.tmac_ = Mac(targetMac); 
			packet.arp_.tip_ = htonl(Ip(targetIp)); 
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}
		void captureArpPacket();
		
		int getSenderCount(){
			return this->sender_counter;
		}
		Ip getSenderIp(int idx){
			return this->senders_ip[idx];
		}
		Ip getTargetIp(int idx){
			return this->targets_ip[idx];
		}
		Mac getMac(){
			return mymac;
		}
		void setIpMac(string ip,string mac);
		Ip getIp(){
			return myip;
		}
};

string hextoIp(const u_char* packet){
	string mac="";
	for(int i=0;i<6;i++){
		std::stringstream stream;
		stream << hex << setfill('0') << setw(2) << static_cast<int>(packet[i]);
		mac += stream.str();
		if(i<5) mac += ':';
	}
	return mac;
}

int main(int argc, char* argv[]) {
	//인자가 적을경우 종료 
	if (argc < 4) {
		usage();
		return -1;
	}
	//packet initialize
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFFSIZE, 1, 1, errbuf);
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
	//나의 ip주소 구하기

	//Mac과 Ip로 초기화
	Arpspoofer arpspoofer = Arpspoofer(my_mac_addr,/*Ip*/);
	
	for(int i=2;i<argc;i++){
		string tmp(argv[i]);
		Ip tmpip = Ip(tmp);
		if(i%2==0){
			arpspoofer.addIp("sender",tmpip);
		}
		else{
			arpspoofer.addIp("target",tmpip);
		}

	}
	//Sender와 Target의 mac주소를 ARP request로 알아오기 
	for(int i=0;i<arpspoofer.getSenderCount();i++){
		Ip sender_ip = arpspoofer.getSenderIp(i);
		Ip target_ip = arpspoofer.getTargetIp(i);
		//sender mac주소를 ARP 프로토콜로 Request 
		arpspoofer.sendArpPacket(string(arpspoofer.getMac()),"ff:ff:ff:ff:ff:ff",string(arpspoofer.getIp()),"00:00:00:00:00:00",string(sender_ip),handle,ArpHdr::Request);
		//Sender ARP 응답패킷 캡쳐 
		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			EthHdr* ethhdr = (EthHdr*)packet;
			u_int16_t type = ethhdr->type_;
			packet+=sizeof(ethhdr); /*packet 포인터 이동*/
			/*ARP header Tokenizing*/
			ArpHdr* arphdr = (ArpHdr*)packet;
			Mac smac_ = arphdr->smac_;
			Ip sip_ = arphdr->sip_;
			Mac tmac_ = arphdr->tmac_;
			Ip tip_=arphdr->tip_;

			
		}
		
		//target mac주소를 ARP 프로토콜로 Request 
		arpspoofer.sendArpPacket(string(arpspoofer.getMac()),"ff:ff:ff:ff:ff:ff",string(arpspoofer.getIp()),"00:00:00:00:00:00",string(target_ip),handle,ArpHdr::Request);
		//Target ARP 응답패킷 캡쳐 
		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			EthHdr* ethhdr = (EthHdr*)packet;
			u_int16_t type = ethhdr->type_;
			packet+=sizeof(ethhdr); /*packet 포인터 이동*/
			/*ARP header Tokenizing*/
			ArpHdr* arphdr = (ArpHdr*)packet;
			Mac smac_ = arphdr->smac_;
			Ip sip_ = arphdr->sip_;
			Mac tmac_ = arphdr->tmac_;
			Ip tip_=arphdr->tip_;
		}
	
	}

	//ARP 캐시 테이블 Infection



	pcap_close(handle);
}
