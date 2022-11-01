//
// Created by terrorgarten on 20.10.22.
//

#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <vector>
#include <tuple>
#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <map>
#include <string>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	        //misc, ntohs ntohl
#include <netinet/ether.h> 	    //arp, ether
#include <netinet/ip6.h> 	    //ipv6
#include <netinet/tcp.h>	    //tcp
#include <netinet/ip_icmp.h>	//ipv4, icmp
#include <netinet/ip.h>
#include <netinet/udp.h>

//DEBUG MACRO
#define DEBUG_BUILD 1
#ifdef DEBUG_BUILD
#   define DEBUG(x) do { cout << #x << " " << x } while (0)
#else
#  define DEBUG(x) do {} while (0)
#endif

//DEFINITIONS
    //ARGS
#define DEFAULT_FILE "-"
#define DEFAULT_COLLECTOR_IP "127.0.0.1:2055"
#define DEFAULT_ACTIVE_TIMER 60
#define DEFAULT_INACTIVE_TIMER 10
#define DEFAULT_FLOW_CACHE 1024
    //HEADER SIZES
#define SIZE_ETHERNET 14

    //TIME
#define TIME_BUFF_SIZE 30


//ERRORS
#define FILE_ERROR 1
#define INVALID_IP_PROTOCOL 2

//NAMESPACE
using namespace std;


//STRUCTURES
/**
 * Structure for packet/flow data
 */
struct packet_data
{
    struct tm time_stamp;
    uint8_t source_mac[ETH_ALEN];
    uint8_t destination_mac[ETH_ALEN];
    in_addr source_ip;
    in_addr destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t type_of_service;
    uint8_t ip_protocol;
};
typedef struct packet_data packet_data;

/**
 * key_t is an unique key for a flow stored in a map
 */
typedef tuple<string, string, uint16_t, uint16_t, uint8_t> map_key_t;

;



//FUNCTIONS
packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet);
map_key_t get_flow_key(packet_data pd){
    string source_ip = inet_ntoa(pd.source_ip);
    string destination_ip = inet_ntoa(pd.destination_ip);
    map_key_t key(source_ip, destination_ip, pd.source_port, pd.destination_port, pd.ip_protocol);
    return key;
};

//void add_flow(map<map_key_t, packet_data> flow_map, packet_data pd){
//    map_key_t key = get_flow_key(pd);
//    flow_map.insert({key, pd});
//}

//GLOBAL VARIABLES
pcap_t *pcap_capture;
struct pcap_pkthdr header;
const u_char *packet;
char errbuf[PCAP_ERRBUF_SIZE];





int main(int argc, char **argv) {

    //ARG PARSING
    //Parameter init & default set
    string  src_filename = DEFAULT_FILE,\
            collector_ip = DEFAULT_COLLECTOR_IP;
    int active_timer     = DEFAULT_ACTIVE_TIMER,\
        inactive_timer   = DEFAULT_INACTIVE_TIMER,\
        flow_cache       = DEFAULT_FLOW_CACHE;

    int opt;
    while ((opt = getopt(argc, argv, "f:c:a:i:m:h")) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'f':
                src_filename = optarg;
                break;
            case 'c':
                collector_ip = optarg;
                break;
            case 'a':
                active_timer = atoi(optarg);
                break;
            case 'i':
                inactive_timer = atoi(optarg);
                break;
            case 'm':
                flow_cache = atoi(optarg);
                break;
            case 'h':
                cout << "USAGE:" << endl << "-f\t Set source file" << endl << "-c\t Set NetFlow collector IP" << endl << "-a\t Set active timer" << "-i\t Set inactive timer" << endl << "-m\t Set cache memory size" << endl;
                break;
            case '?':
                cout << "Invalid argument has been passed. Please use -h to print usage." << endl;
                break;
            //FIXME dead code
            case -1:
                break;
        }
    }
    //TODO REMOVE DEBUG
    cout << src_filename << endl << collector_ip << endl << active_timer << endl << inactive_timer << endl << flow_cache << endl;

    //open capture
    pcap_t* pcap_file = pcap_open_offline(src_filename.c_str(), errbuf);
    if(!pcap_file){
        cout << "Could not open the input file \"" << src_filename << "\". Please enter a valid capture file name." << endl;
        return FILE_ERROR;
    }

    map<map_key_t, packet_data> flow_map;
    int ctr = 0;
    /* Grab a packet */
    while((packet = pcap_next(pcap_file, &header))){
        ctr++;
        printf("Jacked a packet with length of [%d]\n", header.len);
        packet_data captured_packet = parse_packet(&header, packet);
        map_key_t flow_key = get_flow_key(captured_packet);
        flow_map[flow_key] = captured_packet;
        cout << ctr << endl;
    }


    /* Print its length */
    /* And close the session */
    pcap_close(pcap_file);
    return(0);
}


packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet)
{
    //init structs  see web for constants
    struct ip *ip;
    int ip_hdr_len;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;
    packet_data new_packet;

    //format and print timestamp
    struct tm *tm_sec = localtime(&(header->ts.tv_sec));
    new_packet.time_stamp = *tm_sec;

    //init ether header struct
    struct ether_header *eth_header = (ether_header*)packet;
    //fill MAC address
    for(auto i = 0; i <= ETH_ALEN; i++)
    {
        new_packet.source_mac[i] = eth_header->ether_shost[i];
        new_packet.destination_mac[i] = eth_header->ether_dhost[i];
    }

    //fill ip data
    ip = (struct ip*)(packet + SIZE_ETHERNET);
    ip_hdr_len = ip->ip_p * 4;

    new_packet.source_ip = ip->ip_src;
    new_packet.destination_ip = ip->ip_src;
    new_packet.ip_protocol = ip->ip_p;
    switch(ip->ip_p){
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr*)(packet + SIZE_ETHERNET + ip_hdr_len);
            new_packet.source_port = tcp_hdr->th_sport;
            new_packet.destination_port = tcp_hdr->th_dport;
            break;
        case IPPROTO_UDP:
            udp_hdr = (struct udphdr*)(packet + SIZE_ETHERNET + ip_hdr_len);
            new_packet.source_port = udp_hdr->uh_sport;
            new_packet.destination_port = udp_hdr->uh_dport;
            break;
        default:
            cerr << "Invalid IP protocol header encountered. The input file might be corrupt." << endl;
            exit(INVALID_IP_PROTOCOL);
    }

    return new_packet;
}



/**
 * FLOW - stejný:
 *          protokol - udp tcp icmp
 *          src, dst
 *
 *
 *          TOS === prio packetů pro zpracování na routeru
 *
 *          dvě omezení . active/inactive timer
 *                          active - pokud nejstarší packet 60s tak exportuj flow a pro další packety založ nový
 *                          inactive - (icmp .. )  pokud bylo spojeni inactive po urcitou dobu (inactive dobu) tak ukoncim a generuju flow
 *
*           STRUKTURA:
 *           1 - sniffer
 *              a) argparse: -c -> 1.1.1.1:1/localhost:1/fit.vutbr.cz:44 <- gethostbyname() -> prevod DNS
 *              b) otevrit pcap soubor -> pcap_fopen_offline(file f)
 *              c) cyklus pro cteni dat ze souboru - pcap_next() [vraci dalsi pcap z .pcap souboru]
 *              d) parsing packetu do datovych struktur ethHeader = (struct ether_header *)frame; ziskat jestli IP nebo ICMP. if(ethHeader->protocol == "IP"){...}
 *                 struct ip *ip header = (struct ip*)(frame + ETH_HEAD_SIZE);
 *                 !! VŠUDE MASKY 32
 *
 *                 eth-> ip/icmp
 *                 ip -> srcip, dstip, tos, iphdr_size ( z UHL)
 *                 tcp-> srcport, dstport
 *              e) vygeneruj flow - projdi celej dict flowů, na každý dám timer -i/-a. Najdu příslušný flow nebo z něj udělám nový
 *              f) ještě předtím projdu list a odstraním staré flows podle a/i hodnot
 *              g) export packetu - prevod ze struktur do NETFLOW packetu
 *
 *
 *              !!TCP - nese info o informaci spojeni - muzes ho ukoncit driv, ale asi to nebude potreba protoze to zvladne time ouit. NEKDO TO ALE MUZE OJEBAT
 *
 *
 *
 * */