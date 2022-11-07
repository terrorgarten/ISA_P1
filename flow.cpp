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
//TODO Remove
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
#define SEC_TO_MSEC 1000

//ERRORS
#define FILE_ERROR 1
#define INVALID_IP_PROTOCOL 2

using namespace std;


/**
 * Structure for packet/flow data
 */
struct packet_data
{
    uint32_t time_stamp;
    uint8_t source_mac[ETH_ALEN];
    uint8_t destination_mac[ETH_ALEN];
    in_addr source_ip;
    in_addr destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t type_of_service;
    uint8_t ip_protocol;
    uint8_t tos;
    uint8_t tcp_flags;
    uint32_t ip_hdr_len;
};

/**
 * @name flow_data
 * @note Structure for saving flow data
 * Fields marked as zero fields are not to be used in this project
 */
struct flow_data
{
    in_addr source_ip;
    in_addr destination_ip;
    uint32_t nexthop;   //ZERO FIELD
    uint16_t input;     //ZERO FIELD
    uint16_t output;    //ZERO FIELD
    uint32_t packet_count;
    uint32_t ip_header_total_size;
    uint32_t first_time;
    uint32_t last_time;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t pad1;           //ZERO FIELD
    uint8_t tcp_flags;
    uint8_t ip_protocol;
    uint8_t tos;
    uint16_t source_as;     //ZERO FIELD
    uint16_t destination_as;//ZERO FIELD
    uint8_t source_mask;    //ZERO FIELD
    uint8_t destination_mask;//ZERO FIELD
    uint16_t pad2;          //ZERO FIELD
};



//NAMESPACE
//STRUCTURES
typedef struct packet_data packet_data;
typedef struct flow_data flow_data;

/**
 * key_t is an unique key for a flow stored in a map
 */
typedef tuple<string, string, uint16_t, uint16_t, uint8_t> map_key_t;


//FUNCTIONS
void print_flow_id(map_key_t flow_key);
packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet);
map_key_t get_flow_key(packet_data pd);
void init_flow(packet_data* packet, flow_data* flow);
void export_flow(flow_data flow);



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

    //init main flow-storing structure
    map<map_key_t, flow_data> flow_map;

    int ctr = 0;
    int exp_ctr = 0;

    //start reading packets
    while((packet = pcap_next(pcap_file, &header))){
         //FIXME REMOVE FOR SHARP VERSION

        //get parsed packet data
        packet_data captured_packet = parse_packet(&header, packet);
        //initialize flow key
        map_key_t flow_key = get_flow_key(captured_packet);
        //update last time stamp - virtual current time
        uint32_t curr_time = captured_packet.time_stamp;

        //go through flows and check their expiration
        for (auto it = flow_map.cbegin(), next_it = it; it != flow_map.cend(); it = next_it)
        {
            ++next_it;
            if((curr_time - it->second.first_time) > (active_timer * SEC_TO_MSEC) || (curr_time - it->second.last_time > (inactive_timer * SEC_TO_MSEC))){
                cout << "AT Erase " << curr_time - it->second.first_time << " ? " << active_timer * SEC_TO_MSEC << " IT Erase " << curr_time - it->second.last_time << " ? " << inactive_timer * SEC_TO_MSEC  << endl;
                export_flow(it->second);
                flow_map.erase(it);
                exp_ctr++;
            }
        }

        //search for a flow record in the storing map
        auto existing_flow = flow_map.find(flow_key);

        //Create new flow record
        if(existing_flow == flow_map.end()){
            ctr++;
            flow_data new_flow;
            init_flow(&captured_packet, &new_flow);
            flow_map[flow_key] = new_flow;
            cout << "ADDED!" << endl;
            print_flow_id(flow_key);
        }
        //Update flow record
        else{
            existing_flow->second.last_time = captured_packet.time_stamp;
            existing_flow->second.ip_header_total_size += captured_packet.ip_hdr_len;
            existing_flow->second.packet_count++;
            existing_flow->second.tcp_flags |= captured_packet.tcp_flags;
            cout << "EXISTS!" << endl;
            print_flow_id(flow_key);
        }
    }
    //export the remaining flows
    for (auto it = flow_map.cbegin(), next_it = it; it != flow_map.cend(); it = next_it)
    {
        ++next_it;
        export_flow(it->second);
        cout<< "END EXPORT ";
        exp_ctr++;
    }

    cout << "FLOWS: " << ctr << " EXPORTED: " << exp_ctr << endl;


    /* Print its length */
    /* And close the session */
    pcap_close(pcap_file);
    return(0);
}
void export_flow(flow_data flow){
    cout << "                      ->>> EXPORTED" << endl;
}

void init_flow(packet_data* packet, flow_data* flow){
    //load data from packet
    flow->source_ip = packet->source_ip;
    flow->destination_ip = packet->destination_ip;
    flow->source_port = packet->source_port;
    flow->ip_protocol = packet->ip_protocol;
    flow->tos = packet->type_of_service;
    flow->first_time = packet->time_stamp;
    flow->last_time = packet->time_stamp; //TODO CHECK JESTLI TOTO NEVYHAZUJE ZBYTECNE
    flow->packet_count = 1; //initiating for first packet
    flow->ip_header_total_size = packet->ip_hdr_len;
    flow->tcp_flags = packet->tcp_flags;
    //zero fields
    flow->nexthop =\
    flow->input =\
    flow->output =\
    flow->pad1 =\
    flow->source_as =\
    flow->destination_as =\
    flow->source_mask =\
    flow->destination_mask =\
    flow->pad2 = 0;
}



void print_flow_id(map_key_t flow_key)
{
    cout << get<0>(flow_key) << "\t" << get<1>(flow_key) << "\t" << get<2>(flow_key) << "\t" << get<3>(flow_key) << "\t" << get<4>(flow_key) << endl << endl;

//    time_t* time = &tm_sec;
//    char time_sec_char[TIME_BUFF_SIZE];
//    strftime(time_sec_char, TIME_BUFF_SIZE, "%d.%m.%Y %H:%M:%S", localtime(*time));
//    cout << "TIMESTAMP: " << tm_sec /*<< ":"<< time_usec_char*/ << endl;
}

map_key_t get_flow_key(packet_data pd){
    string source_ip = inet_ntoa(pd.source_ip);
    string destination_ip = inet_ntoa(pd.destination_ip);
    map_key_t key(source_ip, destination_ip, pd.source_port, pd.destination_port, pd.ip_protocol);
    return key;
};


packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet)
{
    //init structs  see web for constants
    struct ip *ip;
    uint32_t ip_hdr_len;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;
    packet_data new_packet;

    //convert to miliseconds
    uint32_t tm_sec = header->ts.tv_sec * 1000 + header->ts.tv_usec/1000;
    new_packet.time_stamp = tm_sec;

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
    ip_hdr_len = ip->ip_hl * 4;

    new_packet.ip_hdr_len = ip_hdr_len;
    new_packet.source_ip = ip->ip_src;
    new_packet.destination_ip = ip->ip_src;
    new_packet.ip_protocol = ip->ip_p;
    new_packet.tos = ip->ip_tos;


    switch(ip->ip_p){
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr*)(packet + SIZE_ETHERNET + ip_hdr_len);
            new_packet.source_port = tcp_hdr->th_sport;
            new_packet.destination_port = tcp_hdr->th_dport;
            new_packet.tcp_flags = tcp_hdr->th_flags;
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
 *              TODO
 *              Přidat TCP flags, packetcount, doctets
 *
 *
 *
 * */