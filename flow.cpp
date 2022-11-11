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
#include <stdio.h>
#include <iostream>
#include <map>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	        //misc, ntohs ntohl
#include <netinet/ether.h> 	    //arp, ether
#include <netinet/ip6.h> 	    //ipv6
#include <netinet/tcp.h>	    //tcp
#include <netinet/ip_icmp.h>	//ipv4, icmp
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>


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
#define DEFAULT_COLLECTOR_IP "127.0.0.1"
#define DEFAULT_COLLECTOR_PORT "2055"
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
#define INVALID_PORT 3
#define INVALID_C_ARG 4

    //EXPORT BUFFER
#define BUFFER 1024

//namespace
using namespace std;



/**
 * Structure for packet/flow data
 */
struct packet_data
{
    uint32_t time_stamp;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
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

struct netflow_header
{
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
};


//NAMESPACE
//STRUCTURES
typedef struct packet_data packet_data;
typedef struct flow_data flow_data;
typedef struct netflow_header netflow_header;

/**
 * key_t is an unique key for a flow stored in a map
 */
typedef tuple<string, string, uint16_t, uint16_t, uint8_t> map_key_t;


//FUNCTIONS
void print_flow_id(map_key_t flow_key);
packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet);
map_key_t get_flow_key(packet_data pd);
void init_flow(packet_data* packet, flow_data* flow);
void set_netflow_header(netflow_header* nf_header, uint32_t sys_uptime, uint32_t unix_nsecs, uint32_t flow_sequence);
void export_flow(flow_data flow, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, int flow_sequence);



//GLOBAL VARIABLES
pcap_t *pcap_capture;
struct pcap_pkthdr header;
const u_char *packet;
char errbuf[PCAP_ERRBUF_SIZE];


//global program arguments
string  src_filename = DEFAULT_FILE,\
        collector_ip = DEFAULT_COLLECTOR_IP,\
        collector_port = DEFAULT_COLLECTOR_PORT;

int     active_timer     = DEFAULT_ACTIVE_TIMER,\
        inactive_timer   = DEFAULT_INACTIVE_TIMER,\
        flow_cache       = DEFAULT_FLOW_CACHE;



int main(int argc, char **argv) {

    //ARG PARSING
    //Parameter init & default set


    int opt;
    while ((opt = getopt(argc, argv, "f:c:a:i:m:h")) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'f':
                src_filename = optarg;
                break;
            case 'c':
                //parse the IP and Port values
                try{
                    string tmp_str = optarg;
                    int pos = tmp_str.find_first_of(':');
                    collector_port = tmp_str.substr(pos+1),
                    collector_ip = tmp_str.substr(0, pos);
                    if(stoi(collector_port) > 65535 || stoi(collector_port) < 0){
                        cerr << "Invalid port entered: Has to be between 0 - 65535. Aborting." << endl;
                        exit(INVALID_PORT);
                    }
                }
                catch(...){
                    cerr << "Invalid -c argument value. See -h for help." << endl;
                    exit(INVALID_C_ARG);
                }
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
    cout << src_filename << endl << collector_ip << endl << collector_port << endl << active_timer << endl << inactive_timer << endl << flow_cache << endl;

    //open capture
    pcap_t* pcap_file = pcap_open_offline(src_filename.c_str(), errbuf);
    if(!pcap_file){
        cout << "Could not open the input file \"" << src_filename << "\". Please enter a valid capture file name." << endl;
        return FILE_ERROR;
    }

    //init main flow-storing structure
    map<map_key_t, flow_data> flow_map;

    //counters and time variables declaration
    int ctr = 0;
    int exp_ctr = 0;
    bool first_packet_flag = true;
    uint32_t sys_start_time;
    uint32_t curr_time;
    uint32_t unix_secs;
    uint32_t unix_nsecs;

    //start reading packets
    while((packet = pcap_next(pcap_file, &header))){
        //get parsed packet data
        packet_data captured_packet = parse_packet(&header, packet);
        //initialize flow key
        map_key_t flow_key = get_flow_key(captured_packet);

        //update time variables with the data from last incoming packet
        curr_time = captured_packet.time_stamp;
        unix_secs = captured_packet.unix_secs;
        unix_nsecs = captured_packet.unix_nsecs;

        //load the device start with the first incoming packet signified by the first_packet_flag
        if(first_packet_flag){
            //set the start time
            sys_start_time = captured_packet.time_stamp;
            //disable this if statement
            first_packet_flag = false;
        }

        //go through flows and check their expiration
        for (auto it = flow_map.cbegin(), next_it = it; it != flow_map.cend(); it = next_it)
        {
            ++next_it;
            if((curr_time - it->second.first_time) > (active_timer * SEC_TO_MSEC) || (curr_time - it->second.last_time > (inactive_timer * SEC_TO_MSEC))){
                cout << "AT Erase " << curr_time - it->second.first_time << " ? " << active_timer * SEC_TO_MSEC << " IT Erase " << curr_time - it->second.last_time << " ? " << inactive_timer * SEC_TO_MSEC  << endl;
                export_flow(it->second, sys_start_time-curr_time, unix_secs, unix_nsecs, exp_ctr);
                flow_map.erase(it);
                exp_ctr++;
            }
        }


        //search for a flow record in the storing map
        auto existing_flow = flow_map.find(flow_key);

        //Create new flow record
        if(existing_flow == flow_map.end()){
            ctr++;

            if(flow_map.size() == flow_cache){
                //TODO zde odstranit nejstarší packet
            }
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
        export_flow(it->second, sys_start_time-curr_time, unix_secs, unix_nsecs, exp_ctr);
        cout<< "END EXPORT ";
        exp_ctr++;
    }

    cout << "FLOWS: " << ctr << " EXPORTED: " << exp_ctr << endl;

    //close pcap file
    pcap_close(pcap_file);
    return(0);
}
void export_flow(flow_data flow, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, int flow_sequence)
{
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server, from; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    socklen_t len, fromlen;
    char buffer[BUFFER];
//
//
//    memset(&server,0,sizeof(server)); // erase the server structure
//    server.sin_family = AF_INET;
//
//    // make DNS resolution of the first parameter using gethostbyname()
    if ((servent = gethostbyname(collector_ip.c_str())) == NULL) // check the first parameter
    errx(1,"gethostbyname() failed\n");
//
//    servent = gethostbyname()
//
//    // copy the first parameter to the server.sin_addr structure
//    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);
//
//    server.sin_port = htons(atoi(argv[2]));        // server port (network byte order)
//
//    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
//    err(1,"socket() failed\n");
//
//    printf("* Server socket created\n");
//
//    len = sizeof(server);
//    fromlen = sizeof(from);
//
//    printf("* Creating a connected UDP socket using connect()\n");
//    // create a connected UDP socket
//    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
//    err(1, "connect() failed");
//
//    //send data to the server
//    while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0)
//    // read input data from STDIN (console) until end-of-line (Enter) is pressed
//    // when end-of-file (CTRL-D) is received, n == 0
//    {
//    i = send(sock,buffer,msg_size,0);     // send data to the server
//    if (i == -1)                   // check if data was sent correctly
//    err(1,"send() failed");
//    else if (i != msg_size)
//    err(1,"send(): buffer written partially");
//
//    // obtain the local IP address and port using getsockname()
//    if (getsockname(sock,(struct sockaddr *) &from, &len) == -1)
//    err(1,"getsockname() failed");
//
//    printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);
//
//    // read the answer from the server
//    if ((i = recv(sock,buffer, BUFFER,0)) == -1)
//    err(1,"recv() failed");
//    else if (i > 0){
//    // obtain the remote IP adddress and port from the server (cf. recfrom())
//    if (getpeername(sock, (struct sockaddr *)&from, &fromlen) != 0)
//    err(1,"getpeername() failed\n");
//
//    printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
//    printf("%.*s",i,buffer);                   // print the answer
//    }
//    }
//    // reading data until end-of-file (CTRL-D)
//
//    if (msg_size == -1)
//    err(1,"reading failed");
//    close(sock);
//    printf("* Closing the client socket ...\n");
//    return 0;
}



void init_flow(packet_data* packet, flow_data* flow)
{
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


void set_netflow_header(netflow_header* nf_header, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence)
{
    nf_header->version = 5;
    nf_header->sys_uptime = sys_uptime;
    nf_header->unix_secs = unix_secs;
    nf_header->unix_nsecs = unix_nsecs;
    nf_header->flow_sequence = flow_sequence;
    //always exporting serially
    nf_header->count = 1;
    //zero fields
    nf_header->engine_id =\
    nf_header->engine_type =\
    nf_header->sampling_interval = 0;
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
    uint32_t tm_sec = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
    new_packet.time_stamp = tm_sec;
    new_packet.unix_secs = header->ts.tv_sec;
    new_packet.unix_nsecs = header->ts.tv_usec;

    //init ether header struct
    struct ether_header *eth_header = (ether_header*)packet;

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
 *              SYSstarttime ->> prvni packet ever proste ten uplne prvni
 *              sysuptime = currtime - sysstarttime
 *              TCP 105 PACKETU
 *              first = curr - sysstart(oba milisekundy)
 *
 *
 *              OTAZKY
 *
 *              CURRENT TIME -> TYP, VELIČINA milisekundy
 *              FIRST/LAST -> TYP, VELIČINA milisekundy
 *              NETFLW HDR -> sec: sekundy z pakitu
 *
 *               //TODO FINALS: Kontorla inputu arguemntů, exporting celej. Stačí si vzít inputy, vygenerovat header a poslat
 *
 *
 *               usec: mikrosec z pakitu  -- obe z tm, schovat do flow.
 * */