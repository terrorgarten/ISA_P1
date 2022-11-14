/**
 * @file flow.cpp - Netflow generator for .pcap files
 * @author Matěj Konopí, FIT BUT
 * @date November 14th 2022
 */

#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <tuple>
#include <stdio.h>
#include <iostream>
#include <map>
#include <string.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>


//-----DEFINITIONS-----//

//ARGUMENT DEFAULTS
#define DEFAULT_FILE "-"
#define DEFAULT_COLLECTOR_IP "127.0.0.1"
#define DEFAULT_COLLECTOR_PORT "2055"
#define DEFAULT_ACTIVE_TIMER 60
#define DEFAULT_INACTIVE_TIMER 10
#define DEFAULT_FLOW_CACHE 1024

//HEADER SIZES
#define SIZE_ETHERNET 14

//TIME CONSTANTS
#define TIME_BUFF_SIZE 30
#define SEC_TO_MSEC 1000

//ERRORS
#define FILE_ERROR 1
#define INVALID_IP_PROTOCOL 2
#define INVALID_PORT 3
#define INVALID_C_ARG 4
#define HOST_RESOLVE_ERROR 5
#define SOCKET_FAIL 6
#define UDP_CONNECT_FAIL 7
#define PACKET_SEND_FAILED 8
#define PARTIAL_BUFFER_WRITE 9

//EXPORT CONSTANTS
#define EXPORT_BUFFER_SIZE 72
#define FLOWS_PER_EXPORT_PACKET 1
#define NETFLOW_VERSION 5

//namespace
using namespace std;

/**
 * @name packet_data
 * @note Structure for packet/flow data
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
    uint32_t ip_len;
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


/**
 * @name netflow_header structure
 * @note used for generation of netflow header for export packet
 */
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


//STRUCTURE TYPEDEFS
typedef struct packet_data packet_data;
typedef struct flow_data flow_data;
typedef struct netflow_header netflow_header;



/**
 * @name map_key_t
 * @note Serves as an unique key for a flow instance stored in a flow map
 */
typedef tuple<string, string, uint16_t, uint16_t, uint8_t> map_key_t;



//FUNCTION DECLARATIONS
void print_flow_id(map_key_t flow_key);
packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet);
map_key_t get_flow_key(packet_data pd);
void init_flow(packet_data* packet, flow_data* flow, uint32_t first_time);
void set_netflow_header(netflow_header* nf_header, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence);
void export_flow(flow_data flow, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence);
map_key_t get_oldest_flow_key(map<map_key_t, flow_data>* flow_map);


//GLOBAL VARIABLES
int export_dbg_counter = 0;

//global program arguments
string  src_filename = DEFAULT_FILE,\
        collector_ip = DEFAULT_COLLECTOR_IP,\
        collector_port = DEFAULT_COLLECTOR_PORT;

int     active_timer     = DEFAULT_ACTIVE_TIMER,\
        inactive_timer   = DEFAULT_INACTIVE_TIMER,\
        flow_cache       = DEFAULT_FLOW_CACHE;



int main(int argc, char **argv) {
    //parse arguments
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
                    //split string by ":" delimiter
                    int pos = tmp_str.find_first_of(':');
                    collector_port = tmp_str.substr(pos+1),
                            collector_ip = tmp_str.substr(0, pos);
                    //check port validity
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
                cout << "USAGE:" << endl << "-f\t Set source file" << endl << "-c\t Set NetFlow collector IP" << endl << "-a\t Set active timer"<< endl << "-i\t Set inactive timer" << endl << "-m\t Set cache memory size" << endl << endl << "Alternatively, see \"man -l flow.1\"" <<endl ;
                return(0);
                break;
            case '?':
                cout << "Invalid argument has been passed, commencing with default values. Please use -h to print usage." << endl;
                break;
            case -1:
                break;
        }
    }
    //print out program parameters
    cout    << "--------PARAMETERS--------" << endl\
            << "Filename: \t" << src_filename << endl \
            << "Collector ip\t" << collector_ip << endl\
            << "Collector port:\t" << collector_port << endl\
            << "Active timer:\t" << active_timer << endl\
            << "Inactive timer:\t"<< inactive_timer << endl\
            << "Max cache size:\t" << flow_cache << endl\
            << "--------------------------" << endl;

    //print header for verbose prints
    cout    << endl <<"Status\t\t    src ip \t\t\tdst ip\t\t\ts.port  d.port" << endl\
                    <<"-----------------------------------------------------" << endl;

    //declare packet parsing variables
    pcap_t *pcap_capture;
    struct pcap_pkthdr header;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];

    //open pcap file for reading
    pcap_t* pcap_file = pcap_open_offline(src_filename.c_str(), errbuf);
    if(!pcap_file){
        cerr << "Could not open the input file \"" << src_filename << "\". Please enter a valid capture file name." << endl;
        return FILE_ERROR;
    }

    //init main flow-storing map
    map<map_key_t, flow_data> flow_map;

    //counters and time variables declaration
    int ctr = 0, packet_ctr = 0;
    uint32_t exp_ctr = 0;
    uint32_t sys_start_time;
    uint32_t curr_time;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t sys_up_time;
    //flag for getting system start time from the first packet
    bool first_packet_flag = true;

    //start reading packets
    while((packet = pcap_next(pcap_file, &header))){
        packet_ctr++;
        //get parsed packet data
        packet_data captured_packet = parse_packet(&header, packet);
        //initialize flow key
        map_key_t flow_key = get_flow_key(captured_packet);
        //update time variables with the data from last incoming packet
        curr_time = captured_packet.time_stamp;
        unix_secs = captured_packet.unix_secs;
        unix_nsecs = captured_packet.unix_nsecs;

        //load the device start time with the first incoming packet signified by the first_packet_flag
        if(first_packet_flag){
            //set the start time
            sys_start_time = captured_packet.time_stamp;
            //disable this if statement
            first_packet_flag = false;
        }

        //calculate uptime since first packet - current time minus start time
        sys_up_time = curr_time - sys_start_time;

        //go through flows and check their expiration
        for (auto it = flow_map.cbegin(), next = it; it != flow_map.cend(); it = next) {
            ++next;
            //check exportation, if the flow is past expiracy, export it
            if ((sys_up_time - it->second.first_time) > (active_timer * SEC_TO_MSEC) ||
                (sys_up_time - it->second.last_time > (inactive_timer * SEC_TO_MSEC))) {
                //export & erase the flow
                export_flow(it->second, sys_up_time, unix_secs, unix_nsecs, exp_ctr);
                flow_map.erase(it);
                exp_ctr++;
            }
        }

        //search for a flow record in the storing map
        auto existing_flow = flow_map.find(flow_key);

        //create new flow record
        if(existing_flow == flow_map.end()){
            ctr++;
            //check for cache space and remove the latest packet if the cache has been filled
            if(flow_map.size() == flow_cache){
                //find the oldest flow key
                map_key_t oldest_key = get_oldest_flow_key(&flow_map);
                //look it up
                auto oldest_flow = flow_map.find(oldest_key);
                //export & erase
                export_flow(oldest_flow->second, sys_up_time, unix_secs, unix_nsecs, exp_ctr);
                flow_map.erase(oldest_flow);
                exp_ctr++;
            }
            //create new flow
            flow_data new_flow;
            init_flow(&captured_packet, &new_flow, sys_up_time);
            //add the flow to the flow map
            flow_map[flow_key] = new_flow;
            cout << "Flow added: \t";
            print_flow_id(get_flow_key(captured_packet));

        }
        //Update flow record
        else{
            existing_flow->second.last_time = sys_up_time;
            existing_flow->second.ip_header_total_size += captured_packet.ip_len;
            existing_flow->second.packet_count++;
            existing_flow->second.tcp_flags |= captured_packet.tcp_flags;
            cout << "Flow updated: \t";
            print_flow_id(existing_flow->first);
            if(captured_packet.tcp_flags & TH_RST || captured_packet.tcp_flags & TH_FIN){
                export_flow(existing_flow->second, sys_up_time, unix_secs, unix_nsecs, exp_ctr);
                flow_map.erase(existing_flow);
                exp_ctr++;
            }

        }
    }

    //reading has finished, now export the remaining flows
    for (auto it = flow_map.cbegin(), next = it; it != flow_map.cend(); it = next)
    {
        ++next;
        export_flow(it->second, (sys_up_time), unix_secs, unix_nsecs, exp_ctr);
        exp_ctr++;
    }

    cout<< endl\
        << "----FINAL STATISTICS----" << endl\
        << "Flows: " << ctr << " Exported: " << exp_ctr << endl\
        << "Packets: " << packet_ctr << endl\
        << "------------------------" << endl;

    //close pcap file
    pcap_close(pcap_file);
    return(0);
}

/**
 * Finds the key to the oldest flow in map
 * @param flow_map
 * @return key to the oldest map
 */
map_key_t get_oldest_flow_key(map<map_key_t, flow_data>* flow_map){
    map_key_t oldest_key;
    uint32_t lowest_time = UINT32_MAX;
    for (auto it = flow_map->cbegin(), next_it = it; it != flow_map->cend(); it = next_it) {
        ++next_it;
        if(it->second.first_time < lowest_time){
            oldest_key = it->first;
        }
    }
    return oldest_key;
}

/**
 * Prints flow identification
 * @param flow_key flow key to print
 */
void print_flow_id(map_key_t flow_key){
    cout << get<0>(flow_key) << "\t" << get<1>(flow_key) << "\t" << get<2>(flow_key) << "\t" << get<3>(flow_key) << endl;
}

/**
 * Creates unique flow identifier
 * @param pd packet
 * @return unique key
 */
map_key_t get_flow_key(packet_data pd){
    string source_ip = inet_ntoa(pd.source_ip);
    string destination_ip = inet_ntoa(pd.destination_ip);
    map_key_t key(source_ip, destination_ip, pd.source_port, pd.destination_port, pd.ip_protocol);
    return key;
};

/**
 * Exports the flow to the collector
 * DISCLAIMER - SECTION OF THIS FUNCTION WAS TAKEN FROM Petr Matoušek's echo-udp-client2.c
 * https://moodle.vut.cz/pluginfile.php/502893/mod_folder/content/0/udp/echo-udp-client2.c?forcedownload=1
 * @param flow flow_data to export
 * @param sys_uptime system uptime
 * @param unix_secs time since epoch (sec)
 * @param unix_nsecs time since epoch (nsecs)
 * @param flow_sequence sequence number of the flow to export
 */
void export_flow(flow_data flow, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence)
{
    netflow_header nf_header;
    set_netflow_header(&nf_header, sys_uptime, unix_secs, unix_nsecs, flow_sequence);

    //convert header members to net byte order
    nf_header.count = htons(nf_header.count);
    nf_header.version = htons(nf_header.version);
    nf_header.sys_uptime = htonl(nf_header.sys_uptime);
    nf_header.unix_secs = htonl(nf_header.unix_secs);
    nf_header.unix_nsecs = htonl(nf_header.unix_nsecs);
    nf_header.flow_sequence = htonl(nf_header.flow_sequence);


    //convert flow members to net byte order
    flow.source_port = htons(flow.source_port);
    flow.destination_port = htons(flow.destination_port);
    flow.first_time = htonl(flow.first_time);
    flow.last_time = htonl(flow.last_time);
    flow.packet_count = htonl(flow.packet_count);
    flow.ip_header_total_size = htonl(flow.ip_header_total_size);


    int sock, i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    char buffer[EXPORT_BUFFER_SIZE];



    //----------- START OF CODE TAKEN FROM echo-udp-client2.c-----------//
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    // make DNS resolution of the first parameter using gethostbyname()
    if ((servent = gethostbyname(collector_ip.c_str())) == NULL) { // check the first parameter
        err(HOST_RESOLVE_ERROR, "Hostname resolution failed during flow export\n");
    }

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);
    server.sin_port = htons(stoi(collector_port));        // server port (network byte order)

    //create a socket
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){
        err(SOCKET_FAIL,"socket() failed\n");
    }

    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){
        err(UDP_CONNECT_FAIL, "connect() failed");
    }

    //copy header and flow data into buffer right next_it to each other
    auto nf_header_size = sizeof(nf_header);
    auto flow_size = sizeof(flow);
    memcpy(buffer, &nf_header, nf_header_size);
    memcpy(buffer + nf_header_size, &flow, flow_size);

    //send the buffer to collector
    i = send(sock,buffer,(nf_header_size + flow_size),0);     // send data to the server
    if (i == -1) {                   // check if data was sent correctly
        err(PACKET_SEND_FAILED, "send() failed");
    }
    else if (i != (nf_header_size + flow_size)) {
        err(PARTIAL_BUFFER_WRITE, "send(): buffer written partially");
    }
    close(sock);
    //----------END OF CODE TAKEN FROM echo-udp-client2.c--------------//
}

/**
 * Initializes new flow
 * @param packet packet data which will be parsed into flow data
 * @param flow initiated flow
 * @param first_time current system uptime
 */
void init_flow(packet_data* packet, flow_data* flow, uint32_t first_time)
{
    //load data from packet
    flow->source_ip = packet->source_ip;
    flow->destination_ip = packet->destination_ip;
    flow->source_port = packet->source_port;
    flow->destination_port = packet->destination_port;
    flow->ip_protocol = packet->ip_protocol;
    flow->tos = packet->type_of_service;
    flow->first_time = first_time;
    flow->last_time = first_time; //TODO CHECK JESTLI TOTO NEVYHAZUJE ZBYTECNE
    flow->packet_count = 1; //initiating for first packet
    flow->ip_header_total_size = packet->ip_len;
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

/**
 * Prepares netflow header for export
 * @param nf_header netflow header structure
 * @param sys_uptime current system uptime
 * @param unix_secs time since epoch (sec)
 * @param unix_nsecs time since epoch (nanosec)
 * @param flow_sequence number of flow in export sequence
 */
void set_netflow_header(netflow_header* nf_header, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence)
{
    nf_header->version = NETFLOW_VERSION;
    nf_header->sys_uptime = sys_uptime;
    nf_header->unix_secs = unix_secs;
    nf_header->unix_nsecs = unix_nsecs;
    nf_header->flow_sequence = flow_sequence;
    //always exporting serially - one by one
    nf_header->count = FLOWS_PER_EXPORT_PACKET;
    //zero fields
    nf_header->engine_id =\
    nf_header->engine_type =\
    nf_header->sampling_interval = 0;
}

/**
 * Parses the pcap packet to intern representation (packet_data)
 * @param header pcap header (from pcap next() or loop()
 * @param packet p packet data
 * @return new prepared packet
 */
packet_data parse_packet(const struct pcap_pkthdr* header, const u_char *packet)
{
    //init structs  see web for constants
    struct ip *ip;
    uint32_t ip_hdr_len;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;
    packet_data new_packet;

    //convert to milliseconds
    uint32_t tm_sec = header->ts.tv_sec * SEC_TO_MSEC + header->ts.tv_usec / 1000;
    new_packet.time_stamp = tm_sec;
    new_packet.unix_secs = header->ts.tv_sec;
    new_packet.unix_nsecs = header->ts.tv_usec*1000;

    //fill ip data
    ip = (struct ip*)(packet + SIZE_ETHERNET);
    ip_hdr_len = ip->ip_hl * 4;
    new_packet.ip_len = ntohs(ip->ip_len);
    new_packet.source_ip = ip->ip_src;
    new_packet.destination_ip = ip->ip_dst;
    new_packet.ip_protocol = ip->ip_p;
    new_packet.tos = ip->ip_tos;

    //fill the rest depending on the packets ip protocol
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
            new_packet.tcp_flags = 0;
            break;
        case IPPROTO_ICMP:
            new_packet.source_port = 0;
            new_packet.destination_port = 0;
            new_packet.tcp_flags = 0;
        default:
            cerr << "Invalid IP protocol header encountered. The input file might be corrupt." << endl;
            exit(INVALID_IP_PROTOCOL);
    }
    return new_packet;
}
