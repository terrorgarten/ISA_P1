//
// Created by terrorgarten on 20.10.22.
//

#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <vector>
#include <pcap.h>
#include <stdlib.h>
#include <iostream>
#include <string>

//FIXME ?
#define OPT1 0
//DEFINITIONS
#define DEFAULT_FILE "-"
#define DEFAULT_COLLECTOR_IP "127.0.0.1:2055"
#define DEFAULT_ACTIVE_TIMER 60
#define DEFAULT_INACTIVE_TIMER 10
#define DEFAULT_FLOW_CACHE 1024

#define FILE_ERROR 1

//NAMESPACE
using namespace std;

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
    /* Grab a packet */
    while((packet = pcap_next(pcap_file, &header))){
        printf("Jacked a packet with length of [%d]\n", header.len);
    }

    /* Print its length */
    /* And close the session */
    pcap_close(pcap_file);
    return(0);





    return 0;


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