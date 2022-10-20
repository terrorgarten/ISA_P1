//
// Created by terrorgarten on 20.10.22.
//

#include "stdlib.h"
#include "pcap.h"
#include "arpa/inet.h"
#include "getopt.h"
#include "netinet/"
#include "vector"

#define OPT1 0

namespace std;

int main(int argc, char **argv)
{
    parse_args(argc, argv);
    return 0;
}

char* parse_args(int argc, char ** argv)
{
    //define flags

    //options
    static struct option long_opt[] =
            {
                    //setters
                    {"interface", optional_argument, NULL, 'i'},
                    {"num", required_argument, NULL, 'n'},
                    //flags
                    {"tcp", no_argument, &tcp_flag, 1},
                    {"udp", no_argument, &udp_flag, 1},
                    {"arp", no_argument, &arp_flag, 1},
                    {"icmp", no_argument, &icmp_flag, 1},
                    {0, 0, 0, 0}
            };

    //short options
    static char short_opt[] = "i::p:tun:h";

    //cmd line argument
    int cla;
    //index
    extern int optind;
    //cla loading loop
    while((cla = getopt_long(argc, argv, short_opt, long_opt, &optind)) != -1)
    {
        char* tmp_optarg = NULL;
        switch (cla)
        {
            //flag set
            case 0:
                break;
            case 'i': //inspired by https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
                //check if the option argument exits
                if(!optarg && argv[optind] != NULL && '-' != argv[optind][0])
                {
                    //if so, load it to the tmp var
                    tmp_optarg = argv[optind];
                }
                //check if load occured
                if(tmp_optarg){
                    //save the option argument int othe interface variable
                    interface.append(tmp_optarg);
                }
                    // -i was specified alone, special case
                else
                {
                    // -i without param -> print interfaces
                    print_interfaces();
                }
                break;

            case 'p':
                //load port number into the specifier var
                port = stoi(optarg);
                //printf("port: %d", port);
                //cout << "Port: " << port << endl;
                break;

            case 't':
                //set TCP flag
                tcp_flag = 1;
                //cout << "TCP set" << endl;
                break;

            case 'u':
                //set UDP flag
                udp_flag = 1;
                //cout << "UDP set" << endl;
                break;

            case 'n':
                try
                {
                    packet_num = stoi(optarg);
                }
                catch(...)
                {
                    cerr << "Invalid parameter for -n. Use only positive numbers" << endl;
                    exit(ERROR);
                }
                if(packet_num <= 0)
                {
                    cerr << "Invalid parameter for -n. Use only positive numbers" << endl;
                    exit(ERROR);
                }
                break;
            case 'h':
                print_help(argv[0]);
                break;
            case '?':
            default:
                cout << "Uknown option. use -h for help.";
                break;
        }
    }
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