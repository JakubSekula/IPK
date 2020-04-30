#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<getopt.h>
#include<unistd.h>
#include<netdb.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
#include<time.h>
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>   
#include<netinet/ip.h>   
#include<linux/ipv6.h> 
#include<ctype.h>
#include<stdbool.h> 

/*
** Funkce kontroluje spravnost ciselnych argumentu
*/
bool isNumber(char number[]);

/*
** Funkce tiskne prvni radek a to pro ipv4
*/
void printFirstLine( struct iphdr *iph, const u_char * packet, const struct pcap_pkthdr *header, int type );

/*
** Funkce tiskne prvni radek a to pro ipv6
*/
void printFirstLineIPV6( struct ipv6hdr *iph, const u_char * packet, const struct pcap_pkthdr *header, int type );

/*
** Funkce ziska z paketu jeho delku a dale taky o jaky protokol se jedna. Dale zjistuje, jestli je paket linuxovy nebo klasicky ethernetovy, respketive jeho hlavicky
*/
void packet_handle( u_char *, const struct pcap_pkthdr *, const u_char * );

/*
** Funkce prochazi paket a vola funkce pro vypis 16 znaku na radek
*/
void PrintData ( const u_char * , int );

/*
** Funkce tiskne samotny obsah paketu na radek
*/
void print_message( const u_char * packet , int Size );

// promenna pro uchovani typu hlavicky
int linux;
