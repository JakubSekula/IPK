#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<getopt.h>
#include<unistd.h>
#include <netdb.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
#include <time.h>
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>   
#include<netinet/ip.h>    

void printFirstLine( struct iphdr *iph, const u_char * packet, const struct pcap_pkthdr *header, int type );
void packet_handle( u_char *, const struct pcap_pkthdr *, const u_char * );
void PrintData ( const u_char * , int );

void PrintData ( const u_char * data , int Size ){
    int i , j;
    i = 0;
    while( i < Size ){
    	// Na radek se tiskne 16 znaku
        if( i != 0 && i % 16 == 0 )   
        {
        	// vytisknu mezery na radku
            printf("         ");

            for( j = i - 16; j < i; j++){
            	// jestlize je znak mezu ASCII 32 a 126 tak ho vypisu, jinak .
            	if( data[ j ] >= 32 && data[ j ] <= 126 ){
                    printf("%c",(unsigned char)data[j]); 
            	} else {
            		printf( ".");
            	}
            }
            // na konci radku tisknu novy radek
            printf( "\n");
        } 

        // na zacatek radku vytisknu hexa iterator, pokud se nachazim na zacatku radku
        if( i % 16 == 0 ){
         	printf( "0x%04x", i );
        }

        // tisknu hexa znaky
        printf( " %02x", ( unsigned int ) data[ i ] );
             
        // tisknu posledni znaky
        if( i == Size - 1 ){
            
            // tisknu mezery do konce radku, abych pak mohl vypsat zpravu na stejne urovni jako plny radek
            for( j = 0; j < 15 - i % 16; j++ ) {
              printf( "   " );
            }

            // mezera mezi hexa cislami a zpravou
            printf( "         " );
             
            // tisknu 16 znaku jakozto zpravu
            for( j = i - i % 16; j <= i; j++ ){
            	// jestlize je znak v ASCII mezi 32 a 126 tisknu jinak tisknu .
            	if( data[ j ] >= 32 && data[ j ] <= 126 ){
                  printf( "%c", ( unsigned char ) data[ j ] );
                } else {
                  printf( ".");
                }
            }
            printf(  "\n" );
            }
    	i++;
	}
}

void printFirstLine( struct iphdr *iph, const u_char * packet, const struct pcap_pkthdr *header, int type ){

	unsigned short iphdrlen;
	struct sockaddr_in source, dest;

	char hostnames[ NI_MAXHOST ];
    char hostnamed[ NI_MAXHOST ];

	// ip hlavicka paketu
  	struct iphdr *ipht = ( struct iphdr * )( packet  + sizeof( struct ethhdr ) );
  	
  	// velikost hlavicky paketu
    iphdrlen = ipht->ihl*4;

    // ziskani tcp hlavicky paketu, odlisnost od udp paketu
    struct tcphdr *tcph=( struct tcphdr* )( packet + iphdrlen + sizeof( struct ethhdr ) );
    struct udphdr *udph=( struct udphdr* )( packet + iphdrlen + sizeof( struct ethhdr ) );

    // vynulovani pozice v pameti a odkaz na strukturu, kvuli ip adrese zdroje
	memset( &source, 0, sizeof( source ) );
    source.sin_addr.s_addr = iph->saddr;

    // vynulovani pozice v pameti a odkaz na strukturu, kvuli ip adrese cile 
    dest.sin_addr.s_addr = iph->daddr;
    
    struct in_addr addr;
    // prevod na ip
    inet_aton( inet_ntoa( source.sin_addr ), &addr );
        
    // konverze casu z hlavicky na struct tm
    struct tm *timeinfo = gmtime(( const time_t *) &header->ts.tv_sec );

    // uprava pro funkci getnameinfo
    source.sin_family = AF_INET;
    dest.sin_family = AF_INET;

    // prevod na format ip
    inet_pton( AF_INET, inet_ntoa( source.sin_addr ), &source.sin_addr );

    int founds = 0;
    int foundd = 0;

    if( getnameinfo( ( struct sockaddr* ) &source, sizeof( source ), hostnames, sizeof( hostnames ), NULL, 0, NI_NAMEREQD ) == 0 ){
    	founds = 1;
    }

    if( getnameinfo( ( struct sockaddr* ) &dest, sizeof( dest ), hostnamed, sizeof( hostnamed ), NULL, 0, NI_NAMEREQD ) == 0 ){
    	foundd = 1;
    }

    // promenne pro ulozeni ip adres, nebo fqdn
    char* src_ip;
    char* dst_ip;

    if( founds == 1 ){
    	src_ip = hostnames;
    } else {
    	src_ip = inet_ntoa( source.sin_addr );
    }

    if ( foundd == 1 ){
    	dst_ip = hostnamed;
    } else {
    	dst_ip = inet_ntoa( dest.sin_addr );
    }

    // vypis 1. radku vypisu 
    if( type == 6 ){
		printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d \n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, src_ip, ntohs( tcph->source), dst_ip, ntohs( tcph->dest ) ); 
  	} else {
  		printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d \n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, src_ip, ntohs( udph->source), dst_ip, ntohs( udph->dest ) );
  	}
}

void packet_handle( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{
	// ziskani velikosti packetu
    int size = header->len;

    // nastaveni prekladace aby ignoroval nepouzitou promennou args
    u_char* a __attribute__(( unused ));

   	a = args;

   	// ip ziskani hlavicky paketu, kvuli protokolu
    struct iphdr *iph = ( struct iphdr* )( packet + sizeof( struct ethhdr ) );

    switch ( iph->protocol ) 
    {
         case 6:  
         	// TCP Protocol, volani oproti UDP pouziva jinak struktury
         	printFirstLine( iph, packet, header, 6 );
         	PrintData( packet, size );
            break;
        case 17: 
        	// UDP Protocol
        	printFirstLine( iph, packet, header, 17 );
        	PrintData( packet, size );
            break;
        default: 
        	// Jestlize neni TCP ani UDP tak nedelam nic a jdu na dalsi paket pokud je
            break;
    }
}   

int main( int argc, char *argv[] ){
		
		// promenne pro argumenty vstupu
		int both = 1;
	    char* p = NULL;
	    int count = 1;
	    char* interface = NULL;
	    int udp = 0;
	    int tcp = 0;
	    
	    // promenne a struktura pro funkci getopt_long
	    int opt;
	    int option_index = 0;
	    static struct option long_options[] = {
	            { "udp",  no_argument, 0,  'u' },
	            { "tcp",  no_argument, 0,  't' }
	    };

	    // funkce getopt_long ziska ze vstupu argumenty programu a rozdeli je do promennych
	    while( ( opt = getopt_long( argc, argv, "i:n:utp:", long_options, &option_index ) ) != -1 ){
        switch( opt ){
            case 'i':
                interface = optarg;
                break;
            case 'p':
                p = optarg;
                break;
            case 'u':
                udp = 1;
                both = 0;
                break;
            case 't':
            	tcp = 1;
                both = 0;
                break;
            case 'n':
                count = atoi( optarg );
                break;
            default:
                return( 32 );
        	}
    	}

    	// promenna pro chybove vystupy pcap funkci
    	char errbuf[ PCAP_ERRBUF_SIZE ];
    	
    		// jestlize nebylo zadane rozhrani
	    	if( interface == NULL ){
	    	pcap_if_t *alldevsp, *device;
	    	
	    	if( pcap_findalldevs( &alldevsp , errbuf) )
		    {
		        printf( "Error finding devices : %s" , errbuf );
		        return( 32 );
		    }
		    // vypisu dostupna rozhrani
		    for( device = alldevsp; device != NULL; device = device->next )
		    {
		        printf( "%s\n" ,  device->name );
		    }
		    return( 0 );
		}
    	
    	char* port = NULL;

    	// jestlize byl zadan parametr port
    	if( p ){
			char* a = "port ";
			port = malloc( 1 + strlen( a ) + strlen( p ) );
		}

		if( udp == 1 && tcp == 1 ){
        	both = 1;
        	udp = 0;
        	tcp = 0;
    	}

    	// nastavim odpovidajici filtr na port a pripadne i protokol
    	if( port ){
			if( tcp == 1 ){
				strcpy( port, "tcp port " );
			} else if( udp == 1 ){
				strcpy( port, "udp port " );
			} else if ( both == 1 ) {
				strcpy( port, "port " );
			} else {
				return( 32 );
			}


			strcat( port, p );

		// jestlize nebyl zadan port
		} else {
			if( tcp == 1 ){
				port = "tcp";
			} else if ( udp == 1 ){
				port = "udp";
			} else {
				port = "";
			}
		}

    	pcap_t *handle;			/* handler sezeni */
		char *dev;			/* zarizeni pro sniffovani */
		struct bpf_program fp;		/* zkompilovany filter */
		char* filter_exp = port;	/* filtrovane zarizeni */
		bpf_u_int32 mask;		/* Nase netmask */
		bpf_u_int32 net;		/* Nase IP */

		/* definice rozhrani */

		dev = interface;
		if (dev == NULL) {
			fprintf( stderr, "Couldn't find default device: %s\n", errbuf );
			return( 2 );
		}

		/* Nalezeni vlastnosti rozhrani */
		if ( pcap_lookupnet( dev, &net, &mask, errbuf ) == -1 ) {
			fprintf( stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf );
			net = 0;
			mask = 0;
		}

		/* otevreni sezeni v promiskuitnim modu */
		handle = pcap_open_live( dev, BUFSIZ, 1, 1000, errbuf );
		if ( handle == NULL ) {
			fprintf( stderr, "Couldn't open device %s: %s\n", dev, errbuf );
			return( 2 );
		}
		/* zkompiluj a uplatni filtr */
		if ( pcap_compile( handle, &fp, filter_exp, 0, net ) == -1 ) {
			fprintf( stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr( handle ) );
			return( 2 );
		}
		if ( pcap_setfilter( handle, &fp ) == -1 ) {
			fprintf( stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr( handle ) );
			return( 2 );
		}
		
		/* Smycka pro paket, ktera se provede count krat, a odvolava se na callback funkci packet_handle */
		pcap_loop( handle , count , packet_handle , NULL );
		
		/* uzavreni sezeni */
		pcap_close(handle);
		return(0);
       
}