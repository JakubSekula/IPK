#include "ipk-sniffer.h"

void print_message( const u_char * packet , int Size ){

	// provadi tisk maximalne 16 znaku
	int test = 0;
	while( test < Size ){
		// tisknu hexa znaky
    	printf( " %02x", ( unsigned int ) packet[ test ] );	
    	test++;
	}

	// jestlize Size neni 16 takze musim do konce radku vypisu psat mezery
	if( test != 15 ){
		while( test < 16 ){
			printf( "   " );
			test++;
		}
	}

	// mezera mezi vypisy
	printf( "     " );

	// tiskne samotnou zpravu paketu
	for( int j = 0; j < Size; j++){
            	// jestlize je znak mezu ASCII 32 a 126 tak ho vypisu, jinak .
            	if( packet[ j ] >= 32 && packet[ j ] <= 126 ){
                    printf( "%c",( unsigned char ) packet[ j ] ); 
            	} else {
            		printf( ".");
            	}
            }
    printf( "\n" );
}


void PrintData ( const u_char * packet , int Size ){

    int i;
    i = 0;
    while( i < Size ){
    	
    	// na zacatek radku vytisknu hexa iterator
        printf( "0x%04x", i );

        // jestlize lze vytisknou plny radek
        if( i + 16 < Size ){
        	print_message( i + packet, 16 );
        	i = i + 16;
        } else {
        	print_message( i + packet, Size - i );
        	break;
        }
	}
	printf( "\n" );
}


void printFirstLineIPV6( struct ipv6hdr *iph, const u_char * packet, const struct pcap_pkthdr *header, int type ){
	
	// struktura pro uchovani ipv6 portu
	struct sockaddr_in6 source, dest;

	// prevod timestamp z hlavicky paketu
	struct tm *timeinfo = localtime(( const time_t *) &header->ts.tv_sec );

	// promenne pro fqdn
	char hostnames[ NI_MAXHOST ];
    char hostnamed[ NI_MAXHOST ];

    // inicializace pameti a prirazeni portu
    memset( &source, 0, sizeof( source ) );
    source.sin6_addr = iph->saddr;

    memset( &dest, 0, sizeof( dest ) );
    dest.sin6_addr = iph->saddr;

    // rodina adres pro ipv6
    source.sin6_family = AF_INET6;
    dest.sin6_family = AF_INET6;

    // ziskani fqdn nebo ip adresy
    getnameinfo( ( struct sockaddr* ) &source, sizeof( source ), hostnames, sizeof( hostnames ), NULL, 0, 0 );
    getnameinfo( ( struct sockaddr* ) &dest, sizeof( source ), hostnamed, sizeof( hostnamed ), NULL, 0, 0 );
    
    // tcp a udp cast paketu je posunuta o 40 bytu oproti ipv4
    struct tcphdr *tcph=( struct tcphdr* )( packet + 40 + sizeof( struct ethhdr ) );
    struct udphdr *udph=( struct udphdr* )( packet + 40 + sizeof( struct ethhdr ) );

    // 6 znaci tcp paket
    if( type == 6 ){
    	printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d\n\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, hostnames, ntohs( tcph->source ), hostnamed, ntohs( tcph->dest ) );
	} else {
		printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d\n\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, hostnamed, ntohs( udph->source ), hostnamed, ntohs( udph->dest ) );
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
    
    // konverze casu z hlavicky na struct tm
    struct tm *timeinfo = localtime(( const time_t *) &header->ts.tv_sec );

    // rodina adres pro ipv4
    source.sin_family = AF_INET;
    dest.sin_family = AF_INET;

    // prevod na format ip
    inet_pton( AF_INET, inet_ntoa( source.sin_addr ), &source.sin_addr );

    // ziskani fqdn nebo ip adresy
    getnameinfo( ( struct sockaddr* ) &source, sizeof( source ), hostnames, sizeof( hostnames ), NULL, 0, 0 );
    getnameinfo( ( struct sockaddr* ) &dest, sizeof( dest ), hostnamed, sizeof( hostnamed ), NULL, 0, 0 );

    // promenne pro ulozeni ip adres, nebo fqdn
    char* src_ip;
    char* dst_ip;

    src_ip = hostnames;

	dst_ip = hostnamed;
    

    // vypis 1. radku vypisu, 6 znaci tcp paket 
    if( type == 6 ){
		printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d \n\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, src_ip, ntohs( tcph->source ), dst_ip, ntohs( tcph->dest ) ); 
  	} else {
  		printf ( "%02d:%02d:%02d.%02ld %s : %d > %s : %d \n\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, header->ts.tv_usec, src_ip, ntohs( udph->source ), dst_ip, ntohs( udph->dest ) );
  	}
}


void packet_handle( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{
	// ziskani velikosti packetu
    int size = header->len;

    // nastaveni prekladace aby ignoroval nepouzitou promennou args
    u_char* a __attribute__(( unused ));

   	a = args;

   	int version;
   	struct iphdr* iph;

   	// ip ziskani hlavicky paketu, kvuli protokolu
    if( linux == DLT_EN10MB ){
    	iph = ( struct iphdr* )( packet + sizeof( struct ethhdr ) );
    	version = iph->version;
	} else if ( linux == DLT_LINUX_SLL ){
		iph = ( struct iphdr* )( packet + 16 );
    	version = iph->version;
	}

    if( version == 4 ){ 

	    switch ( iph->protocol ){
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
	} else {
		// Jedna se o ipv6
		struct ipv6hdr *iph = ( struct ipv6hdr* )( packet + sizeof( struct ethhdr ) );
		
		switch( iph->nexthdr ){
			case 6:
				printFirstLineIPV6( iph, packet, header, 6 );
				PrintData( packet, size );
				break;
			case 17:
				printFirstLineIPV6( iph, packet, header, 17 );
				PrintData( packet, size );
				break;
			default:
				break;
		}
	}
}   

bool isNumber(char number[]){
    int i = 0;

    // nesmi byt zaporne cisla
    if (number[0] == '-'){
        return false;
    }
    for (; number[i] != 0; i++)
    {
        // cislo v rozmezi 0-9
        if (!isdigit(number[i]))
            return false;
    }
    return true;
}

/*
** Main cast programu se stara o praci s argumenty, a zacatek prace s pakety a jejich filtraci
*/
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
	    static struct option long_options[] = {
	            { "udp",  no_argument, 0,  'u' },
	            { "tcp",  no_argument, 0,  't' },
	            {0, 0, 0, 0}
	    };

	    // funkce getopt_long ziska ze vstupu argumenty programu a rozdeli je do promennych
	    while( ( opt = getopt_long( argc, argv, "i:p:tun:", long_options, NULL ) ) != -1 ){
        switch( opt ){
            case 'i':
                interface = optarg;
                break;
            case 'p':
            	if( isNumber( optarg ) ){
                	p = optarg;
                	break;
            	} else {
            		fprintf( stderr, "Chyba u parametru p\n" );
            		return( 16 );
            	}
            case 'u':
                udp = 1;
                both = 0;
                break;
            case 't':
            	tcp = 1;
                both = 0;
                break;
            case 'n':
            	if( isNumber( optarg ) ){
	            	count = atoi( optarg );
	            	break;
	        	} else {
	        		fprintf( stderr, "Chyba u parametru n\n" );
	        		return( 16 );
	        	}
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
				strcpy( port, "tcp or udp and port " );
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
				port = "tcp or udp";
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

		linux = pcap_datalink( handle );
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