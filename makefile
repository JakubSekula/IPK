proj=ipk-sniffer

make:
	@gcc -std=c99 -Wall -Wextra -D_DEFAULT_SOURCE ipk.c -o $(proj) -lpcap 
clean:
	@rm $(proj)
