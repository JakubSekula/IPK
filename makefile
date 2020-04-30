proj=ipk-sniffer

make:
	@gcc -std=c99 -Wall -Wextra -D_DEFAULT_SOURCE $(proj).c $(proj).h -o $(proj) -lpcap 
clean:
	@rm $(proj)
