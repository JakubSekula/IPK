proj=args.c

make:
	@gcc -std=c99 -Wall -Wextra args.c -o args

clean:
	@rm args
