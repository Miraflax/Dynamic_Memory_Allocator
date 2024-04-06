FLAGS = -Wall -Werror -std=gnu99
APP = mem_alloc

all: main test

main : $(APP).c main.c
	gcc $(FLAGS) $^ -o $@

test : $(APP).c test_main.c
	gcc $(FLAGS) $^ -o $@

clean:
	rm -f main test
