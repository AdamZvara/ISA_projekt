CC = g++
CFLAGS = -g -Wall -Wextra
LFLAGS = -lpcap

project = flow
src = $(project).cpp $(project).hpp parse.cpp parse.hpp common.hpp

.PHONY: clean

$(project): $(src)
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS) 
	
clean:
	rm -rf flow