CXX = g++
CXXFLAGS = -g -Wall -Wextra
LFLAGS = -lpcap

project = flow
src = $(project).o parse.o common.o

.PHONY: clean

$(project): $(src)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LFLAGS)

clean:
	rm -rf flow *.o