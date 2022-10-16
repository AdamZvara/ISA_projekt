CXX = g++
CXXFLAGS = -g -Wall -Wextra
LFLAGS = -lpcap

PROJECT = flow
SRC = $(wildcard *.cpp)
SRC += $(wildcard src/*.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))
DEPENDS := $(patsubst %.cpp, %.d, $(SRC))

.PHONY: all clean test

all: $(PROJECT)

$(PROJECT): $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LFLAGS)

# generating dependency files
# source https://stackoverflow.com/a/52036564
-include $(DEPENDS)

%.o: %.cpp %.hpp Makefile
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

clean:
	$(RM) $(PROJECT) $(DEPENDS) $(OBJ)
	$(RM) test/out/*.pcap_out test/out/*.pcap_fcache test/out/*.pcap_timers

test: $(PROJECT)
	cd test; ./test.sh