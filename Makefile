CXX = g++
CXXFLAGS = -g -Wall -Wextra
LFLAGS = -lpcap

PROJECT = flow
SRC = $(wildcard *.cpp)
SRC += $(wildcard src/*.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

.PHONY: all clean

all: $(PROJECT)

$(PROJECT): $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LFLAGS)

%.o: %.cpp %.hpp Makefile
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf flow *.o src/*.o *.d