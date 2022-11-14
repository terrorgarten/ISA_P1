#FILE: Makefile for flow.cpp
#AUTHOR: Matěj Konopík
#DATE: November 14th 2022
#COPYRIGHT DISCLAIMER:	This makefile was inspired by florin on stack overflow (https://stackoverflow.com/users/18308/florin)
#						From the thread https://stackoverflow.com/questions/287259/minimum-c-make-file-for-linux


SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)
BINS=$(SOURCES:.cpp=)

CXXFLAGS+= -lpcap

all: $(BINS)

.PHONY: clean

clean:
	$(RM) $(OBJECTS) $(BINS)

run: all
	./$(BINS)

-include $(DEPS)