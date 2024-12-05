.PHONY: all debug release clean

Compiler = g++
RELEASE_FLAGS = -O2 -Wall -DNDEBUG -Iheaders
DEBUG_FLAGS   = -g -O0 -Wall -Iheaders
RELEASE_EXEC  = AES
SOURCES       = main.cpp AES.cpp
OBJECTS       = $(SOURCES:.cpp=.o)  
LIBARY        = -lcryptopp 

all: release

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(OBJECTS)
	$(Compiler) $(RELEASE_FLAGS) $(OBJECTS) -o $(RELEASE_EXEC) $(LIBARY)


%.o: %.cpp
	$(Compiler) $(RELEASE_FLAGS) -c $< -o $@

clean:
	rm -f $(RELEASE_EXEC) $(OBJECTS)
