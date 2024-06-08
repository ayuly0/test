# Compiler
CC = cl
# Linker
LD = link

# Compiler flags
CFLAGS = /FA /c /O2 /GS- /Gz
# Linker flags
LDFLAGS = /NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:WinMainCRTStartup
LIBS = kernel32.lib user32.lib Advapi32.lib

# Source files
SRCS = $(wildcard src/*.cpp)
# Object files
OBJS = $(patsubst src/%.cpp, objs/%.obj, $(patsubst src/%.cpp, objs/%.obj, $(SRCS)))

# Targets
build: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -out:bin/crackmes.exe

run: build
	bin/crackmes.exe

all: build

# Compile .cpp files
objs/%.obj: src/%.cpp
	$(CC) $(CFLAGS) $< -Fo$@

clean:
	del /Q objs\*
	del /Q bin\*

# cl /FA /c /O2 /GS- /Gz crackme.cpp lib.cpp && link /NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:WinMainCRTStartup crackme.obj lib.obj kernel32.lib user32.lib && crackme.exe