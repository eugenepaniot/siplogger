CC          = gcc -std=gnu99

WARNCFLAGS  = -Wall -Wextra -W -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wno-variadic-macros
INCLUDE     = -I/usr/local/include -I/usr/include
DEFINES     = -D_GNU_SOURCE -Wp,-D_FORTIFY_SOURCE=2

OFLAGS      = $(DEFINES) -O2 -g -pipe -fpic -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fno-strict-aliasing -fwrapv -MP -MMD

CFLAGS      = ${OFLAGS} ${WARNCFLAGS} ${INCLUDE}

LDFLAGS     = -lrt -Wl,--as-needed -Wl,-z,relro  -Wl,--hash-style=gnu -rdynamic -pthread

LIBS        = -L/usr/local/lib -L/usr/lib -L/usr/lib/x86_64-linux-gnu/ -lpthread -lrt -ljemalloc -lm -lzmq -liniparser -lpcap -losipparser2

SRCDIR		= src
OBJDIR		= obj
BINDIR		= bin

SOURCES     = $(wildcard $(SRCDIR)/*.c)
OBJECTS     = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPENDENCY  = $(OBJECTS:.o=.d)
TARGETS 	= $(BINDIR)/siplogger

.PHONY: all clean

all: build ${TARGETS}

$(TARGETS): $(OBJECTS)
	@echo "=== $@ ==="
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@echo "=== making object: $@ ==="
	$(CC) $(LDFLAGS) $(CFLAGS) -c $< -o $@	

build:
	@mkdir -pv $(BINDIR) $(OBJDIR)

clean:
	@echo "=== $@ ==="
	@rm -fv *.o *~
	@rm -fv $(SRCDIR)/*.o $(SRCDIR)/*~

	@rm -Rfv $(OBJDIR)
	@rm -Rfv $(BINDIR)
	

-include $(DEPENDENCY)