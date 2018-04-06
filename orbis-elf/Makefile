TOP ?= $(CURDIR)/..

include $(TOP)/make/config.mk
include $(TOP)/make/patterns.mk

CFLAGS += -I $(TOP)/liborbis-elf/include

VPATH += $(TOP)/liborbis-elf

.PHONY: all
all: orbis-elf

orbis-elf: orbis-elf.o -lorbis-elf

orbis-elf.o: orbis-elf.c

.PHONY: clean
clean:
	$(RM) orbis-elf
	$(RM) orbis-elf.o

.PHONY: test
test:

.PHONY: install
install: orbis-elf
	install -d $(DESTDIR)$(PREFIX)/bin
	install orbis-elf $(DESTDIR)$(PREFIX)/bin

$(V).SILENT:
