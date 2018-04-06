TOP ?= $(CURDIR)/..

include $(TOP)/make/config.mk
include $(TOP)/make/patterns.mk

headers += include/orbis-elf-api.h
headers += include/orbis-elf-enums.h
headers += include/orbis-elf-types.h

CFLAGS += -I $(CURDIR)/include

.PHONY: all
all: liborbis-elf.a

liborbis-elf.a: source/orbis-elf-api.o

source/orbis-elf-api.o: source/orbis-elf-api.c $(headers)

.PHONY: clean
clean:
	$(RM) liborbis-elf.a
	$(RM) source/orbis-elf-api.o

.PHONY: install
install: liborbis-elf.a
	install -d $(DESTDIR)$(PREFIX)/include
	install $(headers) $(DESTDIR)$(PREFIX)/include
	install -d $(DESTDIR)$(PREFIX)/lib
	install liborbis-elf.a $(DESTDIR)$(PREFIX)/lib

$(V).SILENT:
