BINARY := freecell
EXEFLAGS :=
ARCH := linux
CRCLIB := crcutil.a -Icrcutil-1.0/code -Icrcutil-1.0/examples
CRC := crcutil-1.0 crcutil.a
STRIPARG := -s

ifeq ($(OS), Windows_NT)
  BINARY := FreeCell.exe
  EXEFLAGS := -static
  ARCH := windows
else
  ifeq ($(shell uname -s), Darwin)
    EXEFLAGS := -framework IOKit -framework CoreFoundation
    ARCH := macosx
    CRCLIB := crc32.c
    CRC := crc32.c crc32.h
    STRIPARG :=
  endif
endif

DISTNAME := $(shell pwd | awk -F '/' '{print $$(NF - 1)}')
ZIPNAME := $(shell pwd | awk -F '/' '{print $$(NF - 1)}' | tr "A-Z" "a-z").zip

.PHONY: all
all:
	@make --no-print-directory $(BINARY)

.PHONY: clean
clean:
	rm -rf freecell FreeCell.exe crcutil.a *.o

.PHONY: dist
dist:
	make clean
	make all
	cp $(BINARY) ..
	(cd .. ; ./$(BINARY) -h 2>&1 | sed "s/$$/\r/" > README.txt)
	make clean
	rm -rf ../$(ZIPNAME) ../../$(ZIPNAME)
	(cd ../.. ; zip -r $(ZIPNAME) $(DISTNAME))
	mv ../../$(ZIPNAME) ../$(ZIPNAME)

$(BINARY): main.cc $(ARCH).c $(ARCH).h md5.c md5.h sha1.c sha1.h $(CRC)
	g++ -O3 -Wall -Werror -o $@ $(EXEFLAGS) main.cc $(ARCH).c md5.c sha1.c $(CRCLIB)
	strip $(STRIPARG) $@

crcutil.a: crcutil-1.0
	rm -rf *.o
	g++ -O3 -Wall -mcrc32 -c crcutil-1.0/examples/interface.cc crcutil-1.0/code/*.cc -Icrcutil-1.0/code -Icrcutil-1.0/tests -Icrcutil-1.0/examples
	ar r crcutil.a *.o
	rm -rf *.o

crcutil-1.0:
	wget -q -O - http://crcutil.googlecode.com/files/crcutil-1.0.tar.gz | tar xfz -
	chmod -R og-w+rX crcutil-1.0
	chown -R 0.0 crcutil-1.0
	touch crcutil-1.0
