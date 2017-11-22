EXE		= quickbms
CFLAGS	+= -s -O2
PREFIX	= /usr/local
BINDIR	= $(PREFIX)/bin
SRC		= $(EXE).c

all:
	$(CC) $(CFLAGS) -c compression/blast.c
	$(CC) $(CFLAGS) -c lzma/LzmaDec.c
	$(CC) $(CFLAGS) -c lzma/Lzma2Dec.c
	$(CC) $(CFLAGS) -c lzma/Bra86.c
	$(CC) $(CFLAGS) -c encryption/tea.c
	$(CC) $(CFLAGS) -c encryption/xtea.c
	$(CC) $(CFLAGS) -c encryption/xxtea.c
	$(CC) $(CFLAGS) -c compression/unlzx.c
	$(CC) $(CFLAGS) -c compression/unlzwx.c
	$(CC) $(CFLAGS) -c compression/unlzw.c
	$(CC) $(CFLAGS) -c compression/unmslzx.c
	$(CC) $(CFLAGS) -c compression/sflcomp.c
	$(CC) $(CFLAGS) -c compression/uncompress.c
	$(CC) $(CFLAGS) -c compression/undmc.c
	$(CC) $(CFLAGS) -c encryption/twofish.c
	$(CC) $(CFLAGS) -c encryption/seed.c
	$(CC) $(CFLAGS) -c encryption/serpent.c
	$(CC) $(CFLAGS) -c compression/lzhuf.c
	$(CC) $(CFLAGS) -c compression/lzari.c
	$(CC) $(CFLAGS) -c compression/bpd.c
	$(CC) $(CFLAGS) -c compression/quicklz.c
	$(CC) $(CFLAGS) -c encryption/ice.c
	$(CC) $(CFLAGS) -c compression/doomhuff.c
	$(CC) $(CFLAGS) -c compression/depacks.c
	$(CC) $(CFLAGS) -c compression/lzf_d.c
	$(CC) $(CFLAGS) -c compression/lzf_c.c
	$(CC) $(CFLAGS) -c compression/de_lzah.c
	$(CC) $(CFLAGS) -c compression/de_lzh.c
	$(CC) $(CFLAGS) -c compression/unshrink.c
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c compression/unquad.cpp
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c compression/unbalz.cpp
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c ppmd/unppmdi.cpp
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c ppmd/unppmdg.cpp
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c ppmd/unppmdh.cpp
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c ppmd/unppmdj.cpp
	$(CC) $(CFLAGS) -c compression/depack.c
	$(CC) $(CFLAGS) -c compression/brieflz.c
	$(CC) $(CFLAGS) -fno-exceptions -fno-rtti -fno-threadsafe-statics -c compression/unpaq6v2.cpp
	$(CC) $(CFLAGS) -c compression/shclib.c
	$(CC) $(CFLAGS) -c compression/hstest.c
	$(CC) $(CFLAGS) -c compression/sixpack.c
	$(CC) $(CFLAGS) -c compression/ashford.c
	$(CC) $(CFLAGS) -c compression/shc.c
	$(CC) $(CFLAGS) -c compression/unjam.c
	$(CC) $(CFLAGS) -c compression/lzhxlib.c
	$(CC) $(CFLAGS) -c compression/srank.c
	$(CC) $(CFLAGS) -c zziplib/block.c
	$(CC) $(CFLAGS) -c zziplib/bwt.c
	$(CC) $(CFLAGS) -c zziplib/coding.c
	$(CC) $(CFLAGS) -c zziplib/struct_model0.c
	$(CC) $(CFLAGS) -c zziplib/struct_model1.c
	$(CC) $(CFLAGS) -c compression/scexpand.c
	$(CC) $(CFLAGS) -c compression/bpe2.c
	$(CC) $(CFLAGS) -c bcl/huffman.c
	$(CC) $(CFLAGS) -c bcl/lz.c
	$(CC) $(CFLAGS) -c bcl/rice.c
	$(CC) $(CFLAGS) -c bcl/rle.c
	$(CC) $(CFLAGS) -c bcl/shannonfano.c
	$(CC) $(CFLAGS) -c compression/scz_decompress_lib.c
	$(CC) $(CFLAGS) -c szip/sz_api.c
	$(CC) $(CFLAGS) -c szip/rice.c -o rice2.o
	$(CC) $(CFLAGS) -c compression/sr3c.c
	$(CC) $(CFLAGS) -c compression/huffmanlib.c
	$(CC) $(CFLAGS) -c compression/yuke_bpe.c
	$(CC) $(CFLAGS) -c lzhl/Huff.cpp
	$(CC) $(CFLAGS) -c lzhl/Lz.cpp
	$(CC) $(CFLAGS) -c lzhl/Lzhl.cpp
	$(CC) $(CFLAGS) -c compression/d3101.c
	$(CC) $(CFLAGS) -c compression/usq.c
	$(CC) $(CFLAGS) -c compression/lzrw3-a.c
	$(CC) $(CFLAGS) -c tdcb/ahuff.c
	$(CC) $(CFLAGS) -c tdcb/arith.c
	$(CC) $(CFLAGS) -c tdcb/arith1.c
	$(CC) $(CFLAGS) -c tdcb/arith1e.c
	$(CC) $(CFLAGS) -c tdcb/arith-n.c
	$(CC) $(CFLAGS) -c tdcb/compand.c
	$(CC) $(CFLAGS) -c tdcb/huff.c
	$(CC) $(CFLAGS) -c tdcb/lzss.c
	$(CC) $(CFLAGS) -c tdcb/lzw12.c
	$(CC) $(CFLAGS) -c tdcb/lzw15v.c
	$(CC) $(CFLAGS) -c tdcb/silence.c
	$(CC) $(CFLAGS) -c tdcb/mn_incs.c
	$(CC) $(CFLAGS) -c compression/dmc2.c
	$(CC) $(CFLAGS) -c compression/libLZR.c
	$(CC) $(CFLAGS) -c compression/gz_unpack.c
	$(CC) $(CFLAGS) -c encryption/3way.c
	$(CC) $(CFLAGS) -c encryption/skipjack.c
	$(CC) $(CFLAGS) -c encryption/anubis.c
	$(CC) $(CFLAGS) -c encryption/aria.c
	$(CC) $(CFLAGS) -c encryption/crypton.c
	$(CC) $(CFLAGS) -c encryption/frog.c
	$(CC) $(CFLAGS) -c encryption/gost.c
	$(CC) $(CFLAGS) -c encryption/lucifer.c
	$(CC) $(CFLAGS) -c encryption/mars.c
	$(CC) $(CFLAGS) -c encryption/misty1.c
	$(CC) $(CFLAGS) -c encryption/NoekeonDirectRef.c
	$(CC) $(CFLAGS) -c encryption/seal.c
	$(CC) $(CFLAGS) -c encryption/safer.c
	$(CC) $(CFLAGS) -c compression/rnc.c
	$(CC) $(CFLAGS) -c compression/alone_unpack.c
	$(CC) $(CFLAGS) -c compression/S-Decompressor.c
	$(CC) $(CFLAGS) -c compression/E-Decompressor.c
	$(CC) $(CFLAGS) -c compression/K-Decompressor.c
	$(CC) $(CFLAGS) -c compression/N-Decompressor.c
	$(CC) $(CFLAGS) -c encryption/libkirk/crypto.c
	$(CC) $(CFLAGS) -c encryption/libkirk/kirk_engine.c
	$(CC) $(CFLAGS) -c compression/nitroCompLib.c 
	$(CC) $(SRC) $(CFLAGS) -o $(EXE) *.o -ldl -lcrypto -lz -lbz2 -lstdc++ -lm -DDISABLE_LZO -DDISABLE_UCL -DDISABLE_MCRYPT -DDISABLE_TOMCRYPT
	# $(CC) $(SRC) $(CFLAGS) -o $(EXE) *.o -ldl -lcrypto -lz -lbz2 -lstdc++ -lm -llzo -lucl -lmcrypt -ltomcrypt # you need these 4 libraries

install:
	install -m 755 -d $(BINDIR)
	install -m 755 $(EXE) $(BINDIR)/$(EXE)

.PHONY:
	install
