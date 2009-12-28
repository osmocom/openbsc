
ASN1C=../../../tmp/rrlp/asn1c/asn1c/asn1c
ASN1_INCLUDE=/home/tnt/tmp/rrlp/asn1c/skeletons
CC=gcc
CFLAGS=-I$(ASN1_INCLUDE) -Iasn1_gen -O3 -Wall

ASN1_FILES=$(wildcard asn1/*.asn)


all: rrlp-test


rrlp-test: libgsm-asn1.a gps.o ubx.o ubx-parse.o rrlp.o main.o
	$(CC) -o $@ gps.o ubx.o ubx-parse.o rrlp.o main.o -L. -lgsm-asn1 -lm


#
# ASN1 file autogeneration (need recursive makefile call)
#

ASN1_SOURCES = $(wildcard asn1_gen/*.c)
ASN1_OBJECTS = $(ASN1_SOURCES:.c=.o)

libgsm-asn1.a: $(ASN1_FILES)
	mkdir -p asn1_gen && \
	cd asn1_gen && \
	$(ASN1C) -fskeletons-copy -fnative-types -gen-PER $(addprefix ../,$^)
	@rm asn1_gen/converter-sample.c asn1_gen/Makefile.am.sample
	@$(MAKE) libgsm-asn1.a.submake

libgsm-asn1.a.submake: $(ASN1_OBJECTS)
	$(AR) rcs libgsm-asn1.a $^

.PHONY: libgsm-asn1.a.submake


#
# Clean
#

clean:
	rm -Rf asn1_gen
	rm -f libgsm-asn1.a *.o rrlp-test

