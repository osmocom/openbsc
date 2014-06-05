
OBJS = testconv_main.o

CC = gcc
CFLAGS = -O0 -ggdb -Wall
LDFLAGS =
CPPFLAGS = -I../.. -I../../include $(shell pkg-config --cflags libosmocore) $(shell pkg-config --cflags libbcg729)
LIBS =  ../../src/libmgcp/libmgcp.a ../../src/libcommon/libcommon.a $(shell pkg-config --libs libosmocore) $(shell pkg-config --libs libbcg729) -lgsm -lrt

testconv: $(OBJS)
	$(CC)  -o $@ $^ $(LDFLAGS) $(LIBS)

testconv_main.o: testconv_main.c

$(OBJS):
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
