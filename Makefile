OBJS = radiotap-parser.o sniffer.o
CC = gcc
CFLAGS = -Wall -O -g

rssi : $(OBJS)
	$(CC) $(OBJS) -o rssi -lpcap
radiotap-parser.o : radiotap-parser.c radiotap-parser.h byteorder.h ieee80211_radiotap.h
	$(CC) $(CFLAGS) -c radiotap-parser.c -o radiotap-parser.o
sniffer.o : sniffer.c radiotap-parser.h sniffer.h
	$(CC) $(CFLAGS) -c sniffer.c -o sniffer.o -lpcap
clean:
	rm -rf *.o rssi