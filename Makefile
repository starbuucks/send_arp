all : pcap_test

pcap_test: main.o pcap_lib.o pcap_handle.o
	g++ -g -o pcap_test pcap_lib.o pcap_handle.o main.o -lpcap

pcap_lib.o: pcap_lib.cpp pcap_lib.h
	g++ -g -c -o pcap_lib.o pcap_lib.cpp

pcap_handle.o: pcap_handle.cpp pcap_handle.h
	g++ -g -c -o pcap_handle.o pcap_handle.cpp

main.o: main.cpp pcap_lib.h pcap_handle.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_test
	rm -f *.o

