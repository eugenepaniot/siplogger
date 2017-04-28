extern void write_pcap(pcap_dumper_t *pcap_dumper, const u_char *h, const u_char *p);
extern void teardown_pcap(pcap_dumper_t *pcap_dumper);
extern pcap_dumper_t* setup_pcap(char* pcap_file);
extern void* start_pcap_dump();