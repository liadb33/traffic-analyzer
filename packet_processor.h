#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <pcap.h>
#include "models.h"

// Core callback for pcap_loop
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif