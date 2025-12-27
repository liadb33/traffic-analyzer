#include "packet_processor.h"
#include "helpers.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <algorithm>

//callback function
// automatically be called by pcap_loop for every captured packet
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  
    // cast the generic user data pointer to our AnalysisContext type
    AnalysisContext* ctx = reinterpret_cast<AnalysisContext*>(user_data);

    // Only do time tracking and baseline logic if anomaly detection is enabled
    if (ctx->anomaly_detection_enabled) {
        //time tracking using packet's timestamp
        long current_ts = pkthdr->ts.tv_sec;
        if (ctx->first_packet_ts == 0) 
            ctx->first_packet_ts = current_ts;
        
        // check if we should switch from learning to detection mode
        if (ctx->is_learning_baseline && (current_ts - ctx->first_packet_ts > ctx->baseline_limit_seconds)) {
            ctx->is_learning_baseline = false;
            
            // Calculate baseline traffic rates for all devices
            long baseline_duration = current_ts - ctx->first_packet_ts;
            if (baseline_duration > 0) {
                for (auto& [ip, asset] : ctx->inventory) {
                    asset.baseline.baseline_total_bytes = asset.total_bytes;
                    asset.baseline.baseline_total_packets = asset.total_packets;
                    asset.baseline.baseline_bytes_per_sec = (double)asset.total_bytes / baseline_duration;
                    asset.baseline.baseline_packets_per_sec = (double)asset.total_packets / baseline_duration;
                    
                    // Reset detection phase counters
                    asset.detection_phase_packets = 0;
                    asset.detection_phase_bytes = 0;
                    asset.detection_phase_start_ts = current_ts;
                }
            }
            
            // std::cout << "[SYSTEM] Baseline window closed. Monitoring for anomalies..." << std::endl;
        }
        
        // Update last packet timestamp
        ctx->last_packet_ts = current_ts;
    }

    struct ether_header* eth = (struct ether_header*) packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)  return;
   

    // Process only IPv4 traffic
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const u_char* ip_ptr = packet + sizeof(struct ether_header);
        struct ip* ip_header = (struct ip*) ip_ptr;

        // Validation: Ensure IP header length is safe and fits in captured data
        int ip_hdr_len = ip_header->ip_hl * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > (int)pkthdr->caplen) return;

        std::string src_ip = inet_ntoa(ip_header->ip_src);
        std::string dst_ip = inet_ntoa(ip_header->ip_dst);
        
        // Update communication graph
        std::string proto_name = (ip_header->ip_p == IPPROTO_TCP) ? "TCP" :
                                 (ip_header->ip_p == IPPROTO_UDP) ? "UDP" : "OTHER";
        std::string comm_key = src_ip + " -> " + dst_ip + " | " + proto_name;
        CommStats& comm_stats = ctx->graph[comm_key];
        comm_stats.packet_count++;
        comm_stats.byte_count += pkthdr->len;

        // Update BOTH Source and Destination in the inventory
        DeviceAsset& src_asset = ctx->inventory[src_ip];
        src_asset.total_bytes += pkthdr->len;
        src_asset.total_packets++;
        //record that src communicated with dst
        src_asset.top_peers[dst_ip]++;

        DeviceAsset& dst_asset = ctx->inventory[dst_ip];
        dst_asset.total_bytes += pkthdr->len;
        //record that dst communicated with src
        dst_asset.top_peers[src_ip]++;

        // Initialize src metadata if new
        if (src_asset.ip_address.empty()) {
            src_asset.ip_address = src_ip;
            src_asset.mac_address = format_mac(eth->ether_shost);
        }
        src_asset.total_packets++;
        src_asset.total_bytes += pkthdr->len;

        // Initialize dst metadata if new (Note: MAC might be gateway MAC if external)
        if (dst_asset.ip_address.empty()) {
            dst_asset.ip_address = dst_ip;
            dst_asset.mac_address = format_mac(eth->ether_dhost);
        }

        // Layer 4: Extract Ports
        const u_char* l4_ptr = ip_ptr + ip_hdr_len;
        uint16_t dst_port = 0;

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*) l4_ptr;
            dst_port = ntohs(tcp->th_dport); // Use Destination Port for Role/Service identification
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr* udp = (struct udphdr*) l4_ptr;
            dst_port = ntohs(udp->uh_dport);
        }

        // Update port activity for both sides
        if (dst_port > 0) {
            // Source used this port as a client (Outgoing)
            src_asset.port_activity[dst_port].outgoing_hits++;
            // Destination received traffic on this port (Incoming/Service)
            dst_asset.port_activity[dst_port].incoming_hits++;
        }

        // Baseline Learning vs. Detection Logic - only if anomaly detection is enabled
        if (ctx->anomaly_detection_enabled) {
            if (ctx->is_learning_baseline) {
                // Build the Baseline: Add everything to "known" sets
                src_asset.baseline.known_ports.insert(dst_port);
                src_asset.baseline.known_peers.insert(dst_ip);
            } 
            else {
                // Track detection phase traffic for spike detection
                src_asset.detection_phase_packets++;
                src_asset.detection_phase_bytes += pkthdr->len;
                
                // Detect Anomalies: Check if we've seen this before
                
                // A. New Peer Anomaly
                if (src_asset.baseline.known_peers.find(dst_ip) == src_asset.baseline.known_peers.end()) {
                    std::string alert = "[ALERT] New Peer: " + src_ip + " -> " + dst_ip;
                    ctx->anomalies.push_back(alert);
                    // std::cout << alert << std::endl;
                    src_asset.baseline.known_peers.insert(dst_ip); // Alert only once
                }

                // B. New Port Anomaly (with Scanner Detection)
                if (src_asset.baseline.known_ports.find(dst_port) == src_asset.baseline.known_ports.end()) {
                    src_asset.new_ports_in_detection.insert(dst_port);
                    src_asset.baseline.known_ports.insert(dst_port);
                    
                    // Check if this IP is a scanner
                    if (!src_asset.is_flagged_as_scanner && 
                        src_asset.new_ports_in_detection.size() > ctx->scanner_port_threshold) {
                        // Flag as scanner and create aggregated alert
                        src_asset.is_flagged_as_scanner = true;
                        std::string alert = "[ALERT] Port Scan Detected: " + src_ip + 
                                          " accessed " + std::to_string(src_asset.new_ports_in_detection.size()) + 
                                          " unique new ports";
                        ctx->anomalies.push_back(alert);
                        
                        // Store scanner info for summary
                        AnalysisContext::ScannerInfo scanner;
                        scanner.ip = src_ip;
                        scanner.unique_ports_scanned = src_asset.new_ports_in_detection.size();
                        // Find min/max ports
                        scanner.first_port = *std::min_element(src_asset.new_ports_in_detection.begin(), 
                                                               src_asset.new_ports_in_detection.end());
                        scanner.last_port = *std::max_element(src_asset.new_ports_in_detection.begin(), 
                                                              src_asset.new_ports_in_detection.end());
                        ctx->detected_scanners.push_back(scanner);
                    } 
                    else if (!src_asset.is_flagged_as_scanner) {
                        // Only log individual port alerts if not yet a scanner
                        std::string alert = "[ALERT] New Port: " + src_ip + " accessed Port " + std::to_string(dst_port);
                        ctx->anomalies.push_back(alert);
                    }
                    // If already flagged as scanner, silently track but don't add individual alerts
                }
                
                // C. Traffic Spike Anomaly - Check periodically (every ~10 seconds of detection)
                long detection_duration = ctx->last_packet_ts - src_asset.detection_phase_start_ts;
                if (detection_duration >= 10 && src_asset.baseline.baseline_bytes_per_sec > 0) {
                    double current_bytes_per_sec = (double)src_asset.detection_phase_bytes / detection_duration;
                    double current_packets_per_sec = (double)src_asset.detection_phase_packets / detection_duration;
                    
                    // Check if current rate exceeds baseline by threshold
                    if (current_bytes_per_sec > src_asset.baseline.baseline_bytes_per_sec * ctx->spike_threshold_multiplier) {
                        std::string alert = "[ALERT] Traffic Spike: " + src_ip + " - " +
                                          std::to_string((int)current_bytes_per_sec) + " bytes/s (baseline: " +
                                          std::to_string((int)src_asset.baseline.baseline_bytes_per_sec) + " bytes/s)";
                        ctx->anomalies.push_back(alert);
                        // std::cout << alert << std::endl;
                        
                        // Reset detection window to avoid repeated alerts
                        src_asset.detection_phase_packets = 0;
                        src_asset.detection_phase_bytes = 0;
                        src_asset.detection_phase_start_ts = ctx->last_packet_ts;
                    }
                    else if (detection_duration >= 20) {
                        // Reset window periodically even if no spike to keep measurements current
                        src_asset.detection_phase_packets = 0;
                        src_asset.detection_phase_bytes = 0;
                        src_asset.detection_phase_start_ts = ctx->last_packet_ts;
                    }
                }
            }
        }
    }
}

