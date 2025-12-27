#ifndef MODELS_H
#define MODELS_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <vector>
#include <cstdint>

// Statistics to differentiate between hosting a service (incoming)
// and accessing a service (outgoing).
struct PortStats {
    uint32_t incoming_hits = 0; // Packets where device was the Destination (Server behavior)
    uint32_t outgoing_hits = 0; // Packets where device was the Source (Client behavior)
};

struct BaselineData{
    std::unordered_set<uint16_t> known_ports;
    std::unordered_set<std::string> known_peers;
    
    // Traffic baseline metrics
    uint64_t baseline_total_bytes = 0;
    uint32_t baseline_total_packets = 0;
    double baseline_bytes_per_sec = 0.0;
    double baseline_packets_per_sec = 0.0;
};

// Represents a unique network device
struct DeviceAsset {
    std::string ip_address;
    std::string mac_address;
    uint32_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    // For traffic spike detection during monitoring phase
    uint32_t detection_phase_packets = 0;
    uint64_t detection_phase_bytes = 0;
    long detection_phase_start_ts = 0;
    
    // Maps Port Number -> PortStats structure
    std::map<uint16_t, PortStats> port_activity;
    // tracking for top peers, key: peer IP, value: packet count
    std::unordered_map<std::string, uint32_t> top_peers;

    BaselineData baseline;
    
    // Scanner detection during anomaly phase
    std::unordered_set<uint16_t> new_ports_in_detection;  // Ports accessed after baseline
    bool is_flagged_as_scanner = false;
};

struct CommStats {
    uint32_t packet_count = 0;
    uint64_t byte_count = 0;
};

// Container for the analysis state, passed to the pcap_loop callback
struct AnalysisContext {
    std::unordered_map<std::string, DeviceAsset> inventory;

    // Key: Composite string "src_ip -> dst_ip | protocol"
    // Requirement 2: Tracking (src, dst, protocol) pairs
    std::unordered_map<std::string, CommStats> graph;

    //baseline configuration
    long baseline_limit_seconds = 0;
    long first_packet_ts = 0; // epoch time of first packet
    bool is_learning_baseline = true;
    bool anomaly_detection_enabled = false; // Only enable if baseline > 0
    long last_packet_ts = 0; // Track time for rate calculations
    
    // Traffic spike detection parameters
    double spike_threshold_multiplier = 3.0; // Alert if traffic is 3x baseline

    // recorded anomalies during analysis
    std::vector<std::string> anomalies;
    
    // Scanner detection threshold
    uint32_t scanner_port_threshold = 50; // If IP accesses > 50 new ports, it's a scanner
    
    // Aggregated scanner data for summary
    struct ScannerInfo {
        std::string ip;
        uint32_t unique_ports_scanned;
        uint16_t first_port;
        uint16_t last_port;
    };
    std::vector<ScannerInfo> detected_scanners;
};

#endif