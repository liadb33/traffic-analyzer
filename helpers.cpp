#include "helpers.h"

#include <cstdio>   // snprintf
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

// Formats raw MAC address bytes into a readable string (aa:bb:cc:dd:ee:ff)
std::string format_mac(const u_char* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Map port numbers to human-readable protocol names for OT/IT awareness
std::string get_port_label(uint16_t port) {
    if (port == 502)   return "Modbus";
    if (port == 102)   return "S7-Comm";
    if (port == 44818) return "EtherNet/IP";
    if (port == 53)    return "DNS";
    if (port == 123)   return "NTP";
    if (port == 80)    return "HTTP";
    if (port == 443)   return "HTTPS";
    if (port == 22)    return "SSH";
    if (port == 949)   return "GPS-RTK/System";
    return "Unknown";
}

// Helper to print Top items from a map
void print_top_peers(const std::unordered_map<std::string, uint32_t>& peers) {
    // 1. Move to vector for sorting
    std::vector<std::pair<std::string, uint32_t>> sorted_peers(peers.begin(), peers.end());
    
    // 2. Sort by value descending
    std::sort(sorted_peers.begin(), sorted_peers.end(), 
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // 3. Print top 3
    int count = 0;
    for (const auto& p : sorted_peers) {
        if (++count > 3) break;
        std::cout << p.first << "(" << p.second << " pkts) ";
    }
}

// Helper function to escape strings for JSON
std::string json_escape(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '\"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

// Generate JSON output file
void generate_json_output(const AnalysisContext& ctx, const std::string& output_file) {
    std::ofstream out(output_file);
    if (!out.is_open()) {
        std::cerr << "Error: Could not open output file " << output_file << std::endl;
        return;
    }

    out << "{\n";
    
    // Anomaly Summary Section (added first for quick overview)
    out << "  \"anomaly_summary\": {\n";
    
    // Count anomalies by type
    uint32_t new_peer_count = 0;
    uint32_t new_port_count = 0;
    uint32_t traffic_spike_count = 0;
    uint32_t port_scan_count = 0;
    
    for (const auto& anomaly : ctx.anomalies) {
        if (anomaly.find("New Peer:") != std::string::npos) new_peer_count++;
        else if (anomaly.find("New Port:") != std::string::npos) new_port_count++;
        else if (anomaly.find("Traffic Spike:") != std::string::npos) traffic_spike_count++;
        else if (anomaly.find("Port Scan Detected:") != std::string::npos) port_scan_count++;
    }
    
    out << "    \"total_anomalies\": " << ctx.anomalies.size() << ",\n";
    out << "    \"by_type\": {\n";
    out << "      \"new_peer\": " << new_peer_count << ",\n";
    out << "      \"new_port\": " << new_port_count << ",\n";
    out << "      \"traffic_spike\": " << traffic_spike_count << ",\n";
    out << "      \"port_scan_detected\": " << port_scan_count << "\n";
    out << "    },\n";
    
    // Scanners detected section
    out << "    \"scanners_detected\": [\n";
    bool first_scanner = true;
    for (const auto& scanner : ctx.detected_scanners) {
        if (!first_scanner) out << ",\n";
        first_scanner = false;
        out << "      {\n";
        out << "        \"ip\": \"" << json_escape(scanner.ip) << "\",\n";
        out << "        \"unique_ports_scanned\": " << scanner.unique_ports_scanned << ",\n";
        out << "        \"port_range\": \"" << scanner.first_port << "-" << scanner.last_port << "\",\n";
        out << "        \"severity\": \"" << (scanner.unique_ports_scanned > 500 ? "high" : "medium") << "\"\n";
        out << "      }";
    }
    out << "\n    ]\n";
    out << "  },\n";
    
    // Assets section
    out << "  \"assets\": [\n";
    bool first_asset = true;
    for (const auto& [ip, asset] : ctx.inventory) {
        if (!first_asset) out << ",\n";
        first_asset = false;
        
        out << "    {\n";
        out << "      \"ip\": \"" << json_escape(ip) << "\",\n";
        out << "      \"mac\": \"" << json_escape(asset.mac_address) << "\",\n";
        out << "      \"total_connections\": " << asset.total_packets << ",\n";
        out << "      \"total_bytes\": " << asset.total_bytes << ",\n";
        
        // Top peers
        out << "      \"top_peers\": [\n";
        std::vector<std::pair<std::string, uint32_t>> sorted_peers(asset.top_peers.begin(), asset.top_peers.end());
        std::sort(sorted_peers.begin(), sorted_peers.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        bool first_peer = true;
        for (size_t i = 0; i < std::min(sorted_peers.size(), size_t(5)); ++i) {
            if (!first_peer) out << ",\n";
            first_peer = false;
            out << "        {\"ip\": \"" << json_escape(sorted_peers[i].first) 
                << "\", \"packets\": " << sorted_peers[i].second << "}";
        }
        out << "\n      ],\n";
        
        // Top destination ports
        out << "      \"top_destination_ports\": [\n";
        std::vector<std::pair<uint16_t, PortStats>> sorted_ports(asset.port_activity.begin(), asset.port_activity.end());
        std::sort(sorted_ports.begin(), sorted_ports.end(),
                  [](const auto& a, const auto& b) { 
                      return (a.second.incoming_hits + a.second.outgoing_hits) > 
                             (b.second.incoming_hits + b.second.outgoing_hits); 
                  });
        
        bool first_port = true;
        for (size_t i = 0; i < std::min(sorted_ports.size(), size_t(10)); ++i) {
            if (!first_port) out << ",\n";
            first_port = false;
            out << "        {\"port\": " << sorted_ports[i].first 
                << ", \"service\": \"" << json_escape(get_port_label(sorted_ports[i].first))
                << "\", \"incoming\": " << sorted_ports[i].second.incoming_hits
                << ", \"outgoing\": " << sorted_ports[i].second.outgoing_hits << "}";
        }
        out << "\n      ]\n";
        
        out << "    }";
    }
    out << "\n  ],\n";
    
    // Communications section
    out << "  \"communications\": [\n";
    bool first_comm = true;
    for (const auto& [comm_key, stats] : ctx.graph) {
        if (!first_comm) out << ",\n";
        first_comm = false;
        
        // Parse comm_key: "src_ip -> dst_ip | protocol"
        size_t arrow_pos = comm_key.find(" -> ");
        size_t pipe_pos = comm_key.find(" | ");
        std::string src_ip = comm_key.substr(0, arrow_pos);
        std::string dst_ip = comm_key.substr(arrow_pos + 4, pipe_pos - arrow_pos - 4);
        std::string protocol = comm_key.substr(pipe_pos + 3);
        
        out << "    {";
        out << "\"src_ip\": \"" << json_escape(src_ip) << "\", ";
        out << "\"dst_ip\": \"" << json_escape(dst_ip) << "\", ";
        out << "\"protocol\": \"" << json_escape(protocol) << "\", ";
        out << "\"events\": " << stats.packet_count << ", ";
        out << "\"bytes\": " << stats.byte_count;
        out << "}";
    }
    out << "\n  ],\n";
    
    // Anomalies section
    out << "  \"anomalies\": [\n";
    bool first_anomaly = true;
    for (const auto& anomaly : ctx.anomalies) {
        if (!first_anomaly) out << ",\n";
        first_anomaly = false;
        out << "    \"" << json_escape(anomaly) << "\"";
    }
    out << "\n  ]\n";
    
    out << "}\n";
    out.close();
}
