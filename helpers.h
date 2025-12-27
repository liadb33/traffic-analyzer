#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include <unordered_map>
#include <cstdint>
#include "models.h"

// Formats raw MAC address bytes into a readable string (aa:bb:cc:dd:ee:ff)
std::string format_mac(const u_char* mac);

// Map port numbers to human-readable protocol names for OT/IT awareness
std::string get_port_label(uint16_t port);

// Helper to print Top items from a map
void print_top_peers(const std::unordered_map<std::string, uint32_t>& peers);

// Helper function to escape strings for JSON
std::string json_escape(const std::string& str);

// Generate JSON output file
void generate_json_output(const AnalysisContext& ctx, const std::string& output_file);

#endif
