#include <iostream>
#include <iomanip>
#include <pcap.h>

#include "models.h"
#include "packet_processor.h"
#include "helpers.h"


int main(int argc, char* argv[]) {
    std::string input_file = "4SICS-GeekLounge-151020.pcap";
    int baseline_mins = 0;

    // Simple CLI Parser for baseline arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc) input_file = argv[++i];
        if (arg == "--baseline-minutes" && i + 1 < argc) baseline_mins = std::stoi(argv[++i]);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(input_file.c_str(), errbuf);

    if (!handle) {
        std::cerr << "Error: " << errbuf << std::endl;
        return 1;
    }

    AnalysisContext ctx;
    ctx.baseline_limit_seconds = baseline_mins * 60; // Convert to seconds
    ctx.anomaly_detection_enabled = (baseline_mins > 0); // Only enable anomaly detection if baseline specified

    std::cout << "Starting Mini-iSID Analysis (" << baseline_mins << "m Baseline)" << std::endl;
    std::cout << "Analyzing PCAP for Assets and Roles (Professional Mode)..." << std::endl;

    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&ctx));

    // Generate JSON output
    std::string output_file = "analysis_results.json";
    generate_json_output(ctx, output_file);
    
    // Print summary to console
    std::cout << "\n============================================================\n";
    std::cout << "Analysis Complete!\n";
    std::cout << "============================================================\n";
    std::cout << "Assets discovered: " << ctx.inventory.size() << "\n";
    std::cout << "Communication pairs: " << ctx.graph.size() << "\n";
    std::cout << "Anomalies detected: " << ctx.anomalies.size() << "\n";
    std::cout << "\nResults written to: " << output_file << "\n";
    std::cout << "============================================================\n";

    pcap_close(handle);
    return 0;
}