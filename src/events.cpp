#include "events.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

namespace {

std::string escapeJSON(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        if (c == '"') ss << "\\\"";
        else if (c == '\\') ss << "\\\\";
        else if (c == '\b') ss << "\\b";
        else if (c == '\f') ss << "\\f";
        else if (c == '\n') ss << "\\n";
        else if (c == '\r') ss << "\\r";
        else if (c == '\t') ss << "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
        } else {
            ss << c;
        }
    }
    return ss.str();
}

std::string ipToStr(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

} // namespace

std::string anomalyTypeToString(AnomalyType type) {
    switch (type) {
        case AnomalyType::PORT_SCAN: return "PORT_SCAN";
        case AnomalyType::SYN_FLOOD: return "SYN_FLOOD";
        case AnomalyType::DNS_TUNNEL: return "DNS_TUNNEL";
        default: return "UNKNOWN";
    }
}

std::string AnomalyEvent::toJSON() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "{\"event\":\"anomaly\","
       << "\"ts\":" << timestamp << ","
       << "\"type\":\"" << anomalyTypeToString(type) << "\","
       << "\"detail\":{"
       << "\"src_ip\":\"" << escapeJSON(src_ip) << "\","
       << "\"target\":\"" << escapeJSON(target_ip) << "\","
       << "\"count\":" << count << ","
       << "\"info\":\"" << escapeJSON(detail) << "\"}"
       << "}";
    return ss.str();
}

std::string SecurityAlert::toJSON() const {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3);
    ss << "{\"event\":\"security_alert\","
       << "\"ts\":" << timestamp << ","
       << "\"alert_type\":\"" << escapeJSON(alert_type) << "\","
       << "\"five_tuple\":{"
       << "\"src_ip\":\"" << ipToStr(tuple.src_ip) << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_ip\":\"" << ipToStr(tuple.dst_ip) << "\","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"proto\":\"" << (tuple.protocol == 6 ? "TCP" : tuple.protocol == 17 ? "UDP" : std::to_string(tuple.protocol)) << "\"},"
       << "\"app_or_domain\":\"" << escapeJSON(app_or_domain) << "\","
       << "\"blocked\":" << (blocked ? "true" : "false") << ","
       << "\"reason\":\"" << escapeJSON(reason) << "\","
       << "\"detail\":\"" << escapeJSON(detail) << "\""
       << "}";
    return ss.str();
}

std::string SecurityStats::toJSON(uint64_t total_packets, uint64_t total_bytes, uint64_t total_blocked) const {
    std::ostringstream ss;
    ss << "{"
       << "\"total_packets\":" << total_packets << ","
       << "\"total_bytes\":" << total_bytes << ","
       << "\"blocked_total\":" << total_blocked << ","
       << "\"scan_alerts\":" << port_scan_alerts.load() << ","
       << "\"syn_flood_alerts\":" << syn_flood_alerts.load() << ","
       << "\"dns_tunnel_alerts\":" << dns_tunnel_alerts.load() << ","
       << "\"malicious_domain_blocks\":" << malicious_domain_blocks.load() << ","
       << "\"vpn_detections\":" << vpn_detections.load() << ","
       << "\"vpn_blocks\":" << vpn_blocks.load()
       << "}";
    return ss.str();
}

EventSink& EventSink::instance() {
    static EventSink s_instance;
    return s_instance;
}

EventSink::~EventSink() {
    closeFile();
}

void EventSink::setCallback(EventCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(cb);
}

bool EventSink::openFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outfile_.is_open()) {
        outfile_.close();
    }
    outfile_.open(filepath, std::ios::out | std::ios::app);
    return outfile_.is_open();
}

void EventSink::closeFile() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outfile_.is_open()) {
        outfile_.close();
    }
}

void EventSink::emitAnomaly(const AnomalyEvent& event) {
    switch (event.type) {
        case AnomalyType::PORT_SCAN:
            stats_.port_scan_alerts++;
            break;
        case AnomalyType::SYN_FLOOD:
            stats_.syn_flood_alerts++;
            break;
        case AnomalyType::DNS_TUNNEL:
            stats_.dns_tunnel_alerts++;
            break;
    }

    std::string json = event.toJSON();
    emitRawJSON(json);

    if (console_alerts_) {
        std::cout << "\033[1;31m[ALERT] " << anomalyTypeToString(event.type)
                  << " detected from " << event.src_ip
                  << " -> " << event.target_ip
                  << " (" << event.detail << ")\033[0m\n";
    }
}

void EventSink::emitAlert(const SecurityAlert& alert) {
    if (alert.reason == "MALICIOUS") {
        stats_.malicious_domain_blocks++;
    } else if (alert.reason == "VPN_DETECTED") {
        stats_.vpn_detections++;
        if (alert.blocked) {
            stats_.vpn_blocks++;
        }
    }

    std::string json = alert.toJSON();
    emitRawJSON(json);

    if (console_alerts_) {
        std::string color = alert.blocked ? "\033[1;31m" : "\033[1;33m";
        std::cout << color << "[SECURITY] " << alert.alert_type
                  << (alert.blocked ? " [BLOCKED]" : " [FLAGGED]")
                  << " " << alert.app_or_domain
                  << " (" << alert.detail << ")\033[0m\n";
    }
}

void EventSink::emitRawJSON(const std::string& json) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (outfile_.is_open()) {
        outfile_ << json << "\n";
        outfile_.flush();
    }
    if (callback_) {
        callback_(json);
    }
}

} // namespace DPI
