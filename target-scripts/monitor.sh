#!/bin/bash
# Enhanced monitoring script for the target VM
# Monitors system activity, network connections, and security events

LOG_FILE="/var/log/target-monitor.log"
ALERT_THRESHOLD=10
CONNECTION_COUNT=0

# Colors for output (when running interactively)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_message() {
    echo "$(date -Iseconds) - $1" | tee -a "$LOG_FILE"
}

log_alert() {
    echo "$(date -Iseconds) - [ALERT] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo "$(date -Iseconds) - [INFO] $1" | tee -a "$LOG_FILE"
}

check_suspicious_connections() {
    # Monitor for suspicious connection patterns
    local tcp_connections=$(ss -tuln | wc -l)
    local established=$(ss -tun state established | wc -l)
    
    if [ "$established" -gt "$ALERT_THRESHOLD" ]; then
        log_alert "High number of established connections: $established"
    fi
    
    # Check for connections to vulnerable ports
    local vuln_port_9000=$(ss -tln | grep ":9000" | wc -l)
    local vuln_port_8080=$(ss -tln | grep ":8080" | wc -l)
    
    if [ "$vuln_port_9000" -gt 0 ] || [ "$vuln_port_8080" -gt 0 ]; then
        log_info "Vulnerable services active - TCP:$vuln_port_9000, HTTP:$vuln_port_8080"
    fi
}

check_system_resources() {
    # Monitor CPU and memory usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}')
    
    # Log if usage is high
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        log_alert "High CPU usage: ${cpu_usage}%"
    fi
    
    if (( $(echo "$mem_usage > 90" | bc -l) )); then
        log_alert "High memory usage: ${mem_usage}%"
    fi
    
    log_info "Resources - CPU: ${cpu_usage}%, Memory: ${mem_usage}%"
}

check_failed_connections() {
    # Check for failed connection attempts (basic intrusion detection)
    local failed_ssh=$(journalctl --since "5 minutes ago" | grep -i "failed\|invalid\|refused" | wc -l)
    
    if [ "$failed_ssh" -gt 5 ]; then
        log_alert "Multiple failed connection attempts detected: $failed_ssh"
    fi
}

check_vulnerable_services() {
    # Check if our vulnerable services are running
    local tcp_server_status="STOPPED"
    local web_server_status="STOPPED"
    
    if systemctl is-active --quiet vulnerable-server.service; then
        tcp_server_status="RUNNING"
    fi
    
    if systemctl is-active --quiet vulnerable-web.service; then
        web_server_status="RUNNING"
    fi
    
    log_info "Service Status - TCP Server: $tcp_server_status, Web Server: $web_server_status"
    
    # Alert if services are down
    if [ "$tcp_server_status" = "STOPPED" ] || [ "$web_server_status" = "STOPPED" ]; then
        log_alert "One or more vulnerable services are not running"
    fi
}

check_file_changes() {
    # Monitor important files for changes
    local sensitive_files="/etc/passwd /etc/shadow /etc/hosts"
    
    for file in $sensitive_files; do
        if [ -f "$file" ]; then
            local current_hash=$(md5sum "$file" | awk '{print $1}')
            local hash_file="/tmp/$(basename $file).hash"
            
            if [ -f "$hash_file" ]; then
                local stored_hash=$(cat "$hash_file")
                if [ "$current_hash" != "$stored_hash" ]; then
                    log_alert "File modified: $file"
                fi
            fi
            
            echo "$current_hash" > "$hash_file"
        fi
    done
}

log_network_activity() {
    # Log current network connections and listening ports
    echo "$(date -Iseconds) - === NETWORK SNAPSHOT ===" >> "$LOG_FILE"
    echo "Active connections:" >> "$LOG_FILE"
    ss -tuln >> "$LOG_FILE" 2>/dev/null
    
    echo "Established connections:" >> "$LOG_FILE"
    ss -tun state established >> "$LOG_FILE" 2>/dev/null
    
    echo "Network processes:" >> "$LOG_FILE"
    lsof -i >> "$LOG_FILE" 2>/dev/null || netstat -tulpn >> "$LOG_FILE" 2>/dev/null
    echo "---" >> "$LOG_FILE"
}

log_system_snapshot() {
    # Log system state
    echo "$(date -Iseconds) - === SYSTEM SNAPSHOT ===" >> "$LOG_FILE"
    echo "System load:" >> "$LOG_FILE"
    uptime >> "$LOG_FILE"
    
    echo "Memory usage:" >> "$LOG_FILE"
    free -h >> "$LOG_FILE"
    
    echo "Disk usage:" >> "$LOG_FILE"
    df -h >> "$LOG_FILE" 2>/dev/null
    
    echo "Top processes:" >> "$LOG_FILE"
    ps aux --sort=-%cpu | head -10 >> "$LOG_FILE"
    echo "---" >> "$LOG_FILE"
}

check_attack_indicators() {
    # Look for common attack indicators in recent logs
    local indicators="sudo su whoami id /etc/passwd ../../../ <script> SELECT FROM"
    
    for indicator in $indicators; do
        local count=$(journalctl --since "5 minutes ago" | grep -i "$indicator" | wc -l)
        if [ "$count" -gt 0 ]; then
            log_alert "Potential attack indicator detected: '$indicator' ($count occurrences)"
        fi
    done
    
    # Check vulnerable service logs for exploitation attempts
    if [ -f "/var/log/vulnerable-server.log" ]; then
        local exploit_attempts=$(tail -50 /var/log/vulnerable-server.log | grep -i "exec\|file\|dangerous" | wc -l)
        if [ "$exploit_attempts" -gt 0 ]; then
            log_alert "TCP server exploitation attempts: $exploit_attempts"
        fi
    fi
    
    if [ -f "/var/log/vulnerable-web.log" ]; then
        local web_exploits=$(tail -50 /var/log/vulnerable-web.log | grep -i "script>\|passwd\|critical" | wc -l)
        if [ "$web_exploits" -gt 0 ]; then
            log_alert "Web server exploitation attempts: $web_exploits"
        fi
    fi
}

# Main monitoring loop
main() {
    log_message "=== TARGET MONITORING STARTED ==="
    log_info "Monitoring system for security events and performance"
    log_info "Alert threshold: $ALERT_THRESHOLD connections"
    
    # Initial system check
    check_vulnerable_services
    check_system_resources
    log_network_activity
    log_system_snapshot
    
    # Continuous monitoring loop
    while true; do
        # Quick checks every 30 seconds
        check_suspicious_connections
        check_vulnerable_services
        check_attack_indicators
        
        # Detailed logging every 2 minutes (4 cycles)
        if [ $(($(date +%s) % 120)) -lt 30 ]; then
            log_network_activity
            check_system_resources
            check_failed_connections
            check_file_changes
        fi
        
        # Full system snapshot every 10 minutes
        if [ $(($(date +%s) % 600)) -lt 30 ]; then
            log_system_snapshot
            log_info "=== PERIODIC SYSTEM CHECK COMPLETE ==="
        fi
        
        sleep 30
    done
}

# Signal handlers
cleanup() {
    log_message "=== TARGET MONITORING STOPPED ==="
    exit 0
}

# Handle termination signals gracefully
trap cleanup SIGTERM SIGINT

# Start monitoring if run as main script
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Check if running as root for better monitoring capabilities
    if [ "$EUID" -eq 0 ]; then
        log_info "Running with root privileges - full monitoring enabled"
    else
        log_info "Running as user - limited monitoring capabilities"
    fi
    
    main
fi