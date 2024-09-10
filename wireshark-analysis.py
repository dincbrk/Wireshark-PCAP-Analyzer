import pyshark
import argparse
from fpdf import FPDF
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime

# Wireshark pcap dosyasını analiz eden fonksiyon
def analyze_pcap(file_path, filter_ip=None, filter_port=None):
    capture = pyshark.FileCapture(file_path)
    risk_report = []
    statistics = {
        'total_packets': 0,
        'protocols': Counter(),
        'ip_addresses': Counter(),
        'dns_queries': Counter(),
        'tcp_ports': Counter(),
        'udp_ports': Counter(),
        'timestamps': [],
        'per_packet_analysis': []
    }

    for packet in capture:
        statistics['total_packets'] += 1
        packet_info = {
            'packet_number': statistics['total_packets'],
            'protocol': packet.highest_layer,
            'source_ip': '',
            'destination_ip': '',
            'dns_query': '',
            'timestamp': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
            'risks': []
        }

        try:
            # IP adresleri analizi
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                packet_info['source_ip'] = src_ip
                packet_info['destination_ip'] = dst_ip
                statistics['ip_addresses'][src_ip] += 1
                statistics['ip_addresses'][dst_ip] += 1

                if filter_ip and (src_ip == filter_ip or dst_ip == filter_ip):
                    packet_info['risks'].append({
                        'risk': "[CUSTOM RISK] Filtered IP Activity",
                        'description': f"Packet detected involving the IP address {filter_ip}.",
                        'solution': "Investigate if this IP is known to your network."
                    })

            # Protokol analizi
            statistics['protocols'][packet.highest_layer] += 1
            packet_time = datetime.strptime(packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
            statistics['timestamps'].append(packet_time)

            # HTTP risk analizi
            if hasattr(packet, 'http'):
                packet_info['risks'].append({
                    'risk': "[HIGH RISK] HTTP Unencrypted Traffic",
                    'description': "Unencrypted HTTP traffic detected, which is vulnerable to man-in-the-middle attacks.",
                    'solution': "Consider using HTTPS for secure communication."
                })

            # DNS risk analizi
            if hasattr(packet, 'dns'):
                statistics['dns_queries'][packet.dns.qry_name] += 1
                packet_info['dns_query'] = packet.dns.qry_name
                packet_info['risks'].append({
                    'risk': "[MEDIUM RISK] DNS Query",
                    'description': f"DNS query detected: {packet.dns.qry_name}",
                    'solution': "Ensure the DNS server being queried is trusted and not malicious."
                })

            # Telnet risk analizi
            if hasattr(packet, 'telnet'):
                packet_info['risks'].append({
                    'risk': "[HIGH RISK] Telnet Traffic",
                    'description': "Telnet traffic detected, which is an insecure protocol.",
                    'solution': "Replace Telnet with a secure protocol like SSH."
                })

            # FTP risk analizi
            if hasattr(packet, 'ftp'):
                packet_info['risks'].append({
                    'risk': "[HIGH RISK] FTP Traffic",
                    'description': "Unencrypted FTP traffic detected, which is vulnerable to credential theft.",
                    'solution': "Use SFTP or SCP for secure file transfers."
                })

            # ICMP risk analizi
            if hasattr(packet, 'icmp'):
                packet_info['risks'].append({
                    'risk': "[MEDIUM RISK] ICMP Traffic",
                    'description': "ICMP traffic detected, which can be used for network reconnaissance.",
                    'solution': "Limit ICMP traffic to essential use cases."
                })

            # TCP ve UDP port analizleri
            if hasattr(packet, 'tcp'):
                port = int(packet.tcp.dstport)
                statistics['tcp_ports'][port] += 1
                if filter_port and port == filter_port:
                    packet_info['risks'].append({
                        'risk': "[CUSTOM RISK] Filtered Port Activity",
                        'description': f"Packet detected involving the TCP port {filter_port}.",
                        'solution': "Check if this port is allowed and secure."
                    })

            if hasattr(packet, 'udp'):
                port = int(packet.udp.dstport)
                statistics['udp_ports'][port] += 1
                if filter_port and port == filter_port:
                    packet_info['risks'].append({
                        'risk': "[CUSTOM RISK] Filtered Port Activity",
                        'description': f"Packet detected involving the UDP port {filter_port}.",
                        'solution': "Check if this port is allowed and secure."
                    })

            statistics['per_packet_analysis'].append(packet_info)

        except AttributeError:
            continue

    capture.close()
    return risk_report, statistics

# Zaman temelli trafik analizi
def time_based_analysis(statistics):
    time_counts = Counter([t.strftime('%Y-%m-%d %H:%M') for t in statistics['timestamps']])
    plt.figure(figsize=(10, 6))
    plt.bar(time_counts.keys(), time_counts.values(), color='blue')
    plt.xticks(rotation=90)
    plt.xlabel("Time (Minute)")
    plt.ylabel("Packet Count")
    plt.title("Packet Traffic Over Time")
    plt.tight_layout()
    plt.savefig("time_analysis.png")
    plt.close()

# PDF raporu oluşturma fonksiyonu (kurumsal ve şık tasarım)
def generate_pdf(report_data, statistics, output_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Kurumsal başlık
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Wireshark Detailed Analysis Report", ln=True, align="C")
    pdf.ln(10)
    
    # Genel İstatistikler
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="General Statistics", ln=True, align="L")
    pdf.ln(5)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Total Packets: {statistics['total_packets']}", ln=True, align="L")
    pdf.cell(200, 10, txt=f"Protocols Analyzed: {len(statistics['protocols'])}", ln=True, align="L")
    pdf.ln(10)

    # Her Paket için Detaylı Analiz
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Per Packet Analysis", ln=True, align="L")
    pdf.ln(5)
    pdf.set_font("Arial", size=10)
    
    for packet in statistics['per_packet_analysis']:
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(200, 10, txt=f"Packet {packet['packet_number']}", ln=True, align="L")
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=f"Protocol: {packet['protocol']}", ln=True, align="L")
        pdf.cell(200, 10, txt=f"Source IP: {packet['source_ip']}", ln=True, align="L")
        pdf.cell(200, 10, txt=f"Destination IP: {packet['destination_ip']}", ln=True, align="L")
        pdf.cell(200, 10, txt=f"DNS Query: {packet['dns_query']}", ln=True, align="L")
        pdf.cell(200, 10, txt=f"Timestamp: {packet['timestamp']}", ln=True, align="L")
        pdf.ln(5)

        if packet['risks']:
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(200, 10, txt="Risks:", ln=True, align="L")
            pdf.set_font("Arial", size=10)
            for risk in packet['risks']:
                pdf.cell(200, 10, txt=f"Risk: {risk['risk']}", ln=True, align="L")
                pdf.multi_cell(0, 10, f"Description: {risk['description']}")
                pdf.multi_cell(0, 10, f"Solution: {risk['solution']}")
                pdf.ln(5)
        else:
            pdf.cell(200, 10, txt="No risks detected.", ln=True, align="L")

    # Genel Tavsiyeler
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Overall Risk Summary", ln=True, align="L")
    pdf.ln(5)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 10, "1. Ensure secure communication using encryption such as HTTPS.\n"
                          "2. Regularly review and monitor DNS queries for potential threats.\n"
                          "3. Replace insecure protocols such as Telnet and FTP with their secure alternatives.\n"
                          "4. Restrict ICMP traffic to minimize reconnaissance activities.\n")

    # Zaman temelli analiz grafiği ekleme
    pdf.ln(10)
    pdf.image("time_analysis.png", x=10, w=180)
    
    pdf.output(output_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analyze a Wireshark pcap file and generate a PDF report.")
    parser.add_argument('-f', '--file', required=True, help="Wireshark pcap file to analyze")
    parser.add_argument('-o', '--output', required=True, help="Output PDF report file")
    parser.add_argument('--filter-ip', help="Filter packets by specific IP address")
    parser.add_argument('--filter-port', type=int, help="Filter packets by specific TCP/UDP port")
    
    args = parser.parse_args()

    print(f"Analyzing {args.file}...")

    risk_report, statistics = analyze_pcap(args.file, filter_ip=args.filter_ip, filter_port=args.filter_port)

    print("Generating time-based traffic analysis...")
    time_based_analysis(statistics)

    print(f"Generating PDF report: {args.output}")
    generate_pdf(risk_report, statistics, args.output)

    print("Analysis complete.")
