# Wireshark PCAP Analyzer

This Python script analyzes a Wireshark pcap file and generates a detailed PDF report. The analysis includes protocol statistics, IP address analysis, DNS queries, TCP/UDP port analysis, and identification of potential security risks. The report also features a time-based traffic analysis graph.

## Features

- **Protocol Analysis:** Counts the occurrence of different protocols in the captured packets.
- **IP Address Analysis:** Tracks the source and destination IP addresses.
- **DNS Query Analysis:** Monitors DNS queries and flags potential security concerns.
- **TCP/UDP Port Analysis:** Analyzes traffic on specific TCP/UDP ports and flags unusual activities.
- **Risk Detection:** Identifies potential security risks related to unencrypted traffic, insecure protocols (Telnet, FTP), and ICMP traffic.
- **Time-Based Traffic Analysis:** Generates a graph showing packet traffic over time.
- **PDF Report Generation:** Compiles all analysis results into a professional-looking PDF report.

## Installation

To run this script, you need to have Python installed along with the following dependencies:

```bash
pip install pyshark fpdf matplotlib
```

## Usage

To use this script, run it from the command line with the following options:

```bash
python analyze_pcap.py -f <path_to_pcap_file> -o <output_pdf_file> [--filter-ip <ip_address>] [--filter-port <port_number>]
```

### Command Line Options

- `-f, --file`: **(Required)** Path to the Wireshark pcap file you want to analyze.
- `-o, --output`: **(Required)** Name of the output PDF report file.
- `--filter-ip`: **(Optional)** Filter packets involving a specific IP address.
- `--filter-port`: **(Optional)** Filter packets involving a specific TCP/UDP port.

### Example

```bash
python analyze_pcap.py -f capture.pcap -o report.pdf --filter-ip 192.168.1.1 --filter-port 80
```

This command analyzes the `capture.pcap` file, filters packets involving the IP address `192.168.1.1` or TCP/UDP port `80`, and generates a report called `report.pdf`.

## Output

The output is a detailed PDF report containing:

- General statistics about the pcap file.
- Detailed per-packet analysis, including protocol, IP addresses, DNS queries, and any identified risks.
- A time-based traffic analysis graph.
- A summary of overall risks and suggested actions.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue for any bugs or feature requests.

## Acknowledgements

This script uses the following Python libraries:
- [PyShark](https://github.com/KimiNewt/pyshark) for parsing pcap files.
- [FPDF](http://www.fpdf.org/) for generating PDF reports.
- [Matplotlib](https://matplotlib.org/) for creating graphs.

## Author
[Burak Dinç](https://github.com/dincbrk)
