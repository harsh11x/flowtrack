
# FlowTrack: Network Traffic Analyzer

## Overview

FlowTrack is a powerful network traffic analysis tool designed for monitoring, analyzing, and visualizing network packets in real-time. Built using Python and Scapy, it provides users with insights into their network traffic, making it easier to detect anomalies and understand usage patterns.

## Features

- **Real-Time Packet Capture**: Capture and analyze packets on specified network interfaces.
- **Traffic Visualization**: Visualize network traffic patterns and protocols using built-in graphing tools.
- **Anomaly Detection**: Identify unusual traffic patterns or spikes that may indicate security issues.
- **Protocol Filtering**: Filter packets based on protocols for focused analysis.
- **Traffic Summary**: Generate summaries of captured traffic for quick insights.

## How It Works

FlowTrack uses the Scapy library to sniff network packets on a specified interface. As packets are captured, the tool processes them to extract relevant information such as source and destination IP addresses, protocols, and packet sizes. The collected data is saved in a CSV file for further analysis and visualization.

## Installation

To get started with FlowTrack, follow these steps:

#### Run this tool as root user.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/harsh11x/flowtrack.git
   ```
   ```bash
   cd flowtrack
   ```

2. **Install required dependencies**:
   FlowTrack requires Python 3 and the following libraries:
   ```bash
   pip install scapy pandas colorama
   ```

3. **Run the tool**:
   - Edit the `flowtrack.py` file to set your network interface (e.g., `en0`, `eth0`):
     ```python
     interface = "en0"  # Change this to your network interface
     ```
   - Start the packet capture:
     ```bash
     python flowtrack.py
     ```

## How to Use

1. Once the tool is running, it will start capturing packets on the specified network interface.
2. You will see real-time updates about the number of captured packets and visualizations as they are processed.
3. Use the built-in commands to filter protocols and summarize traffic.

## Why FlowTrack is Better

FlowTrack offers several advantages over traditional packet analyzers:
- **Simplicity**: A straightforward command-line interface makes it easy to use, even for beginners.
- **Real-Time Analysis**: Unlike some tools that provide post-capture analysis, FlowTrack gives you insights as data is collected.
- **Anomaly Detection**: Helps in identifying potential security threats by monitoring unusual traffic patterns.

## Use Cases

- **Network Monitoring**: Ideal for system administrators looking to monitor network performance.
- **Security Auditing**: Helps in identifying suspicious activities on the network.
- **Educational Purposes**: Useful for students learning about network protocols and traffic analysis.

## Contribution

Contributions to FlowTrack are welcome! If you'd like to improve the tool or add features, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- **Harsh Dev** - [harsh11x](https://github.com/harsh11x)
