from scapy.all import sniff, IP
import pandas as pd
import os
import time
from utils.visualization import visualize_traffic
from colorama import Fore, Style  # Import colorama

# Global variables
packet_data = []
data_file = 'data/captured_packets.csv'


def print_title():
    """Print the title with a star pattern and author name."""
    star_title = [
        "  *************   **                  ***********    **             ***             **   ***************   ***********          ****          *************   **      **   ",
        "  *************   **                ***************   **           ** **           **    ***************   ***********         **  **         *************   **    **     ",
        "  **              **               **             **   **         **   **         **           ***         **       **        **    **        **              **  **       ",
        "  ***********     **              **               **   **       **     **       **            ***         ** * * * **       **      **       **              ****         ",
        "  ***********     **              **               **    **     **       **     **             ***         ** **            ************      **              ****         ",
        "  **              **               **             **      **   **         **   **              ***         **   **         **          **     **              **  **       ",
        "  **              *************     ***************        ** **           ** **               ***         **     **      **            **    *************   **    **     ",
        "  **              *************       ***********           ***             ***                ***         **       **   **              **   *************   **      **   ",
    ]
    
    # Print the star title
    for line in star_title:
        print(Fore.RED + line)
    
    print(Fore.CYAN + "Made by: Harsh Dev\n" + Style.RESET_ALL)  # Reset color


def capture_packets(interface):
    """Capture packets from the specified network interface."""
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)


def process_packet(packet):
    """Process each captured packet."""
    if IP in packet:
        data = {
            'timestamp': time.time(),
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'protocol': packet[IP].proto,
            'length': len(packet)
        }
        packet_data.append(data)

        # Save packet data to a CSV file
        save_packet_data()

        # Visualize traffic after every 100 packets
        if len(packet_data) % 100 == 0:
            df = pd.DataFrame(packet_data)
            visualize_traffic(df)

        # Detect anomalies only if DataFrame is defined
        if len(packet_data) > 0:  # Ensure there are packets to analyze
            detect_anomalies(pd.DataFrame(packet_data))


def save_packet_data():
    """Save captured packet data to a CSV file."""
    df = pd.DataFrame(packet_data)
    df.to_csv(data_file, index=False)
    print(f"Saved {len(packet_data)} packets to {data_file}")


def detect_anomalies(df):
    """Detect and alert for anomalies in network traffic."""
    total_bytes = df['length'].sum()
    avg_packet_size = df['length'].mean()

    # Check for high average packet size
    if avg_packet_size > 1500:  # Adjust threshold as needed
        print("Anomaly detected: High average packet size!")
    
    # Check for high traffic volume in the last 100 packets
    if len(df) > 1000:  # Example threshold for packet count
        recent_traffic = df.tail(100)
        if recent_traffic['length'].sum() > 50000:  # Adjust as needed
            print("Anomaly detected: High traffic volume in the last 100 packets!")


def filter_packets(protocol=None):
    """Filter captured packets based on protocol."""
    df = pd.DataFrame(packet_data)
    if protocol:
        df = df[df['protocol'] == protocol]
    return df


def summarize_traffic():
    """Print a summary of captured traffic."""
    df = pd.DataFrame(packet_data)
    print("Traffic Summary:")
    print(df['protocol'].value_counts())


if __name__ == "__main__":
    print_title()  # Print the title when the program starts
    interface = "en0"  # Change this to your network interface
    capture_packets(interface)