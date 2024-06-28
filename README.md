# Basic - Network Intrusion Detection System
This project is a simple Network Intrusion Detection System (NIDS) written in Python using the Scapy library. The NIDS monitors network traffic, extracts relevant features from each packet, and detects anomalies based on predefined rules.

## Features
- ##### Real-time Packet Capture: Captures network packets in real-time for analysis.
- ##### Feature Extraction: Extracts important features such as source IP, destination IP, source port, destination port, and protocol.
- ##### Anomaly Detection: Detects anomalies based on predefined criteria (e.g., unexpected destination ports).
- ##### Logging: Logs events (both normal and anomalous traffic) to a file for further analysis.


## Here's an explanation of the key components and functionality:
#### 1.Imports:
* scapy.all for network packet capturing and processing.
* logging for logging events.

#### 2.process_packet Function:
* Processes each captured packet.
* Extracts features from the packet using the extract_features function.
* Checks for anomalies in the extracted features using the detect_anomalies function.
* Logs and prints events based on whether anomalies are detected or not.

#### 3.extract_features Function:
* Extracts relevant features from the packet, such as source IP, destination IP, source port, destination port, and protocol (TCP/UDP).

#### 4.detect_anomalies Function:
* Checks if the destination port is in a set of known ports (80, 443, 21, 22).
* Flags the packet as anomalous if the destination port is not in the known ports.

#### 5.log_event Function:
* Logs events to a file (ids.log).

#### 6.Logging Configuration:
* Configures logging to write info-level logs to ids.log.

#### 7.Packet Sniffing:
* Uses sniff from Scapy to capture packets and process them with process_packet.
* Captures 20 packets for processing.

## How It Works:
- The script captures network packets using Scapy.
- For each packet, it extracts features like IP addresses and ports.
- It checks if the destination port is among known, expected ports.
- If the port is not expected, it logs and prints an "anomalies detected" event.
- If the port is expected, it logs and prints a "normal traffic" event.
- Events are logged to a file for further analysis.

## Example Use Case:
This script could be used as a basic tool to monitor a network for unusual traffic, such as connections to unexpected ports, which might indicate suspicious activity.

## Requirements:
To run this script, you need to have Scapy installed. You can install it using pip:

```bash
pip install scapy
```
Make sure you run the script with appropriate permissions to capture network traffic, usually requiring administrator or root privileges.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
