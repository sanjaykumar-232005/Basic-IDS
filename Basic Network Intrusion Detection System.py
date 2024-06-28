from scapy.all import sniff, IP, TCP, UDP
import logging
def process_packet(packet):
    #print(packet.summary())
    features=extract_features(packet)
    #print(features)
    if detect_anomalies(features):
        event = f"anomalies detected: {features}"
        print(event)
        log_event(event)
    else:
        event = f"normal traffic: {features}"
        print(event)
        log_event(event)

def extract_features(packet):
    features={}
    if packet.haslayer(IP):
        ip_layer=packet[IP]
        features['src_ip']=ip_layer.src
        features['dst_ip']=ip_layer.dst

    if packet.haslayer(UDP):
        udp_layer=packet[UDP]
        features['src_port']=udp_layer.sport
        features['dst_port']=udp_layer.dport
        features['protocol']='UDP'
    elif packet.haslayer(TCP):
        tcp_layer=packet[TCP]
        features['src_port']=tcp_layer.sport
        features['dst_port']=tcp_layer.dport
        features['protocol']='TCP'
    return features 

def detect_anomalies(features):
    Knownports={80,443,21,22}
    if features['dst_port'] not in Knownports:
        return True
    return False

def log_event(event):
    logging.info(event)

logging.basicConfig(filename='ids.log',level=logging.INFO)
sniff(prn=process_packet,count=20)