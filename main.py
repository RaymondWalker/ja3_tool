# TLS Client Hello parsing
from scapy.all import *
load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello

def packet_callback(pkt):
    if pkt.haslayer(TLSClientHello):
        hello = pkt[TLSClientHello]
        print(f"Version: {hello.version}")
        print(f"CiphersL {[c for c in hello.ciphers]}")
        #inspect the extensions manually
        for ext in hello.ext:
            print(f" Extensiosn type: {ext.type}")
    
sniff(filter="tcp port 443", prn=packet_callback, store=0)