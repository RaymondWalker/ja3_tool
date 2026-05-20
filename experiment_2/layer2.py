import hashlib
from scapy.all import sniff
from scapy.layers.tls.handshake import TLSClientHello

GREASE = {0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,
          0x6a6a,0x7a7a,0x8a8a,0x9a9a,0xaaaa,0xbaba,
          0xcaca,0xdada,0xeaea,0xfafa}

KNOWN_HASHES = {
    "7dcce5b76c8b17472d024758970a406b": "Firefox",
    "773906b0efdefa24a7f2b8eb6985bf37": "Chrome",
}

def compute_ja3(hello):
    version = hello.version
    ciphers = [c for c in hello.ciphers if c not in GREASE]
    extensions, curves, point_formats = [], [], []   # ← fixed name

    for ext in (hello.ext or []):
        if ext.type in GREASE:
            continue
        extensions.append(ext.type)
        if ext.type == 10:
            curves = [g for g in ext.groups if g not in GREASE]
        if ext.type == 11:
            point_formats = list(ext.ecpl)           # ← consistent name

    ja3_str = ",".join([
        str(version),
        "-".join(map(str, ciphers)),
        "-".join(map(str, extensions)),
        "-".join(map(str, curves)),
        "-".join(map(str, point_formats))
    ])
    return hashlib.md5(ja3_str.encode()).hexdigest(), ja3_str

def packet_callback(pkt):                            # ← only one definition
    if pkt.haslayer(TLSClientHello):
        hello = pkt[TLSClientHello]
        ja3_hash, ja3_str = compute_ja3(hello)

        src_ip = pkt['IP'].src if pkt.haslayer('IP') else "unknown"
        client = KNOWN_HASHES.get(ja3_hash, "unknown client")

        print(f"\n[+] Source IP  : {src_ip}")
        print(f"[+] JA3 String : {ja3_str}")
        print(f"[+] JA3 Hash   : {ja3_hash}")
        print(f"[+] Known As   : {client}")

sniff(filter="tcp port 443", prn=packet_callback, store=0)