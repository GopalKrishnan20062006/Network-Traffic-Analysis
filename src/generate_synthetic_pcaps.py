import csv
import pathlib
import random
import sys

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    wrpcap,
)


random.seed(42)

OUTPUT_DIR = pathlib.Path(
    sys.argv[1] if len(sys.argv) > 1 else "data"
)

PCAP_DIR = OUTPUT_DIR / "pcaps"
PCAP_DIR.mkdir(parents=True, exist_ok=True)


VICTIM_IP = "192.168.56.10"
VICTIM_MAC = "08:00:27:aa:00:10"

ATTACKER_IP = "192.168.56.20"
ATTACKER_MAC = "08:00:27:bb:00:20"

GATEWAY_IP = "192.168.56.1"
GATEWAY_MAC = "08:00:27:cc:00:01"

CLIENTS = [
    ("192.168.56.30", "08:00:27:dd:00:30"),
    ("192.168.56.31", "08:00:27:dd:00:31"),
]

EXTERNAL_IP = "203.0.113.50"

labels = []


def create_tcp_session(
    start_time,
    source_ip,
    source_mac,
    destination_ip,
    destination_mac,
    source_port,
    destination_port,
    payload=b"",
    successful=True,
    reply=None,
):
    packets = []
    current_time = start_time

    client_ethernet = Ether(
        src=source_mac,
        dst=destination_mac
    )

    server_ethernet = Ether(
        src=destination_mac,
        dst=source_mac
    )

    def add_packet(packet, time_difference=0.001):
        nonlocal current_time

        packet.time = current_time
        packets.append(packet)
        current_time += time_difference

    syn_packet = (
        client_ethernet
        / IP(
            src=source_ip,
            dst=destination_ip
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="S",
            seq=100
        )
    )

    add_packet(syn_packet)

    syn_ack_packet = (
        server_ethernet
        / IP(
            src=destination_ip,
            dst=source_ip
        )
        / TCP(
            sport=destination_port,
            dport=source_port,
            flags="SA",
            seq=500,
            ack=101
        )
    )

    add_packet(syn_ack_packet)

    ack_packet = (
        client_ethernet
        / IP(
            src=source_ip,
            dst=destination_ip
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="A",
            seq=101,
            ack=501
        )
    )

    add_packet(ack_packet)

    if payload:
        data_packet = (
            client_ethernet
            / IP(
                src=source_ip,
                dst=destination_ip
            )
            / TCP(
                sport=source_port,
                dport=destination_port,
                flags="PA",
                seq=101,
                ack=501
            )
            / Raw(payload)
        )

        add_packet(data_packet)

        if reply is None:
            reply = b"ok" if successful else b"denied"

        if reply:
            response_packet = (
                server_ethernet
                / IP(
                    src=destination_ip,
                    dst=source_ip
                )
                / TCP(
                    sport=destination_port,
                    dport=source_port,
                    flags="PA",
                    seq=501,
                    ack=101 + len(payload)
                )
                / Raw(reply)
            )

            add_packet(response_packet)

    client_fin = (
        client_ethernet
        / IP(
            src=source_ip,
            dst=destination_ip
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="FA",
            seq=200,
            ack=600
        )
    )

    add_packet(client_fin)

    server_fin = (
        server_ethernet
        / IP(
            src=destination_ip,
            dst=source_ip
        )
        / TCP(
            sport=destination_port,
            dport=source_port,
            flags="FA",
            seq=600,
            ack=201
        )
    )

    add_packet(server_fin)

    return packets, current_time


def generate_benign_traffic(
    output_path,
    start_time,
    number_of_sessions
):
    packets = []
    current_time = start_time

    for _ in range(number_of_sessions):

        source_ip, source_mac = random.choice(CLIENTS)

        traffic_type = random.choice([
            "http",
            "ssh",
            "dns",
            "ping"
        ])

        if traffic_type == "http":

            source_port = random.randint(40000, 60000)

            http_request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: lab\r\n"
                b"\r\n"
            )

            http_request += (
                b"x" * random.randint(0, 400)
            )

            session_packets, current_time = create_tcp_session(
                current_time,
                source_ip,
                source_mac,
                VICTIM_IP,
                VICTIM_MAC,
                source_port,
                80,
                http_request,
            )

            packets.extend(session_packets)

        elif traffic_type == "ssh":

            source_port = random.randint(40000, 60000)

            ssh_data = (
                b"SSH-2.0-OpenSSH_9.6"
                + b"x" * random.randint(100, 800)
            )

            session_packets, current_time = create_tcp_session(
                current_time,
                source_ip,
                source_mac,
                VICTIM_IP,
                VICTIM_MAC,
                source_port,
                22,
                ssh_data,
            )

            packets.extend(session_packets)

        elif traffic_type == "dns":

            dns_query = (
                Ether(
                    src=source_mac,
                    dst=GATEWAY_MAC
                )
                / IP(
                    src=source_ip,
                    dst=GATEWAY_IP
                )
                / UDP(
                    sport=random.randint(40000, 60000),
                    dport=53
                )
                / DNS(
                    rd=1,
                    qd=DNSQR(qname="example.com")
                )
            )

            dns_query.time = current_time
            packets.append(dns_query)

            current_time += 0.001

        else:

            ping_packet = (
                Ether(
                    src=source_mac,
                    dst=VICTIM_MAC
                )
                / IP(
                    src=source_ip,
                    dst=VICTIM_IP
                )
                / ICMP()
            )

            ping_packet.time = current_time
            packets.append(ping_packet)

            current_time += 0.001

        current_time += random.uniform(0.2, 1.5)

    arp_response = (
        Ether(
            src=GATEWAY_MAC,
            dst=VICTIM_MAC
        )
        / ARP(
            op=2,
            hwsrc=GATEWAY_MAC,
            psrc=GATEWAY_IP,
            hwdst=VICTIM_MAC,
            pdst=VICTIM_IP
        )
    )

    arp_response.time = current_time
    packets.append(arp_response)

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "benign",
        "",
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_port_scan(
    output_path,
    start_time=1_700_001_000.0
):
    packets = []
    current_time = start_time

    ports_to_scan = random.sample(
        range(1, 1025),
        150
    )

    for destination_port in ports_to_scan:

        syn_packet = (
            Ether(
                src=ATTACKER_MAC,
                dst=VICTIM_MAC
            )
            / IP(
                src=ATTACKER_IP,
                dst=VICTIM_IP
            )
            / TCP(
                sport=44444,
                dport=destination_port,
                flags="S"
            )
        )

        syn_packet.time = current_time
        packets.append(syn_packet)

        current_time += 0.003

        reset_packet = (
            Ether(
                src=VICTIM_MAC,
                dst=ATTACKER_MAC
            )
            / IP(
                src=VICTIM_IP,
                dst=ATTACKER_IP
            )
            / TCP(
                sport=destination_port,
                dport=44444,
                flags="RA"
            )
        )

        reset_packet.time = current_time
        packets.append(reset_packet)

        current_time += 0.003

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "port_scan",
        ATTACKER_IP,
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_ssh_bruteforce(
    output_path,
    start_time=1_700_002_000.0
):
    packets = []
    current_time = start_time

    for _ in range(60):

        source_port = random.randint(30000, 60000)

        ssh_authentication = (
            b"SSH-2.0-libssh_0.9 AUTH"
        )

        session_packets, current_time = create_tcp_session(
            current_time,
            ATTACKER_IP,
            ATTACKER_MAC,
            VICTIM_IP,
            VICTIM_MAC,
            source_port,
            22,
            ssh_authentication,
            successful=False,
        )

        packets.extend(session_packets)

        current_time += 0.15

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "ssh_bruteforce",
        ATTACKER_IP,
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_arp_spoof(
    output_path,
    start_time=1_700_003_000.0
):
    packets = []
    current_time = start_time

    legitimate_arp = (
        Ether(
            src=GATEWAY_MAC,
            dst=VICTIM_MAC
        )
        / ARP(
            op=2,
            hwsrc=GATEWAY_MAC,
            psrc=GATEWAY_IP,
            hwdst=VICTIM_MAC,
            pdst=VICTIM_IP
        )
    )

    legitimate_arp.time = current_time
    packets.append(legitimate_arp)

    current_time += 1

    for _ in range(40):

        spoofed_arp = (
            Ether(
                src=ATTACKER_MAC,
                dst=VICTIM_MAC
            )
            / ARP(
                op=2,
                hwsrc=ATTACKER_MAC,
                psrc=GATEWAY_IP,
                hwdst=VICTIM_MAC,
                pdst=VICTIM_IP
            )
        )

        spoofed_arp.time = current_time
        packets.append(spoofed_arp)

        current_time += 0.5

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "arp_spoof",
        ATTACKER_IP,
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_syn_flood(
    output_path,
    start_time=1_700_004_000.0
):
    packets = []
    current_time = start_time

    for _ in range(1500):

        source_port = random.randint(
            1024,
            65535
        )

        syn_packet = (
            Ether(
                src=ATTACKER_MAC,
                dst=VICTIM_MAC
            )
            / IP(
                src=ATTACKER_IP,
                dst=VICTIM_IP
            )
            / TCP(
                sport=source_port,
                dport=80,
                flags="S"
            )
        )

        syn_packet.time = current_time
        packets.append(syn_packet)

        current_time += 0.0004

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "syn_flood",
        ATTACKER_IP,
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_exfiltration(
    output_path,
    start_time=1_700_005_000.0
):
    packets = []
    current_time = start_time

    for _ in range(430):

        data_packet = (
            Ether(
                src=VICTIM_MAC,
                dst=GATEWAY_MAC
            )
            / IP(
                src=VICTIM_IP,
                dst=EXTERNAL_IP
            )
            / TCP(
                sport=51000,
                dport=4444,
                flags="PA"
            )
            / Raw(
                b"A" * 1400
            )
        )

        data_packet.time = current_time
        packets.append(data_packet)

        current_time += 0.01

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "exfiltration",
        VICTIM_IP,
        EXTERNAL_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def generate_cleartext_telnet(
    output_path,
    start_time=1_700_006_000.0
):
    packets = []
    current_time = start_time

    for _ in range(3):

        telnet_data = (
            b"labuser\r\n"
            b"labpass\r\n"
        )

        telnet_reply = b"Welcome\r\n"

        source_port = random.randint(
            40000,
            60000
        )

        session_packets, current_time = create_tcp_session(
            current_time,
            CLIENTS[0][0],
            CLIENTS[0][1],
            VICTIM_IP,
            VICTIM_MAC,
            source_port,
            23,
            telnet_data,
            reply=telnet_reply,
        )

        packets.extend(session_packets)

        current_time += 1

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "cleartext_protocol",
        CLIENTS[0][0],
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def create_tls_client_hello(version=0x0301):

    random_bytes = bytes(
        random.getrandbits(8)
        for _ in range(32)
    )

    handshake_body = (
        version.to_bytes(2, "big")
        + random_bytes
        + b"\x00"
        + (2).to_bytes(2, "big")
        + b"\x00\x2f"
        + b"\x01\x00"
    )

    handshake = (
        b"\x01"
        + len(handshake_body).to_bytes(3, "big")
        + handshake_body
    )

    tls_record = (
        b"\x16"
        + version.to_bytes(2, "big")
        + len(handshake).to_bytes(2, "big")
        + handshake
    )

    return tls_record


def generate_weak_tls(
    output_path,
    start_time=1_700_007_000.0
):
    packets = []

    tls_client_hello = create_tls_client_hello(
        version=0x0301
    )

    source_port = random.randint(
        40000,
        60000
    )

    session_packets, _ = create_tcp_session(
        start_time,
        CLIENTS[1][0],
        CLIENTS[1][1],
        VICTIM_IP,
        VICTIM_MAC,
        source_port,
        443,
        tls_client_hello,
        reply=b"",
    )

    packets.extend(session_packets)

    wrpcap(str(output_path), packets)

    labels.append((
        output_path.name,
        "weak_tls",
        CLIENTS[1][0],
        VICTIM_IP,
        float(packets[0].time),
        float(packets[-1].time)
    ))


def main():

    generate_benign_traffic(
        PCAP_DIR / "benign_01.pcap",
        1_700_000_000.0,
        120
    )

    generate_benign_traffic(
        PCAP_DIR / "benign_02.pcap",
        1_700_000_500.0,
        150
    )

    generate_port_scan(
        PCAP_DIR / "portscan_01.pcap"
    )

    generate_ssh_bruteforce(
        PCAP_DIR / "sshbrute_01.pcap"
    )

    generate_arp_spoof(
        PCAP_DIR / "arpspoof_01.pcap"
    )

    generate_syn_flood(
        PCAP_DIR / "synflood_01.pcap"
    )

    generate_exfiltration(
        PCAP_DIR / "exfil_01.pcap"
    )

    generate_cleartext_telnet(
        PCAP_DIR / "telnet_01.pcap"
    )

    generate_weak_tls(
        PCAP_DIR / "weaktls_01.pcap"
    )

    labels_file = OUTPUT_DIR / "labels.csv"

    with open(
        labels_file,
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "pcap_file",
            "attack_type",
            "attacker_ip",
            "victim_ip",
            "start_ts",
            "end_ts",
        ])

        writer.writerows(labels)

    print(
        f"Generated {len(labels)} PCAP files."
    )

    print(
        f"PCAP files: {PCAP_DIR}"
    )

    print(
        f"Labels file: {labels_file}"
    )


if __name__ == "__main__":
    main()