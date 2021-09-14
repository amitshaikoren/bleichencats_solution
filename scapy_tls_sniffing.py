import scapy
import scapy.all as scapy
from scapy.layers.tls.session import TLSSession
from scapy.sendrecv import AsyncSniffer
import os
import time
SNIFFED_PACKETS_PATH = "sniffed_packets"

scapy.load_layer("tls")


def sniffer():
    sniffer = AsyncSniffer(
        session=TLSSession,
        prn=lambda packet: packet.summary(),
        lfilter=lambda packet: scapy.Raw in packet,
        iface="lo" #lo0 on mac
    )

    sniffer.start()
    time.sleep(7)
    sniffer.stop()

    sniffed_packets = sniffer.results
    return sniffed_packets


def main():
    sniffed_packets = sniffer()
    print("saving...")

    try:
        os.mkdir(f"{os.getcwd()}/{SNIFFED_PACKETS_PATH}")
    except FileExistsError:
        pass


    for i in range(len(sniffed_packets)):
        file_name = f'{SNIFFED_PACKETS_PATH}/sniffed{i}.pcap'
        scapy.wrpcap(file_name, sniffed_packets[i])


if __name__ == "__main__":
    main()
