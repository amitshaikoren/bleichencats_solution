import scapy.all as scapy

scapy.load_layer("tls")

CLIENT_HELLO = 1
SERVER_HELLO = 3
CLIENT_CKE = 9
ENCRYPTED_DATA_PACKETS = [15, 17]
TLS1_2_VERSION = b'\x03\x03'
APPLICATION_DATA_IDENTIFIER = b'\x17\x03\x03'
SNIFFED_PACKETS_PATH = "sniffed_packets"


def get_client_tls_random():
    client_hello_packet = scapy.rdpcap(f"{SNIFFED_PACKETS_PATH}/sniffed{CLIENT_HELLO}.pcap")[0]
    client_hello_raw_data = client_hello_packet[scapy.Raw].load

    first_tls_version_occurrence = client_hello_raw_data.index(TLS1_2_VERSION)

    second_tls_version_occurrence = client_hello_raw_data.index(TLS1_2_VERSION, first_tls_version_occurrence + 2)

    client_random_index = second_tls_version_occurrence + 2

    client_random = client_hello_raw_data[client_random_index: client_random_index + 32]  # client random is 32 bytes

    return client_random


def get_server_tls_random():
    server_hello_packet = scapy.rdpcap(f"{SNIFFED_PACKETS_PATH}/sniffed{SERVER_HELLO}.pcap")[0]
    server_hello_raw_data = server_hello_packet[scapy.Raw].load

    first_tls_version_occurrence = server_hello_raw_data.index(TLS1_2_VERSION)

    second_tls_version_occurrence = server_hello_raw_data.index(TLS1_2_VERSION, first_tls_version_occurrence + 2)

    server_random_index = second_tls_version_occurrence + 2

    server_random = server_hello_raw_data[server_random_index: server_random_index + 32]  # client random is 32 bytes

    return server_random


def get_pms():
    client_key_exchange_packet = scapy.rdpcap(f"{SNIFFED_PACKETS_PATH}/sniffed{CLIENT_CKE}.pcap")[0]
    client_key_exchange_raw_data = client_key_exchange_packet[scapy.Raw].load

    pms_header_bytes_len = 10  # 11 bytes from the beginning of payload until pms
    pms_len = 256  # by convention
    end_of_pms = pms_header_bytes_len + pms_len + 1

    first_tls_version_occurrence = client_key_exchange_raw_data.index(TLS1_2_VERSION)

    start_of_pms = first_tls_version_occurrence + pms_header_bytes_len

    pms = client_key_exchange_raw_data[start_of_pms:end_of_pms]

    return pms


def get_encrypted_data():
    encrypted_data = list()

    for i in range(len(ENCRYPTED_DATA_PACKETS)):

        application_message_packet = scapy.rdpcap(f"{SNIFFED_PACKETS_PATH}/sniffed{ENCRYPTED_DATA_PACKETS[i]}.pcap")[0]
        application_message_raw_data = application_message_packet[scapy.Raw].load

        header_len = 5
        message_len = 64

        if i==0:
            encrypted_data.append(application_message_raw_data[header_len:header_len + message_len]) #encrypted application message

            application_data_index = application_message_raw_data.index(APPLICATION_DATA_IDENTIFIER)
            encrypted_data.append(application_message_raw_data[application_data_index + header_len:])

        else:
            encrypted_data.append(application_message_raw_data[header_len:])



    return encrypted_data


if __name__ == "__main__":
    print("loading...")
    print(get_client_tls_random())
    print(get_server_tls_random())
    print(get_pms())
    print(get_encrypted_data())

