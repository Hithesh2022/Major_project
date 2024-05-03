# import pyshark

# # Define a packet callback function
# def packet_callback(packet):
#     print('Captured Packet:')
#     print(packet)

# # Define a function to capture packets
# def capture_packets(interface='Wi-Fi 3', django_port=8000):
#     print(f'Starting packet capture on interface {interface}...')

#     try:
#         # Create a LiveCapture object with a display filter for port 8000
#         display_filter = f'tcp.port == {django_port}'
#         capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)

#         # Apply the packet callback function to each captured packet
#         capture.apply_on_packets(packet_callback)

#     except KeyboardInterrupt:
#         print('Packet capture stopped by user.')

#     except Exception as e:
#         print(f'An error occurred: {e}')

#     finally:
#         # Close the capture when finished
#         capture.close()

# # Run the capture_packets function with default arguments
# capture_packets()

###############################################################################3
import pyshark
import datetime
def packet_callback(packet):
    extracted_data = {}
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    data_loc={}
    data_loc['src_ip']=src_ip
    data_loc['dst_ip']=dst_ip

    # Store IP addresses in the extracted_data dictionary
   
    try:
        duration = packet.frame_info.time
        duration = duration.replace("India Standard Time", "").strip()
        # Parse the datetime string and format it
        duration = datetime.datetime.strptime(duration, "%b %d, %Y %H:%M:%S.%f000").strftime("%H:%M:%S")
    except AttributeError:
        duration = '0'
    extracted_data['Duration'] = duration

    extracted_data['Wrong Fragment'] = 1 if packet.ip.flags_df else 0

    try:
        hot = packet.ip.dsfield
    except AttributeError:
        hot = '0'
    extracted_data['Hot'] = hot

    extracted_data['Logged In'] = 1 if packet.ip.flags_mf else 0

    try:
        num_compromised = packet.ip.ttl
    except AttributeError:
        num_compromised = '0'
    extracted_data['Num Compromised'] = num_compromised

    try:
        root_shell = packet.tcp.seq
    except AttributeError:
        root_shell = '0'
    extracted_data['Root Shell'] = root_shell

    try:
        num_root = packet.tcp.ack
    except AttributeError:
        num_root = '0'
    extracted_data['Num Root'] = num_root

    try:
        num_file_creations = packet.tcp.len
    except AttributeError:
        num_file_creations = '0'
    extracted_data['Num File Creations'] = num_file_creations

    try:
        num_access_files = packet.tcp.hdr_len
    except AttributeError:
        num_access_files = '0'
    extracted_data['Num Access Files'] = num_access_files

    try:
        same_service_rate = packet.tcp.window_size
    except AttributeError:
        same_service_rate = '0'
    extracted_data['Same Service Rate'] = same_service_rate

    try:
        srv_diff_host_rate = packet.ip.id
    except AttributeError:
        srv_diff_host_rate = '0'
    extracted_data['Srv Diff Host Rate'] = srv_diff_host_rate

    try:
        dst_host_count = packet.ip.dsfield_dscp
    except AttributeError:
        dst_host_count = '0'
    extracted_data['Dst Host Count'] = dst_host_count

    try:
        dst_host_same_src_port_rate = packet.ip.dsfield_ecn
    except AttributeError:
        dst_host_same_src_port_rate = '0'
    extracted_data['Dst Host Same Src Port Rate'] = dst_host_same_src_port_rate

    try:
        dst_host_rerror_rate = packet.udp.length if packet.udp else 0
    except AttributeError:
        dst_host_rerror_rate = '0'
    extracted_data['Dst Host Rerror Rate'] = dst_host_rerror_rate

    try:
        dst_host_serror_rate = packet.udp.stream if packet.udp else 0
    except AttributeError:
        dst_host_serror_rate = '0'
    extracted_data['Dst Host Serror Rate'] = dst_host_serror_rate

    try:
        protocol_type_icmp = packet.ip.dsfield_dscp
    except AttributeError:
        protocol_type_icmp = '0'
    extracted_data['Protocol Type ICMP'] = protocol_type_icmp

    try:
        protocol_type_tcp = packet.ip.dsfield_ecn
    except AttributeError:
        protocol_type_tcp = '0'
    extracted_data['Protocol Type TCP'] = protocol_type_tcp

    try:
        protocol_type_udp = packet.udp.stream if packet.udp else 0
    except AttributeError:
        protocol_type_udp = '0'
    extracted_data['Protocol Type UDP'] = protocol_type_udp

    try:
        service_domain = packet.ip.dsfield_dscp
    except AttributeError:
        service_domain = '0'
    extracted_data['Service Domain'] = service_domain

    try:
        service_http = packet.ip.dsfield_ecn
    except AttributeError:
        service_http = '0'
    extracted_data['Service HTTP'] = service_http

    try:
        service_telnet = packet.udp.stream if packet.udp else 0
    except AttributeError:
        service_telnet = '0'
    extracted_data['Service Telnet'] = service_telnet

    try:
        flag_OTH = packet.ip.dsfield_dscp
    except AttributeError:
        flag_OTH = '0'
    extracted_data['Flag OTH'] = flag_OTH

    try:
        flag_REJ = packet.ip.dsfield_ecn
    except AttributeError:
        flag_REJ = '0'
    extracted_data['Flag REJ'] = flag_REJ

    try:
        flag_RSTO = packet.udp.stream if packet.udp else 0
    except AttributeError:
        flag_RSTO = '0'
    extracted_data['Flag RSTO'] = flag_RSTO

    try:
        flag_RSTOS0 = packet.ip.dsfield_dscp
    except AttributeError:
        flag_RSTOS0 = '0'
    extracted_data['Flag RSTOS0'] = flag_RSTOS0

    try:
        flag_RSTR = packet.ip.dsfield_ecn
    except AttributeError:
        flag_RSTR = '0'
    extracted_data['Flag RSTR'] = flag_RSTR

    try:
        flag_S0 = packet.udp.stream if packet.udp else 0
    except AttributeError:
        flag_S0 = '0'
    extracted_data['Flag S0'] = flag_S0

    try:
        flag_S1 = packet.ip.dsfield_dscp
    except AttributeError:
        flag_S1 = '0'
    extracted_data['Flag S1'] = flag_S1

    try:
        flag_SF = packet.ip.dsfield_ecn
    except AttributeError:
        flag_SF = '0'
    extracted_data['Flag SF'] = flag_SF

    # Print the extracted features
    print(extracted_data)
    print(data_loc)
    with open('extracted_data.txt', 'a') as file:
        file.write(str(extracted_data) + '\n')
    with open('location_data.txt', 'a') as file:
        file.write(str(data_loc) + '\n')

# Define a function to capture packets
def capture_packets(interface='Wi-Fi 3', django_port=8000):
    print(f'Starting packet capture on interface {interface}...')

    try:
        # Create a LiveCapture object with a display filter for port 8000
        display_filter = f'tcp.port == {django_port}'
        capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)

        # Apply the packet callback function to each captured packet
        capture.apply_on_packets(packet_callback)

    except KeyboardInterrupt:
        print('Packet capture stopped by user.')

    except Exception as e:
        print(f'An error occurred: {e}')

    finally:
        # Close the capture when finished
        capture.close()

# Run the capture_packets function with default arguments
capture_packets()





# import pyshark

# # Define a packet callback function
# def packet_callback(packet):
#     # Extracting specific fields from the packet
#     try:
#         duration = packet.frame_info.time
#     except AttributeError:
#         duration = None

#     try:
#         wrong_fragment = packet.ip.flags_df
#     except AttributeError:
#         wrong_fragment = None

#     try:
#         hot = packet.ip.dsfield
#     except AttributeError:
#         hot = None

#     try:
#         logged_in = packet.ip.flags_mf
#     except AttributeError:
#         logged_in = None

#     try:
#         num_compromised = packet.ip.ttl
#     except AttributeError:
#         num_compromised = None

#     try:
#         root_shell = packet.tcp.seq
#     except AttributeError:
#         root_shell = None

#     try:
#         num_root = packet.tcp.ack
#     except AttributeError:
#         num_root = None

#     try:
#         num_file_creations = packet.tcp.len
#     except AttributeError:
#         num_file_creations = None

#     try:
#         num_access_files = packet.tcp.hdr_len
#     except AttributeError:
#         num_access_files = None

#     try:
#         same_service_rate = packet.tcp.window_size
#     except AttributeError:
#         same_service_rate = None

#     try:
#         srv_diff_host_rate = packet.ip.id
#     except AttributeError:
#         srv_diff_host_rate = None

#     try:
#         dst_host_count = packet.ip.dsfield_dscp
#     except AttributeError:
#         dst_host_count = None

#     try:
#         dst_host_same_src_port_rate = packet.ip.dsfield_ecn
#     except AttributeError:
#         dst_host_same_src_port_rate = None

#     try:
#         dst_host_rerror_rate = packet.udp.length
#     except AttributeError:
#         dst_host_rerror_rate = None

#     try:
#         dst_host_serror_rate = packet.udp.stream
#     except AttributeError:
#         dst_host_serror_rate = None

#     try:
#         protocol_type_icmp = packet.ip.dsfield_dscp
#     except AttributeError:
#         protocol_type_icmp = None

#     try:
#         protocol_type_tcp = packet.ip.dsfield_ecn
#     except AttributeError:
#         protocol_type_tcp = None

#     try:
#         protocol_type_udp = packet.udp.stream
#     except AttributeError:
#         protocol_type_udp = None

#     try:
#         service_domain = packet.ip.dsfield_dscp
#     except AttributeError:
#         service_domain = None

#     try:
#         service_http = packet.ip.dsfield_ecn
#     except AttributeError:
#         service_http = None

#     try:
#         service_telnet = packet.udp.stream
#     except AttributeError:
#         service_telnet = None

#     try:
#         flag_OTH = packet.ip.dsfield_dscp
#     except AttributeError:
#         flag_OTH = None

#     try:
#         flag_REJ = packet.ip.dsfield_ecn
#     except AttributeError:
#         flag_REJ = None

#     try:
#         flag_RSTO = packet.udp.stream
#     except AttributeError:
#         flag_RSTO = None

#     try:
#         flag_RSTOS0 = packet.ip.dsfield_dscp
#     except AttributeError:
#         flag_RSTOS0 = None

#     try:
#         flag_RSTR = packet.ip.dsfield_ecn
#     except AttributeError:
#         flag_RSTR = None

#     try:
#         flag_S0 = packet.udp.stream
#     except AttributeError:
#         flag_S0 = None

#     try:
#         flag_S1 = packet.ip.dsfield_dscp
#     except AttributeError:
#         flag_S1 = None

#     try:
#         flag_SF = packet.ip.dsfield_ecn
#     except AttributeError:
#         flag_SF = None

#     # Print the extracted features
#     print(f"Duration: {duration}")
#     print(f"Wrong Fragment: {wrong_fragment}")
#     print(f"Hot: {hot}")
#     print(f"Logged In: {logged_in}")
#     print(f"Num Compromised: {num_compromised}")
#     print(f"Root Shell: {root_shell}")
#     print(f"Num Root: {num_root}")
#     print(f"Num File Creations: {num_file_creations}")
#     print(f"Num Access Files: {num_access_files}")
#     print(f"Same Service Rate: {same_service_rate}")
#     print(f"Srv Diff Host Rate: {srv_diff_host_rate}")
#     print(f"Dst Host Count: {dst_host_count}")
#     print(f"Dst Host Same Src Port Rate: {dst_host_same_src_port_rate}")
#     print(f"Dst Host Rerror Rate: {dst_host_rerror_rate}")
#     print(f"Dst Host Serror Rate: {dst_host_serror_rate}")
#     print(f"Protocol Type ICMP: {protocol_type_icmp}")
#     print(f"Protocol Type TCP: {protocol_type_tcp}")
#     print(f"Protocol Type UDP: {protocol_type_udp}")
#     print(f"Service Domain: {service_domain}")
#     print(f"Service HTTP: {service_http}")
#     print(f"Service Telnet: {service_telnet}")
#     print(f"Flag OTH: {flag_OTH}")
#     print(f"Flag REJ: {flag_REJ}")
#     print(f"Flag RSTO: {flag_RSTO}")
#     print(f"Flag RSTOS0: {flag_RSTOS0}")
#     print(f"Flag RSTR: {flag_RSTR}")
#     print(f"Flag S0: {flag_S0}")
#     print(f"Flag S1: {flag_S1}")
#     print(f"Flag SF: {flag_SF}")

# def capture_packets(interface='Wi-Fi 3', django_port=8000):
#     print(f'Starting packet capture on interface {interface}...')

#     try:
#         # Create a LiveCapture object with a display filter for port 8000
#         display_filter = f'tcp port {django_port}'
#         capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)

#         # Apply the packet callback function to each captured packet
#         for packet in capture.sniff_continuously(packet_count=10):
#             packet_callback(packet)

#     except KeyboardInterrupt:
#         print('Packet capture stopped by user.')

#     except Exception as e:
#         print(f'An error occurred: {e}')

#     finally:
#         # Close the capture when finished
#         capture.close()

# # Run the capture_packets function with default arguments
# capture_packets()