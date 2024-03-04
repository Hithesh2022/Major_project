import pyshark

# Define a packet callback function
def packet_callback(packet):
    print('Captured Packet:')
    print(packet)

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
