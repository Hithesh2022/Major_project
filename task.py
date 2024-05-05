# tasks.py
from queue import Queue
 # Import the function from the packet module
from predictpackets import predict_attack  # Import the function from the attack module
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
import pyshark
import datetime
task_queue = Queue()

def network_detection_task():
    # Code for network detection
   
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

    pass

def attack_detection_task():
    predict_attack()
    pass

def email_sending_task():
    load_dotenv()

    def send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, smtp_username, smtp_password):
        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email

        # Read the contents of location_data.txt
        with open('location_data.txt', 'r') as loc_file:
            location = loc_file.readline().strip()

        # Read the contents of predicted_attack.txt
        with open('predicted_attack.txt', 'r') as attack_file:
            attack_type = attack_file.readline().strip()

        # Your custom message
        custom_message = "Attack dected and stopped Please take necessary actions to address the detected suspicious activity."

        # Create the body of the message (a plain-text and an HTML version).
        alert_html = """
        <html>
        <head>
            <style>
            .alert {{
                padding: 20px;
                background-color: #f44336;
                color: white;
            }}
            .location {{
                margin-bottom: 10px;
            }}
            </style>
        </head>
        <body>
            <div class="alert">
            <h1>Alert!</h1> <img src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwww.centerforpetsafety.org%2Fwp-content%2Fuploads%2F2015%2F12%2FAlert_HiRes.jpg&f=1&nofb=1&ipt=7364e6037f771a03a38e131d5a30de93c6e716ba62ae2e5eeb5415b46b16ff42&ipo=images height=300px width=300px" alt="Warning">
            </div>
            <div class="location">
            <strong>Attacker Location:</strong> {}
            </div>
            <div>
            <strong>Attack Type:</strong> {}
            </div>
            <div>
            <p>{}</p>
            </div>
        </body>
        </html>
        """.format(location, attack_type, custom_message)

        # Record the MIME types of both parts - text/plain and text/html.
        alert_part = MIMEText(alert_html, 'html')

        # Attach parts into message container.
        msg.attach(alert_part)

        try:
            # Send the message via Gmail's SMTP server.
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(smtp_username, smtp_password)
                server.sendmail(sender_email, receiver_email, msg.as_string())
            print("Email sent successfully!")
        except Exception as e:
            print(f"An error occurred while sending email: {e}")

    # Example usage
    sender_email = 'hith68616@gmail.com'
    receiver_email = 'hcprajwal9901@gmail.com'
    subject = 'Warning!! Suspicious Activity Detected!'
    body = 'This is my second email.'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 465
    smtp_username = os.getenv('USER')
    smtp_password = os.getenv('PASS')

    send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, smtp_username, smtp_password)

    pass

def process_task_queue():
    while not task_queue.empty():
        task = task_queue.get()
        task()
