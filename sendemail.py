import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
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
