# import smtplib
# from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText

# def send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, smtp_username, smtp_password):
#     # Create message container - the correct MIME type is multipart/alternative.
#     msg = MIMEMultipart('alternative')
#     msg['Subject'] = subject
#     msg['From'] = sender_email
#     msg['To'] = receiver_email

#     # Create the body of the message (a plain-text and an HTML version).
#     text = body
#     html = """\
#     <html>
#       <body>
#         <p>{}</p>
#       </body>
#     </html>
#     """.format(body)

#     # Record the MIME types of both parts - text/plain and text/html.
#     part1 = MIMEText(text, 'plain')
#     part2 = MIMEText(html, 'html')

#     # Attach parts into message container.
#     msg.attach(part1)
#     msg.attach(part2)

#     # Send the message via SMTP server.
#     with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
#         server.login(smtp_username, smtp_password)
#         server.sendmail(sender_email, receiver_email, msg.as_string())

# # Example usage
# sender_email = 'hith68616@gmail.com'
# receiver_email = 'hitheshkp100@gmail.com'
# subject = 'Test Email'
# body = 'This is a test email.'
# smtp_server = 'smtp.gmail.com'
# smtp_port = 465
# smtp_username = 'hith68616@gmail.com'
# smtp_password = 'test123'

# send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, smtp_username, smtp_password)



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
    with open('location_data.txt', 'r') as file:
        body = file.readline()
    # Create the body of the message (a plain-text and an HTML version).
    text = body
    html = """\
    <html>
      <body>
        <p>{}</p>
      </body>
    </html>
    """.format(body)

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    msg.attach(part1)
    msg.attach(part2)

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
receiver_email = 'hitheshkp100@gmail.com'
subject = 'Test Email'
body = 'This is my second email.'
smtp_server = 'smtp.gmail.com'
smtp_port = 465
smtp_username = os.getenv('USER')
smtp_password = os.getenv('PASS')

send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, smtp_username, smtp_password)

