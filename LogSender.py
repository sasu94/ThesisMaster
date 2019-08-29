import smtplib
from email.mime.multipart import  MIMEMultipart
from email.mime.text import MIMEText


class LogSender:

    def __init__(self):
        self.user = 'naspy19@gmail.com'
        with open('email.naspy', 'r') as credentials:
            self.password = credentials.readline()
        self.server_address = 'smtp.gmail.com'
        self.server_port = 465

    def send(self, addressees, body, subject, attachment=None, att_type=None, fname='attachment'):
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.user

        if isinstance(addressees, str):
            msg['To'] = addressees
        else:
            msg['To'] = ', '.join(addressees)

        content = MIMEText(body, 'plain')
        msg.attach(content)

        if attachment is not None:
            if type(attachment)==list:
                for i in range(len(attachment)):
                    if att_type[i] is None:
                        att_type[i] = 'filename'

                    if att_type[i] == 'filename':
                        with open(attachment[i], 'r') as file:
                            payload = MIMEText(file.read())
                        filename = attachment[i]
                    elif att_type[i] == 'text':
                        payload = MIMEText(attachment[i])
                        filename = '%s.txt' % fname[i]
                    elif att_type[i] == 'json':
                        payload = MIMEText(attachment[i])
                        filename = '%s.json' % fname[i]
                    else:
                        print('Error, attachment must be text, json or filename')
                        return

                    payload.add_header('Content-Disposition', 'attachment', filename=filename)
                    msg.attach(payload)
            else:       
                    
                if att_type is None:
                    att_type = 'filename'

                if att_type == 'filename':
                    with open(attachment, 'r') as file:
                        payload = MIMEText(file.read())
                    filename = attachment
                elif att_type == 'text':
                    payload = MIMEText(attachment)
                    filename = '%s.txt' % fname
                elif att_type == 'json':
                    payload = MIMEText(attachment)
                    filename = '%s.json' % fname
                else:
                    print('Error, attachment must be text, json or filename')
                    return

                payload.add_header('Content-Disposition', 'attachment', filename=filename)
                msg.attach(payload)

        try:
            server = smtplib.SMTP_SSL(self.server_address, self.server_port)
            server.ehlo()
            server.login(self.user, self.password)
            server.sendmail(self.user, addressees, msg.as_string())
            server.close()
            print('Email Sent!')
        except Exception as e:
            print('Something went wrong... %s' % e)