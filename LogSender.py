import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class LogSender:
    """
    A class useful to send email address with or without attachments
    ----------
    user : str
        The email address used to send mail
    password : str
        The password of the account
    server_address : str
        The address of the server SMTP
    server_port : int
        The port on which the server is listening
    Methods
    -------
    send(addresses, body, subject, attachment, att_type, fname)
        A method that sends an email with the possibility to add an attachment taken from a string or a file
    """

    def __init__(self):
        self.user = 'naspy19@gmail.com'
        with open('email.naspy', 'r') as credentials:
            data = json.loads(credentials.read())
        self.password = data["password"]
        self.addresses = data["addresses"]
        self.server_address = 'smtp.gmail.com'
        self.server_port = 465

    def send(self, body, subject, addresses=None, attachment=None, att_type=None, fname='attachment'):
        """
        A method that sends an email with the possibility to add an attachment taken from a string or a file

        Parameters
        ----------
        body:str
            The body of the mail
        subject:str
            The subject of the mail
        addresses:list(str)
            The list of addresses to check
        attachment:list(str)
            A facultative field used to pass an attachment as string or a series of attachments
        att_type:list(str)
            A facultative field used to discriminate the nature of the attachments. It could be a string or a list of string
        fname:list(str)
            The name to give at the attachment(s). In case it is not passed it takes the name attachment
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.user

        if addresses == None:
            addresses = self.addresses

        if isinstance(addresses, str):
            msg['To'] = addresses
        else:
            msg['To'] = ', '.join(addresses)

        content = MIMEText(body, 'plain')
        msg.attach(content)

        if attachment is not None:
            if type(attachment) == list:
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
                    return False

                payload.add_header('Content-Disposition', 'attachment', filename=filename)
                msg.attach(payload)

        num_attempt = 0
        while num_attempt < 10:
            try:
                server = smtplib.SMTP_SSL(self.server_address, self.server_port)
                server.ehlo()
                server.login(self.user, self.password)
                server.sendmail(self.user, addresses, msg.as_string())
                return True
            except Exception:
                if num_attempt >= 10:
                    print('Something went wrong...')
                    return False
                num_attempt += 1
                print('Error, retrying')
            finally:
                server.close()

