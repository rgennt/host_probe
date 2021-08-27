import logging, ssl, smtplib
class Notifier():
  def notify(self, msg):
    print("Notification: " + msg)

class LogNotifier(Notifier):
  def notify(self, msg):
    logging.error(msg)

class EmailNotifier(Notifier):
  server_addr = None
  port = None
  sender = None
  password = None
  receiver = None

  def __init__(self, server_addr, port, sender, receiver, ssl=True, password=None):
    self.server_addr = server_addr
    self.receiver = receiver
    self.port = port
    self.sender = sender
    self.password = password
    self.ssl = ssl
    if not self.sender: 
      self.sender = self.receiver

  def notify(self, msg):
    message = "From: " + self.sender + "\n" +\
    "To: " + self.receiver + "\n" +\
    """Subject: Probe Fail

    """ + msg
    
    if self.ssl:
      context = ssl.create_default_context()
      server = smtplib.SMTP_SSL(self.server_addr, self.port, context=context)
      server.login(self.sender, self.password)
    else:
      server = smtplib.SMTP(self.server_addr, self.port)
    server.sendmail(self.sender,self.receiver,message)
    
