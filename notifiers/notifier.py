import logging, ssl, smtplib
class Notifier():
  def __init__(self, config):
    pass

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

  def __init__(self, config):
    self.server_addr = config.get('server_addr', '')
    self.receiver = config.get('receiver', '')
    self.port = config.get('port', 25)
    self.sender = config.get('sender', '')
    self.password = config.get('password', '')
    self.ssl = config.get('ssl', False)
    self.subject = config.get('subject', 'Probe Failed')
    if not self.sender: 
      self.sender = self.receiver

  def notify(self, msg):
    message = "From: " + self.sender + "\n" +\
    "To: " + self.receiver + "\n" +\
    "Subject: " + self.subject + "\n\n" +\
     msg
    
    if self.ssl:
      context = ssl.create_default_context()
      server = smtplib.SMTP_SSL(self.server_addr, self.port, context=context)
      server.login(self.sender, self.password)
    else:
      server = smtplib.SMTP(self.server_addr, self.port)
    server.sendmail(self.sender,self.receiver,message)
    
