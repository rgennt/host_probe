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

  def __init__(self,server_addr,port,sender,password,receiver):
    self.server_addr = server_addr
    self.receiver = receiver
    self.port = port
    self.sender = sender
    self.password = password

  def notify(self, msg):
    context = ssl.create_default_context()
    message = """\
    Subject: Probe Fail

    """ + msg
    with smtplib.SMTP_SSL(self.server_addr, self.port, context=context) as server:
      server.login(self.sender, self.password)
      server.sendmail(self.receiver,self.receiver,message)

    
