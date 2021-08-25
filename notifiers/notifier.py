import logging
class Notifier():
  def notify(self, msg):
    print("Notification: " + msg)

class LogNotifier(Notifier):
  def notify(self, msg):
    logging.error(msg)
    
