from probes.probe import *
from notifiers.notifier import *
import csv, sys

def str_to_class(classname):
    return getattr(sys.modules[__name__], classname)

FILE = 'subscriptions.csv'

sender = ''
password = ''
receiver = ''

reader = {}
with open(FILE) as csvfile:
  reader = csv.DictReader(csvfile)

  for row in reader:
    probe = str_to_class(row['class'])(row['url'])
    probe.setNotifyOnError(EmailNotifier('smtp.gmail.com','465',sender,password,receiver))
    probe.run()

#probe = TLSExpiryProbe('/tmp/apache-selfsigned.crt')
#probe.setNotifyOnError(LogNotifier())
#probe.run()
