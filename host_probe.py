from probes.probe import *
from notifiers.notifier import *
import csv, sys, json, os, glob, importlib

def str_to_class(classname):
    return getattr(sys.modules[__name__], classname)

CONFIG_FILE = os.getenv('PROBE_CONFIG_FILE') or 'subscriptions.json'
with open(f"{os.path.dirname(os.path.abspath(__file__))}/{CONFIG_FILE}") as json_file:
 subscriptions = json.load(json_file)

for sub in subscriptions:
  print(sub['notifier'])
  if sub['probe'] == "SSH_PKCS_KeystoreProbe": sub['probe'] = "SSH_KeystoreProbe"
  probe = str_to_class(sub['probe'])(sub['probe_config'])
  probe.setNotifyOnError(str_to_class(sub['notifier'])(sub['notifier_config']))
  probe.run()

