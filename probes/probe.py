import logging, requests, ssl, certifi, os, OpenSSL, datetime, json, re

import paramiko

logging.basicConfig(level=logging.INFO)
class Probe():

  notifier = None
  days_critical = 30

  def run(self):
    err = None
    result = ""
    print("Dummy run")

    if err:
      notifier.notify()
    return result, err

  def convertDict(self, data):
    new_msg = """\
          Host               Cert Label                              Cert Path           Days Until Expiry   Issue Date         Expiry Date        
          ==========================================================+++++++++++++++++============================================================
        """
    body= """\
          <html>
            <head>
              <style>
                tr:nth-child(even) {background-color: #f2f2f2;}
                table, th, td {
                  border: 1px solid black;
                  border-collapse: collapse;
                }

                th, td {
                  padding: 15px;
                }
              </style>
            </head>
            <body>
              <table>
                <tr>
                  <th>Host</th>
                  <th>Cert Label</th>
                  <th>Cert Path</th>
                  <th>Days Until Expiry</th>
                  <th>Issue Date</th>
                  <th>Expiry Date</th>
                </tr>
        """
    for i,entry in enumerate(data['expiring_certificates']):
      new_msg += "{host:19} {lbl:39} {path:19} {exp:19} {issue:19} {expiry:19}\n".format(host = entry['host'] if "host" in entry else data['host'] , lbl = entry['name'], path = entry['type'], exp = str(entry['expiry']), issue = entry['issue_date'].strftime("%Y-%m-%d %H:%M"), expiry = entry['expiry_date'].strftime("%Y-%m-%d %H:%M"))
      style = "" if i%2==1 else "<tr style=\"background-color: #a9a9a9;\""
      if (entry['expiry'] < 0): style = "background-color: #000000; color: #A52A2A;"
      elif entry['expiry'] < self.days_critical: style = "background-color: #A52A2A;"
      
      body += "<tr style=\""+style+"\">"
      body += "<td>" + entry['host'] if "host" in entry else data['host'] + "</td>"
      body += "<td>" + entry['name'] + "</td>"
      body += "<td>" + entry['type'] + "</td>"
      body += "<td>" + str(entry['expiry']) + "</td>"
      body += "<td>" + entry['issue_date'].strftime("%Y-%m-%d %H:%M") + "</td>"
      body += "<td>" + entry['expiry_date'].strftime("%Y-%m-%d %H:%M") + "</td>"
      body += "</tr>"
          
    return new_msg, body
      

  # Decorate `run` with sending notifications on error
  def setNotifyOnError(self, notifier):
    old_run = self.run
    def wrapper():
      res, err = old_run()
      if isinstance(err,dict):
        if len(err["expiring_certificates"]) == 0: return
        plain,html = self.convertDict(err)
        err = plain
      logging.debug("Checking notification")
      if err:
        self.notifier.notify(err,html=html)
    self.notifier = notifier
    self.run = wrapper



class HttpProbe(Probe):
  url = ''

  def __init__(self,config):
    self.url = config.get('url','')

  def run(self):
    err = None
    result = ""
    try:
      response = requests.get(self.url, verify=False)
      response.raise_for_status()
      if response.status_code == 200:
        logging.info(self.url + " is OK")
        return response.status_code, None
    except Exception as err:
      return None, self.url + ": " + str(err)


class TLSValidityProbe(Probe):
  url = ''

  def __init__(self,config):
    self.url = config.get('url','')

  def run(self):
    err = None
    result = ""
    url_split = self.url.replace('/','').lower().split(':')
    try:
      proto = url_split[0]
    except IndexError:
      proto = None

    try:
      address = url_split[1]
    except IndexError:
      address = None
    try:
      port = url_split[2]
    except IndexError:
      port = None

    if not proto == 'https':
      return None, self.url + ": " + 'TLS verification can be performed only on HTTPS protocol'
    if not port:
      port = 443
    try:
      cert = ssl.get_server_certificate((address, port), ca_certs=os.path.relpath(certifi.where()))
      logging.info("TLS for " + self.url + " is OK")
      return cert , None
    except Exception as err:
      return '', self.url + ": " + str(err)

class TLSExpiryProbe(Probe):
  url = ''
  days = 14

  def __init__(self,config):
    self.url = config.get('url','')
    self.days = config.get('days', 14)

  def run(self):
    err = None
    result = ""
    if ':/' in self.url:

      url_split = self.url.replace('/','').lower().split(':')
      try:
        proto = url_split[0]
      except IndexError:
        proto = None
      try:
        address = url_split[1]
      except IndexError:
        address = None
      try:
        port = url_split[2]
      except IndexError:
        port = None

      if not proto == 'https':
        return None, self.url + ": " + 'TLS verification can be performed only on HTTPS protocol'
      if not port:
        port = 443
      try:
        cert = ssl.get_server_certificate((address, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
      except Exception as err:
        return '', self.url + ": " + str(err)
    else:
      x509 = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open(self.url).read()
      )
    date = x509.get_notAfter()
    expiry_date = datetime.datetime.strptime(date.decode(),'%Y%m%d%H%M%SZ')
    now = datetime.datetime.now()
    delta = expiry_date - now 
    if delta.days < self.days:
      return '',  self.url + ": Expiring in less then " + str(self.days) + " days"
    logging.info("TLS expiry at " + self.url + " is OK")
    return x509 , None



class APIBarracudaLBProbe(Probe):
  url = ''
  username = ''
  password = ''
  days = 14

  def __init__(self,config):
    self.url = config.get('url','')
    self.days = config.get('days','')
    self.username = config.get('username','')
    self.password = config.get('password','')
    if "days_critical" in config:
      self.days_critical = config.get('days_critical')

  def run(self):
    err = ""
    result = ""
    try:

      headers =  {"Content-Type":"application/json"}
      todo = {"username": self.username, "password": self.password}
      response = requests.post(self.url + "login", data=json.dumps(todo), headers=headers, verify=False)
      response.raise_for_status()
      if response.status_code == 200:
        token = response.json()['token']
        response = requests.get(self.url + "certificates", headers=headers, verify=False, auth=(token,''))
        response.raise_for_status()
        all_certs = response.json()['data'][0]

        data = {}
        data['host'] = self.url
        data['expiring_certificates'] = []
        data['ok_certificates'] = []
        # loop through types of certs
        for cert_type in all_certs.keys():
          certs = all_certs[cert_type]
          for cert in certs:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['certificate'])
            date = x509.get_notAfter()
            expiry_date = datetime.datetime.strptime(date.decode(),'%Y%m%d%H%M%SZ')
            issue_date = datetime.datetime.strptime(x509.get_notBefore().decode(),'%Y%m%d%H%M%SZ')
            now = datetime.datetime.now()
            delta = expiry_date - now 
            certificate = {}
            certificate['name'] = cert['name']
            certificate['expiry'] = delta.days
            certificate['issue_date'] = issue_date
            certificate['expiry_date'] = expiry_date
            certificate['type'] = cert_type
            
            if delta.days < self.days:
              #err = err + ( cert['name'] + "," + str(delta.days) + "," + issue_date.strftime("%Y-%m-%d %H:%M") + "," + expiry_date.strftime("%YYYY-%m-%d %H:%M") +"\n")
              data['expiring_certificates'].append(certificate)
            else:
              data['ok_certificates'].append(certificate)
              logging.info("TLS expiry at " + cert['name'] + " is OK")
        return response.status_code, data
      else:
        return "Error connecting", "Did you set username and password? or, perhaps, server is not reachable"
    except Exception as err:
      return None, self.url + ": " + str(err)


class SSH_KeystoreProbe(Probe):
  """
      1 [
      2     {
      3         "name": "Example",
      4         "notifier": "LogNotifier",
      5         "probe": "SSH_PKCS_KeystoreProbe",
      6         "notifier_config": {
      7         },
      8         "probe_config": {
      9           "host": "host.example.com",
     10           "user": "remote_ssh_user",
     11           "key": "/path/to/ssh/key",
     12           "key_pass": "SSHKeyPassword",
     13           "keystores": ["/path/to/keystore1.p12","/path/to/keystore2.p12",{"path": "/path", "pass": "password"}],
     14           "keystore_pass": "keystorePassword",
     15           "days": 300
     16         }
     17     }
     18 ]
  """
  host = ''
  days = 14

  def __init__(self,config):
    self.host = config.get('host','')
    self.user = config.get('user','')
    self.port = config.get('port','22')
    self.key = config.get('key','')
    self.key_pass = config.get('key_pass')
    self.keystores = config.get('keystores',[])
    self.keystore_pass = config.get('keystore_pass','')
    self.days = config.get('days', 14)
    if "days_critical" in config:
      self.days_critical = config.get('days_critical')

  def run(self):
    err = None
    result = ""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    

    # convert to list with single element if only one keystore was provided
    if (isinstance(self.keystores, str)):
      self.keystores = [self.keystores]
    data = {}
    data['host'] = self.host
    data['expiring_certificates'] = []
    data['ok_certificates'] = []
    connected_to = ""
    for keystore in self.keystores:
      keystore_pass = self.keystore_pass
      host = self.host
      port = self.port
      username = self.user
      key_filename = self.key
      password=self.key_pass
      if isinstance(keystore,dict):
        if "keystore_pass" in keystore:
          keystore_pass = keystore["keystore_pass"]
        if "store_type" in keystore:
          extension = keystore["store_type"]

        if "host" in keystore:
          host = keystore["host"]
        if "port" in keystore:
          port = keystore["port"]
        if "user" in keystore:
          username = keystore["user"]
        if "key" in keystore:
          key_filename = keystore["key"]
        if "key_pass" in keystore:
          password = keystore["key_pass"]
        # must be the last if
        if "path" in keystore:
          keystore = keystore["path"]
      try: extension
      except NameError: extension = keystore.split(".")[-1]
      command = 'echo not able to identify keystore/certificate type. a: Err:unknown keystore type b: NA c: 01/01/00 00:00 am d: 10/10/00 00:00 am'
      expression =  re.compile('.*a: (?P<alias>.*) b: (?P<subject>.*) c: (?P<from>.*) d: (?P<until>.*)$')
      date_format = '%m/%d/%y %H:%M %p'
      if extension == "p12":
        expression = re.compile('\n*^Alias name: (?P<alias>.*)$\n^Owner: (?P<subject>.*)$\n^Valid from: (?P<from>.*) until: (?P<until>.*)$', re.MULTILINE)
        command = '(out=$(keytool -list -v -storetype PKCS12 -keystore ' + keystore + ' -storepass ' + keystore_pass + ')&& echo "$out" || >&2 echo "$out") | grep Alias | cut -d " " -f3 | while read alias; do if ! keytool -exportcert -storetype PKCS12 -keystore ' + keystore + ' -storepass ' + keystore_pass + ' -alias $alias 2>/dev/null | openssl x509 -inform der -checkend ' + str(self.days * 86400) + ' -noout 2>/dev/null; then keytool -list -v -storetype PKCS12 -keystore ' + keystore + ' -storepass ' + keystore_pass + ' -alias $alias | grep -E "^Alias|^Owner|^Valid"; echo; fi; done'
        date_format = '%m/%d/%y %H:%M %p'
      elif extension == "crt" or extension == "cert":
        expression = re.compile('^.*Not Before: (?P<from>.*)$\n^.*Not After : (?P<until>.*)$\n^.*Subject:(?P<subject>.).*CN=(?P<alias>.*)$', re.MULTILINE)
        command = 'openssl x509 -text -noout -in ' + keystore + ' | grep -E "Subject:|Not Before|Not After"'
        date_format = '%b %d %H:%M:%S %Y %Z'
      elif extension == "jks":
        expression = re.compile('\n*^Alias name: (?P<alias>.*)$\n^Owner: (?P<subject>.*)$\n^Valid from: (?P<from>.*) until: (?P<until>.*)$', re.MULTILINE)
        command = '(out=$(keytool -list -v -storetype JKS -keystore ' + keystore + ' -storepass ' + keystore_pass + ')&& echo "$out" || >&2 echo "$out") | grep Alias | cut -d " " -f3 | while read alias; do if ! keytool -exportcert -storetype JKS -keystore ' + keystore + ' -storepass ' + keystore_pass + ' -alias $alias 2>/dev/null | openssl x509 -inform der -checkend ' + str(self.days * 86400) + ' -noout 2>/dev/null; then keytool -list -v -storetype JKS -keystore ' + keystore + ' -storepass ' + keystore_pass + ' -alias $alias | grep -E "^Alias|^Owner|^Valid"; echo; fi; done'
        date_format = '%m/%d/%y %H:%M %p'
        
      #print(command)
      if connected_to != host and client.get_transport() and client.get_transport().is_active():
        logging.info("Disconnecting from: {}".format(connected_to))
        client.close()
      if not client.get_transport():
        try:
          logging.info("Connecting to server: {}".format(host))
          client.connect(host, port=port, username=username, key_filename=key_filename, password=password)
          connected_to = host
          pass
        except paramiko.ssh_exception.AuthenticationException as e:
          certificate = {}
          certificate['host'] = host
          certificate['name'] = "Erro connecting to host"
          certificate['expiry'] = 0
          certificate['issue_date'] = datetime.datetime.now()
          certificate['expiry_date'] = datetime.datetime.now()
          certificate['type'] = ""
          data['expiring_certificates'].append(certificate)
          continue
      
      stdin, stdout, stderr = client.exec_command(command)
      stdout.channel.recv_exit_status()
      certs = stdout.readlines()
      error = stderr.readlines()

      if (error):
        result += self.host + ": " + str(error) + "\n"
        data['expiring_certificates'].append({"name": "".join(error), "expiry":0,"issue_date":datetime.datetime.now(),"expiry_date": datetime.datetime.now(),"type":"NA"})

    # Parse data
      for item in "".join(certs).split("\n\n"):
        if not item: break
        search = expression.match(item)
        if not search: continue
        alias = search.group('alias')
        subject = search.group('subject')
        issue_date = datetime.datetime.strptime(search.group('from') ,date_format)
        expiry_date = datetime.datetime.strptime(search.group('until') ,date_format)
        now = datetime.datetime.now()
        delta = expiry_date - now 
        certificate = {}
        certificate['host'] = host
        certificate['name'] = alias
        certificate['expiry'] = delta.days
        certificate['issue_date'] = issue_date
        certificate['expiry_date'] = expiry_date
        certificate['type'] = keystore
        if delta.days < self.days:
          result += self.host + ":" + alias + ": Expiring in " + str(delta.days) + " days\n"
          data['expiring_certificates'].append(certificate)
        else:
          data['ok_certificates'].append(certificate)
          logging.info("Cert "  + self.host + ":" + alias + " is OK")
    if (client):
      client.close()
    return None , data
