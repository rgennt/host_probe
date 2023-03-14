import logging, requests, ssl, certifi, os, OpenSSL, datetime, json

logging.basicConfig(level=logging.INFO)
class Probe():

  notifier = None

  def run(self):
    err = None
    result = ""
    print("Dummy run")

    if err:
      notifier.notify()
    return result, err

  # Decorate `run` with sending notifications on error
  def setNotifyOnError(self, notifier):
    old_run = self.run
    def wrapper():
      res, err = old_run()
      logging.debug("Checking notification")
      if err:
        self.notifier.notify(err)
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

        # loop through types of certs
        for cert_type in all_certs.keys():
          certs = all_certs[cert_type]
          for cert in certs:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['certificate'])
            date = x509.get_notAfter()
            expiry_date = datetime.datetime.strptime(date.decode(),'%Y%m%d%H%M%SZ')
            now = datetime.datetime.now()
            delta = expiry_date - now 

            if delta.days < self.days:
              err = err + ( cert['name'] + ": Expiring in less than " + str(self.days) + " days\n")
            else:
              logging.info("TLS expiry at " + cert['name'] + " is OK")
        return response.status_code, err
      else:
        return "Error connecting", "Did you set username and password? or, perhaps, server is not reachable"
    except Exception as err:
      return None, self.url + ": " + str(err)
