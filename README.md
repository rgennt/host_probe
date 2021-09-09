# host_probe

Just another uptime checker simmilar to Uptime Robot and Uptime Kuma.

#### Rationale
To have simple and extendable commandline based utility to perform periodic checks and notify on errors.

#### Install


```
git clone https://github.com/rgennt/host_probe.git
chmod +x $PWD/host_probe/host_probe.py
sudo sh -c "echo '0 4 * * *   nobody  cd $PWD/host_probe && ./host_probe.py'"
```

#### Configure
Append to subscriptions.csv probetype and url for your endpoints

```
ProbeClass, URI
```

##### Probe Classes
Currently supported probes:
* HttpProbe - connects to specified address using HTTP, fails on any code other than HTTP 200
* TLSValidityProbe - grabs certificate provided by HTTPS and performs certificate validation, fails if certificate is invalid
* TLSExpiryProbe - grabs certificate provided by HTTPS and checks it's expiry date, fails if certificate is expired or going to expire in 14 days

#### Extending Probes
Add new class to ./probes/probe.py that inherits from Probe and implement `run()` method 
