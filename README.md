# openstack-charms-cert-validator

A small tool to validate an SSL certificate chain for openstack charms.

Kind of like:

```
openssl verify -CAfile ca.crt -untrusted intermediate.crt leaf.crt
```

But more user-friendly errors.

## Usage

```
$ openstack-charms-cert-validator -h
usage: openstack-charms-cert-validator [-h] [--key KEY] [--ca CA] cert [hostname ...]

Validate X.509 certificate path/chain, for Openstack charms

positional arguments:
  cert        SSL certificate file. Expected format is mod_ssl's SSLCertificateFile. Please refer to: https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile
  hostname    Hostname to be checked against the certificate. Multiple hostnames can be passed.

options:
  -h, --help  show this help message and exit
  --key KEY   SSL certificate key file. No check will be made if it is not RSA key.
  --ca CA     SSL CA file
```

Example valid certificate:

```
$ openstack-charms-cert-validator --ca ca.crt cert.crt
[ssl_cert]

subject=Common Name: localhost
subject_alt_name=['localhost']
issuer=Common Name: Localhost Intermediate CA, Organization: Localhost

subject=Common Name: Localhost Intermediate CA, Organization: Localhost
issuer=Common Name: Localhost Root CA, Organization: Localhost

[ssl_ca]

subject=Common Name: Localhost Root CA, Organization: Localhost
issuer=Common Name: Localhost Root CA, Organization: Localhost

OK: SSL certificate validation passed.
```

## Development

Create a virtual environment and install as editable with pip:

```
python -m venv venv
source venv/bin/activate
pip install -e .
```

Then run as:

```
openstack-charms-cert-validator

# or
python ./openstack_charms_cert_validator.py
```

There is also a snapcraft config file, so you can build a snap with:

```
snapcraft
```

## Installation

This is a standard python project - see the pyproject.toml file.
Install as usual with pip or however you prefer.

It can also be installed as a snap from the configuration provided.

```
snapcraft
# dangerous flag is required for local unsigned snaps,
# and it's an unconfined snap so it can access system ca certificate paths
sudo snap install ./openstack-charms-cert-validator_*_amd64.snap --dangerous --classic
```

## License

Copyright 2023 Canonical Ltd.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranties of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
