# openstack-charms-cert-validator

A small tool to validate an SSL certificate chain for openstack charms.

Kind of like:

```
openssl verify -CAfile ca.crt -untrusted intermediate.crt leaf.crt
```

But more user-friendly errors.

## Development

Create a virtual environment and install as editable with pip:

```
make develop

# equivalent to:
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
# it is strictly confined, but dangerous flag required for local snaps
sudo snap install ./openstack-charms-cert-validator_*_amd64.snap --dangerous
```

## License

Copyright 2023 Canonical Ltd.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranties of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
