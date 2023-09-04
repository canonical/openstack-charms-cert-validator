#!/bin/bash

# run this with working directory set to the project root

set -e

echo ":: test ECC certificates"
echo ":: test local cert with ca; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/cert.crt --ca tests/fixtures/localhost-ecc-chain/ca.crt

echo ":: test local cert with ca and key; should be valid, but key is ignored for non-rsa keys currently"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/cert.crt --ca tests/fixtures/localhost-ecc-chain/ca.crt --key tests/fixtures/localhost-ecc-chain/cert.key

echo ":: test local cert without providing ca; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/cert.crt

echo ":: test local cert that has intermediate CA first in the file; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/wrong-order-cert.crt --ca tests/fixtures/localhost-ecc-chain/ca.crt

echo ":: test local cert with ca against a valid hostname; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/cert.crt localhost --ca tests/fixtures/localhost-ecc-chain/ca.crt

echo ":: test local cert with ca against an invalid hostname; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-ecc-chain/cert.crt invalid.hostname --ca tests/fixtures/localhost-ecc-chain/ca.crt


echo ":: test RSA certificates"
echo ":: test local cert with ca; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt --ca tests/fixtures/localhost-rsa-chain/ca.crt

echo ":: test local cert with ca and key; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt --ca tests/fixtures/localhost-rsa-chain/ca.crt --key tests/fixtures/localhost-rsa-chain/cert.key

echo ":: test local cert with ca against a mismatched key; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt --ca tests/fixtures/localhost-rsa-chain/ca.crt --key tests/fixtures/localhost-rsa-chain/mismatch.key

echo ":: test local cert without providing ca; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt

echo ":: test local cert with ca against a valid hostname; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt test.localhost --ca tests/fixtures/localhost-rsa-chain/ca.crt

echo ":: test local cert with ca against multiple valid hostnames; should be valid"
coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt test.localhost another.localhost --ca tests/fixtures/localhost-rsa-chain/ca.crt

echo ":: test local cert with ca against an invalid hostname; should fail"
! coverage run -a openstack_charms_cert_validator.py tests/fixtures/localhost-rsa-chain/cert.crt test.localhost invalid.hostname --ca tests/fixtures/localhost-rsa-chain/ca.crt
