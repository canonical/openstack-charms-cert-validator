#!/usr/bin/env python3
# This file is part of openstack-charm-cert-validator.
# Copyright 2023 Canonical Ltd.
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranties of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
$ openstack-charms-cert-validator -h
usage: openstack-charms-cert-validator [-h] --cert CERT [--key KEY] [--ca CA] [hostname ...]

Validate X.509 Certificate Path/Chain

positional arguments:
  hostname     Hostname to be checked against the certificate. Multiple hostnames can be passed.

options:
  -h, --help   show this help message and exit
  --cert CERT  SSL certificate file. Expected format is mod_ssl's SSLCertificateFile. Please refer to:
               https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile
  --key KEY    SSL certificate key file. No check will be made if it is not RSA key.
  --ca CA      SSL CA file

"""
__version__ = "0.1"

import argparse
import hashlib

from asn1crypto import keys, pem, x509
from certvalidator import CertificateValidator, ValidationContext


def show_human_friendly_header(der_bytes, modulus_digest=None):
    cert = x509.Certificate.load(der_bytes)
    print("subject={}".format(cert.subject.human_friendly))
    if cert.subject_alt_name_value:
        print("subject_alt_name={}".format(cert.subject_alt_name_value.native))
    if modulus_digest:
        print("rsa_modulus_digest_sha256={}".format(modulus_digest))
    print("issuer={}\n".format(cert.issuer.human_friendly))


def rsa_cert_modulus_digest_sha256(der_bytes):
    cert = x509.Certificate.load(der_bytes)
    tbs_certificate = cert["tbs_certificate"]
    subject_public_key_info = tbs_certificate["subject_public_key_info"]
    subject_public_key_algorithm = subject_public_key_info["algorithm"]
    if subject_public_key_algorithm["algorithm"].native != "rsa":
        # https://security.stackexchange.com/a/73131
        return
    subject_public_key = subject_public_key_info["public_key"].parsed
    modulus = str(subject_public_key["modulus"].native)
    modulus_digest_sha256 = hashlib.sha256(modulus.encode()).hexdigest()
    return modulus_digest_sha256


def rsa_key_modulus_digest_sha256(der_bytes):
    key_info = keys.PrivateKeyInfo.load(der_bytes)
    try:
        algorithm = key_info["private_key_algorithm"]["algorithm"].native
        if algorithm != "rsa":
            return
    except ValueError:
        print(
            'WARNING: Failed to get key_info["private_key_algorithm"]["algorithm"]'
        )
        return
    key = key_info["private_key"].parsed
    modulus = str(key["modulus"].native)
    modulus_digest_sha256 = hashlib.sha256(modulus.encode()).hexdigest()
    return modulus_digest_sha256


def validate(cert_path, key_path, ca_path, hostnames):
    end_entity_cert = None
    intermediates = []
    with open(cert_path, "rb") as f:
        print("[ssl_cert]\n")
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            if end_entity_cert is None:
                end_entity_cert = der_bytes
                cert_modulus_digest = rsa_cert_modulus_digest_sha256(der_bytes)
                show_human_friendly_header(der_bytes, cert_modulus_digest)
            else:
                intermediates.append(der_bytes)
                show_human_friendly_header(der_bytes)

    key_modulus_digest = None
    if key_path:
        print("[ssl_key]\n")
        with open(key_path, "rb") as f:
            _, _, der_bytes = pem.unarmor(f.read())
            key_modulus_digest = rsa_key_modulus_digest_sha256(der_bytes)
            print("rsa_modulus_digest_sha256={}\n".format(key_modulus_digest))

    extra_trust_roots = []
    if ca_path:
        with open(ca_path, "rb") as f:
            print("[ssl_ca]\n")
            for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
                extra_trust_roots.append(der_bytes)
                show_human_friendly_header(der_bytes)

    context = ValidationContext(extra_trust_roots=extra_trust_roots)
    validator = CertificateValidator(
        end_entity_cert, intermediates, validation_context=context
    )

    try:
        if hostnames:
            for hostname in hostnames:
                validator.validate_tls(hostname=hostname)
        else:
            validator.validate_usage(set(["digital_signature"]), set(["server_auth"]))
        print("OK: SSL certificate validation passed.")
    except Exception as e:
        print("ERROR: {}".format(e))

    if (
        cert_modulus_digest
        and key_modulus_digest
        and cert_modulus_digest != key_modulus_digest
    ):
        print(
            "\nERROR: modulus of the SSL certificate and key didn't match. "
            "Please double check if the cert and key pair is valid."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Validate X.509 Certificate Path/Chain"
    )
    parser.add_argument(
        "--cert",
        required=True,
        help=(
            "SSL certificate file. Expected format is mod_ssl's SSLCertificateFile. "
            "Please refer to: https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile"
        ),
    )
    parser.add_argument(
        "--key",
        help="SSL certificate key file. No check will be made if it is not RSA key.",
    )
    parser.add_argument("--ca", help="SSL CA file")
    parser.add_argument(
        "hostname",
        nargs="*",
        help=(
            "Hostname to be checked against the certificate. Multiple hostnames can be passed."
        ),
    )
    args = parser.parse_args()
    validate(
        cert_path=args.ssl_cert,
        key_path=args.ssl_key,
        ca_path=args.ssl_ca,
        hostnames=args.hostname,
    )


if __name__ == "__main__":
    main()
