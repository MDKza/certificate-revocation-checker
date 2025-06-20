import ssl
import socket
import idna
import datetime
import requests
import urllib3
import os
import base64

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization

urllib3.disable_warnings()

def get_certificate_from_fqdn(hostname):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    conn.settimeout(5)
    conn.connect((hostname, 443))
    der_cert = conn.getpeercert(True)
    conn.close()

    return x509.load_der_x509_certificate(der_cert, default_backend()), der_cert

def download_crl(crl_url):
    try:
        print(f"\n📂 Downloaded CRL from: {crl_url}")
        r = requests.get(crl_url, timeout=10, verify=False)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"❌ Failed to download CRL: {e}")
        return None

def parse_crl(crl_data):
    try:
        return x509.load_der_x509_crl(crl_data, default_backend())
    except Exception:
        return x509.load_pem_x509_crl(crl_data, default_backend())

def get_ocsp_status(cert, issuer_cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_urls = [desc.access_location.value for desc in aia.value if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"]
        if not ocsp_urls:
            print("⚠️ No OCSP responder URL found in certificate.")
            return
        ocsp_url = ocsp_urls[0]

        builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer_cert, cert.signature_hash_algorithm)
        req = builder.build()
        headers = {'Content-Type': 'application/ocsp-request'}
        resp = requests.post(ocsp_url, data=req.public_bytes(serialization.Encoding.DER), headers=headers, timeout=10)

        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
        status = ocsp_resp.certificate_status

        print("\n🔎 Live Status Check (OCSP):")
        if status == ocsp.OCSPCertStatus.GOOD:
            print("✅ Certificate is GOOD (OCSP)")
        elif status == ocsp.OCSPCertStatus.REVOKED:
            print("❌ Certificate is REVOKED (OCSP)")
        else:
            print("⚠️ Certificate status is UNKNOWN (OCSP)")
    except Exception as e:
        print(f"❌ OCSP check failed: {e}")

def main():
    print("📋 Certificate Revocation Checker")
    test_mode = input("Run in test mode with known good serial from CRL? (y/n): ").strip().lower() == "y"

    if not test_mode:
        fqdn = input("Enter FQDN of site (e.g. www.example.com): ").strip()
        try:
            cert, der_cert = get_certificate_from_fqdn(idna.encode(fqdn).decode())
        except Exception as e:
            print(f"❌ Failed to retrieve certificate: {e}")
            return
    else:
        crl_path = input("Enter path to CRL file (.crl, .der, .pem): ").strip()
        if not os.path.isfile(crl_path):
            print("❌ CRL file not found.")
            return
        with open(crl_path, "rb") as f:
            crl_data = f.read()
        crl = parse_crl(crl_data)
        try:
            revoked_certs = crl.revoked_certificates
        except AttributeError:
            try:
                revoked_certs = crl.revoked_certificates()
            except Exception:
                revoked_certs = []
        if not revoked_certs:
            print("❌ No revoked certificates found in CRL.")
            return
        cert = revoked_certs[0]
        print(f"🔍 Test mode using known serial: {cert.serial_number}")
        print("🔎 This simulates a revoked certificate.")
        return

    print("\n🔐 Certificate Details from Site:")
    print(f"  🌐 Subject     : {cert.subject.rfc4514_string()}")
    print(f"  🛡️  Issuer      : {cert.issuer.rfc4514_string()}")
    print(f"  🆔 Serial      : {format(cert.serial_number, '040X')}")
    print(f"  📆 Valid From  : {cert.not_valid_before_utc}")
    print(f"  📆 Valid Until : {cert.not_valid_after_utc}")

    now = datetime.datetime.now(datetime.UTC)
    if now < cert.not_valid_before_utc:
        print("  📌 Status      : ⏳ Not yet valid!")
    elif now > cert.not_valid_after_utc:
        print("  📌 Status      : ❌ Expired!")
    else:
        print("  📌 Status      : ✅ Currently within valid date range")

    crl_urls = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for dp in ext.value:
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    crl_urls.append(name.value)
    except Exception:
        pass

    if crl_urls:
        crl_url = crl_urls[0]
        print(f"\n🔗 CRL Distribution Point: {crl_url}")
        crl_data = download_crl(crl_url)
        if crl_data:
            crl = parse_crl(crl_data)
            try:
                revoked_certs = crl.revoked_certificates
            except AttributeError:
                try:
                    revoked_certs = crl.revoked_certificates()
                except Exception:
                    revoked_certs = []

            print("\n🔎 Revocation Check (CRL):")
            if any(rev.serial_number == cert.serial_number for rev in revoked_certs or []):
                print("❌ Certificate is listed in CRL (revoked).")
            else:
                print("✅ Certificate is NOT in CRL (good).")
    else:
        print("\n🔗 CRL Distribution Point: None")
        print("⚠️ No CRL distribution point found in certificate.")

    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        issuer_urls = [desc.access_location.value for desc in aia.value if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"]
        issuer_cert = None
        if issuer_urls:
            issuer_resp = requests.get(issuer_urls[0], timeout=10, verify=False)
            issuer_cert = x509.load_der_x509_certificate(issuer_resp.content, default_backend())
        if issuer_cert:
            get_ocsp_status(cert, issuer_cert)
        else:
            print("⚠️ Could not load issuer certificate for OCSP check.")
    except Exception as e:
        print(f"❌ Failed to get OCSP status: {e}")

if __name__ == "__main__":
    main()
