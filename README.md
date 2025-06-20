# 🔐 Certificate Revocation Checker

A Python script that checks the validity and revocation status of SSL/TLS certificates via:

- ✅ Date validation (expiry, not-before)
- 🔗 CRL (Certificate Revocation List)
- 🔎 OCSP (Online Certificate Status Protocol)

---

## 📦 Requirements

Install dependencies:

```bash
pip install cryptography pyOpenSSL idna requests
```

---

## 🚀 Usage

Run the script:

```bash
python crl-checker.py
```

You’ll be prompted to:

- Choose **test mode** (load a CRL from file)
- Or enter an **FQDN** (e.g. `example.com`) to fetch the live certificate

---

## 🧪 Sample Output

```text
📋 Certificate Revocation Checker
Run in test mode with known good serial from CRL? (y/n): n
Enter FQDN of site (e.g. www.example.com): revoked.badssl.com

🔐 Certificate Details from Site:
  🌐 Subject     : CN=revoked.badssl.com
  🆔 Serial      : 000005CE00A415B941325C294E31682C36B5B7FC
  📆 Valid From  : 2025-04-29 20:03:06+00:00
  📆 Valid Until : 2025-07-28 20:03:05+00:00
  📌 Status      : ✅ Currently within valid date range

🔗 CRL Distribution Point: http://e5.c.lencr.org/125.crl
📂 Downloaded CRL from: http://e5.c.lencr.org/125.crl

🔎 Revocation Check (CRL):
✅ Certificate is NOT in CRL (good).

🔎 Live Status Check (OCSP):
❌ OCSP check failed: OCSP response status is not successful...
```

---

## 🧯 Notes

- Certificates without CRL or OCSP extensions will return warnings.
- Some CRLs include **IDP extensions**, which mark all unlisted certs as "Unknown".
- OCSP is often more reliable for live revocation checks.
- Your system must have outbound HTTP access to CRL/OCSP URLs.

---

## 📜 License

MIT License – free for personal or commercial use.
