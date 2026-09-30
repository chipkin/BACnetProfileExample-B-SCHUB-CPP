#!/usr/bin/env python3
"""
Checks --generate-csr and --sign-csr (signing a device's own certificate
signing request with the hub's existing issuer). Runs the executable itself in
a temporary certificate folder; needs no running hub.

    python tests/sc/csr_test.py --exe build/Release/BACnetExampleBSCHUB.exe

  1. --generate-certs 1, then --generate-csr --cert-label ahu-7: a P-256 key and
     a CSR whose signature verifies, in clients/ahu-7/.
  2. --sign-csr on that CSR (no --cert-label - the folder is found from the
     CSR's path): a certificate for that key, signed by the issuer, EKU
     clientAuth, plus the .pfx/YABE files because the key is in the folder.
  3. --sign-csr on a CSR made elsewhere (RSA 2048, its own subject, asking for
     serverAuth and a SAN) with --cert-label customer: the certificate keeps
     the CSR's subject and key but gets the client profile (clientAuth only,
     no SAN), and the folder holds no private key and no .pfx.
  4. Refusals: a CSR with a broken signature, an RSA 1024 CSR, a not-a-CSR
     file, signing into a folder that already has a certificate, and a
     folder whose private key is not the CSR's.

Exit code 0 = every check passed.
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def run(exe, cert_dir, *args):
    proc = subprocess.run([str(exe), "--sc-cert-dir", str(cert_dir), *args], capture_output=True, text=True,
                          timeout=60)
    return proc.returncode, proc.stdout + proc.stderr


def public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def check_signed_by(cert, issuer):
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:  # noqa: BLE001 - any failure means "not signed by it"
        return False


def eku(cert):
    try:
        return list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return []


def make_csr(key, common_name, extra_extensions=True):
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Customer Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    if extra_extensions:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("customer.example")]),
                                        critical=False)
    return builder.sign(key, hashes.SHA256())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--exe", required=True, help="path to BACnetExampleBSCHUB")
    args = parser.parse_args()
    exe = Path(args.exe).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        certs = tmp / "certs"
        rc, out = run(exe, certs, "--generate-certs", "1")
        record("--generate-certs 1", rc == 0, out.strip().splitlines()[-1] if out.strip() else "")
        issuer = x509.load_pem_x509_certificate((certs / "issuer-certificate.pem").read_bytes())

        # 1. --generate-csr
        rc, out = run(exe, certs, "--generate-csr", "--cert-label", "ahu-7")
        folder = certs / "clients" / "ahu-7"
        record("--generate-csr exits 0", rc == 0, out.strip())
        csr = x509.load_pem_x509_csr((folder / "certificate-signing-request.pem").read_bytes())
        key = serialization.load_pem_private_key((folder / "private-key.pem").read_bytes(), None)
        record("CSR signature verifies", csr.is_signature_valid)
        record("CSR is for the folder's key", public_der(csr.public_key()) == public_der(key.public_key()))
        record("key is ECDSA P-256", isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name == "secp256r1")
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        record("CSR CN names the label", cn == "Chipkin Example B-SCHUB ahu-7", cn)
        record("no certificate yet", not (folder / "operational-certificate.pem").exists())
        rc, _ = run(exe, certs, "--generate-csr", "--cert-label", "ahu-7")
        record("--generate-csr refuses to overwrite", rc != 0)

        # 2. --sign-csr on it, label found from the CSR's folder
        rc, out = run(exe, certs, "--sign-csr", str(folder / "certificate-signing-request.pem"))
        record("--sign-csr (own CSR) exits 0", rc == 0, out.strip().splitlines()[-1] if out.strip() else "")
        cert = x509.load_pem_x509_certificate((folder / "operational-certificate.pem").read_bytes())
        record("certificate signed by the issuer", check_signed_by(cert, issuer))
        record("certificate is for the folder's key", public_der(cert.public_key()) == public_der(key.public_key()))
        record("certificate EKU is clientAuth", eku(cert) == [ExtendedKeyUsageOID.CLIENT_AUTH])
        record("certificate keeps the CSR's subject", cert.subject == csr.subject)
        for name in ("ahu-7.pfx", "yabe-bacnetsc.config", "bacnetsc.config", "issuer-certificate.pem",
                     "issuer-certificate.cer"):
            record(f"folder has {name}", (folder / name).exists())
        record("listed in certificates.txt", "ahu-7 | client" in (certs / "certificates.txt").read_text())
        rc, _ = run(exe, certs, "--sign-csr", str(folder / "certificate-signing-request.pem"))
        record("--sign-csr refuses a folder that already has a certificate", rc != 0)

        # 3. A customer's own CSR, made elsewhere
        customer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        customer_csr = make_csr(customer_key, "Customer AHU 12")
        csr_path = tmp / "customer.csr"
        csr_path.write_bytes(customer_csr.public_bytes(serialization.Encoding.PEM))
        rc, out = run(exe, certs, "--sign-csr", str(csr_path), "--cert-label", "customer")
        folder = certs / "clients" / "customer"
        record("--sign-csr (customer CSR) exits 0", rc == 0, out.strip().splitlines()[-1] if out.strip() else "")
        cert = x509.load_pem_x509_certificate((folder / "operational-certificate.pem").read_bytes())
        record("customer certificate signed by the issuer", check_signed_by(cert, issuer))
        record("customer certificate keeps the CSR's subject", cert.subject == customer_csr.subject,
               cert.subject.rfc4514_string())
        record("customer certificate is for the CSR's key",
               public_der(cert.public_key()) == public_der(customer_key.public_key()))
        record("customer certificate EKU is clientAuth only (serverAuth request ignored)",
               eku(cert) == [ExtendedKeyUsageOID.CLIENT_AUTH])
        try:
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            record("requested SAN not copied", False)
        except x509.ExtensionNotFound:
            record("requested SAN not copied", True)
        record("no private key in the customer folder", not (folder / "private-key.pem").exists())
        record("no .pfx in the customer folder", not list(folder.glob("*.pfx")))
        record("customer folder has bacnetsc.config", (folder / "bacnetsc.config").exists())

        # DER input, default label = next client-NN
        der_path = tmp / "customer2.der"
        der_path.write_bytes(make_csr(ec.generate_private_key(ec.SECP256R1()), "Customer VAV 3", False)
                             .public_bytes(serialization.Encoding.DER))
        rc, out = run(exe, certs, "--sign-csr", str(der_path))
        record("--sign-csr accepts DER, default label client-02",
               rc == 0 and (certs / "clients" / "client-02" / "operational-certificate.pem").exists(), out.strip())

        # 4. Refusals
        bad = bytearray(customer_csr.public_bytes(serialization.Encoding.DER))
        bad[-5] ^= 0xFF  # inside the signature
        bad_path = tmp / "broken.der"
        bad_path.write_bytes(bytes(bad))
        rc, out = run(exe, certs, "--sign-csr", str(bad_path), "--cert-label", "broken")
        record("broken signature refused", rc != 0 and not (certs / "clients" / "broken").exists(),
               out.strip().splitlines()[-1] if out.strip() else "")

        weak_path = tmp / "weak.csr"
        weak_path.write_bytes(make_csr(rsa.generate_private_key(public_exponent=65537, key_size=1024), "Weak", False)
                              .public_bytes(serialization.Encoding.PEM))
        rc, out = run(exe, certs, "--sign-csr", str(weak_path), "--cert-label", "weak")
        record("RSA 1024 refused", rc != 0 and not (certs / "clients" / "weak").exists(),
               out.strip().splitlines()[-1] if out.strip() else "")

        junk_path = tmp / "junk.csr"
        junk_path.write_text("not a CSR\n")
        rc, _ = run(exe, certs, "--sign-csr", str(junk_path), "--cert-label", "junk")
        record("not-a-CSR refused", rc != 0 and not (certs / "clients" / "junk").exists())

        # "other" gets its own key from --generate-csr, not the customer's
        run(exe, certs, "--generate-csr", "--cert-label", "other")
        rc, out = run(exe, certs, "--sign-csr", str(csr_path), "--cert-label", "other")
        record("folder with a different private key refused",
               rc != 0 and not (certs / "clients" / "other" / "operational-certificate.pem").exists(),
               out.strip().splitlines()[-1] if out.strip() else "")

        rc, _ = run(exe, certs, "--sign-csr", str(csr_path), "--generate-csr")
        record("--sign-csr with --generate-csr refused", rc != 0)

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
