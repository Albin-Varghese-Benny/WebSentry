"""
gen_certs.py -- create the project's private CA and certificates.

    python gen_certs.py                       # CA, proxy cert, client certs for alice, bob, carol
    python gen_certs.py --users alice bob dave
    python gen_certs.py --san 192.168.1.20    # also valid for this IP / hostname
    python gen_certs.py --add-user dave       # one more client certificate from the EXISTING CA

Output:
    certs/ca.crt, certs/ca.key            private certificate authority
    certs/proxy.crt, certs/proxy.key      proxy server certificate (CN = netproxy)
    certs/clients/<user>.crt / .key       client certificates; the CN is the user's identity

Clients verify the proxy against the name "netproxy" (it is always in the
certificate), so the same certificate works whatever IP the proxy runs on.

Uses the 'cryptography' package if installed (pip install cryptography),
otherwise falls back to the openssl command-line tool.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DAYS = 825


def _sans(extra):
    names = ["netproxy", "localhost", "127.0.0.1", "::1"] + list(extra or [])
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


# --------------------------------------------------------------------------- cryptography backend
def generate_with_cryptography(outdir: Path, users, extra_sans):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)

    def key():
        return ec.generate_private_key(ec.SECP256R1())

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN Lab Proxy Project"),
                          x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def write(path: Path, cert, k):
        path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        path.with_suffix(".key").write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                                              serialization.PrivateFormat.PKCS8,
                                                              serialization.NoEncryption()))

    ca_key = key()
    ca = (x509.CertificateBuilder().subject_name(name("NetProxy Lab CA")).issuer_name(name("NetProxy Lab CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + dt.timedelta(days=DAYS * 2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    write(outdir / "ca", ca, ca_key)

    def issue(cn, eku, sans=None):
        k = key()
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject)
             .public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + dt.timedelta(days=DAYS))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
        if sans:
            entries = []
            for s in sans:
                try:
                    entries.append(x509.IPAddress(ipaddress.ip_address(s)))
                except ValueError:
                    entries.append(x509.DNSName(s))
            b = b.add_extension(x509.SubjectAlternativeName(entries), critical=False)
        return b.sign(ca_key, hashes.SHA256()), k

    cert, k = issue("netproxy", ExtendedKeyUsageOID.SERVER_AUTH, _sans(extra_sans))
    write(outdir / "proxy", cert, k)
    for user in users:
        cert, k = issue(user, ExtendedKeyUsageOID.CLIENT_AUTH)
        write(outdir / "clients" / user, cert, k)


# --------------------------------------------------------------------------- openssl fallback
def generate_with_openssl(outdir: Path, users, extra_sans):
    ossl = shutil.which("openssl")
    if not ossl:
        sys.exit("Neither the 'cryptography' package nor the 'openssl' tool is available.\n"
                 "Install one:  pip install cryptography")

    def run(*args):
        subprocess.run([ossl, *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        subj = "/O=CN Lab Proxy Project/CN="
        run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(outdir / "ca.key"))
        (tmp / "ca.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                                    "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"
                                    "subjectKeyIdentifier=hash\n")
        run("req", "-x509", "-new", "-key", str(outdir / "ca.key"), "-sha256", "-days", str(DAYS * 2),
            "-subj", subj + "NetProxy Lab CA", "-out", str(outdir / "ca.crt"),
            "-extensions", "v3_ca", "-config", _openssl_cnf(tmp))

        def issue(base: Path, cn: str, ext: str):
            run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(base) + ".key.ec")
            run("pkcs8", "-topk8", "-nocrypt", "-in", str(base) + ".key.ec", "-out", str(base) + ".key")
            os.remove(str(base) + ".key.ec")
            run("req", "-new", "-key", str(base) + ".key", "-subj", subj + cn, "-out", str(tmp / "req.csr"))
            (tmp / "leaf.ext").write_text(ext)
            run("x509", "-req", "-in", str(tmp / "req.csr"), "-CA", str(outdir / "ca.crt"), "-CAkey",
                str(outdir / "ca.key"), "-CAcreateserial", "-days", str(DAYS), "-sha256",
                "-extfile", str(tmp / "leaf.ext"), "-out", str(base) + ".crt")

        alt = ",".join(("IP:" if _is_ip(s) else "DNS:") + s for s in _sans(extra_sans))
        issue(outdir / "proxy", "netproxy",
              f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName={alt}\n")
        for user in users:
            issue(outdir / "clients" / user, user, "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n")
        srl = outdir / "ca.srl"
        if srl.exists():
            srl.unlink()


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _openssl_cnf(tmp: Path) -> str:
    cnf = tmp / "openssl.cnf"
    cnf.write_text("[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
                   "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\nsubjectKeyIdentifier=hash\n")
    return str(cnf)


def add_users(outdir: Path, users, backend: str = "auto") -> str:
    """Issue client certificates from the EXISTING CA, so the proxy and other users keep working."""
    if not (outdir / "ca.crt").exists() or not (outdir / "ca.key").exists():
        sys.exit(f"no CA in {outdir} - run python gen_certs.py first")
    (outdir / "clients").mkdir(parents=True, exist_ok=True)
    if backend in ("auto", "cryptography"):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        except ImportError:
            if backend == "cryptography":
                raise
        else:
            ca = x509.load_pem_x509_certificate((outdir / "ca.crt").read_bytes())
            ca_key = serialization.load_pem_private_key((outdir / "ca.key").read_bytes(), None)
            now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
            for user in users:
                k = ec.generate_private_key(ec.SECP256R1())
                name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN Lab Proxy Project"),
                                  x509.NameAttribute(NameOID.COMMON_NAME, user)])
                cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject)
                        .public_key(k.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=DAYS))
                        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                        .sign(ca_key, hashes.SHA256()))
                base = outdir / "clients" / user
                base.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                base.with_suffix(".key").write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                                                     serialization.PrivateFormat.PKCS8,
                                                                     serialization.NoEncryption()))
            return "cryptography"
    ossl = shutil.which("openssl")
    if not ossl:
        sys.exit("Neither the 'cryptography' package nor the 'openssl' tool is available (pip install cryptography)")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n")
        for user in users:
            base = str(outdir / "clients" / user)
            for args in (["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", base + ".key.ec"],
                         ["pkcs8", "-topk8", "-nocrypt", "-in", base + ".key.ec", "-out", base + ".key"],
                         ["req", "-new", "-key", base + ".key", "-subj", f"/O=CN Lab Proxy Project/CN={user}",
                          "-out", str(tmp / "req.csr")],
                         ["x509", "-req", "-in", str(tmp / "req.csr"), "-CA", str(outdir / "ca.crt"), "-CAkey",
                          str(outdir / "ca.key"), "-CAcreateserial", "-CAserial", str(tmp / "ca.srl"), "-days",
                          str(DAYS), "-sha256", "-extfile", str(tmp / "leaf.ext"), "-out", base + ".crt"]):
                subprocess.run([ossl, *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            os.remove(base + ".key.ec")
    return "openssl"


def generate(outdir: Path = ROOT / "certs", users=("alice", "bob", "carol"), extra_sans=(), backend: str = "auto"):
    (outdir / "clients").mkdir(parents=True, exist_ok=True)
    if backend in ("auto", "cryptography"):
        try:
            import cryptography  # noqa: F401  (just checking it is installed)
            generate_with_cryptography(outdir, users, extra_sans)
            return "cryptography"
        except ImportError:
            if backend == "cryptography":
                raise
    generate_with_openssl(outdir, users, extra_sans)
    return "openssl"


def main():
    ap = argparse.ArgumentParser(description="Generate the CA, proxy and client certificates.")
    ap.add_argument("--out", default=str(ROOT / "certs"), help="output directory (default certs/)")
    ap.add_argument("--users", nargs="+", default=["alice", "bob", "carol"], help="client identities")
    ap.add_argument("--san", nargs="*", default=[], help="extra IPs / hostnames for the proxy certificate")
    ap.add_argument("--add-user", nargs="+", metavar="NAME",
                    help="only issue client certificates for these users, signed by the existing CA")
    ap.add_argument("--backend", choices=["auto", "cryptography", "openssl"], default="auto")
    args = ap.parse_args()
    if args.add_user:
        used = add_users(Path(args.out), args.add_user, args.backend)
        for u in args.add_user:
            print(f"  clients/{u}.crt / .key   client identity '{u}' (signed by the existing CA, using {used})")
        print("Add the new user to a group in config/policy.json (or: adminctl.py GROUP ADD students <name>).")
        return
    used = generate(Path(args.out), args.users, args.san, args.backend)
    print(f"certificates written to {args.out} (using {used}):")
    rows = [("ca.crt / ca.key", "private CA - give ca.crt to clients, keep ca.key secret"),
            ("proxy.crt / proxy.key", "server certificate, names: " + ", ".join(_sans(args.san)))]
    rows += [(f"clients/{u}.crt / .key", f"client identity '{u}'") for u in args.users]
    width = max(len(a) for a, _ in rows) + 3
    for a, b in rows:
        print(f"  {a.ljust(width)}{b}")


if __name__ == "__main__":
    main()
