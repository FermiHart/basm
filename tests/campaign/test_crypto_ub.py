#!/usr/bin/env python3
"""Test the explicitly bundled diagnostic crypto, never the absent ../../crypto.

RFC 8032 section 7.1 vectors are fixed fixtures. Additional expected signatures,
public keys and SHA-512 digests come from cryptography/OpenSSL and hashlib.
An optional original source reproduces the removed UB under UBSan and compares
all valid signature bytes using an ordinary build of the original source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RFC8032 = [
    ("test-1-empty", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("test-2-one-byte", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "72", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("test-3-two-bytes", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "af82", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]

DRIVER = r'''#include "bear_ed25519.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int bytes(FILE *file,void *out,size_t len) { return fread(out,1,len,file)==len; }
static uint32_t little32(const uint8_t b[4]) {
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    FILE *file=fopen(argv[1],"rb"); if (!file) return 3;
    uint8_t countbytes[4]; if (!bytes(file,countbytes,4)) return 4;
    uint32_t count=little32(countbytes); unsigned checks=0;
    for (uint32_t index=0;index<count;index++) {
        uint8_t seed[32],message[1025],pk[32],sk[64],signature[64],expected_pk[32],expected_sig[64],digest[64],expected_digest[64],length[4];
        if (!bytes(file,seed,32)||!bytes(file,length,4)) return 5;
        uint32_t len=little32(length); if (len>ED25519_MAX_MSG) return 6;
        memset(message,0,sizeof(message));
        if (!bytes(file,message,len)||!bytes(file,expected_pk,32)||!bytes(file,expected_sig,64)||!bytes(file,expected_digest,64)) return 7;
        ed25519_keypair_from_seed(seed,pk,sk);
        if (memcmp(pk,expected_pk,32)||memcmp(sk,seed,32)||memcmp(sk+32,pk,32)) return 10;
        checks++;
        if (ed25519_sign(signature,message,len,sk)||memcmp(signature,expected_sig,64)) return 11;
        checks++;
        if (ed25519_verify(expected_sig,message,len,expected_pk)) return 12;
        checks++;
#ifndef BASM_TEST_ORIGINAL_VALID_ONLY
        /* RFC 8032 section 5.1.7: these three scalar encodings are invalid. */
        static const uint8_t order[32]={0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
        uint8_t noncanonical[64]; memcpy(noncanonical,signature,64);
        memcpy(noncanonical+32,order,32);
        if (ed25519_verify(noncanonical,message,len,pk)==0) return 22;
        unsigned carry=0;
        for (int i=0;i<32;i++) {
            unsigned sum=(unsigned)signature[32+i]+order[i]+carry;
            noncanonical[32+i]=(uint8_t)sum; carry=sum>>8;
        }
        if (carry || ed25519_verify(noncanonical,message,len,pk)==0) return 23;
        memset(noncanonical+32,255,32);
        if (ed25519_verify(noncanonical,message,len,pk)==0) return 24;
        checks+=3;
#endif
        sha512(message,len,digest); if (memcmp(digest,expected_digest,64)) return 13;
        checks++;
        static const int positions[]={0,31,32,63};
        for (unsigned j=0;j<sizeof(positions)/sizeof(positions[0]);j++) {
            signature[positions[j]]^=1;
            if (ed25519_verify(signature,message,len,pk)==0) return 14;
            signature[positions[j]]^=1; checks++;
        }
        message[0]^=1;
        if (ed25519_verify(signature,message,len ? len : 1,pk)==0) return 15;
        message[0]^=1; checks++;
        pk[0]^=1;
        if (ed25519_verify(signature,message,len,pk)==0) return 16;
        pk[0]^=1; checks++;
        if (ed25519_sign(signature,message,1025,sk)!=-1 || ed25519_verify(signature,message,1025,pk)!=-1) return 17;
        checks+=2;
    }
    if (fgetc(file)!=EOF || fclose(file)) return 18;
    /* Exercise the additional public group APIs with identity/base cases. */
    uint8_t zero[32]={0},one[32]={1},two[32]={2},identity[32]={1},base[32],twice[32],sum[32],mult[32];
    ed25519_scalarbase(zero,base); if (memcmp(base,identity,32)) return 19;
    ed25519_scalarbase(one,base);
    static const uint8_t encoded_base[32]={0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};
    if (memcmp(base,encoded_base,32)) return 20;
    ed25519_scalarbase(two,twice); ed25519_scalarmult(mult,base,two);
    if (ed25519_point_add(sum,base,base)||memcmp(sum,twice,32)||memcmp(mult,twice,32)) return 21;
    checks+=3;
    printf("{\"vectors\":%u,\"checks\":%u}\n",count,checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--original", type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="basm-crypto-"))
    output.mkdir(parents=True, exist_ok=True)
    cc = shutil.which(args.cc)
    if not cc:
        parser.error("host C compiler unavailable")
    vectors = []
    for name, seed_hex, msg_hex, pk_hex, sig_hex in RFC8032:
        seed, msg = bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        sig = key.sign(msg)
        assert pk == bytes.fromhex(pk_hex) and sig == bytes.fromhex(sig_hex), name
        vectors.append((name, seed, msg, pk, sig))
    lengths = [0, 1, 2, 3, 15, 16, 31, 32, 63, 64, 111, 112, 113, 127, 128, 129, 255, 256, 511, 512, 1023, 1024]
    for index, length in enumerate(lengths):
        seed = hashlib.sha256(f"BearBasm diagnostic KAT seed {index}".encode()).digest()
        msg = hashlib.shake_256(f"BearBasm diagnostic message {index}".encode()).digest(length)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        vectors.append((f"independent-length-{length}", seed, msg,
                        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), key.sign(msg)))
    for value in (0, 1, 127, 128, 254, 255):
        seed, msg = bytes([value]) * 32, bytes([value]) * 1024
        key = Ed25519PrivateKey.from_private_bytes(seed)
        vectors.append((f"independent-repeated-{value}", seed, msg,
                        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), key.sign(msg)))
    vector_file = output / "vectors.bin"
    scalar_order = 2**252 + 27742317777372353535851937790883648493
    for name, seed, msg, pk, sig in vectors:
        key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        for scalar in (scalar_order, int.from_bytes(sig[32:], "little") + scalar_order, 2**256 - 1):
            try:
                key.verify(sig[:32] + scalar.to_bytes(32, "little"), msg)
            except InvalidSignature:
                continue
            raise AssertionError(f"independent provider accepted noncanonical scalar: {name}")
    with vector_file.open("wb") as file:
        file.write(struct.pack("<I", len(vectors)))
        for _, seed, msg, pk, sig in vectors:
            file.write(seed + struct.pack("<I", len(msg)) + msg + pk + sig + hashlib.sha512(msg).digest())
    driver = output / "crypto_driver.c"
    driver.write_text(DRIVER)
    report = {"schema": "BASM-BUNDLED-CRYPTO-UB-v1", "scope": "bundled diagnostic crypto only; canonical ../../crypto absent; no formal or side-channel audit",
              "rfc_source": "https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1",
              "canonical_scalar_requirement": "https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7",
              "independent_noncanonical_scalar_rejections": 3 * len(vectors),
              "independent_provider": {"cryptography": cryptography.__version__, "openssl": default_backend().openssl_version_text()},
              "source_sha256": hashlib.sha256((root / "bear_ed25519.c").read_bytes()).hexdigest(),
              "header_sha256": hashlib.sha256((root / "bear_ed25519.h").read_bytes()).hexdigest(),
              "vectors_sha256": hashlib.sha256(vector_file.read_bytes()).hexdigest(),
              "vectors": [{"name": name, "message_bytes": len(msg), "public_key": pk.hex(), "signature": sig.hex()} for name, _, msg, pk, sig in vectors],
              "compiler_version": subprocess.run([cc, "--version"], capture_output=True, text=True, check=True).stdout,
              "runs": []}
    jobs = [("candidate-normal", root / "bear_ed25519.c", False, False),
            ("candidate-asan-ubsan", root / "bear_ed25519.c", True, False)]
    if args.original:
        jobs += [("original-valid-byte-compatibility", args.original.resolve(), False, False),
                 ("original-ubsan-reproduction", args.original.resolve(), True, True)]
    for name, source, sanitize, expected_ub in jobs:
        executable = output / name
        flags = ["-std=c11", "-O1" if sanitize else "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fno-omit-frame-pointer"]
        if name.startswith("original-"):
            flags.append("-DBASM_TEST_ORIGINAL_VALID_ONLY=1")
        if sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
        argv = [cc] + flags + ["-I" + str(root), str(driver), str(source), "-o", str(executable)]
        compiled = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
        result = subprocess.run([str(executable), str(vector_file)], env=environment, capture_output=True, text=True, timeout=120) if compiled.returncode == 0 else compiled
        bad_diagnostic = any(marker in result.stderr for marker in ("runtime error:", "AddressSanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer"))
        passed = compiled.returncode == 0 and result.returncode == 0 and not bad_diagnostic
        if expected_ub:
            passed = compiled.returncode == 0 and result.returncode != 0 and "left shift of negative value" in result.stderr
        record = {"name": name, "pass": passed, "compile_argv": argv, "compile_rc": compiled.returncode,
                  "compile_stderr": compiled.stderr, "returncode": result.returncode, "stdout": result.stdout,
                  "stderr": result.stderr, "expected_original_ub": expected_ub,
                  "ASAN_OPTIONS": environment["ASAN_OPTIONS"],
                  "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest() if executable.exists() else None}
        report["runs"].append(record)
        print(("PASS " if passed else "FAIL ") + name, flush=True)
    report["passed"] = sum(run["pass"] for run in report["runs"])
    report["failed"] = len(report["runs"]) - report["passed"]
    path = output / "results.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Bundled diagnostic crypto: {len(vectors)} vectors; {report['passed']} builds passed; {report['failed']} failed. Evidence: {path}")
    return int(report["failed"] != 0)


if __name__ == "__main__":
    sys.exit(main())
