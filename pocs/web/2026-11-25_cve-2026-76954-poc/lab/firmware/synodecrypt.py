import json
import os
import tarfile
from io import BytesIO
from pathlib import Path

import msgpack
import pysodium

import argparse
import logging

TAR_BLOCK_SIZE = 0x200
LOG = logging.getLogger(__name__)

# extract keys from `synoarchive_open_with_keytype` in libsynocodesign.so
KEYS = None

def u32b(b): return int.from_bytes(b[:4], "big")
def u32l(b): return int.from_bytes(b[:4], "little")

def read_u32b(s): return u32b(s.read(4))
def read_u32l(s): return u32l(s.read(4))


class Entry:
    def __init__(self, offset: int, size: int, checksum: bytes):
        self.offset = offset
        self.size = size
        self.checksum = checksum

    def __str__(self):
        return f"{self.__class__.__name__}(offset={self.offset}, size={self.size})"

class Archive:
    def __init__(self, filename: str, keytype: int = None, dev_signing_key: bool = False):
        self.filename = filename

        with open(self.filename, "rb") as f:
            self.s = BytesIO(f.read())


        # check magic bytes
        magic_bytes = read_u32b(self.s) & 0xffffff
        assert magic_bytes == 0xadbeef, f"bad magic bytes: {hex(magic_bytes)} (expected 0xadbeef)"
        
        # read header
        header_len = read_u32l(self.s)
        self.header = self.s.read(header_len)
        self.header_sig = self.s.read(0x40)

        # choose the keys
        if keytype:
            for keypair in KEYS["keypairs"]:
                if keytype in keypair.get("keytypes", []):
                    self.signing_key = bytes.fromhex(keypair["signing"])
                    self.master_key = bytes.fromhex(keypair["master"])
                    LOG.info(f"[+] using keys with keytype={keytype}")
                    break
        else:
            self.signing_key, self.master_key = self.find_keys(self.header, self.header_sig)
            LOG.info("[+] found matching keys")

        if dev_signing_key:
            self.signing_key = bytes.fromhex(KEYS["dev_signing_key"])
            LOG.debug("[+] using the dev signing key")

        LOG.debug(f"[+] signing key: {self.signing_key.hex()}")
        LOG.debug(f"[+] master key: {self.master_key.hex()}")


    def find_keys(self, buffer, buffer_sig):
        for keypair in KEYS["keypairs"]:
            signing_key = bytes.fromhex(keypair["signing"])
            master_key = bytes.fromhex(keypair["master"])

            try:
                pysodium.crypto_sign_verify_detached(buffer_sig, buffer, signing_key)
                return signing_key, master_key
            except:
                pass

        raise RuntimeError("keys not found")


    def decrypt_into(self, w):
        s = self.s

        # check header signature
        try:
            pysodium.crypto_sign_verify_detached(self.header_sig, self.header, self.signing_key)
        except:
            LOG.error("[-] error while checking the signature")
            raise

        LOG.info("[+] header signature verified")

        # unserialise the header
        mp = msgpack.unpackb(self.header)
        data, entries_info, info, serial_number, not_valid_before, *_ = mp
        LOG.info(f"[+] {len(entries_info)} entries")

        uuid = data[:0x20]
        ctx = data[0x18:0x18+7] + b"\x00"
        subkey_id = int.from_bytes(data[0x10:0x10+8], "little")

        # derive the decryption key
        self.kdf_subkey = pysodium.crypto_kdf_derive_from_key(0x20, subkey_id, ctx, self.master_key)
        LOG.debug(f"[+] decryption key: {self.kdf_subkey.hex()}")

        # get the offset of each entry using the content from the unserialised header
        self.entries = []
        for idx, (entry_len, checksum) in enumerate(entries_info):
            self.entries.append(Entry(s.tell(), entry_len, checksum))
            s.seek(entry_len, os.SEEK_CUR)

        # decrypt the entries
        for idx, entry in enumerate(self.entries):
            s.seek(entry.offset, os.SEEK_SET)

            state = pysodium.crypto_generichash_init()

            # read the content of the entry
            rem = entry.size
            while n := min(0x400000, rem):
                pysodium.crypto_generichash_update(state, s.read(n))
                rem -= n

            # compute and verify the hash of the entry
            h = pysodium.crypto_generichash_final(state)
            if entry.checksum != h:
                LOG.warning(f"[-] invalid hash for entry #{idx}")

            # go back to the beginning of the entry
            s.seek(entry.offset, os.SEEK_SET)
            cipher_header = s.read(0x18)
        
            # initiliase the cryptographic state
            state = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(cipher_header, self.kdf_subkey)

            # decrypt the entry header
            try:
                decrypted_entry_header, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state, s.read(0x193), None)
            except:
                LOG.error("[-] error while decrypting the entry header")
                raise

            decrypted_entry_header = decrypted_entry_header.ljust(TAR_BLOCK_SIZE, b"\x00")
            w.write(decrypted_entry_header)

            offset = TAR_BLOCK_SIZE
            size = entry.size - offset
            s.seek(entry.offset + offset, os.SEEK_SET)

            # create a tar entry header from the decrypted entry header
            tinfo = tarfile.TarInfo.frombuf(decrypted_entry_header, "ascii", "strict")

            # the size of the encrypted entry is the size specified in the tar entry header
            size = tinfo.size
            LOG.info(tinfo.name)

            try:
                # read the nonce
                cipher_header = s.read(0x18)
                state = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(cipher_header, self.kdf_subkey)

                # decrypt the content of the entry
                rem = size
                while (n := min(0x400000, rem)) > 0:
                    n += 17
                    m, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state, s.read(n), None)
                    w.write(m)

                    rem -= len(m)
            except Exception as e:
                LOG.error(f"[-] cannot decrypt entry #{idx}:", e)
                raise

            # complete the last block
            pad = TAR_BLOCK_SIZE - (w.tell() % TAR_BLOCK_SIZE)
            if pad % TAR_BLOCK_SIZE:
                w.write(bytes(pad))

        # write end of file (2 null blocks)
        w.write(bytes(TAR_BLOCK_SIZE*2))
        LOG.info("[+] archive successfully decrypted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("archive")
    parser.add_argument("-o", "--output", help='name of the decrypted archive, defaults to archive path with ".tar" suffix')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-k", "--keytype", help="force a specific keytype", type=int)
    parser.add_argument("-f", "--keyfile", help="path to the json containing the encryption keys")
    parser.add_argument("-d", "--dev-signing-key", help="use the dev signing key, must specify the keytype", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")


    if args.dev_signing_key and not args.keytype:
        raise Exception("Keytype not specified while using the dev signing key")

    if not args.keyfile:
        keyfile_path = Path(__file__).parent / "keys.json"
    else:
        keyfile_path = args.keyfile

    LOG.debug(f"[+] using keys from {keyfile_path}")
    with open(keyfile_path) as f:
        KEYS = json.loads(f.read())
    
    output = args.output
    if not output:
        archive_path = Path(args.archive)
        if archive_path.suffix == ".tar":
            raise ValueError("Please specify an output file")

        output = archive_path.with_suffix(".tar")

    archive = Archive(args.archive, keytype=args.keytype, dev_signing_key=args.dev_signing_key)
    with open(output, "wb") as f:
        archive.decrypt_into(f)

    LOG.info(f"[+] output at {output}")
