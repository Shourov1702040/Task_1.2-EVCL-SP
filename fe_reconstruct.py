import subprocess
import binascii, blake3
from pathlib import Path
from typing import Optional


def read_puf_response(cmd: str = "read_puf_response") -> str:

    out = subprocess.check_output(cmd, shell=True, text=True)
    return out.strip()

def fe_reconstruct_key(puf_raw: str, helper_path: str = "helper.dat",
                       fe_script: str = "fe_reconstruct.py") -> bytes:
    helper = Path(helper_path)
    if not helper.exists():
        raise FileNotFoundError(f"Missing helper data file: {helper_path}")

    # Run the FE reconstruction script
    proc = subprocess.run(
        ["python", fe_script, puf_raw, str(helper)],
        check=True,
        capture_output=True,
        text=True
    )
    key_str = proc.stdout.strip()
    try:
        return binascii.unhexlify(key_str)
    except Exception:
        return key_str.encode("utf-8")

def get_puf_derived_device_key(helper_path: str = "helper.dat",
                              read_cmd: str = "read_puf_response",
                              fe_script: str = "fe_reconstruct.py") -> bytes:
    puf_raw = read_puf_response(read_cmd)
    stable_key = fe_reconstruct_key(puf_raw, helper_path=helper_path, fe_script=fe_script)
    return stable_key


#To avoid hardware releted unexpected errors and simplicity, we are loading the PUF-derived key from the helper.dat file 


def derive_es_key(es_id: str, out_len: int = 32) -> str:

    dat_path = r"helper.dat"
    secret = Path(dat_path).read_bytes() 

    ctx = b"EVCL-PUF-DERIVE-v1"

    h = blake3.blake3(ctx)
    h.update(secret)
    h.update(b"|")
    h.update(es_id.encode("utf-8"))

    return h.digest(length=out_len).hex()

# print(derive_es_key("ES_01",))


