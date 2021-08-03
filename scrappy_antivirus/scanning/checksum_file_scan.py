from typing import Optional

import re
import hashlib

from pathlib import Path
from peewee import DoesNotExist

from scrappy_antivirus import ROOT_PATH
from scrappy_antivirus.constants import CONFIDENT
from scrappy_antivirus.database import Hash
from scrappy_antivirus.scanning.checksums import checksum
from scrappy_antivirus.scanning import Threat, get_files_to_scan


EXCLUDE = re.compile(r'C:\\\$Recycle\.Bin\\.*')


def search_hash(checksum: Optional[str]=None,) -> Optional[Hash]:
    try:
        checksum = Hash.select().where(Hash.checksum == checksum).get() # type: Hash

    except DoesNotExist:
        checksum = None


    if checksum:
        return checksum


def checksum_scan(start_from: Path=Path(r'C:\\'), **kwargs):
    for file in get_files_to_scan(start_from=start_from, exclude=EXCLUDE, **kwargs):
        print(f"Checking {file}")

        sha1_checksum = checksum(file, hash_type=hashlib.sha1)
        sha256_checksum = checksum(file, hash_type=hashlib.sha256)

        if not sha1_checksum or not sha256_checksum:
            continue


        filtered_sha1 = search_hash(sha1_checksum)
        filtered_sha256 = search_hash(sha256_checksum)


        if filtered_sha1 is not None:
            yield Threat(confidence=CONFIDENT, location=file, name=filtered_sha1.threat.name)

        if filtered_sha256 is not None:
            yield Threat(confidence=CONFIDENT, location=file, name=filtered_sha256.threat.name)


        print(f"Checked {file}")


if __name__ == "__main__":
    LOOK_IN = [
        Path(r'C:\\ProgramFiles'),
        Path(r'C:\\Users\\Admin')
    ]

    with open(Path(f"{ROOT_PATH}/tests/found.txt"), 'w') as found:
        for look_in in LOOK_IN:
            for threat in checksum_scan(look_in, pattern='*.exe'):
                print("Found:", threat)
                found.write(threat.location)
