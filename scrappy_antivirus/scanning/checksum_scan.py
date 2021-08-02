from typing import Generator, Optional, Union

import re
import hashlib

from itertools import chain
from pathlib import Path

from scrappy_antivirus import ROOT_PATH
from scrappy_antivirus.constants import CONFIDENT
from scrappy_antivirus.scanning.checksums import Checksum, checksum
from scrappy_antivirus.scanning import Threat, get_files_to_scan


EXCLUDE = re.compile(r'C:\\\$Recycle\.Bin\\.*')


def get_zoo_checksums(path: Union[str, bytes, Path]=Path(f"{ROOT_PATH}/scrappy_antivirus/virus_data/signatures/scrapped/zoo_checksums.txt")) -> Generator[Checksum, None, None]:
    checksum_file = open(path, 'r')

    for raw_checksum in checksum_file:
        triple = raw_checksum.strip().split(';')
        checksum = Checksum(triple[0], triple[1], triple[2])

        yield checksum

    checksum_file.close()


def get_virusshare_checksums(path: Union[str, bytes, Path]=Path(f"{ROOT_PATH}/scrappy_antivirus/virus_data/signatures/scrapped/virusshare_unpacked_md5_hashes.txt")) -> Generator[Checksum, None, None]:
    checksum_file = open(path, 'r')

    for raw_checksum in checksum_file:
        pair = raw_checksum.strip().split('  ')
        checksum = Checksum("md5", pair[0], 'Unknown')

        yield checksum

    checksum_file.close()


def get_all_checksums() -> chain[Checksum]:
    all_checksums = chain(get_virusshare_checksums(), get_zoo_checksums())

    return all_checksums


def filter_checksums(checksum: Optional[str]=None, **kwargs) -> Optional[Checksum]:
    for chsum in get_all_checksums(**kwargs):
        if chsum.checksum == checksum:
            return chsum

    return None


def checksum_scan(start_from: Path=Path(r'C:\\'), **kwargs):
    for file in get_files_to_scan(start_from=start_from, exclude=EXCLUDE, **kwargs):
        sha1_checksum = checksum(file, hash_type=hashlib.sha1)
        sha256_checksum = checksum(file, hash_type=hashlib.sha256)

        if not sha1_checksum or not sha256_checksum:
            continue


        filtered_sha1 = filter_checksums(sha1_checksum)
        filtered_sha256 = filter_checksums(sha256_checksum)


        if filtered_sha1 is not None:
            yield Threat(confidence=CONFIDENT, location=file, name=filtered_sha1.threat_name)

        if filtered_sha256 is not None:
            yield Threat(confidence=CONFIDENT, location=file, name=filtered_sha256.threat_name)


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
