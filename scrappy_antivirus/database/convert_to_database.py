from typing import Generator, Union

from pathlib import Path
from itertools import chain

from scrappy_antivirus import ROOT_PATH
from scrappy_antivirus.scanning.checksums import Checksum,
from scrappy_antivirus.database import Hash, Threat


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


def add_all_checksums_to_database():
    for i, checksum in enumerate(get_all_checksums()):
        db_threat = Threat.create(type=None, name=checksum.threat_name)
        db_checksum = Hash.create(threat=db_threat, hash_type=checksum.checksum_type, checksum=checksum.checksum)

        print(f"{i}. added:", db_threat.name, db_checksum.checksum)


if __name__ == "__main__":
    add_all_checksums_to_database()
