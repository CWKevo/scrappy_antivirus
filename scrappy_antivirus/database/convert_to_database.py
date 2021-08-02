from scrappy_antivirus.scanning.checksum_from_file_scan import get_all_checksums
from scrappy_antivirus.database import Hash, Threat


def add_all_checksums_to_database():
    for checksum in get_all_checksums():
        db_threat = Threat.create(type=None, name=checksum.threat_name)
        db_checksum = Hash.create(threat=db_threat, hash_type=checksum.checksum_type, checksum=checksum.checksum)

        print("Added", db_threat.name, db_checksum.checksum)


if __name__ == "__main__":
    add_all_checksums_to_database()
