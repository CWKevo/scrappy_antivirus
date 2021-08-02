from typing import Callable, Union, Optional

import hashlib
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Checksum:
    checksum_type: str
    checksum: str
    threat_name: Optional[str] = None


def checksum(file_path: Union[str, bytes, Path], hash_type: Callable[..., 'hashlib._Hash']=hashlib.sha256, chunk_size: int=65536):
    hash = hash_type()

    try:
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(chunk_size)

                if not data:
                    break

                hash.update(data)
    
    except PermissionError:
        return None

    return hash.hexdigest()



if __name__ == "__main__":
    chsum = checksum(r'C:\Users\Admin\Documents\Programming\crappy-antivirus\scrappy_antivirus\virus_data\signatures\zoo-checksums.txt', hashlib.md5)

    print(chsum)
