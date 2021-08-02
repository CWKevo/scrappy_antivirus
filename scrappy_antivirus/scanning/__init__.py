from typing import Generator, Optional

import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Threat:
    confidence: int
    location: Path
    name: str = 'Generic.Unknown'


def get_files_to_scan(start_from: Path=Path('.'), pattern: str='*', match: Optional[re.Pattern]=None, exclude: Optional[re.Pattern]=None) -> Generator[Path, None, None]:
    for path in start_from.rglob(pattern):
        try:
            resolved = path.resolve()

        except PermissionError:
            continue


        if exclude:
            if exclude.match(f"{resolved}"):
                continue

        if match:
            if match.match(f"{resolved}"):
                yield resolved
            continue


        if resolved.exists():
            yield resolved


if __name__ == "__main__":
    print(Threat(confidence=0))

    exclude = re.compile(r'C:\\\$Recycle\.Bin\\.*')

    for path in get_files_to_scan(Path(r'C:\\'), exclude=exclude):
        print(path)
