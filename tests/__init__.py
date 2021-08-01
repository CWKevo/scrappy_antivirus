import sys
from pathlib import Path

ROOT_PATH = Path(__file__).parent.parent.absolute()


def normalize_path():
    sys.path.append(ROOT_PATH)


if __name__ == "__main__":
    normalize_path()
