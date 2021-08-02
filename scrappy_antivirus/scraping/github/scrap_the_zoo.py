# https://github.com/ytisf/theZoo

from typing import Generator, Union

from bs4 import BeautifulSoup
from pathlib import Path

from scrappy_antivirus import ROOT_PATH
from scrappy_antivirus.scanning.checksums import Checksum
from scrappy_antivirus.scraping import grab_text_from_url

GITHUB_LINK = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries"
ZOO_CHECKSUMS = Path(f"{ROOT_PATH}/scrappy_antivirus/virus_data/signatures/scrapped/zoo_checksums.txt")


def grab_checksum_links() -> set[str]:
    all_links = set() # type: set[str]
    all_folders_html = grab_text_from_url(GITHUB_LINK)

    parser = BeautifulSoup(all_folders_html, features="html.parser")
    files_box = parser.select('#repo-content-pjax-container div[aria-labelledby="files"]')

    for file_div in files_box:
        anchors = file_div.find_all_next("a", {"class": "js-navigation-open Link--primary"})

        for anchor in anchors:
            all_links.add((f"https://raw.githubusercontent.com{anchor['href'].replace('/tree', '')}/{anchor['title']}", anchor['title']))

    return all_links


def grab_checksums(checksum_types: list[str]=["sha", "sha256"]) -> Generator[Checksum, None, None]:
    checksum_links = grab_checksum_links()

    for link in checksum_links:
        for checksum_type in checksum_types:
            checksum = grab_text_from_url(f"{link[0]}.{checksum_type}")

            if checksum:
                checksum = checksum.strip()

                if checksum_type == "sha" or checksum_type == "sha256":
                    patrition = checksum.partition('  ')

                    yield Checksum(checksum_type, patrition[0], link[1])
            
                else:
                    yield Checksum('unknown', checksum, 'Generic.Unknown')


def save_checksums(save_to: Union[str, bytes, Path]=ZOO_CHECKSUMS, **kwargs):
    with open(Path(f"{save_to}"), 'w') as checksum_file:
        for checksum in grab_checksums(**kwargs):
            checksum_file.write(f'{checksum.checksum_type};{checksum.checksum};{checksum.threat_name}\n')
            print(checksum)


if __name__ == "__main__":
    print(f"Writing checksum file to {ZOO_CHECKSUMS}...")
    save_checksums(ZOO_CHECKSUMS)
    print("Successfuly saved checksum file!")
