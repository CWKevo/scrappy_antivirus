from pathlib import Path
from peewee import *

from scrappy_antivirus import ROOT_PATH


DATABASE_PATH = Path(f"{ROOT_PATH}/scrappy_antivirus/database/database.sqlite")
database = SqliteDatabase(f"{DATABASE_PATH}")


class BaseModel(Model):
    class Meta:
        database = database


class Threat(BaseModel):
    type = CharField(max_length=20, null=True, default=None)
    name = CharField(null=True, default=None)


class Hash(BaseModel):
    threat = ForeignKeyField(Threat, backref='hashes', null=True, default=None)
    hash_type = CharField(max_length=10)
    checksum = CharField()


database.create_tables([Threat, Hash])

if __name__ == "__main__":
    import time
    TO_FIND = 'e5d4c1d746c193e655c51fc2b07e6aeb1bc8deb55eb894bc809fa5db2f4c4388'

    start = time.time()
    found = Hash.select().where(Hash.checksum == TO_FIND).get() # type: Hash

    if found:
        print(found.threat.name, found.checksum)
    
    end = time.time()
    owo = end - start
    print(f"Took {owo} seconds")
