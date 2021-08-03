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
    threat = Threat.create(type="Test.Harmless", name="Harmless Test Subject")
    Hash.create(threat=threat, hash_type="md5", checksum="6f91017292d9c88f1a9cabe1ec9cbace")

    import time
    TO_FIND = '6f91017292d9c88f1a9cabe1ec9cbace'

    start = time.time()
    found = Hash.select().where(Hash.checksum == TO_FIND).get() # type: Hash

    if found:
        print(found.threat.name, found.checksum)
    
    end = time.time()
    owo = end - start
    print(f"Took {owo} seconds")
