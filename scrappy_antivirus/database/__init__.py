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
