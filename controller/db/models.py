import uuid
import logging
from pydantic import BaseModel, Field
from typing import Self, Optional, List
from enum import IntEnum
from ipaddress import IPv4Address

from controller.db.database import DatabaseHandler

logger = logging.getLogger(__name__)


class BaseObject(BaseModel):
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def save(self, db: DatabaseHandler) -> Self:
        db.mock_db[self.uid] = self  # почти ORM
        return self

    def delete_by_id(_id: str, db: DatabaseHandler) -> Self:
        logger.debug(f"deleting {_id}, {db.mock_db}")
        return db.mock_db.pop(_id, None)

    def get_by_id(db: DatabaseHandler, _id: str) -> Optional[Self]:
        return db.mock_db[_id] if _id in db.mock_db else None

    def get_all(db: DatabaseHandler) -> List[Self]:
        return list(db.mock_db.values())


class Protocol(IntEnum):
    tcp = 6
    udp = 17
    icmp = 1
    ip = 0


class BalanceAlgroithm(IntEnum):
    round_robin = 0  # NX_GROUP_SELECT_ROUND_ROBIN
    hash = 1   # NX_GROUP_SELECT_HASH


class BalanceRule(BaseObject):
    protocol: Protocol
    port: Optional[int] = None
    virtual_ip: IPv4Address
    backend_ip: List[IPv4Address]
    algorithm: BalanceAlgroithm
