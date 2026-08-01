from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from db import Base


class Scan(Base):

    __tablename__ = "scans"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    url = Column(
        String,
        nullable=False
    )

    risk_score = Column(
        Integer
    )

    label = Column(
        String
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )