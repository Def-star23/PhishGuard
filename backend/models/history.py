from sqlalchemy import Column, Integer, String, JSON
from db import Base


class ScanHistory(Base):

    __tablename__ = "scan_history"


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


    analysis = Column(
        JSON
    )


    explanation = Column(
        String
    )