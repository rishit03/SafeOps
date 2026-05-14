from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.database import Base

class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, default="Default Account")
    provider = Column(String, default="aws")
    aws_account_id = Column(String, nullable=True)
    aws_region = Column(String, default="us-east-1")
    role_arn = Column(String, nullable=True)
    is_default = Column(Boolean, default=True)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("Scan", back_populates="cloud_account")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    cloud_account_id = Column(Integer, ForeignKey("cloud_accounts.id"))

    asset_id = Column(String, nullable=True)
    asset_type = Column(String)
    name = Column(String)
    raw = Column(JSON)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    cloud_account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=True)
    profile = Column(String, default="default")
    risk_score = Column(Integer, default=0)
    risk_level = Column(String, default="Low")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    cloud_account = relationship("CloudAccount", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))

    fingerprint = Column(String, index=True)
    title = Column(String)
    severity = Column(String)
    status = Column(String)
    module = Column(String)
    remediation_priority = Column(String)
    raw = Column(JSON)

    scan = relationship("Scan", back_populates="findings")
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    asset = relationship("Asset")

class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    details = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class WorkspaceSettings(Base):
    __tablename__ = "workspace_settings"

    id = Column(Integer, primary_key=True, index=True)
    aws_region = Column(String, default="us-east-1")
    role_arn = Column(String, nullable=True)
    slack_webhook_url = Column(String, nullable=True)
    scan_frequency_minutes = Column(Integer, default=60)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    aws_connected = Column(Boolean, default=False)

class FixHistory(Base):
    __tablename__ = "fix_history"

    id = Column(Integer, primary_key=True, index=True)

    issue_id = Column(String)
    title = Column(String)
    severity = Column(String)

    status = Column(String)  # success / failed
    message = Column(String)

    before_risk_score = Column(Integer)
    after_risk_score = Column(Integer)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"

    id = Column(Integer, primary_key=True)
    from_asset_id = Column(Integer, ForeignKey("assets.id"))
    to_asset_id = Column(Integer, ForeignKey("assets.id"))

    relation_type = Column(String)  # e.g. "can_assume", "exposes", "connects_to"