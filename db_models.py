from sqlalchemy import Column, Integer, String, Text, Float, SmallInteger, DateTime, Enum, ForeignKey
from datetime import datetime
from database import Base


class Engagement(Base):
    __tablename__ = "ii_apibom_engagement"

    Id                    = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementName        = Column(String(255), nullable=False)
    ClientName            = Column(String(255), nullable=False)
    Mode                  = Column(Enum("passive", "active"), default="passive")
    StartedAt             = Column(DateTime)
    CompletedAt           = Column(DateTime)
    OverallRisk           = Column(String(50), default="UNKNOWN")
    Narrative             = Column(Text)
    TotalApis             = Column(Integer, default=0)
    InboundApiCount       = Column(Integer, default=0)
    OutboundApiCount      = Column(Integer, default=0)
    OutboundExternalCount = Column(Integer, default=0)
    OutboundInternalCount = Column(Integer, default=0)
    ValidCount            = Column(Integer, default=0)
    ShadowCount           = Column(Integer, default=0)
    NewCount              = Column(Integer, default=0)
    RogueCount            = Column(Integer, default=0)
    UnclassifiedCount     = Column(Integer, default=0)
    SecretsCount          = Column(Integer, default=0)
    OWASPFindingsTotal    = Column(Integer, default=0)
    InferredOWASPFindings = Column(Integer, default=0)
    LiveOWASPFindings     = Column(Integer, default=0)
    CVEFindingsTotal      = Column(Integer, default=0)
    HighCriticalRiskCount = Column(Integer, default=0)
    EndpointsWithoutAuth  = Column(Integer, default=0)
    ExternalIntegrations  = Column(Integer, default=0)
    SensitivityCritical   = Column(Integer, default=0)
    SensitivityHigh       = Column(Integer, default=0)
    SensitivityMedium     = Column(Integer, default=0)
    SensitivityLow        = Column(Integer, default=0)
    SensitivityUnknown    = Column(Integer, default=0)
    TechStackRuntime      = Column(String(100))
    TechStackLanguage     = Column(String(100))
    TechStackFramework    = Column(String(100))
    TechStackFrontend     = Column(String(100))
    CreatedDate           = Column(DateTime, default=datetime.utcnow)
    UpdatedDate           = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive              = Column(SmallInteger, default=1)


class ApiEndpoint(Base):
    __tablename__ = "ii_apibom_endpoint"

    Id                = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId      = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    ApiDirection      = Column(String(20), default="inbound")
    EndpointUrl       = Column(Text, nullable=False)
    HttpMethod        = Column(String(20), default="UNKNOWN")
    Classification    = Column(String(50), default="UNCLASSIFIED")
    RiskScore         = Column(Integer, default=0)
    RiskBand          = Column(String(20), default="LOW")
    AuthType          = Column(String(100))
    DataSensitivity   = Column(String(20), default="UNKNOWN")
    Exposure          = Column(String(50))
    Environment       = Column(String(100))
    FunctionalModule  = Column(String(200))
    FunctionalType    = Column(String(100))
    ApiVersion        = Column(String(20))
    TechStack         = Column(String(100))
    InferredOwner     = Column(String(200))
    Owner             = Column(String(200))
    BaselineStatus    = Column(String(100))
    StatusCode        = Column(Integer)
    ContentType       = Column(String(100))
    ResponseSizeBytes = Column(Integer)
    Remediation       = Column(Text)
    SourceFile        = Column(Text)
    FirstSeen         = Column(DateTime)
    LastSeen          = Column(DateTime)
    CreatedDate       = Column(DateTime, default=datetime.utcnow)
    UpdatedDate       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive          = Column(SmallInteger, default=1)


class Discovery_Source(Base):
    __tablename__ = "ii_apibom_discovery_source"

    Id           = Column("Id", Integer, primary_key=True, autoincrement=True)
    EndpointId   = Column(Integer, ForeignKey("ii_apibom_endpoint.Id"), nullable=False)
    EngagementId = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    SourceName   = Column(String(100), nullable=False)
    CreatedDate  = Column(DateTime, default=datetime.utcnow)
    UpdatedDate  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=1)


class OWASP_Finding(Base):
    __tablename__ = "ii_apibom_owasp_finding"

    Id           = Column("Id", Integer, primary_key=True, autoincrement=True)
    EndpointId   = Column(Integer, ForeignKey("ii_apibom_endpoint.Id"))
    EngagementId = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    Category     = Column(String(20))
    CategoryName = Column(String(200))
    Finding      = Column(Text)
    Severity     = Column(String(20), default="INFO")
    Source       = Column(String(50))
    Remediation  = Column(Text)
    EndpointUrl  = Column(Text)
    CreatedDate  = Column(DateTime, default=datetime.utcnow)
    UpdatedDate  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=1)


class OWASP_Conformance(Base):
    __tablename__ = "ii_apibom_owasp_conformance"

    Id               = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId     = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    OWASPId          = Column(String(10))
    Name             = Column(String(200))
    Status           = Column(String(50))
    AffectedCount    = Column(Integer, default=0)
    Note             = Column(Text)
    ConformanceLevel = Column(String(100))
    CreatedDate      = Column(DateTime, default=datetime.utcnow)
    UpdatedDate      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive         = Column(SmallInteger, default=1)


class Secret_Finding(Base):
    __tablename__ = "ii_apibom_secret_finding"

    Id             = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    SecretType     = Column(String(100))
    FilePath       = Column(Text)
    LineNumber     = Column(Integer)
    Repo           = Column(Text)
    MatchPreview   = Column(String(200))
    Severity       = Column(String(20), default="CRITICAL")
    Recommendation = Column(Text)
    CreatedDate    = Column(DateTime, default=datetime.utcnow)
    UpdatedDate    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=1)


class Outbound_Api(Base):
    __tablename__ = "ii_apibom_outboundapi"

    Id             = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    Url            = Column(Text)
    Host           = Column(String(255))
    PathPrefix     = Column(String(255))
    HttpMethod     = Column(String(20), default="UNKNOWN")
    Integration    = Column(String(200))
    Category       = Column(String(100))
    Exposure       = Column(String(20), default="External")
    Risk           = Column(String(20), default="MEDIUM")
    AuthMethod     = Column(String(100))
    SourceFiles    = Column(Text)
    LineNumber     = Column(Integer)
    Repo           = Column(Text)
    OWASPReference = Column(String(100))
    Recommendation = Column(Text)
    CreatedDate    = Column(DateTime, default=datetime.utcnow)
    UpdatedDate    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=1)


class Package_Dependency(Base):
    __tablename__ = "ii_apibom_package_dependency"

    Id           = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    Name         = Column(String(255))
    Version      = Column(String(100))
    Type         = Column(String(100))
    Ecosystem    = Column(String(100))
    CreatedDate  = Column(DateTime, default=datetime.utcnow)
    UpdatedDate  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=1)


class CVE_Finding(Base):
    __tablename__ = "ii_apibom_cve_finding"

    Id            = Column("Id", Integer, primary_key=True, autoincrement=True)
    EndpointId    = Column(Integer, ForeignKey("ii_apibom_endpoint.Id"))
    EngagementId  = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    CVENumber     = Column(String(50))
    Description   = Column(Text)
    Severity      = Column(String(50))
    CVSS          = Column(Float)
    EndpointCount = Column(Integer, default=0)
    CreatedDate   = Column(DateTime, default=datetime.utcnow)
    UpdatedDate   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive      = Column(SmallInteger, default=1)


class Shadow_Rogue_Register(Base):
    __tablename__ = "ii_apibom_shadow_rogue_register"

    Id             = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    EndpointId     = Column(Integer, ForeignKey("ii_apibom_endpoint.Id"), nullable=False)
    Classification = Column(String(50), nullable=False)
    RiskScore      = Column(Integer, default=0)
    ActionRequired = Column(Text)
    CreatedDate    = Column(DateTime, default=datetime.utcnow)
    UpdatedDate    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=1)


class Scan_Phase_Log(Base):
    __tablename__ = "ii_apibom_scan_phase_log"

    Id             = Column("Id", Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("ii_apibom_engagement.Id"), nullable=False)
    PhaseNumber    = Column(Integer)
    PhaseName      = Column(String(100))
    Status         = Column(String(50), default="completed")
    StartedAt      = Column(DateTime)
    CompletedAt    = Column(DateTime)
    EndpointsFound = Column(Integer, default=0)
    Notes          = Column(Text)
    CreatedDate    = Column(DateTime, default=datetime.utcnow)
    UpdatedDate    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=1)