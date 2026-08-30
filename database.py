"""
Database abstraction layer for CYBERSICKER
Provides ORM-like interface for threat data persistence
"""

from typing import List, Optional, Dict, Any, Generic, TypeVar
from abc import ABC, abstractmethod
from datetime import datetime
import sqlite3
from pathlib import Path
import json

T = TypeVar('T')

class DatabaseConnection(ABC):
    """Abstract base for database connections"""
    
    @abstractmethod
    def execute(self, query: str, params: tuple = None) -> List[tuple]:
        pass
    
    @abstractmethod
    def execute_single(self, query: str, params: tuple = None) -> Optional[tuple]:
        pass
    
    @abstractmethod
    def insert(self, query: str, params: tuple) -> int:
        pass
    
    @abstractmethod
    def close(self):
        pass

class SQLiteConnection(DatabaseConnection):
    """SQLite database connection implementation"""
    
    def __init__(self, db_path: str = "cybersicker.db"):
        self.db_path = Path(db_path)
        self.connection = sqlite3.connect(str(self.db_path))
        self.connection.row_factory = sqlite3.Row
    
    def execute(self, query: str, params: tuple = None) -> List[tuple]:
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchall()
    
    def execute_single(self, query: str, params: tuple = None) -> Optional[tuple]:
        cursor = self.connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchone()
    
    def insert(self, query: str, params: tuple) -> int:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        self.connection.commit()
        return cursor.lastrowid
    
    def close(self):
        self.connection.close()

class BaseModel:
    """Base model for database entities"""
    
    table_name: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary"""
        return {
            key: value for key, value in self.__dict__.items()
            if not key.startswith('_')
        }
    
    def to_json(self) -> str:
        """Convert model to JSON"""
        return json.dumps(self.to_dict())

class ThreatIndicator(BaseModel):
    """Model for threat indicators"""
    
    table_name = "threat_indicators"
    
    def __init__(
        self,
        indicator: str,
        threat_type: str,
        severity: str,
        source: str,
        first_seen: datetime = None,
        id: Optional[int] = None
    ):
        self.id = id
        self.indicator = indicator
        self.threat_type = threat_type
        self.severity = severity
        self.source = source
        self.first_seen = first_seen or datetime.utcnow()
        self.last_seen = datetime.utcnow()

class NetworkScan(BaseModel):
    """Model for network scans"""
    
    table_name = "network_scans"
    
    def __init__(
        self,
        target: str,
        scan_type: str,
        status: str,
        results: Dict = None,
        timestamp: datetime = None,
        id: Optional[int] = None
    ):
        self.id = id
        self.target = target
        self.scan_type = scan_type
        self.status = status
        self.results = json.dumps(results or {})
        self.timestamp = timestamp or datetime.utcnow()

class Repository(Generic[T], ABC):
    """Generic repository pattern for data access"""
    
    def __init__(self, db_connection: DatabaseConnection, model_class: type):
        self.db = db_connection
        self.model_class = model_class
    
    @abstractmethod
    def create(self, model: T) -> int:
        pass
    
    @abstractmethod
    def read(self, id: int) -> Optional[T]:
        pass
    
    @abstractmethod
    def update(self, model: T) -> bool:
        pass
    
    @abstractmethod
    def delete(self, id: int) -> bool:
        pass
    
    @abstractmethod
    def list_all(self) -> List[T]:
        pass

class ThreatIndicatorRepository(Repository):
    """Repository for threat indicators"""
    
    def create(self, model: ThreatIndicator) -> int:
        query = """
            INSERT INTO threat_indicators 
            (indicator, threat_type, severity, source, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        params = (
            model.indicator,
            model.threat_type,
            model.severity,
            model.source,
            model.first_seen.isoformat(),
            model.last_seen.isoformat(),
        )
        return self.db.insert(query, params)
    
    def read(self, id: int) -> Optional[ThreatIndicator]:
        query = "SELECT * FROM threat_indicators WHERE id = ?"
        result = self.db.execute_single(query, (id,))
        if not result:
            return None
        
        return ThreatIndicator(
            indicator=result['indicator'],
            threat_type=result['threat_type'],
            severity=result['severity'],
            source=result['source'],
            first_seen=datetime.fromisoformat(result['first_seen']),
            id=result['id']
        )
    
    def update(self, model: ThreatIndicator) -> bool:
        query = """
            UPDATE threat_indicators 
            SET last_seen = ?, severity = ?
            WHERE id = ?
        """
        params = (model.last_seen.isoformat(), model.severity, model.id)
        self.db.insert(query, params)
        return True
    
    def delete(self, id: int) -> bool:
        query = "DELETE FROM threat_indicators WHERE id = ?"
        self.db.insert(query, (id,))
        return True
    
    def list_all(self) -> List[ThreatIndicator]:
        query = "SELECT * FROM threat_indicators ORDER BY first_seen DESC"
        results = self.db.execute(query)
        
        indicators = []
        for row in results:
            indicators.append(
                ThreatIndicator(
                    indicator=row['indicator'],
                    threat_type=row['threat_type'],
                    severity=row['severity'],
                    source=row['source'],
                    first_seen=datetime.fromisoformat(row['first_seen']),
                    id=row['id']
                )
            )
        return indicators
    
    def find_by_indicator(self, indicator: str) -> Optional[ThreatIndicator]:
        query = "SELECT * FROM threat_indicators WHERE indicator = ?"
        result = self.db.execute_single(query, (indicator,))
        if not result:
            return None
        
        return ThreatIndicator(
            indicator=result['indicator'],
            threat_type=result['threat_type'],
            severity=result['severity'],
            source=result['source'],
            first_seen=datetime.fromisoformat(result['first_seen']),
            id=result['id']
        )
    
    def find_by_severity(self, severity: str) -> List[ThreatIndicator]:
        query = "SELECT * FROM threat_indicators WHERE severity = ? ORDER BY first_seen DESC"
        results = self.db.execute(query, (severity,))
        
        indicators = []
        for row in results:
            indicators.append(
                ThreatIndicator(
                    indicator=row['indicator'],
                    threat_type=row['threat_type'],
                    severity=row['severity'],
                    source=row['source'],
                    first_seen=datetime.fromisoformat(row['first_seen']),
                    id=row['id']
                )
            )
        return indicators

class DatabaseMigrations:
    """Handle database schema migrations"""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def initialize_schema(self):
        """Create initial database schema"""
        # Create threat_indicators table
        self.db.insert("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """, ())
        
        # Create network_scans table
        self.db.insert("""
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT,
                timestamp TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """, ())
        
        # Create indices
        self.db.insert(
            "CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_indicators(severity)",
            ()
        )
        self.db.insert(
            "CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_indicators(threat_type)",
            ()
        )
        self.db.insert(
            "CREATE INDEX IF NOT EXISTS idx_scan_status ON network_scans(status)",
            ()
        )

class DatabaseService:
    """High-level database service"""
    
    def __init__(self, db_path: str = "cybersicker.db"):
        self.connection = SQLiteConnection(db_path)
        self.threat_repository = ThreatIndicatorRepository(self.connection, ThreatIndicator)
        
        # Initialize schema
        migrations = DatabaseMigrations(self.connection)
        migrations.initialize_schema()
    
    def close(self):
        """Close database connection"""
        self.connection.close()
