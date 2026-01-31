#!/usr/bin/env python3
"""
SHADOW - SQLite Data Layer

كل شي بيتخزن هون. لا files منفصلة.
"""

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Asset:
    """Host/Subdomain"""
    id: int = None
    domain: str = ""
    ip: str = ""
    source: str = ""
    first_seen: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class Service:
    """HTTP/Port service"""
    id: int = None
    asset_id: int = None
    port: int = 443
    protocol: str = "https"
    status_code: int = 0
    title: str = ""
    technology: str = ""
    server: str = ""
    content_length: int = 0
    redirect_url: str = ""


@dataclass
class Endpoint:
    """URL with params"""
    id: int = None
    service_id: int = None
    path: str = ""
    method: str = "GET"
    params: Dict[str, str] = None
    content_type: str = ""
    interesting_score: int = 0
    tags: List[str] = None

    def __post_init__(self):
        if self.params is None:
            self.params = {}
        if self.tags is None:
            self.tags = []


@dataclass
class Finding:
    """Vulnerability or interesting observation"""
    id: int = None
    endpoint_id: int = None
    finding_type: str = ""  # xss, sqli, ssrf, info, etc
    severity: str = "info"  # info, low, medium, high, critical
    title: str = ""
    evidence: str = ""
    confirmed: bool = False
    false_positive: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

class Database:
    """SQLite database for all recon data"""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        ip TEXT,
        source TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        tags TEXT DEFAULT '[]',
        UNIQUE(domain)
    );
    
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        port INTEGER DEFAULT 443,
        protocol TEXT DEFAULT 'https',
        status_code INTEGER,
        title TEXT,
        technology TEXT,
        server TEXT,
        content_length INTEGER,
        redirect_url TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id),
        UNIQUE(asset_id, port, protocol)
    );
    
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        method TEXT DEFAULT 'GET',
        params TEXT DEFAULT '{}',
        content_type TEXT,
        interesting_score INTEGER DEFAULT 0,
        tags TEXT DEFAULT '[]',
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (service_id) REFERENCES services(id),
        UNIQUE(service_id, path, method)
    );
    
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id INTEGER,
        finding_type TEXT NOT NULL,
        severity TEXT DEFAULT 'info',
        title TEXT,
        evidence TEXT,
        confirmed BOOLEAN DEFAULT 0,
        false_positive BOOLEAN DEFAULT 0,
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
    );
    
    CREATE INDEX IF NOT EXISTS idx_assets_domain ON assets(domain);
    CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id);
    CREATE INDEX IF NOT EXISTS idx_endpoints_service ON endpoints(service_id);
    CREATE INDEX IF NOT EXISTS idx_endpoints_score ON endpoints(interesting_score DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Create tables if not exist"""
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ─────────────────────────────────────────────────────────────────────────
    # ASSETS
    # ─────────────────────────────────────────────────────────────────────────

    def add_asset(self, domain: str, ip: str = "", source: str = "",
                  tags: List[str] = None) -> int:
        """Add or update an asset, return its ID"""
        tags = tags or []
        try:
            cur = self.conn.execute(
                """INSERT INTO assets (domain, ip, source, tags) 
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(domain) DO UPDATE SET
                   ip = COALESCE(NULLIF(excluded.ip, ''), assets.ip),
                   source = assets.source || ',' || excluded.source
                   RETURNING id""",
                (domain, ip, source, json.dumps(tags))
            )
            row = cur.fetchone()
            self.conn.commit()
            return row[0]
        except Exception:
            # If RETURNING not supported, query separately
            self.conn.execute(
                """INSERT OR IGNORE INTO assets (domain, ip, source, tags) 
                   VALUES (?, ?, ?, ?)""",
                (domain, ip, source, json.dumps(tags))
            )
            self.conn.commit()
            cur = self.conn.execute(
                "SELECT id FROM assets WHERE domain = ?", (domain,)
            )
            return cur.fetchone()[0]

    def add_assets_bulk(self, assets: List[Dict]) -> int:
        """Bulk insert assets. Returns count added."""
        count = 0
        for asset in assets:
            try:
                self.conn.execute(
                    """INSERT OR IGNORE INTO assets (domain, ip, source, tags) 
                       VALUES (?, ?, ?, ?)""",
                    (asset.get('domain', ''),
                     asset.get('ip', ''),
                     asset.get('source', ''),
                     json.dumps(asset.get('tags', [])))
                )
                count += 1
            except:
                pass
        self.conn.commit()
        return count

    def get_asset(self, domain: str) -> Optional[Asset]:
        """Get asset by domain"""
        cur = self.conn.execute(
            "SELECT * FROM assets WHERE domain = ?", (domain,)
        )
        row = cur.fetchone()
        if row:
            return Asset(
                id=row['id'],
                domain=row['domain'],
                ip=row['ip'] or "",
                source=row['source'] or "",
                first_seen=row['first_seen'],
                tags=json.loads(row['tags'] or '[]')
            )
        return None

    def get_assets(self, limit: int = 1000) -> List[Asset]:
        """Get all assets"""
        cur = self.conn.execute(
            "SELECT * FROM assets ORDER BY first_seen DESC LIMIT ?", (limit,)
        )
        return [Asset(
            id=row['id'],
            domain=row['domain'],
            ip=row['ip'] or "",
            source=row['source'] or "",
            first_seen=row['first_seen'],
            tags=json.loads(row['tags'] or '[]')
        ) for row in cur.fetchall()]

    def count_assets(self) -> int:
        cur = self.conn.execute("SELECT COUNT(*) FROM assets")
        return cur.fetchone()[0]

    # ─────────────────────────────────────────────────────────────────────────
    # SERVICES
    # ─────────────────────────────────────────────────────────────────────────

    def add_service(self, asset_id: int, port: int = 443, protocol: str = "https",
                    status_code: int = 0, title: str = "", technology: str = "",
                    server: str = "", content_length: int = 0,
                    redirect_url: str = "") -> int:
        """Add or update a service"""
        try:
            self.conn.execute(
                """INSERT INTO services 
                   (asset_id, port, protocol, status_code, title, technology, 
                    server, content_length, redirect_url)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
                   status_code = excluded.status_code,
                   title = excluded.title,
                   technology = COALESCE(excluded.technology, services.technology),
                   server = COALESCE(excluded.server, services.server)""",
                (asset_id, port, protocol, status_code, title, technology,
                 server, content_length, redirect_url)
            )
            self.conn.commit()
            cur = self.conn.execute(
                """SELECT id FROM services 
                   WHERE asset_id = ? AND port = ? AND protocol = ?""",
                (asset_id, port, protocol)
            )
            return cur.fetchone()[0]
        except Exception:
            return -1

    def get_services(self, asset_id: int = None, alive_only: bool = False) -> List[Service]:
        """Get services, optionally filtered"""
        query = "SELECT * FROM services WHERE 1=1"
        params = []

        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)

        if alive_only:
            query += " AND status_code > 0 AND status_code < 500"

        cur = self.conn.execute(query, params)
        return [Service(
            id=row['id'],
            asset_id=row['asset_id'],
            port=row['port'],
            protocol=row['protocol'],
            status_code=row['status_code'] or 0,
            title=row['title'] or "",
            technology=row['technology'] or "",
            server=row['server'] or "",
            content_length=row['content_length'] or 0,
            redirect_url=row['redirect_url'] or ""
        ) for row in cur.fetchall()]

    def count_services(self, alive_only: bool = False) -> int:
        if alive_only:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM services WHERE status_code > 0 AND status_code < 500"
            )
        else:
            cur = self.conn.execute("SELECT COUNT(*) FROM services")
        return cur.fetchone()[0]

    # ─────────────────────────────────────────────────────────────────────────
    # ENDPOINTS
    # ─────────────────────────────────────────────────────────────────────────

    def add_endpoint(self, service_id: int, path: str, method: str = "GET",
                     params: Dict = None, content_type: str = "",
                     interesting_score: int = 0, tags: List[str] = None) -> int:
        """Add or update an endpoint"""
        params = params or {}
        tags = tags or []

        try:
            self.conn.execute(
                """INSERT INTO endpoints 
                   (service_id, path, method, params, content_type, interesting_score, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(service_id, path, method) DO UPDATE SET
                   params = excluded.params,
                   interesting_score = MAX(endpoints.interesting_score, excluded.interesting_score)""",
                (service_id, path, method, json.dumps(params), content_type,
                 interesting_score, json.dumps(tags))
            )
            self.conn.commit()
            cur = self.conn.execute(
                """SELECT id FROM endpoints 
                   WHERE service_id = ? AND path = ? AND method = ?""",
                (service_id, path, method)
            )
            return cur.fetchone()[0]
        except:
            return -1

    def get_endpoints(self, service_id: int = None, min_score: int = 0,
                      limit: int = 1000) -> List[Endpoint]:
        """Get endpoints with optional filters"""
        query = "SELECT * FROM endpoints WHERE interesting_score >= ?"
        params = [min_score]

        if service_id:
            query += " AND service_id = ?"
            params.append(service_id)

        query += " ORDER BY interesting_score DESC LIMIT ?"
        params.append(limit)

        cur = self.conn.execute(query, params)
        return [Endpoint(
            id=row['id'],
            service_id=row['service_id'],
            path=row['path'],
            method=row['method'],
            params=json.loads(row['params'] or '{}'),
            content_type=row['content_type'] or "",
            interesting_score=row['interesting_score'] or 0,
            tags=json.loads(row['tags'] or '[]')
        ) for row in cur.fetchall()]

    def count_endpoints(self, min_score: int = 0) -> int:
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM endpoints WHERE interesting_score >= ?",
            (min_score,)
        )
        return cur.fetchone()[0]

    # ─────────────────────────────────────────────────────────────────────────
    # FINDINGS
    # ─────────────────────────────────────────────────────────────────────────

    def add_finding(self, endpoint_id: int, finding_type: str, severity: str = "info",
                    title: str = "", evidence: str = "", confirmed: bool = False) -> int:
        """Add a finding"""
        cur = self.conn.execute(
            """INSERT INTO findings 
               (endpoint_id, finding_type, severity, title, evidence, confirmed)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (endpoint_id, finding_type, severity, title, evidence, confirmed)
        )
        self.conn.commit()
        return cur.lastrowid

    def get_findings(self, severity: str = None, confirmed_only: bool = False,
                     exclude_fp: bool = True) -> List[Finding]:
        """Get findings with filters"""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if confirmed_only:
            query += " AND confirmed = 1"

        if exclude_fp:
            query += " AND false_positive = 0"

        query += " ORDER BY CASE severity "
        query += "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        query += "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"

        cur = self.conn.execute(query, params)
        return [Finding(
            id=row['id'],
            endpoint_id=row['endpoint_id'],
            finding_type=row['finding_type'],
            severity=row['severity'],
            title=row['title'] or "",
            evidence=row['evidence'] or "",
            confirmed=bool(row['confirmed']),
            false_positive=bool(row['false_positive'])
        ) for row in cur.fetchall()]

    def count_findings(self, severity: str = None) -> int:
        if severity:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = ? AND false_positive = 0",
                (severity,)
            )
        else:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM findings WHERE false_positive = 0"
            )
        return cur.fetchone()[0]

    # ─────────────────────────────────────────────────────────────────────────
    # QUERIES
    # ─────────────────────────────────────────────────────────────────────────

    def get_top_targets(self, limit: int = 20) -> List[Dict]:
        """Get top interesting targets with full context"""
        cur = self.conn.execute("""
            SELECT 
                a.domain,
                s.port,
                s.protocol,
                s.title,
                s.technology,
                e.path,
                e.params,
                e.interesting_score,
                e.tags,
                GROUP_CONCAT(DISTINCT f.finding_type) as finding_types,
                COUNT(f.id) as finding_count
            FROM endpoints e
            JOIN services s ON e.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            LEFT JOIN findings f ON f.endpoint_id = e.id AND f.false_positive = 0
            WHERE e.interesting_score > 0
            GROUP BY e.id
            ORDER BY e.interesting_score DESC, finding_count DESC
            LIMIT ?
        """, (limit,))

        results = []
        for row in cur.fetchall():
            results.append({
                'domain': row['domain'],
                'url': f"{row['protocol']}://{row['domain']}:{row['port']}{row['path']}",
                'title': row['title'] or "",
                'technology': row['technology'] or "",
                'params': json.loads(row['params'] or '{}'),
                'score': row['interesting_score'],
                'tags': json.loads(row['tags'] or '[]'),
                'findings': row['finding_types'].split(',') if row['finding_types'] else [],
                'finding_count': row['finding_count']
            })

        return results

    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'assets': self.count_assets(),
            'services': self.count_services(),
            'services_alive': self.count_services(alive_only=True),
            'endpoints': self.count_endpoints(),
            'endpoints_interesting': self.count_endpoints(min_score=5),
            'findings': self.count_findings(),
            'findings_high': self.count_findings('high'),
            'findings_critical': self.count_findings('critical')
        }

    def export_urls(self, min_score: int = 0) -> List[str]:
        """Export all URLs for external tools"""
        cur = self.conn.execute("""
            SELECT s.protocol, a.domain, s.port, e.path
            FROM endpoints e
            JOIN services s ON e.service_id = s.id
            JOIN assets a ON s.asset_id = a.id
            WHERE e.interesting_score >= ?
            ORDER BY e.interesting_score DESC
        """, (min_score,))

        urls = []
        for row in cur.fetchall():
            port = row['port']
            protocol = row['protocol']
            # Skip default ports in URL
            if (protocol == 'https' and port == 443) or (protocol == 'http' and port == 80):
                url = f"{protocol}://{row['domain']}{row['path']}"
            else:
                url = f"{protocol}://{row['domain']}:{port}{row['path']}"
            urls.append(url)

        return urls
