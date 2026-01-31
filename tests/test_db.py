#!/usr/bin/env python3
"""
SHADOW - Database Tests

Tests for SQLite data layer operations.
"""

from core.db import Asset, Service


class TestDatabaseInit:
    """Tests for database initialization"""

    def test_create_database(self, temp_db):
        """Test database creation"""
        assert temp_db.conn is not None
        assert temp_db.db_path.exists()

    def test_schema_created(self, temp_db):
        """Test that schema tables are created"""
        tables = ['assets', 'services', 'endpoints', 'findings']

        for table in tables:
            cur = temp_db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,)
            )
            assert cur.fetchone() is not None, f"Table '{table}' should exist"

    def test_indexes_created(self, temp_db):
        """Test that indexes are created"""
        indexes = [
            'idx_assets_domain',
            'idx_services_asset',
            'idx_endpoints_service',
            'idx_endpoints_score',
            'idx_findings_severity'
        ]

        for idx in indexes:
            cur = temp_db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
                (idx,)
            )
            assert cur.fetchone() is not None, f"Index '{idx}' should exist"


class TestAssets:
    """Tests for asset operations"""

    def test_add_asset(self, temp_db):
        """Test adding an asset"""
        asset_id = temp_db.add_asset(
            domain="test.example.com",
            ip="192.168.1.1",
            source="subfinder",
            tags=["test"]
        )

        assert asset_id > 0

    def test_add_asset_duplicate(self, temp_db):
        """Test adding duplicate asset updates instead of duplicating"""
        id1 = temp_db.add_asset(domain="test.example.com", source="subfinder")
        id2 = temp_db.add_asset(domain="test.example.com", source="amass")

        # Should return same ID
        assert id1 == id2

        # Source should be updated
        asset = temp_db.get_asset("test.example.com")
        assert "subfinder" in asset.source

    def test_get_asset(self, temp_db):
        """Test getting an asset by domain"""
        temp_db.add_asset(
            domain="test.example.com",
            ip="192.168.1.1",
            source="test"
        )

        asset = temp_db.get_asset("test.example.com")

        assert asset is not None
        assert isinstance(asset, Asset)
        assert asset.domain == "test.example.com"
        assert asset.ip == "192.168.1.1"

    def test_get_asset_not_found(self, temp_db):
        """Test getting non-existent asset"""
        asset = temp_db.get_asset("nonexistent.example.com")
        assert asset is None

    def test_get_assets(self, temp_db):
        """Test getting all assets"""
        domains = ["a.example.com", "b.example.com", "c.example.com"]
        for domain in domains:
            temp_db.add_asset(domain=domain)

        assets = temp_db.get_assets()

        assert len(assets) == 3
        assert all(isinstance(a, Asset) for a in assets)

    def test_count_assets(self, temp_db):
        """Test counting assets"""
        assert temp_db.count_assets() == 0

        temp_db.add_asset(domain="a.example.com")
        temp_db.add_asset(domain="b.example.com")

        assert temp_db.count_assets() == 2

    def test_add_assets_bulk(self, temp_db):
        """Test bulk adding assets"""
        assets = [
            {"domain": "a.example.com", "source": "test"},
            {"domain": "b.example.com", "source": "test"},
            {"domain": "c.example.com", "source": "test"},
        ]

        count = temp_db.add_assets_bulk(assets)

        assert count == 3
        assert temp_db.count_assets() == 3


class TestServices:
    """Tests for service operations"""

    def test_add_service(self, temp_db):
        """Test adding a service"""
        asset_id = temp_db.add_asset(domain="test.example.com")

        service_id = temp_db.add_service(
            asset_id=asset_id,
            port=443,
            protocol="https",
            status_code=200,
            title="Test Page",
            technology="PHP"
        )

        assert service_id > 0

    def test_add_service_duplicate(self, temp_db):
        """Test adding duplicate service updates"""
        asset_id = temp_db.add_asset(domain="test.example.com")

        id1 = temp_db.add_service(asset_id=asset_id, port=443, title="Old")
        id2 = temp_db.add_service(asset_id=asset_id, port=443, title="New")

        assert id1 == id2

    def test_get_services(self, temp_db):
        """Test getting services"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        temp_db.add_service(asset_id=asset_id, port=80, protocol="http")
        temp_db.add_service(asset_id=asset_id, port=443, protocol="https")

        services = temp_db.get_services(asset_id=asset_id)

        assert len(services) == 2
        assert all(isinstance(s, Service) for s in services)

    def test_get_services_alive_only(self, temp_db):
        """Test getting only alive services"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        temp_db.add_service(asset_id=asset_id, port=80, status_code=200)
        temp_db.add_service(asset_id=asset_id, port=443, status_code=0)  # Dead

        services = temp_db.get_services(alive_only=True)

        assert len(services) == 1
        assert services[0].status_code == 200

    def test_count_services(self, temp_db):
        """Test counting services"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        temp_db.add_service(asset_id=asset_id, port=80, status_code=200)
        temp_db.add_service(asset_id=asset_id, port=443, status_code=0)

        assert temp_db.count_services() == 2
        assert temp_db.count_services(alive_only=True) == 1


class TestEndpoints:
    """Tests for endpoint operations"""

    def test_add_endpoint(self, temp_db):
        """Test adding an endpoint"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)

        endpoint_id = temp_db.add_endpoint(
            service_id=service_id,
            path="/api/users",
            method="GET",
            params={"id": "1"},
            interesting_score=5,
            tags=["idor"]
        )

        assert endpoint_id > 0

    def test_add_endpoint_duplicate_keeps_max_score(self, temp_db):
        """Test duplicate endpoint keeps maximum score"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)

        temp_db.add_endpoint(service_id=service_id, path="/api", interesting_score=3)
        temp_db.add_endpoint(service_id=service_id, path="/api", interesting_score=7)

        endpoints = temp_db.get_endpoints(service_id=service_id)

        assert len(endpoints) == 1
        assert endpoints[0].interesting_score == 7

    def test_get_endpoints_by_score(self, temp_db):
        """Test getting endpoints filtered by score"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)

        temp_db.add_endpoint(service_id=service_id, path="/low", interesting_score=2)
        temp_db.add_endpoint(service_id=service_id, path="/mid", interesting_score=5)
        temp_db.add_endpoint(service_id=service_id, path="/high", interesting_score=10)

        high_score = temp_db.get_endpoints(min_score=5)

        assert len(high_score) == 2
        assert all(e.interesting_score >= 5 for e in high_score)

    def test_count_endpoints(self, temp_db):
        """Test counting endpoints"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)

        temp_db.add_endpoint(service_id=service_id, path="/a", interesting_score=2)
        temp_db.add_endpoint(service_id=service_id, path="/b", interesting_score=5)
        temp_db.add_endpoint(service_id=service_id, path="/c", interesting_score=10)

        assert temp_db.count_endpoints() == 3
        assert temp_db.count_endpoints(min_score=5) == 2


class TestFindings:
    """Tests for finding operations"""

    def test_add_finding(self, temp_db):
        """Test adding a finding"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)
        endpoint_id = temp_db.add_endpoint(service_id=service_id, path="/vuln")

        finding_id = temp_db.add_finding(
            endpoint_id=endpoint_id,
            finding_type="xss-reflected",
            severity="high",
            title="XSS in search",
            evidence="<script>alert(1)</script>",
            confirmed=True
        )

        assert finding_id > 0

    def test_get_findings(self, temp_db):
        """Test getting findings"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)
        endpoint_id = temp_db.add_endpoint(service_id=service_id, path="/vuln")

        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="xss", severity="high")
        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="sqli", severity="critical")

        findings = temp_db.get_findings()

        assert len(findings) == 2
        # Should be ordered by severity (critical first)
        assert findings[0].severity == "critical"

    def test_get_findings_by_severity(self, temp_db):
        """Test getting findings by severity"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)
        endpoint_id = temp_db.add_endpoint(service_id=service_id, path="/vuln")

        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="xss", severity="high")
        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="sqli", severity="critical")

        high_only = temp_db.get_findings(severity="high")

        assert len(high_only) == 1
        assert high_only[0].finding_type == "xss"

    def test_count_findings(self, temp_db):
        """Test counting findings"""
        asset_id = temp_db.add_asset(domain="test.example.com")
        service_id = temp_db.add_service(asset_id=asset_id)
        endpoint_id = temp_db.add_endpoint(service_id=service_id, path="/vuln")

        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="a", severity="high")
        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="b", severity="critical")
        temp_db.add_finding(endpoint_id=endpoint_id, finding_type="c", severity="low")

        assert temp_db.count_findings() == 3
        assert temp_db.count_findings(severity="critical") == 1


class TestQueries:
    """Tests for complex queries"""

    def test_get_top_targets(self, populated_db):
        """Test getting top targets"""
        targets = populated_db.get_top_targets(limit=5)

        assert len(targets) > 0
        # Should be ordered by score descending
        scores = [t['score'] for t in targets]
        assert scores == sorted(scores, reverse=True)

    def test_get_top_targets_structure(self, populated_db):
        """Test top targets have correct structure"""
        targets = populated_db.get_top_targets(limit=1)

        assert len(targets) == 1
        target = targets[0]

        required_keys = ['domain', 'url', 'title', 'technology', 'params', 'score', 'tags']
        for key in required_keys:
            assert key in target, f"Missing key: {key}"

    def test_get_stats(self, populated_db):
        """Test getting database statistics"""
        stats = populated_db.get_stats()

        required_keys = [
            'assets', 'services', 'services_alive',
            'endpoints', 'endpoints_interesting',
            'findings', 'findings_high', 'findings_critical'
        ]

        for key in required_keys:
            assert key in stats, f"Missing stat: {key}"

        assert stats['assets'] >= 1
        assert stats['endpoints'] >= 1

    def test_export_urls(self, populated_db):
        """Test URL export"""
        urls = populated_db.export_urls()

        assert len(urls) > 0
        assert all(url.startswith('http') for url in urls)

    def test_export_urls_with_min_score(self, populated_db):
        """Test URL export with minimum score filter"""
        all_urls = populated_db.export_urls(min_score=0)
        high_score_urls = populated_db.export_urls(min_score=7)

        assert len(high_score_urls) < len(all_urls)
