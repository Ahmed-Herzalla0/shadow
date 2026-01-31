#!/usr/bin/env python3
"""
SHADOW - Test Fixtures

Shared fixtures for all tests.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.db import Database
from core.scorer import Scorer


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    db = Database(db_path)
    yield db

    db.close()
    os.unlink(db_path)


@pytest.fixture
def populated_db(temp_db):
    """Database with sample data"""
    # Add assets
    asset_id = temp_db.add_asset(
        domain="api.example.com",
        ip="192.168.1.1",
        source="subfinder",
        tags=["api"]
    )

    # Add service
    service_id = temp_db.add_service(
        asset_id=asset_id,
        port=443,
        protocol="https",
        status_code=200,
        title="Example API",
        technology="PHP, Laravel"
    )

    # Add endpoints with various scores
    endpoints = [
        ("/api/v1/users", {"id": "1"}, 8),
        ("/api/v1/admin/config", {}, 12),
        ("/api/v1/upload", {"file": "test.txt"}, 7),
        ("/static/app.js", {}, 0),
        ("/login", {"redirect": "/"}, 6),
    ]

    for path, params, score in endpoints:
        temp_db.add_endpoint(
            service_id=service_id,
            path=path,
            params=params,
            interesting_score=score,
            tags=["test"]
        )

    # Add findings
    temp_db.add_finding(
        endpoint_id=1,
        finding_type="xss-reflected",
        severity="high",
        title="Reflected XSS in search",
        evidence="<script>alert(1)</script>",
        confirmed=True
    )

    temp_db.add_finding(
        endpoint_id=2,
        finding_type="exposed-config",
        severity="critical",
        title="Config file exposed",
        evidence="database_password=",
        confirmed=True
    )

    return temp_db


@pytest.fixture
def scorer():
    """Create a Scorer instance"""
    return Scorer()


@pytest.fixture
def sample_targets():
    """Sample target data for scoring tests"""
    return [
        {
            "path": "/api/v1/users",
            "params": {"id": "1", "redirect": "http://evil.com"},
            "technology": "PHP",
            "expected_min_score": 5,
        },
        {
            "path": "/admin/config",
            "params": {"file": "../../../etc/passwd"},
            "technology": "Java, Spring",
            "expected_min_score": 10,
        },
        {
            "path": "/static/app.js",
            "params": {},
            "technology": "",
            "expected_max_score": 0,  # Should be noise
        },
        {
            "path": "/graphql",
            "params": {"query": "{ __schema { types { name } } }"},
            "technology": "Node.js",
            "expected_min_score": 4,
        },
        {
            "path": "/debug/console",
            "params": {"cmd": "ls"},
            "technology": "Python, Flask",
            "expected_min_score": 8,
        },
    ]
