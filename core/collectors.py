#!/usr/bin/env python3
"""
SHADOW - Collectors

يجمع data من الأدوات ويخزنها في DB.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from .db import Database
from .scorer import Scorer

# Add utils to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from utils.security import (
        ValidationError,
        build_safe_command,
        validate_domain,
        validate_domains,
    )
except ImportError:
    # Fallback if utils not available
    class ValidationError(Exception):
        pass

    def validate_domain(domain):
        return domain.strip().lower()

    def validate_domains(domains):
        return [d.strip().lower() for d in domains if d.strip()]

    def build_safe_command(tool, args):
        return [tool] + list(args)


class BaseCollector:
    """Base class for all collectors"""

    # Timeouts for different operations
    TIMEOUT_SHORT = 120   # 2 minutes
    TIMEOUT_MEDIUM = 300  # 5 minutes
    TIMEOUT_LONG = 900    # 15 minutes
    TIMEOUT_NUCLEI = 1800 # 30 minutes

    # Retry configuration
    MAX_RETRIES = 2

    def __init__(self, db: Database):
        self.db = db
        self.scorer = Scorer()

    def run_tool(self, cmd: List[str], timeout: int = 600, retries: int = None) -> str:
        """
        Run external tool with timeout, retries, and proper error handling.
        
        Args:
            cmd: Command as list (already validated)
            timeout: Timeout in seconds
            retries: Number of retries (default: MAX_RETRIES)
        
        Returns:
            stdout content or empty string on failure
        """
        retries = retries if retries is not None else self.MAX_RETRIES
        last_error = None

        for attempt in range(retries + 1):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                # Check for non-zero exit (warning, not failure for some tools)
                if result.returncode != 0 and result.stderr:
                    print(f"    [!] {cmd[0]} warning: {result.stderr[:100]}")

                return result.stdout

            except subprocess.TimeoutExpired:
                last_error = f"Timeout after {timeout}s"
                print(f"    [!] Timeout: {' '.join(cmd[:2])} (attempt {attempt + 1})")
                continue

            except FileNotFoundError:
                print(f"    [!] Tool not found: {cmd[0]}")
                return ""

            except Exception as e:
                last_error = str(e)
                print(f"    [!] Error running {cmd[0]}: {e}")
                continue

        if last_error:
            print(f"    [!] All {retries + 1} attempts failed: {last_error}")

        return ""

    def tool_exists(self, name: str) -> bool:
        """Check if tool is installed"""
        try:
            subprocess.run(['which', name], capture_output=True, check=True)
            return True
        except:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainCollector(BaseCollector):
    """Collect subdomains using multiple tools"""

    def collect(self, domain: str) -> int:
        """
        Run subdomain enumeration and store results.
        Returns number of unique subdomains found.
        """
        # Validate domain input
        try:
            domain = validate_domain(domain)
        except ValidationError as e:
            print(f"[!] Invalid domain: {e}")
            return 0

        print(f"[*] Collecting subdomains for: {domain}")

        subdomains = set()

        # Subfinder
        if self.tool_exists('subfinder'):
            print("[*] Running subfinder...")
            cmd = build_safe_command('subfinder', ['-d', domain, '-silent'])
            output = self.run_tool(cmd, timeout=self.TIMEOUT_MEDIUM)
            subs = self._parse_lines(output)
            print(f"    Found: {len(subs)}")
            for sub in subs:
                subdomains.add((sub, 'subfinder'))

        # Assetfinder
        if self.tool_exists('assetfinder'):
            print("[*] Running assetfinder...")
            cmd = build_safe_command('assetfinder', ['--subs-only', domain])
            output = self.run_tool(cmd, timeout=self.TIMEOUT_SHORT)
            subs = self._parse_lines(output)
            print(f"    Found: {len(subs)}")
            for sub in subs:
                subdomains.add((sub, 'assetfinder'))

        # Amass (passive only, with timeout)
        if self.tool_exists('amass'):
            print("[*] Running amass passive...")
            cmd = build_safe_command('amass', ['enum', '-passive', '-d', domain, '-timeout', '5'])
            output = self.run_tool(cmd, timeout=self.TIMEOUT_MEDIUM + 60)
            subs = self._parse_lines(output)
            print(f"    Found: {len(subs)}")
            for sub in subs:
                subdomains.add((sub, 'amass'))

        # Store in database
        count = 0
        for subdomain, source in subdomains:
            # Clean and validate
            try:
                subdomain = validate_domain(subdomain)
            except ValidationError:
                continue

            if not subdomain.endswith(domain):
                continue

            # Score the asset
            score_result = self.scorer.score_asset(subdomain)

            self.db.add_asset(
                domain=subdomain,
                source=source,
                tags=score_result.tags
            )
            count += 1

        print(f"[+] Total unique subdomains: {count}")
        return count

    def _parse_lines(self, output: str) -> List[str]:
        """Parse line-separated output"""
        return [line.strip() for line in output.strip().split('\n') if line.strip()]


# ═══════════════════════════════════════════════════════════════════════════════
# DNS COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class DNSCollector(BaseCollector):
    """Resolve DNS for assets"""

    def collect(self) -> int:
        """
        Resolve DNS for all assets without IP.
        Returns number resolved.
        """
        assets = self.db.get_assets(limit=10000)
        domains = [a.domain for a in assets if not a.ip]

        if not domains:
            print("[*] No domains to resolve")
            return 0

        print(f"[*] Resolving DNS for {len(domains)} domains...")

        if not self.tool_exists('dnsx'):
            print("[!] dnsx not found, skipping DNS resolution")
            return 0

        # Write domains to temp file
        temp_file = '/tmp/shadow_dns_input.txt'
        with open(temp_file, 'w') as f:
            f.write('\n'.join(domains))

        # Run dnsx
        output = self.run_tool(
            ['dnsx', '-l', temp_file, '-a', '-resp', '-silent'],
            timeout=600
        )

        count = 0
        for line in output.strip().split('\n'):
            if not line or '[' not in line:
                continue

            # Parse: domain [ip]
            match = re.match(r'(\S+)\s+\[([^\]]+)\]', line)
            if match:
                domain = match.group(1)
                ip = match.group(2)

                # Update asset with IP
                asset = self.db.get_asset(domain)
                if asset:
                    self.db.conn.execute(
                        "UPDATE assets SET ip = ? WHERE domain = ?",
                        (ip, domain)
                    )
                    count += 1

        self.db.conn.commit()

        # Cleanup
        os.unlink(temp_file)

        print(f"[+] Resolved {count} domains")
        return count


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPCollector(BaseCollector):
    """Probe HTTP services"""

    def collect(self) -> int:
        """
        Probe all assets for HTTP services.
        Returns number of alive services.
        """
        assets = self.db.get_assets(limit=10000)
        domains = [a.domain for a in assets]

        if not domains:
            print("[*] No domains to probe")
            return 0

        print(f"[*] Probing HTTP for {len(domains)} domains...")

        if not self.tool_exists('httpx'):
            print("[!] httpx not found")
            return 0

        # Write domains to temp file
        temp_file = '/tmp/shadow_http_input.txt'
        with open(temp_file, 'w') as f:
            f.write('\n'.join(domains))

        # Run httpx with JSON output
        output = self.run_tool([
            'httpx', '-l', temp_file,
            '-silent',
            '-json',
            '-title',
            '-status-code',
            '-tech-detect',
            '-content-length',
            '-follow-redirects',
            '-threads', '50'
        ], timeout=900)

        count = 0
        for line in output.strip().split('\n'):
            if not line:
                continue

            try:
                data = json.loads(line)

                # Parse URL
                url = data.get('url', '')
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                protocol = parsed.scheme

                # Get asset
                asset = self.db.get_asset(domain)
                if not asset:
                    continue

                # Extract technology
                techs = data.get('tech', [])
                tech_str = ', '.join(techs) if techs else ""

                # Add service
                service_id = self.db.add_service(
                    asset_id=asset.id,
                    port=port,
                    protocol=protocol,
                    status_code=data.get('status_code', 0),
                    title=data.get('title', ''),
                    technology=tech_str,
                    server=data.get('webserver', ''),
                    content_length=data.get('content_length', 0),
                    redirect_url=data.get('final_url', '')
                )

                if service_id > 0:
                    count += 1

            except json.JSONDecodeError:
                continue

        # Cleanup
        os.unlink(temp_file)

        print(f"[+] Found {count} alive services")
        return count


# ═══════════════════════════════════════════════════════════════════════════════
# CRAWL COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class CrawlCollector(BaseCollector):
    """Crawl for endpoints using Katana"""

    def collect(self, max_depth: int = 3) -> int:
        """
        Crawl all alive services for endpoints.
        Returns number of endpoints found.
        """
        services = self.db.get_services(alive_only=True)

        if not services:
            print("[*] No alive services to crawl")
            return 0

        print(f"[*] Crawling {len(services)} services...")

        if not self.tool_exists('katana'):
            print("[!] katana not found")
            return 0

        # Build URLs for alive services
        urls = []
        service_map = {}  # url -> service_id

        for service in services:
            asset = self.db.conn.execute(
                "SELECT domain FROM assets WHERE id = ?", (service.asset_id,)
            ).fetchone()

            if asset:
                if service.port in [80, 443]:
                    url = f"{service.protocol}://{asset[0]}"
                else:
                    url = f"{service.protocol}://{asset[0]}:{service.port}"
                urls.append(url)
                service_map[asset[0]] = service.id

        # Write URLs to temp file
        temp_file = '/tmp/shadow_crawl_input.txt'
        with open(temp_file, 'w') as f:
            f.write('\n'.join(urls))

        # Run katana
        output = self.run_tool([
            'katana', '-list', temp_file,
            '-silent',
            '-depth', str(max_depth),
            '-js-crawl',
            '-known-files', 'all',
            '-form-extraction',
            '-timeout', '10',
            '-concurrency', '20'
        ], timeout=1800)

        count = 0
        seen_endpoints = set()

        for line in output.strip().split('\n'):
            url = line.strip()
            if not url:
                continue

            try:
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                path = parsed.path or '/'

                # Get service_id
                service_id = service_map.get(domain)
                if not service_id:
                    # Try to find matching service
                    asset = self.db.get_asset(domain)
                    if asset:
                        services = self.db.get_services(asset_id=asset.id)
                        if services:
                            service_id = services[0].id

                if not service_id:
                    continue

                # Parse params
                params = {}
                if parsed.query:
                    for key, values in parse_qs(parsed.query).items():
                        params[key] = values[0] if values else ''

                # Dedup
                endpoint_key = f"{service_id}:{path}:{sorted(params.keys())}"
                if endpoint_key in seen_endpoints:
                    continue
                seen_endpoints.add(endpoint_key)

                # Score the endpoint
                service = next((s for s in services if s.id == service_id), None)
                tech = service.technology if service else ""

                score_result = self.scorer.score_endpoint(
                    path=path,
                    params=params,
                    technology=tech
                )

                # Add endpoint
                self.db.add_endpoint(
                    service_id=service_id,
                    path=path,
                    method='GET',
                    params=params,
                    interesting_score=score_result.total,
                    tags=score_result.tags
                )
                count += 1

            except Exception:
                continue

        # Cleanup
        os.unlink(temp_file)

        print(f"[+] Found {count} endpoints")
        return count


# ═══════════════════════════════════════════════════════════════════════════════
# NUCLEI COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class NucleiCollector(BaseCollector):
    """Run nuclei on interesting endpoints"""

    def collect(self, min_score: int = 5, severity: str = "medium,high,critical") -> int:
        """
        Run nuclei on high-score endpoints.
        Returns number of findings.
        """
        endpoints = self.db.get_endpoints(min_score=min_score, limit=500)

        if not endpoints:
            print(f"[*] No endpoints with score >= {min_score}")
            return 0

        print(f"[*] Running nuclei on {len(endpoints)} interesting endpoints...")

        if not self.tool_exists('nuclei'):
            print("[!] nuclei not found")
            return 0

        # Build URLs
        urls = self.db.export_urls(min_score=min_score)

        if not urls:
            return 0

        # Write URLs to temp file
        temp_file = '/tmp/shadow_nuclei_input.txt'
        with open(temp_file, 'w') as f:
            f.write('\n'.join(urls[:500]))  # Limit to 500

        # Run nuclei with JSON output
        output = self.run_tool([
            'nuclei', '-l', temp_file,
            '-silent',
            '-jsonl',
            '-severity', severity,
            '-rate-limit', '100',
            '-timeout', '10',
            '-retries', '1'
        ], timeout=1800)

        count = 0
        for line in output.strip().split('\n'):
            if not line:
                continue

            try:
                data = json.loads(line)

                # Parse finding
                matched_url = data.get('matched-at', '')
                template_id = data.get('template-id', '')
                info = data.get('info', {})

                finding_severity = info.get('severity', 'info')
                finding_name = info.get('name', template_id)

                # Find matching endpoint
                parsed = urlparse(matched_url)
                path = parsed.path or '/'

                # Get endpoint_id (simplified - match by path)
                cur = self.db.conn.execute(
                    """SELECT e.id FROM endpoints e
                       JOIN services s ON e.service_id = s.id
                       JOIN assets a ON s.asset_id = a.id
                       WHERE e.path = ? OR e.path LIKE ?
                       LIMIT 1""",
                    (path, f"{path}%")
                )
                row = cur.fetchone()
                endpoint_id = row[0] if row else None

                # Add finding
                self.db.add_finding(
                    endpoint_id=endpoint_id,
                    finding_type=template_id,
                    severity=finding_severity,
                    title=finding_name,
                    evidence=data.get('extracted-results', str(data.get('matcher-name', ''))),
                    confirmed=True
                )
                count += 1

            except json.JSONDecodeError:
                continue

        # Cleanup
        os.unlink(temp_file)

        print(f"[+] Found {count} vulnerabilities")
        return count


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """Orchestrate all collectors"""

    def __init__(self, db_path: str):
        self.db = Database(db_path)
        self.subdomains = SubdomainCollector(self.db)
        self.dns = DNSCollector(self.db)
        self.http = HTTPCollector(self.db)
        self.crawl = CrawlCollector(self.db)
        self.nuclei = NucleiCollector(self.db)

    def hunt(self, domain: str, skip_nuclei: bool = False) -> Dict:
        """
        Full hunting workflow.
        
        Returns stats dictionary.
        """
        print("=" * 60)
        print(f"  SHADOW - Hunting: {domain}")
        print("=" * 60)
        print()

        stats = {}

        # Validate domain
        try:
            domain = validate_domain(domain)
        except ValidationError as e:
            print(f"[!] Invalid domain: {e}")
            return stats

        # 1. Subdomains
        print("[1/5] Subdomain Enumeration")
        print("-" * 40)
        stats['subdomains'] = self.subdomains.collect(domain)
        print()

        # 2. DNS
        print("[2/5] DNS Resolution")
        print("-" * 40)
        stats['resolved'] = self.dns.collect()
        print()

        # 3. HTTP
        print("[3/5] HTTP Probing")
        print("-" * 40)
        stats['services'] = self.http.collect()
        print()

        # 4. Crawl
        print("[4/5] Crawling")
        print("-" * 40)
        stats['endpoints'] = self.crawl.collect()
        print()

        # 5. Nuclei (optional)
        if not skip_nuclei:
            print("[5/5] Vulnerability Scanning")
            print("-" * 40)
            stats['findings'] = self.nuclei.collect()
            print()

        # Print summary
        self._print_summary(stats)

        # Generate reports
        self._generate_reports(domain)

        return stats

    def _generate_reports(self, domain: str):
        """Generate JSON and markdown reports"""
        try:
            from utils.reports import ReportGenerator

            output_dir = str(self.db.db_path.parent)
            generator = ReportGenerator(output_dir)

            targets = self.db.get_top_targets(limit=100)
            findings = self.db.get_findings()
            db_stats = self.db.get_stats()

            # Convert findings to dict
            findings_list = [
                {
                    'finding_type': f.finding_type,
                    'severity': f.severity,
                    'title': f.title,
                    'evidence': f.evidence[:200] if f.evidence else '',
                }
                for f in findings
            ]

            # Generate all reports
            generator.generate_targets_ranked(targets)
            generator.generate_summary(domain, db_stats, targets, findings_list)
            generator.generate_notes(domain, targets, findings_list)
            generator.generate_jsonl(targets, "targets.jsonl")

            print(f"[+] Reports generated in: {output_dir}/reports/")

        except ImportError:
            # Utils not available
            pass
        except Exception as e:
            print(f"[!] Report generation failed: {e}")

    def _print_summary(self, stats: Dict):
        """Print final summary"""
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)

        db_stats = self.db.get_stats()

        print(f"""
  Assets:      {db_stats['assets']}
  Services:    {db_stats['services_alive']} alive / {db_stats['services']} total
  Endpoints:   {db_stats['endpoints']}
  Interesting: {db_stats['endpoints_interesting']} (score >= 5)
  Findings:    {db_stats['findings']}
    Critical:  {db_stats['findings_critical']}
    High:      {db_stats['findings_high']}
        """)

        # Top targets
        print("-" * 60)
        print("  TOP 10 TARGETS")
        print("-" * 60)

        from .scorer import format_target

        targets = self.db.get_top_targets(limit=10)
        for i, target in enumerate(targets, 1):
            print(f"\n#{i}")
            print(format_target(target))

        print()

    def close(self):
        self.db.close()
