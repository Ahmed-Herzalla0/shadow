"""
SHADOW v6 - Module Runner

Executes Bash modules and parses their output into normalized JSON.
The bridge between tool execution and intelligent decision making.
"""

import subprocess
import os
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

from .schemas import (
    ModuleOutput,
    IntelOutput, ASNInfo, WhoisInfo,
    SubdomainsOutput, Subdomain,
    DNSOutput, DNSRecord,
    HTTPOutput, HTTPHost,
    ContentOutput, DiscoveredPath,
    JSOutput, JSEndpoint, JSSecret,
    ParamsOutput, Parameter,
    VulnOutput, Vulnerability
)
from .state import TargetState


class ModuleStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleRun:
    """Represents a single module execution"""
    module: str
    status: ModuleStatus = ModuleStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output_path: str = ""
    json_output: Optional[ModuleOutput] = None
    error: Optional[str] = None


class ModuleRunner:
    """
    Executes SHADOW modules and normalizes their output to JSON.
    
    This is the bridge between:
    - Old: Run bash, generate files
    - New: Run bash, get structured data for decision engine
    """
    
    def __init__(self, shadow_dir: str, output_dir: str, target: str):
        self.shadow_dir = Path(shadow_dir)
        self.output_dir = Path(output_dir)
        self.target = target
        self.modules_dir = self.shadow_dir / "modules"
        self.runs: Dict[str, ModuleRun] = {}
        
    def run_module(self, module_name: str, 
                   extra_args: List[str] = None,
                   timeout: int = 600) -> ModuleOutput:
        """
        Execute a module and return normalized JSON output.
        
        Args:
            module_name: Name of module (e.g., "01_intel")
            extra_args: Additional arguments to pass
            timeout: Max execution time in seconds
            
        Returns:
            ModuleOutput with normalized data
        """
        module_path = self.modules_dir / f"{module_name}.sh"
        
        if not module_path.exists():
            return ModuleOutput(
                module=module_name,
                target=self.target,
                timestamp=datetime.now().isoformat(),
                success=False,
                error=f"Module not found: {module_path}"
            )
        
        run = ModuleRun(
            module=module_name,
            status=ModuleStatus.RUNNING,
            started_at=datetime.now()
        )
        self.runs[module_name] = run
        
        try:
            # Prepare environment
            env = os.environ.copy()
            env["TARGET"] = self.target
            env["OUTPUT_DIR"] = str(self.output_dir)
            env["SHADOW_DIR"] = str(self.shadow_dir)
            
            # Build command
            cmd = ["bash", str(module_path), self.target]
            if extra_args:
                cmd.extend(extra_args)
            
            # Execute
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(self.shadow_dir)
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse output based on module type
            data = self._parse_module_output(module_name, result.stdout, result.stderr)
            
            run.status = ModuleStatus.COMPLETED
            run.completed_at = datetime.now()
            
            return ModuleOutput(
                module=module_name,
                target=self.target,
                timestamp=start_time.isoformat(),
                success=result.returncode == 0,
                error=result.stderr if result.returncode != 0 else None,
                duration_seconds=duration,
                data=data
            )
            
        except subprocess.TimeoutExpired:
            run.status = ModuleStatus.FAILED
            run.error = f"Timeout after {timeout}s"
            return ModuleOutput(
                module=module_name,
                target=self.target,
                timestamp=datetime.now().isoformat(),
                success=False,
                error=f"Module timed out after {timeout} seconds"
            )
            
        except Exception as e:
            run.status = ModuleStatus.FAILED
            run.error = str(e)
            return ModuleOutput(
                module=module_name,
                target=self.target,
                timestamp=datetime.now().isoformat(),
                success=False,
                error=str(e)
            )
    
    def _parse_module_output(self, module: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Parse module output into structured data.
        
        Each module produces files in output_dir.
        We read those files and normalize to our schema.
        """
        parsers = {
            "01_intel": self._parse_intel,
            "02_subdomains": self._parse_subdomains,
            "03_dns": self._parse_dns,
            "04_ports": self._parse_ports,
            "05_http": self._parse_http,
            "06_content": self._parse_content,
            "07_js": self._parse_js,
            "08_params": self._parse_params,
            "09_vuln": self._parse_vuln,
        }
        
        parser = parsers.get(module)
        if parser:
            try:
                return parser()
            except Exception as e:
                return {"parse_error": str(e), "raw_stdout": stdout[:1000]}
        
        return {"raw_stdout": stdout[:1000]}
    
    def _read_file_lines(self, filename: str) -> List[str]:
        """Read lines from output file"""
        path = self.output_dir / filename
        if path.exists():
            return path.read_text().strip().split('\n')
        return []
    
    def _parse_intel(self) -> Dict[str, Any]:
        """Parse intel module output"""
        output = IntelOutput()
        
        # Parse ASN info
        asn_file = self.output_dir / "asn.txt"
        if asn_file.exists():
            lines = asn_file.read_text().strip().split('\n')
            if lines:
                # Format: ASN | Name | Country
                parts = lines[0].split('|')
                if len(parts) >= 3:
                    output.asn = ASNInfo(
                        number=parts[0].strip(),
                        name=parts[1].strip(),
                        country=parts[2].strip()
                    )
        
        # Parse IP ranges
        ip_file = self.output_dir / "ip_ranges.txt"
        if ip_file.exists():
            output.ip_ranges = [l for l in ip_file.read_text().strip().split('\n') if l]
        
        return output.to_dict()
    
    def _parse_subdomains(self) -> Dict[str, Any]:
        """Parse subdomains module output"""
        output = SubdomainsOutput()
        
        # All subdomains file
        subs_file = self.output_dir / "subdomains.txt"
        if subs_file.exists():
            lines = [l.strip() for l in subs_file.read_text().split('\n') if l.strip()]
            output.total_found = len(lines)
            output.unique_count = len(set(lines))
            output.subdomains = [Subdomain(name=l, source="combined") for l in lines[:1000]]
        
        # Check for wildcard file
        wildcard_file = self.output_dir / "wildcards.txt"
        if wildcard_file.exists():
            output.wildcards = [l for l in wildcard_file.read_text().split('\n') if l.strip()]
        
        return output.to_dict()
    
    def _parse_dns(self) -> Dict[str, Any]:
        """Parse DNS module output"""
        output = DNSOutput()
        
        # Resolved hosts
        resolved_file = self.output_dir / "resolved.txt"
        if resolved_file.exists():
            lines = resolved_file.read_text().strip().split('\n')
            output.resolved_count = len([l for l in lines if l])
            
            for line in lines:
                if not line:
                    continue
                # Format varies: subdomain,ip or subdomain [ip]
                if ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        output.records.append(DNSRecord(
                            subdomain=parts[0],
                            record_type="A",
                            value=parts[1]
                        ))
                        if parts[1] not in output.ips:
                            output.ips.append(parts[1])
        
        # CNAME records
        cname_file = self.output_dir / "cnames.txt"
        if cname_file.exists():
            for line in cname_file.read_text().strip().split('\n'):
                if ' -> ' in line:
                    src, dst = line.split(' -> ', 1)
                    output.cnames[src.strip()] = dst.strip()
        
        # Potential takeovers
        takeover_file = self.output_dir / "takeovers.txt"
        if takeover_file.exists():
            output.potential_takeovers = [
                l for l in takeover_file.read_text().split('\n') if l.strip()
            ]
        
        return output.to_dict()
    
    def _parse_ports(self) -> Dict[str, Any]:
        """Parse ports module output"""
        ports_file = self.output_dir / "ports.txt"
        ports = {}
        
        if ports_file.exists():
            for line in ports_file.read_text().strip().split('\n'):
                if not line:
                    continue
                # Format: host:port or host,port
                if ':' in line:
                    host, port = line.rsplit(':', 1)
                    if host not in ports:
                        ports[host] = []
                    ports[host].append(int(port) if port.isdigit() else port)
        
        return {
            "hosts_scanned": len(ports),
            "ports": ports
        }
    
    def _parse_http(self) -> Dict[str, Any]:
        """Parse HTTP module output"""
        output = HTTPOutput()
        
        # httpx output (JSON lines format)
        httpx_file = self.output_dir / "httpx.json"
        if httpx_file.exists():
            for line in httpx_file.read_text().strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = HTTPHost(
                        url=data.get("url", ""),
                        status_code=data.get("status_code", 0),
                        title=data.get("title", ""),
                        content_length=data.get("content_length", 0),
                        technologies=data.get("technologies", []),
                        server=data.get("webserver", ""),
                        content_type=data.get("content_type", ""),
                        tls_version=data.get("tls", {}).get("version", "")
                    )
                    output.hosts.append(host)
                    
                    # Count technologies
                    for tech in host.technologies:
                        output.technologies_found[tech] = output.technologies_found.get(tech, 0) + 1
                        
                except json.JSONDecodeError:
                    continue
        
        # Also check plain text file
        alive_file = self.output_dir / "alive.txt"
        if alive_file.exists() and not output.hosts:
            lines = [l for l in alive_file.read_text().split('\n') if l.strip()]
            output.alive_count = len(lines)
            output.hosts = [HTTPHost(url=l, status_code=200) for l in lines[:500]]
        else:
            output.alive_count = len(output.hosts)
        
        # WAF detection
        waf_file = self.output_dir / "waf.txt"
        if waf_file.exists():
            content = waf_file.read_text().strip()
            if content:
                output.waf_detected = content.split('\n')[0]
                output.waf_confidence = 0.8
        
        return output.to_dict()
    
    def _parse_content(self) -> Dict[str, Any]:
        """Parse content discovery output"""
        output = ContentOutput()
        
        # ffuf/gobuster output
        dirs_file = self.output_dir / "directories.txt"
        if dirs_file.exists():
            for line in dirs_file.read_text().strip().split('\n'):
                if not line:
                    continue
                
                # Categorize paths
                url = line.strip()
                path = DiscoveredPath(
                    url=url,
                    status_code=200,
                    content_length=0
                )
                
                url_lower = url.lower()
                
                if any(x in url_lower for x in ['admin', 'dashboard', 'panel', 'manage']):
                    path.is_interesting = True
                    path.category = "admin"
                    output.admin_panels.append(url)
                elif any(x in url_lower for x in ['.bak', '.backup', '.old', '.zip', '.tar']):
                    path.is_interesting = True
                    path.category = "backup"
                    output.backup_files.append(url)
                elif any(x in url_lower for x in ['.conf', '.config', '.env', '.ini', '.yml']):
                    path.is_interesting = True
                    path.category = "config"
                    output.config_files.append(url)
                
                output.paths.append(path)
                if path.is_interesting:
                    output.interesting_paths.append(path)
        
        output.paths_found = len(output.paths)
        return output.to_dict()
    
    def _parse_js(self) -> Dict[str, Any]:
        """Parse JS analysis output"""
        output = JSOutput()
        
        # JS files list
        js_files = self.output_dir / "js_files.txt"
        if js_files.exists():
            output.files_analyzed = len([l for l in js_files.read_text().split('\n') if l])
        
        # Endpoints from JS
        endpoints_file = self.output_dir / "js_endpoints.txt"
        if endpoints_file.exists():
            for line in endpoints_file.read_text().strip().split('\n'):
                if not line:
                    continue
                output.endpoints.append(JSEndpoint(
                    url=line.strip(),
                    method="GET",
                    source_file=""
                ))
            output.endpoints_found = len(output.endpoints)
        
        # Secrets from JS
        secrets_file = self.output_dir / "js_secrets.txt"
        if secrets_file.exists():
            for line in secrets_file.read_text().strip().split('\n'):
                if not line:
                    continue
                # Try to categorize secret
                secret_type = "unknown"
                sensitivity = "medium"
                
                if "api" in line.lower():
                    secret_type = "api_key"
                    sensitivity = "high"
                elif "token" in line.lower():
                    secret_type = "token"
                    sensitivity = "high"
                elif "password" in line.lower():
                    secret_type = "password"
                    sensitivity = "critical"
                
                output.secrets.append(JSSecret(
                    type=secret_type,
                    value=line[:50] + "..." if len(line) > 50 else line,
                    file="",
                    line=0,
                    sensitivity=sensitivity
                ))
            output.secrets_found = len(output.secrets)
        
        # Source maps
        sourcemaps_file = self.output_dir / "sourcemaps.txt"
        if sourcemaps_file.exists():
            output.source_maps = [l for l in sourcemaps_file.read_text().split('\n') if l.strip()]
        
        return output.to_dict()
    
    def _parse_params(self) -> Dict[str, Any]:
        """Parse params module output"""
        output = ParamsOutput()
        
        # URLs with params (from katana)
        urls_file = self.output_dir / "urls.txt"
        if urls_file.exists():
            output.urls = [l for l in urls_file.read_text().split('\n') if l.strip()]
            output.urls_found = len(output.urls)
            
            # Extract and categorize parameters
            for url in output.urls:
                params = self._extract_params_from_url(url)
                for p in params:
                    output.parameters.append(p)
                    
                    # Categorize by vuln type
                    name_lower = p.name.lower()
                    
                    if any(x in name_lower for x in ['url', 'redirect', 'next', 'return', 'goto']):
                        output.redirect_candidates.append(url)
                    elif any(x in name_lower for x in ['id', 'user', 'uid', 'account']):
                        output.idor_candidates.append(url)
                    elif any(x in name_lower for x in ['file', 'path', 'page', 'include']):
                        output.lfi_candidates.append(url)
                    elif any(x in name_lower for x in ['search', 'query', 'q', 'name']):
                        output.xss_candidates.append(url)
                    elif any(x in name_lower for x in ['sort', 'order', 'filter', 'where']):
                        output.sqli_candidates.append(url)
        
        output.params_found = len(output.parameters)
        return output.to_dict()
    
    def _extract_params_from_url(self, url: str) -> List[Parameter]:
        """Extract parameters from a URL"""
        params = []
        
        if '?' in url:
            query_string = url.split('?', 1)[1]
            # Remove fragment
            if '#' in query_string:
                query_string = query_string.split('#')[0]
            
            for pair in query_string.split('&'):
                if '=' in pair:
                    name = pair.split('=')[0]
                    params.append(Parameter(
                        name=name,
                        url=url,
                        method="GET"
                    ))
        
        return params
    
    def _parse_vuln(self) -> Dict[str, Any]:
        """Parse vulnerability scan output"""
        output = VulnOutput()
        
        # Nuclei output (JSON lines)
        nuclei_file = self.output_dir / "nuclei.json"
        if nuclei_file.exists():
            for line in nuclei_file.read_text().strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    severity = data.get("info", {}).get("severity", "info")
                    
                    vuln = Vulnerability(
                        name=data.get("info", {}).get("name", "Unknown"),
                        severity=severity,
                        url=data.get("matched-at", ""),
                        template=data.get("template-id", ""),
                        description=data.get("info", {}).get("description", ""),
                        matcher=data.get("matcher-name", "")
                    )
                    
                    output.vulnerabilities.append(vuln)
                    
                    if severity == "critical":
                        output.critical_count += 1
                        output.confirmed.append(vuln)
                    elif severity == "high":
                        output.high_count += 1
                        output.confirmed.append(vuln)
                    elif severity == "medium":
                        output.medium_count += 1
                        output.potential.append(vuln)
                    
                except json.JSONDecodeError:
                    continue
        
        # Also check plain text
        vuln_file = self.output_dir / "vulnerabilities.txt"
        if vuln_file.exists() and not output.vulnerabilities:
            lines = [l for l in vuln_file.read_text().split('\n') if l.strip()]
            output.total_found = len(lines)
        else:
            output.total_found = len(output.vulnerabilities)
        
        return output.to_dict()


class ModuleOrchestrator:
    """
    Orchestrates module execution based on decision engine.
    
    Enforces:
    - Scanner discipline (no heavy scans without evidence)
    - Rate limiting
    - Module dependencies
    """
    
    DEPENDENCIES = {
        "03_dns": ["02_subdomains"],
        "04_ports": ["03_dns"],
        "05_http": ["03_dns"],
        "06_content": ["05_http"],
        "07_js": ["05_http"],
        "08_params": ["05_http"],
        "09_vuln": ["05_http"],
    }
    
    # Modules that require evidence before running
    HEAVY_MODULES = {
        "04_ports",
        "06_content",
        "09_vuln",
    }
    
    def __init__(self, runner: ModuleRunner):
        self.runner = runner
        self.completed: List[str] = []
        self.results: Dict[str, ModuleOutput] = {}
        
    def can_run(self, module: str) -> tuple[bool, str]:
        """Check if a module can be run"""
        # Check dependencies
        deps = self.DEPENDENCIES.get(module, [])
        missing = [d for d in deps if d not in self.completed]
        
        if missing:
            return False, f"Missing dependencies: {missing}"
        
        return True, ""
    
    def should_run(self, module: str, state: TargetState) -> tuple[bool, str]:
        """
        Decide if a module SHOULD be run based on evidence.
        
        This enforces scanner discipline:
        - Don't port scan without subdomains
        - Don't directory bruteforce without live hosts
        - Don't nuclei scan without evidence of vulns
        """
        if module not in self.HEAVY_MODULES:
            return True, "Module is not heavy"
        
        if module == "04_ports":
            # Need at least some resolved hosts
            dns_result = self.results.get("03_dns")
            if not dns_result or not dns_result.data.get("resolved_count", 0):
                return False, "No resolved hosts to scan"
            return True, "Has resolved hosts"
        
        if module == "06_content":
            # Need live HTTP hosts
            http_result = self.results.get("05_http")
            if not http_result or not http_result.data.get("alive_count", 0):
                return False, "No live HTTP hosts"
            return True, "Has live hosts"
        
        if module == "09_vuln":
            # Check for evidence: interesting tech, params, etc.
            http_result = self.results.get("05_http")
            params_result = self.results.get("08_params")
            
            evidence = []
            
            if http_result:
                techs = http_result.data.get("technologies_found", {})
                if any(t.lower() in ['apache', 'nginx', 'php', 'wordpress', 'jira', 'confluence'] 
                       for t in techs.keys()):
                    evidence.append("interesting_tech")
            
            if params_result:
                if params_result.data.get("xss_candidates"):
                    evidence.append("xss_candidates")
                if params_result.data.get("sqli_candidates"):
                    evidence.append("sqli_candidates")
            
            if state.score >= 50:
                evidence.append("high_score")
            
            if not evidence:
                return False, "No evidence for vulnerability scan"
            
            return True, f"Evidence found: {', '.join(evidence)}"
        
        return True, ""
    
    def run(self, module: str, state: Optional[TargetState] = None) -> ModuleOutput:
        """Run a module with checks"""
        # Check dependencies
        can, reason = self.can_run(module)
        if not can:
            return ModuleOutput(
                module=module,
                target=self.runner.target,
                timestamp=datetime.now().isoformat(),
                success=False,
                error=f"Cannot run: {reason}"
            )
        
        # Check evidence (scanner discipline)
        if state:
            should, reason = self.should_run(module, state)
            if not should:
                return ModuleOutput(
                    module=module,
                    target=self.runner.target,
                    timestamp=datetime.now().isoformat(),
                    success=False,
                    error=f"Skipped (discipline): {reason}"
                )
        
        # Run the module
        result = self.runner.run_module(module)
        
        if result.success:
            self.completed.append(module)
            self.results[module] = result
        
        return result
