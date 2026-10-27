import ipaddress
from typing import Dict, Any, Optional

class EnrichmentEngine:
    """
    Automated Context Enrichment Engine.
    Enriches alerts and incidents with Threat Intelligence (IP reputation, GeoIP),
    Internal Asset Inventory context, and Identity/Privilege context.
    """

    # Pre-built Threat Intelligence Database of known malicious indicators
    KNOWN_THREAT_INTEL = {
        # Brute force botnets & scanners
        "185.220.101.5": {
            "reputation": "MALICIOUS",
            "threat_score": 95,
            "threat_category": "Tor Exit Node / SSH Brute Force Botnet",
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "asn": "AS208294",
            "isp": "Tor Network Relays",
            "threat_actors": ["APT28 / Fancy Bear", "FIN7"]
        },
        "198.51.100.45": {
            "reputation": "MALICIOUS",
            "threat_score": 90,
            "threat_category": "Active Password Sprayer / Credential Access",
            "country": "Russia",
            "country_code": "RU",
            "city": "Saint Petersburg",
            "asn": "AS49505",
            "isp": "Selectel Network",
            "threat_actors": ["Midnight Blizzard / Nobelium"]
        },
        "45.33.32.156": {
            "reputation": "SUSPICIOUS",
            "threat_score": 75,
            "threat_category": "Internet Port Scanner / Shodan / Masscan",
            "country": "United States",
            "country_code": "US",
            "city": "Fremont",
            "asn": "AS63949",
            "isp": "Linode LLC",
            "threat_actors": ["Automated Recon Bot"]
        },
        # C2 Servers
        "103.224.182.245": {
            "reputation": "MALICIOUS",
            "threat_score": 98,
            "threat_category": "Cobalt Strike C2 Beacon / Ransomware Staging",
            "country": "Singapore",
            "country_code": "SG",
            "city": "Singapore",
            "asn": "AS133199",
            "isp": "HostUniversal",
            "threat_actors": ["BlackCat / ALPHV", "LockBit 3.0"]
        },
        "91.240.118.172": {
            "reputation": "MALICIOUS",
            "threat_score": 92,
            "threat_category": "DNS Exfiltration / Tunneling C2 Sinkhole",
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "asn": "AS44592",
            "isp": "HostRoyale",
            "threat_actors": ["Lazarus Group"]
        }
    }

    # Internal Asset Inventory Database
    ASSET_INVENTORY = {
        "dc-prod-01": {"role": "Primary Domain Controller", "tier": "Tier-0", "criticality": "CRITICAL", "owner": "Enterprise Identity Team"},
        "dc-backup-02": {"role": "Secondary Domain Controller", "tier": "Tier-0", "criticality": "CRITICAL", "owner": "Enterprise Identity Team"},
        "sql-prod-db": {"role": "Customer Core Database", "tier": "Tier-1", "criticality": "CRITICAL", "owner": "Database Operations"},
        "win-exec-04": {"role": "CEO Executive Workstation", "tier": "Tier-2", "criticality": "HIGH", "owner": "Executive Office"},
        "win-dev-88": {"role": "Software Engineering Workstation", "tier": "Tier-3", "criticality": "MEDIUM", "owner": "Engineering"},
        "linux-server": {"role": "DMZ Application Gateway", "tier": "Tier-1", "criticality": "HIGH", "owner": "Cloud Infra"},
        "win-workstation": {"role": "Finance Operations Workstation", "tier": "Tier-2", "criticality": "HIGH", "owner": "Finance Dept"}
    }

    # Identity and Privilege Database
    IDENTITY_DIRECTORY = {
        "administrator": {"department": "IT Operations", "privilege": "Domain Admin (Tier-0)", "is_privileged": True, "mfa_enabled": True},
        "root": {"department": "System Infrastructure", "privilege": "Superuser / Root", "is_privileged": True, "mfa_enabled": False},
        "analyst": {"department": "Cyber Defense Operations", "privilege": "SOC Analyst (Tier-2)", "is_privileged": False, "mfa_enabled": True},
        "finance_user": {"department": "Finance & Payroll", "privilege": "Standard User", "is_privileged": False, "mfa_enabled": True},
        "hr_lead": {"department": "Human Resources", "privilege": "Standard User", "is_privileged": False, "mfa_enabled": True},
        "svc_backup": {"department": "IT Infrastructure", "privilege": "Service Account", "is_privileged": True, "mfa_enabled": False}
    }

    @classmethod
    def enrich_ip(cls, ip: Optional[str]) -> Dict[str, Any]:
        """Performs IP threat intelligence and GeoIP lookup."""
        if not ip:
            return {"status": "none"}

        # Check if private RFC1918
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    "ip": ip,
                    "type": "Internal RFC-1918",
                    "reputation": "BENIGN_INTERNAL",
                    "threat_score": 0,
                    "country": "Internal Network",
                    "city": "Corporate LAN",
                    "asn": "Private AS",
                    "isp": "Enterprise Intranet"
                }
        except ValueError:
            pass

        # Check threat intel table
        if ip in cls.KNOWN_THREAT_INTEL:
            data = cls.KNOWN_THREAT_INTEL[ip]
            return {
                "ip": ip,
                "type": "External WAN",
                **data
            }

        # Unknown external IP default enrichment
        return {
            "ip": ip,
            "type": "External WAN",
            "reputation": "UNKNOWN",
            "threat_score": 30,
            "country": "Unknown Country",
            "city": "External",
            "asn": "AS-Unknown",
            "isp": "Internet Service Provider"
        }

    @classmethod
    def enrich_asset(cls, hostname: Optional[str]) -> Dict[str, Any]:
        """Looks up asset criticality and role in enterprise CMDB."""
        if not hostname:
            return {"role": "Unregistered Host", "criticality": "LOW", "tier": "Tier-3"}
        
        h_lower = hostname.lower()
        for known_host, details in cls.ASSET_INVENTORY.items():
            if known_host in h_lower:
                return details

        return {"role": "Standard Workstation", "criticality": "MEDIUM", "tier": "Tier-3"}

    @classmethod
    def enrich_user(cls, username: Optional[str]) -> Dict[str, Any]:
        """Looks up user identity, privileges, and MFA status."""
        if not username:
            return {"privilege": "Unknown", "is_privileged": False}

        u_lower = username.lower()
        if u_lower in cls.IDENTITY_DIRECTORY:
            return cls.IDENTITY_DIRECTORY[u_lower]

        return {
            "department": "Corporate User",
            "privilege": "Standard User",
            "is_privileged": False,
            "mfa_enabled": True
        }

    @classmethod
    def enrich_all(cls, entities: Dict[str, Any]) -> Dict[str, Any]:
        """Consolidated enrichment for all alert entities."""
        src_ip = entities.get("src_ip")
        hostname = entities.get("hostname")
        user = entities.get("user")

        ip_context = cls.enrich_ip(src_ip)
        asset_context = cls.enrich_asset(hostname)
        user_context = cls.enrich_user(user)

        # Composite risk score calculation (0 - 100)
        base_score = ip_context.get("threat_score", 10)
        if asset_context.get("criticality") == "CRITICAL":
            base_score = min(100, base_score + 35)
        elif asset_context.get("criticality") == "HIGH":
            base_score = min(100, base_score + 20)

        if user_context.get("is_privileged"):
            base_score = min(100, base_score + 20)

        return {
            "ip_intelligence": ip_context,
            "asset_context": asset_context,
            "identity_context": user_context,
            "composite_risk_score": base_score
        }
