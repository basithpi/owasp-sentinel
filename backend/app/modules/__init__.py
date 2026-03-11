"""OWASP Sentinel custom security modules."""

# C1-C10
from app.modules.ai_scorer import AIScorer
from app.modules.api_scanner import APIScanner
from app.modules.base_module import BaseModule
from app.modules.cors_tester import CORSTester
from app.modules.jwt_suite import JWTSuite
from app.modules.payload_generator import PayloadGenerator
from app.modules.protocol_fuzzer import ProtocolFuzzer
from app.modules.report_correlator import ReportCorrelator
from app.modules.subdomain_takeover import SubdomainTakeover
from app.modules.visual_recon import VisualRecon
from app.modules.waf_detector import WAFDetector

# C11-C20
from app.modules.cache_poisoning import CachePoisoningTester
from app.modules.credential_discovery import CredentialDiscovery
from app.modules.dns_zone_tester import DNSZoneTester
from app.modules.exception_fuzzer import ExceptionFuzzer
from app.modules.http_smuggling import HTTPSmuggling
from app.modules.prototype_pollution import PrototypePollutionTester
from app.modules.race_condition import RaceConditionTester
from app.modules.ssti_polyglot import SSTIPolyglotTester
from app.modules.supply_chain_analyzer import SupplyChainAnalyzer
from app.modules.websocket_tester import WebSocketTester

__all__ = [
    # C1-C10
    "BaseModule",
    "ProtocolFuzzer",
    "PayloadGenerator",
    "ReportCorrelator",
    "AIScorer",
    "VisualRecon",
    "APIScanner",
    "JWTSuite",
    "CORSTester",
    "SubdomainTakeover",
    "WAFDetector",
    # C11-C20
    "ExceptionFuzzer",
    "SupplyChainAnalyzer",
    "CredentialDiscovery",
    "DNSZoneTester",
    "WebSocketTester",
    "RaceConditionTester",
    "HTTPSmuggling",
    "CachePoisoningTester",
    "PrototypePollutionTester",
    "SSTIPolyglotTester",
]
