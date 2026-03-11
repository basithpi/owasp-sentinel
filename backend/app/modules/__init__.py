"""OWASP Sentinel custom security modules."""

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

__all__ = [
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
]
