"""Phase 7 -- scanner adapter, class mapping, and scanner-independence."""
from __future__ import annotations

from pathlib import Path


from app.graph.contract import VULN_CLASSES
from app.engines.validation.independence import Scoreboard, build_scoreboard
from app.engines.validation.scanner import (
    HeuristicMapper, LLMMapper, candidates_from_nuclei, parse_nuclei,
)
from app.engines.validation.scenario import run_scenario

FIXTURE = Path(__file__).with_name("nuclei_scan.jsonl")


def _jsonl():
    return FIXTURE.read_text()


# --------------------------------------------------------------- parsing / mapping

class TestScannerAdapter:
    def test_parse_skips_comments_and_blanks(self):
        findings = parse_nuclei(_jsonl())
        assert len(findings) == 10          # 10 JSON lines, comment ignored

    def test_every_mapped_class_is_in_the_frozen_enum(self):
        for m in candidates_from_nuclei(_jsonl()):
            if m.mappable:
                assert m.candidate.vuln_class in VULN_CLASSES

    def test_sqli_and_rce_map_by_tag_and_template(self):
        mapped = {m.raw["template-id"]: m for m in candidates_from_nuclei(_jsonl())}
        assert mapped["sqli-error-based"].candidate.vuln_class == "sqli"
        assert mapped["CVE-2021-44228"].candidate.vuln_class == "rce"

    def test_cvss_and_cve_are_carried_through(self):
        m = {x.raw["template-id"]: x for x in candidates_from_nuclei(_jsonl())}
        c = m["sqli-error-based"].candidate
        assert c.cve == "CVE-2026-4242" and c.cvss_vector

    def test_endpoint_and_param_are_extracted(self):
        m = {x.raw["template-id"]: x for x in candidates_from_nuclei(_jsonl())}
        c = m["reflected-xss"].candidate
        assert c.endpoint == "/echo" and c.param == "msg"

    def test_info_only_template_is_unmappable_not_forced(self):
        """An info-level tech-detect has no vuln_class; we return None and let
        the diagnostic surface it, rather than force a wrong label."""
        m = {x.raw["template-id"]: x for x in candidates_from_nuclei(_jsonl())}
        assert not m["tech-detect-nginx"].mappable

    def test_heuristic_never_leaves_the_enum(self):
        mapper = HeuristicMapper()
        assert mapper.map({"template-id": "totally-unknown-xyz", "info": {}}) is None


class TestLLMMapperGuardrail:
    def test_llm_proposal_is_rejected_when_outside_the_enum(self):
        """LAW 3: the LLM proposes, a deterministic check ratifies. An out-of-enum
        proposal is discarded, not trusted."""
        m = LLMMapper(ask=lambda p: "definitely-not-a-real-class")
        assert m.map({"template-id": "weird", "info": {}}) is None

    def test_llm_proposal_is_accepted_only_inside_the_enum(self):
        m = LLMMapper(ask=lambda p: "ssrf")
        assert m.map({"template-id": "weird", "info": {}}) == "ssrf"

    def test_heuristic_wins_before_the_llm_is_asked(self):
        called = []
        m = LLMMapper(ask=lambda p: called.append(1) or "rce")
        assert m.map({"template-id": "x", "info": {"tags": ["sqli"]}}) == "sqli"
        assert not called                    # heuristic placed it; LLM not consulted


# --------------------------------------------------------------- scoreboard

class TestScoreboard:
    def test_build_from_statuses(self):
        class V:
            def __init__(self, s): self.status = s
        scanner = [V("validated"), V("false_positive"), V("false_positive"),
                   V("inconclusive")]
        assist = [V("validated")]
        sb = build_scoreboard(scanner, assist, unmappable=1)
        assert sb.raw_findings == 5 and sb.confirmed == 1 and sb.disproved == 2
        assert sb.discovered == 1 and sb.unmappable == 1

    def test_pitch_names_all_three_numbers(self):
        sb = Scoreboard(raw_findings=8, confirmed=4, disproved=2, discovered=1)
        p = sb.pitch()
        assert "8" in p and "2" in p and "1" in p


# --------------------------------------------------------------- end to end

class TestIndependenceScenario:
    def test_scenario_disproves_hallucinations(self):
        sb, _ = run_scenario()
        assert sb.disproved >= 2            # the 500-SQLi and the reflected-XSS

    def test_scenario_catches_a_miss_the_scanner_never_flagged(self):
        sb, _ = run_scenario()
        assert sb.discovered >= 1           # the assist-mode IDOR

    def test_scenario_confirms_real_vulns(self):
        sb, _ = run_scenario()
        assert sb.confirmed >= 3

    def test_confirmed_disproved_inconclusive_sum_to_mapped_findings(self):
        sb, _ = run_scenario()
        mapped = sb.raw_findings - sb.unmappable
        assert sb.confirmed + sb.disproved + sb.inconclusive == mapped

    def test_scenario_is_deterministic(self):
        a, _ = run_scenario()
        b, _ = run_scenario()
        assert a.as_dict() == b.as_dict()
