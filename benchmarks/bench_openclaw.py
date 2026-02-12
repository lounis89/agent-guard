"""Functional benchmark runner for Agent Guard against OpenClaw attack scenarios.

Usage:
    python -m benchmarks.bench_openclaw                          # all scenarios
    python -m benchmarks.bench_openclaw --category cve           # CVE only
    python -m benchmarks.bench_openclaw --severity critical      # critical only
    python -m benchmarks.bench_openclaw --tag rce                # by tag
    python -m benchmarks.bench_openclaw --policy policies/custom.yaml
    python -m benchmarks.bench_openclaw --verbose                # per-scenario detail
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from agent_guard.config import load_policy_config
from agent_guard.engine import evaluate
from agent_guard.models import Decision, PolicyConfig, RequestContext
from benchmarks.scenarios import (
    SCENARIOS,
    Category,
    Scenario,
    Severity,
    get_scenarios_by_category,
    get_scenarios_by_severity,
    get_scenarios_by_tag,
)

# -- Benchmark result model ---------------------------------------------------


@dataclass
class ScenarioResult:
    """Result of running a single scenario."""

    scenario: Scenario
    decision: Decision
    passed: bool
    elapsed_us: float  # microseconds

    @property
    def action_match(self) -> bool:
        return self.decision.action == self.scenario.expected_action

    @property
    def rule_match(self) -> bool:
        if self.scenario.expected_rule_id is None:
            return True
        return self.decision.rule_id == self.scenario.expected_rule_id


@dataclass
class BenchmarkReport:
    """Aggregated benchmark results."""

    results: list[ScenarioResult] = field(default_factory=list)
    total_elapsed_us: float = 0.0

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0

    @property
    def attack_results(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.scenario.category != Category.BENIGN]

    @property
    def benign_results(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.scenario.category == Category.BENIGN]

    @property
    def true_positive_rate(self) -> float:
        """Attacks correctly blocked/redacted."""
        attacks = self.attack_results
        if not attacks:
            return 0.0
        return sum(1 for r in attacks if r.passed) / len(attacks) * 100

    @property
    def false_positive_rate(self) -> float:
        """Benign requests incorrectly blocked."""
        benign = self.benign_results
        if not benign:
            return 0.0
        return sum(1 for r in benign if not r.passed) / len(benign) * 100

    def by_category(self) -> dict[Category, list[ScenarioResult]]:
        groups: dict[Category, list[ScenarioResult]] = {}
        for r in self.results:
            groups.setdefault(r.scenario.category, []).append(r)
        return groups

    def by_severity(self) -> dict[Severity, list[ScenarioResult]]:
        groups: dict[Severity, list[ScenarioResult]] = {}
        for r in self.results:
            groups.setdefault(r.scenario.severity, []).append(r)
        return groups


# -- Runner -------------------------------------------------------------------


def _build_context(scenario: Scenario) -> RequestContext:
    """Convert a scenario into a RequestContext for policy evaluation."""
    return RequestContext(
        provider="anthropic",
        session_tier=scenario.session_tier,
        tool_name=scenario.tool_name,
        tool_args=scenario.tool_args,
        message_content=scenario.message_content,
    )


def run_benchmark(policy: PolicyConfig, scenarios: list[Scenario]) -> BenchmarkReport:
    """Run all scenarios against a policy and collect results."""
    report = BenchmarkReport()
    total_start = time.perf_counter()

    for scenario in scenarios:
        ctx = _build_context(scenario)

        start = time.perf_counter()
        decision = evaluate(policy, ctx)
        elapsed_us = (time.perf_counter() - start) * 1_000_000

        passed = decision.action == scenario.expected_action
        result = ScenarioResult(
            scenario=scenario,
            decision=decision,
            passed=passed,
            elapsed_us=elapsed_us,
        )
        report.results.append(result)

    report.total_elapsed_us = (time.perf_counter() - total_start) * 1_000_000
    return report


# -- Display ------------------------------------------------------------------

# ANSI colors
_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _icon(passed: bool) -> str:
    return f"{_GREEN}PASS{_RESET}" if passed else f"{_RED}FAIL{_RESET}"


def print_report(report: BenchmarkReport, *, verbose: bool = False) -> None:
    """Print a formatted benchmark report to stdout."""
    print()
    print(f"{_BOLD}{'=' * 72}{_RESET}")
    print(f"{_BOLD}  Agent Guard — OpenClaw Functional Benchmark{_RESET}")
    print(f"{_BOLD}{'=' * 72}{_RESET}")
    print()

    # ── Per-scenario detail (verbose) ────────────────────────────────────
    if verbose:
        for r in report.results:
            s = r.scenario
            icon = _icon(r.passed)
            print(f"  [{icon}] {s.id}")
            print(f"       {_DIM}{s.name}{_RESET}")
            print(f"       expected={s.expected_action}  got={r.decision.action}", end="")
            if r.decision.rule_id:
                print(f"  rule={r.decision.rule_id}", end="")
            print(f"  {_DIM}({r.elapsed_us:.0f}µs){_RESET}")
            if not r.passed:
                print(f"       {_RED}^ MISMATCH{_RESET}", end="")
                if s.expected_rule_id and r.decision.rule_id != s.expected_rule_id:
                    print(f"  expected_rule={s.expected_rule_id}", end="")
                print()
            print()

    # ── By category ──────────────────────────────────────────────────────
    print(f"  {_BOLD}Results by category:{_RESET}")
    print(f"  {'-' * 56}")
    for cat, results in sorted(report.by_category().items(), key=lambda x: x[0]):
        passed = sum(1 for r in results if r.passed)
        total = len(results)
        rate = passed / total * 100
        color = _GREEN if rate == 100 else _YELLOW if rate >= 80 else _RED
        print(f"    {cat.value:<24s} {color}{passed:>2d}/{total:<2d} ({rate:5.1f}%){_RESET}")
    print()

    # ── By severity ──────────────────────────────────────────────────────
    print(f"  {_BOLD}Results by severity:{_RESET}")
    print(f"  {'-' * 56}")
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for sev in severity_order:
        results = report.by_severity().get(sev, [])
        if not results:
            continue
        passed = sum(1 for r in results if r.passed)
        total = len(results)
        rate = passed / total * 100
        color = _GREEN if rate == 100 else _YELLOW if rate >= 80 else _RED
        print(f"    {sev.value:<24s} {color}{passed:>2d}/{total:<2d} ({rate:5.1f}%){_RESET}")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"  {_BOLD}Summary:{_RESET}")
    print(f"  {'-' * 56}")
    if report.pass_rate == 100:
        overall_color = _GREEN
    elif report.pass_rate >= 80:
        overall_color = _YELLOW
    else:
        overall_color = _RED
    print(f"    Total scenarios:         {report.total}")
    rate_str = f"{report.passed}/{report.total} ({report.pass_rate:.1f}%)"
    print(f"    Passed:                  {overall_color}{rate_str}{_RESET}")

    tp = report.true_positive_rate
    fp = report.false_positive_rate
    tp_color = _GREEN if tp == 100 else _YELLOW if tp >= 80 else _RED
    fp_color = _GREEN if fp == 0 else _YELLOW if fp <= 5 else _RED
    print(f"    True positive rate:      {tp_color}{tp:.1f}%{_RESET}  (attacks caught)")
    print(f"    False positive rate:     {fp_color}{fp:.1f}%{_RESET}  (benign blocked)")
    elapsed_ms = report.total_elapsed_us / 1000
    print(f"    Total eval time:         {report.total_elapsed_us:.0f}µs ({elapsed_ms:.1f}ms)")
    if report.results:
        avg = report.total_elapsed_us / report.total
        print(f"    Avg per scenario:        {avg:.0f}µs")
    print()

    # ── Failed scenarios ─────────────────────────────────────────────────
    failed = [r for r in report.results if not r.passed]
    if failed:
        print(f"  {_RED}{_BOLD}Failed scenarios ({len(failed)}):{_RESET}")
        print(f"  {'-' * 56}")
        for r in failed:
            s = r.scenario
            print(f"    {_RED}{s.id}{_RESET}")
            print(f"      expected: {s.expected_action}  got: {r.decision.action}")
            if s.cve:
                print(f"      CVE: {s.cve}")
            print()

    print(f"{_BOLD}{'=' * 72}{_RESET}")
    print()


# -- CLI ----------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Agent Guard functional benchmarks against OpenClaw attack scenarios.",
    )
    parser.add_argument(
        "--policy",
        default="policies/openclaw-hardened.yaml",
        help="Path to the policy YAML file (default: policies/openclaw-hardened.yaml)",
    )
    parser.add_argument(
        "--category",
        type=str,
        choices=[c.value for c in Category],
        help="Filter scenarios by category",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=[s.value for s in Severity],
        help="Filter scenarios by severity",
    )
    parser.add_argument(
        "--tag",
        type=str,
        help="Filter scenarios by tag",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-scenario results",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=0.0,
        help="Exit with code 1 if pass rate is below this threshold (0-100)",
    )
    args = parser.parse_args()

    # Load policy
    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
        sys.exit(1)

    policy = load_policy_config(policy_path)
    print(f"\n  Policy: {policy_path} ({len(policy.rules)} rules)")

    # Select scenarios
    scenarios = list(SCENARIOS)
    if args.category:
        scenarios = get_scenarios_by_category(Category(args.category))
    elif args.severity:
        scenarios = get_scenarios_by_severity(Severity(args.severity))
    elif args.tag:
        scenarios = get_scenarios_by_tag(args.tag)

    print(f"  Scenarios: {len(scenarios)}")

    # Run
    report = run_benchmark(policy, scenarios)

    # Display
    print_report(report, verbose=args.verbose)

    # Exit code
    if report.pass_rate < args.fail_under:
        print(
            f"  {_RED}FAIL: pass rate {report.pass_rate:.1f}% "
            f"< threshold {args.fail_under:.1f}%{_RESET}\n",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
