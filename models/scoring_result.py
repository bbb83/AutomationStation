# stores results of scoring engine. Will give transparency from storing each test, if it passed or failed,
# weights, explain it, and final scores.

from dataclasses import dataclass, field
from typing import Any

@dataclass
class TestResult:
    name: str
    category: str #existence, identity, or classification
    source: str #snmp, dhcp, dns, nmap, oui
    passed: bool
    weight: int
    explain: str
    collector_value: Any= None

    def to_dict(self) -> dict[str, Any]:
        return{
            "name": self.name,
            "category": self.category,
            "source": self.source,
            "passed": self.passed,
            "weight": self.weight,
            "explanation": self.explain,
            "collector_value": self.collector_value
        }
    
@dataclass
class ScoringResult:
    existence_score: int = 0
    identity_score: int = 0
    classification_score: int = 0
    overall_score: int= 0
    tests: list[TestResult] = field(default_factory=list)

    def add_test(self, test: TestResult) -> None:
        self.tests.append(test)

    def get_failed_tests(self)-> list[TestResult]:
        return [t for t in self.tests if not t.passed]
    
    def get_passing_tests(self) -> list[TestResult]:
        return [t for t in self.tests if t.passed]
    
    def to_dict(self) -> dict[str,Any]:
        return{
            "existence_score": self.existence_score,
            "identity_score": self.identity_score,
            "classificatoin_score": self.classification_score,
            "overall_score": self.overall_score,
            "tests": [t.to_dict() for t in self.tests],
        }