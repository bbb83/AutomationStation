#makes importing stuff easier

from models.evidence import EvidenceRecord
from models.device_record import DeviceRecord
from models.scoring_result import TestResult, ScoringResult

__all__=["EvidenceRecord", "DeviceRecord", "TestResult", "ScoringResult"]