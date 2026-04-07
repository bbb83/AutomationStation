#gives the system for the end score of existence, identity, and classification score combined

from models.device_record import DeviceRecord
from models.scoring_result import ScoringResult
from scoring.existence import score_existence
from scoring.identity import score_identity
from scoring.classification import score_classification

class ScoringSystem:
    def score(self, device: DeviceRecord) -> ScoringResult:
        existence_score, existence_tests = score_existence(device)
        identity_score, identity_tests = score_identity(device)
        classification_score, classification_tests = score_classification(device)

        overall_score = round((existence_score + identity_score + classification_score)/ 3)

        final_result = ScoringResult(
            existence_score= existence_score,
            identity_score= identity_score,
            classification_score= classification_score,
            overall_score = overall_score,
            tests=[*existence_tests, *identity_tests, *classification_tests],

        )

        return final_result