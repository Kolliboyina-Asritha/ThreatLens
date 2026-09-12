"""
ThreatLens AI - ML Feature Schema & Contract
Version: threatlens_features_v1.0
Contract Definition: Exact 18 features in fixed deterministic order.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# The canonical 18 features in fixed deterministic ordering
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "path_segment_count",
    "query_params_count",
    "special_char_count",
    "digits_count",
    "hyphen_count",
    "underscore_count",
    "at_symbol_count",
    "percent_count",
    "uses_https",
    "is_ip_address",
    "suspicious_keyword_count",
    "suspicious_hostname_pattern",
]

SCHEMA_VERSION = "threatlens_features_v1.0"
MODEL_VERSION = "1.0.0"


class URLFeaturesInput(BaseModel):
    """Pydantic model representing the 18 extracted URL features."""
    url_length: int = Field(..., ge=0, description="Total URL character count")
    hostname_length: int = Field(..., ge=0, description="Hostname character count")
    path_length: int = Field(..., ge=0, description="Pathname character count")
    query_length: int = Field(0, ge=0, description="Query string character count")
    dot_count: int = Field(..., ge=0, description="Total count of '.' in URL")
    subdomain_count: int = Field(..., ge=0, description="Count of subdomain parts")
    path_segment_count: int = Field(..., ge=0, description="Number of path segments")
    query_params_count: int = Field(0, ge=0, description="Count of query parameters")
    special_char_count: int = Field(..., ge=0, description="Count of non-alphanumeric chars")
    digits_count: int = Field(..., ge=0, description="Count of numerical digits in URL")
    hyphen_count: int = Field(..., ge=0, description="Count of '-' in URL")
    underscore_count: int = Field(0, ge=0, description="Count of '_' in URL")
    at_symbol_count: int = Field(0, ge=0, description="Count of '@' in URL")
    percent_count: int = Field(0, ge=0, description="Count of '%' in URL")
    uses_https: int = Field(..., ge=0, le=1, description="1 if HTTPS, 0 if HTTP")
    is_ip_address: int = Field(..., ge=0, le=1, description="1 if host is IP, 0 otherwise")
    suspicious_keyword_count: int = Field(0, ge=0, description="Count of security keywords detected")
    suspicious_hostname_pattern: int = Field(0, ge=0, le=1, description="1 if hostname pattern is suspicious")

    def to_feature_vector(self) -> List[float]:
        """Convert fields to fixed-order float vector for model inference."""
        return [
            float(self.url_length),
            float(self.hostname_length),
            float(self.path_length),
            float(self.query_length),
            float(self.dot_count),
            float(self.subdomain_count),
            float(self.path_segment_count),
            float(self.query_params_count),
            float(self.special_char_count),
            float(self.digits_count),
            float(self.hyphen_count),
            float(self.underscore_count),
            float(self.at_symbol_count),
            float(self.percent_count),
            float(self.uses_https),
            float(self.is_ip_address),
            float(self.suspicious_keyword_count),
            float(self.suspicious_hostname_pattern),
        ]


class PredictRequest(BaseModel):
    """Prediction request payload."""
    features: URLFeaturesInput


class FeatureAssociation(BaseModel):
    """Feature importance association (non-causal model attribute)."""
    feature_name: str
    importance: float
    value: float


class PredictResponse(BaseModel):
    """Structured ML prediction response."""
    prediction: str = Field(..., description="'malicious' or 'benign'")
    probability: float = Field(..., ge=0.0, le=1.0, description="Predicted probability of maliciousness (0.0 to 1.0)")
    model: str = "random_forest"
    model_version: str = MODEL_VERSION
    schema_version: str = SCHEMA_VERSION
    top_contributing_features: List[FeatureAssociation] = []


class ModelMetadata(BaseModel):
    """Model information and evaluation metrics."""
    model_name: str = "Random Forest Classifier"
    model_version: str = MODEL_VERSION
    schema_version: str = SCHEMA_VERSION
    algorithm: str = "RandomForestClassifier(n_estimators=100, max_depth=15, class_weight='balanced', random_state=42)"
    dataset_name: str
    dataset_source: str
    dataset_license: str
    sample_count: int
    train_count: int
    test_count: int
    benign_count: int
    malicious_count: int
    features: List[str]
    metrics: Dict[str, Any]
