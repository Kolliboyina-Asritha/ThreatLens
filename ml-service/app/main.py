"""
ThreatLens AI - Machine Learning Prediction Service (FastAPI)
Exposes the trained Random Forest model via REST API for Node.js backend consumption.
"""

import os
import json
import logging
import joblib
import numpy as np
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import (
    PredictRequest,
    PredictResponse,
    FeatureAssociation,
    FEATURE_NAMES,
    MODEL_VERSION,
    SCHEMA_VERSION
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threatlens-ml")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "random_forest.joblib")
METADATA_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "model_metadata.json")

# In-memory model state loaded once during startup
ml_state: Dict[str, Any] = {
    "model": None,
    "metadata": {},
    "feature_importances": {}
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model and metadata once during application startup."""
    logger.info("Initializing ThreatLens ML Service...")
    if not os.path.exists(MODEL_PATH):
        logger.warning(f"Model file not found at {MODEL_PATH}. Training initial model...")
        from training.train import train_model
        train_model()
        
    try:
        ml_state["model"] = joblib.load(MODEL_PATH)
        logger.info(f"Loaded Random Forest model from {MODEL_PATH}")
        
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, "r") as f:
                ml_state["metadata"] = json.load(f)
                
            # Cache feature importance dictionary
            importances = ml_state["metadata"].get("metrics", {}).get("feature_importances", [])
            ml_state["feature_importances"] = {item["feature"]: item["importance"] for item in importances}
            logger.info("Loaded model metadata and feature importance registry.")
    except Exception as e:
        logger.error(f"Failed to load model during startup: {str(e)}")
        
    yield
    
    logger.info("Shutting down ThreatLens ML Service.")


app = FastAPI(
    title="ThreatLens AI - ML Prediction Service",
    version=MODEL_VERSION,
    description="FastAPI microservice serving the Random Forest URL threat classifier.",
    lifespan=lifespan
)

# Restrict CORS to local backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000", "http://127.0.0.1:5000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Service health and model availability check."""
    is_ready = ml_state["model"] is not None
    return {
        "status": "healthy" if is_ready else "degraded",
        "service": "threatlens-ml",
        "model_loaded": is_ready,
        "model_version": MODEL_VERSION,
        "schema_version": SCHEMA_VERSION
    }


@app.get("/model-info", status_code=status.HTTP_200_OK)
def get_model_info():
    """Returns model metadata, evaluation metrics, and feature schemas."""
    if not ml_state["metadata"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model metadata is currently unavailable."
        )
    return ml_state["metadata"]


@app.post("/predict", response_model=PredictResponse, status_code=status.HTTP_200_OK)
def predict(payload: PredictRequest):
    """
    Predicts URL threat probability using Random Forest classifier.
    Expects strictly validated 18-dimension feature vector.
    """
    model = ml_state.get("model")
    if model is None:
        logger.error("Predict called but Random Forest model is not loaded.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Model is temporarily unavailable."
        )
        
    try:
        # Convert Pydantic features to exact fixed-order DataFrame with feature names
        feature_vector = payload.features.to_feature_vector()
        import pandas as pd
        X_df = pd.DataFrame([feature_vector], columns=FEATURE_NAMES)
        
        # Predict class probabilities: [P(benign), P(malicious)]
        proba = model.predict_proba(X_df)[0]
        malicious_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        prediction_label = "malicious" if malicious_prob >= 0.5 else "benign"
        
        # Compute top feature associations for model transparency (non-causal)
        top_associations = []
        raw_feat_dict = payload.features.model_dump()
        feat_imp_map = ml_state.get("feature_importances", {})
        
        sorted_features = sorted(
            FEATURE_NAMES,
            key=lambda fname: feat_imp_map.get(fname, 0.0),
            reverse=True
        )
        
        for fname in sorted_features[:5]:
            top_associations.append(
                FeatureAssociation(
                    feature_name=fname,
                    importance=float(feat_imp_map.get(fname, 0.0)),
                    value=float(raw_feat_dict.get(fname, 0.0))
                )
            )
            
        logger.info(f"Prediction: label={prediction_label}, prob={malicious_prob:.4f}")
        
        return PredictResponse(
            prediction=prediction_label,
            probability=round(malicious_prob, 4),
            model="random_forest",
            model_version=MODEL_VERSION,
            schema_version=SCHEMA_VERSION,
            top_contributing_features=top_associations
        )
    except Exception as e:
        logger.error(f"Inference error during predict: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )
