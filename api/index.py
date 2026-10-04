from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from account_takeover.account_takeover_service import analyze_account_takeover


app = FastAPI(title="CyberGuard Account Takeover API")


class AccountTakeoverRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)
    profiles: Optional[List[Dict[str, Any]]] = None


def make_json_safe(value):
    if isinstance(value, dict):
        return {str(key): make_json_safe(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [make_json_safe(item) for item in value]

    if isinstance(value, pd.Timestamp):
        return value.isoformat()

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    return value


def health_response():
    return {
        "success": True,
        "service": "CyberGuard Account Takeover Detection",
        "status": "online",
        "detectors": 6,
    }


def run_analysis(request: AccountTakeoverRequest):
    if not request.events:
        raise HTTPException(
            status_code=400,
            detail="No event telemetry supplied.",
        )

    try:
        events_df = pd.DataFrame(request.events)
        profiles_df = (
            pd.DataFrame(request.profiles)
            if request.profiles
            else None
        )

        result = analyze_account_takeover(
            events=events_df,
            profiles=profiles_df,
        )

        return {
            "success": True,
            "type": "account_takeover",
            "result": make_json_safe(result),
        }

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        print("Account Takeover API error:", repr(error))
        raise HTTPException(
            status_code=500,
            detail="Account takeover analysis failed.",
        ) from error


# The Vercel Python function is mounted at /api.
# These aliases intentionally cover the function root and the public
# Account Takeover path so routing remains robust with the rewrite below.
@app.get("/")
def health_root():
    return health_response()


@app.get("/api")
def health_api():
    return health_response()


@app.get("/api/account_takeover")
def health_account_takeover():
    return health_response()


@app.post("/")
def analyze_root(request: AccountTakeoverRequest):
    return run_analysis(request)


@app.post("/api")
def analyze_api(request: AccountTakeoverRequest):
    return run_analysis(request)


@app.post("/api/account_takeover")
def analyze_account_takeover_api(request: AccountTakeoverRequest):
    return run_analysis(request)
