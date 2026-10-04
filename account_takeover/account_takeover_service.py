import pandas as pd

from .account_takeover_engine import (
    detect_multiple_failed_logins,
    detect_password_spraying,
    detect_unusual_locations,
    detect_unknown_devices,
    detect_suspicious_sessions,
    detect_sudden_account_behaviour,
)

from .risk_engine import build_risk_report


# ============================================================
# ACCOUNT TAKEOVER SERVICE
# ============================================================
#
# This file is the single entry point for the entire
# Account Takeover Detection module.
#
# It connects:
#
# CSV / events
#      ↓
# 6 detectors
#      ↓
# Risk Engine
#      ↓
# Structured result
#
# Streamlit, FastAPI, or another frontend can call this
# service without needing to know how the detectors work.
# ============================================================


def analyze_account_takeover(
    events,
    profiles=None
):
    """
    Run the complete Account Takeover Detection pipeline.

    Parameters
    ----------
    events : pandas.DataFrame
        Login/session event data.

    profiles : pandas.DataFrame, optional
        User profile information used by:
        - unusual location detector
        - unknown device detector

    Returns
    -------
    dict
        Structured Account Takeover analysis result.
    """

    # ========================================================
    # VALIDATE EVENTS
    # ========================================================

    if events is None:

        raise ValueError(
            "Events data cannot be None."
        )

    if not isinstance(
        events,
        pd.DataFrame
    ):

        raise TypeError(
            "Events must be a pandas DataFrame."
        )

    if events.empty:

        return {
            "summary": {
                "users_analyzed": 0,
                "accounts_flagged": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "detection_events": 0,
                "detector_types": 6
            },
            "accounts": [],
            "detections": []
        }


    # ========================================================
    # COPY INPUT
    # ========================================================

    events = events.copy()


    # ========================================================
    # CREATE EMPTY PROFILES IF NOT PROVIDED
    # ========================================================

    if profiles is None:

        profiles = pd.DataFrame(
            columns=[
                "user_id",
                "normal_locations",
                "known_devices"
            ]
        )

    elif not isinstance(
        profiles,
        pd.DataFrame
    ):

        raise TypeError(
            "Profiles must be a pandas DataFrame."
        )

    else:

        profiles = profiles.copy()


    # ========================================================
    # DETECTOR 1
    # MULTIPLE FAILED LOGIN ATTEMPTS
    # ========================================================

    failed_login_results = (
        detect_multiple_failed_logins(
            events
        )
    )


    # ========================================================
    # DETECTOR 2
    # PASSWORD SPRAYING
    # ========================================================

    password_spraying_results = (
        detect_password_spraying(
            events
        )
    )


    # ========================================================
    # DETECTOR 3
    # UNUSUAL LOGIN LOCATION
    # ========================================================

    unusual_location_results = (
        detect_unusual_locations(
            events,
            profiles
        )
    )


    # ========================================================
    # DETECTOR 4
    # UNKNOWN / NEW DEVICE
    # ========================================================

    unknown_device_results = (
        detect_unknown_devices(
            events,
            profiles
        )
    )


    # ========================================================
    # DETECTOR 5
    # SUSPICIOUS SESSION ACTIVITY
    # ========================================================

    suspicious_session_results = (
        detect_suspicious_sessions(
            events
        )
    )


    # ========================================================
    # DETECTOR 6
    # SUDDEN ACCOUNT BEHAVIOUR CHANGE
    # ========================================================

    behaviour_change_results = (
        detect_sudden_account_behaviour(
            events
        )
    )


    # ========================================================
    # RISK ENGINE
    # ========================================================

    risk_report, detection_details = (
        build_risk_report(

            failed_login_results,

            password_spraying_results,

            unusual_location_results,

            unknown_device_results,

            suspicious_session_results,

            behaviour_change_results
        )
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    users_analyzed = (
        events["user_id"]
        .nunique()
        if "user_id" in events.columns
        else 0
    )


    accounts_flagged = (
        len(risk_report)
        if not risk_report.empty
        else 0
    )


    if risk_report.empty:

        high_risk = 0
        medium_risk = 0
        low_risk = 0

    else:

        high_risk = int(
            (
                risk_report["risk_level"]
                == "HIGH"
            ).sum()
        )

        medium_risk = int(
            (
                risk_report["risk_level"]
                == "MEDIUM"
            ).sum()
        )

        low_risk = int(
            (
                risk_report["risk_level"]
                == "LOW"
            ).sum()
        )


    detection_events = (
        len(detection_details)
        if not detection_details.empty
        else 0
    )


    # ========================================================
    # CONVERT ACCOUNT REPORT TO JSON-SAFE RECORDS
    # ========================================================

    accounts = []


    if not risk_report.empty:

        for _, row in risk_report.iterrows():

            account = {}

            for column, value in row.items():

                if pd.isna(value):

                    account[column] = None

                elif isinstance(
                    value,
                    (pd.Timestamp,)
                ):

                    account[column] = (
                        value.isoformat()
                    )

                elif hasattr(
                    value,
                    "item"
                ):

                    account[column] = (
                        value.item()
                    )

                else:

                    account[column] = value


            # ------------------------------------------------
            # Convert detector string into a list
            # ------------------------------------------------

            detector_text = account.get(
                "detectors_triggered",
                ""
            )


            if detector_text:

                account[
                    "detectors_triggered"
                ] = [
                    detector.strip()
                    for detector in
                    str(
                        detector_text
                    ).split(",")
                    if detector.strip()
                ]

            else:

                account[
                    "detectors_triggered"
                ] = []


            # ------------------------------------------------
            # Convert reasons into a list
            # ------------------------------------------------

            reason_text = account.get(
                "reasons",
                ""
            )


            if reason_text:

                account[
                    "reasons"
                ] = [
                    reason.strip()
                    for reason in
                    str(
                        reason_text
                    ).split("|")
                    if reason.strip()
                ]

            else:

                account[
                    "reasons"
                ] = []


            accounts.append(
                account
            )


    # ========================================================
    # CONVERT TECHNICAL DETECTIONS
    # ========================================================

    detections = []


    if not detection_details.empty:

        for _, row in detection_details.iterrows():

            detection = {}

            for column, value in row.items():

                if pd.isna(value):

                    detection[column] = None

                elif isinstance(
                    value,
                    (pd.Timestamp,)
                ):

                    detection[column] = (
                        value.isoformat()
                    )

                elif hasattr(
                    value,
                    "item"
                ):

                    detection[column] = (
                        value.item()
                    )

                else:

                    detection[column] = value


            detections.append(
                detection
            )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "summary": {

            "users_analyzed":
                users_analyzed,

            "accounts_flagged":
                accounts_flagged,

            "high_risk":
                high_risk,

            "medium_risk":
                medium_risk,

            "low_risk":
                low_risk,

            "detection_events":
                detection_events,

            "detector_types":
                6
        },


        "accounts":
            accounts,


        "detections":
            detections
    }


    return result
