import pandas as pd


# ============================================================
# RISK LEVEL THRESHOLDS
# ============================================================

LOW_THRESHOLD = 30
HIGH_THRESHOLD = 70


# ============================================================
# DETECTOR BASE WEIGHTS
# ============================================================

DETECTOR_WEIGHTS = {
    "Multiple Failed Login Attempts": 22,
    "Password Spraying": 28,
    "Unusual Login Location": 14,
    "Unknown / New Device": 14,
    "Suspicious Session Activity": 22,
    "Sudden Account Behaviour Change": 18
}


# ============================================================
# HELPERS
# ============================================================

def safe_int(value, default=0):

    try:
        if pd.isna(value):
            return default

        return int(float(value))

    except Exception:
        return default


def safe_float(value, default=0.0):

    try:
        if pd.isna(value):
            return default

        return float(value)

    except Exception:
        return default


# ============================================================
# NORMALISE DETECTION DATA
# ============================================================

def normalise_detection(
    dataframe,
    threat_name
):

    if dataframe is None:
        return pd.DataFrame()

    if not isinstance(
        dataframe,
        pd.DataFrame
    ):
        return pd.DataFrame()

    if dataframe.empty:
        return pd.DataFrame()

    df = dataframe.copy()

    if "user_id" not in df.columns:
        return pd.DataFrame()

    df["threat"] = threat_name

    return df


# ============================================================
# INDIVIDUAL DETECTOR SCORE
# ============================================================

def calculate_detector_score(
    threat,
    detection
):

    base_score = DETECTOR_WEIGHTS.get(
        threat,
        10
    )

    evidence_bonus = 0

    # --------------------------------------------------------
    # MULTIPLE FAILED LOGINS
    # --------------------------------------------------------

    if threat == "Multiple Failed Login Attempts":

        failed_attempts = safe_int(
            detection.get(
                "failed_attempts",
                0
            )
        )

        if failed_attempts >= 10:
            evidence_bonus += 10

        elif failed_attempts >= 7:
            evidence_bonus += 7

        elif failed_attempts >= 5:
            evidence_bonus += 4

    # --------------------------------------------------------
    # PASSWORD SPRAYING
    # --------------------------------------------------------

    elif threat == "Password Spraying":

        targeted_users = safe_int(
            detection.get(
                "targeted_users",
                0
            )
        )

        if targeted_users >= 15:
            evidence_bonus += 12

        elif targeted_users >= 10:
            evidence_bonus += 9

        elif targeted_users >= 7:
            evidence_bonus += 6

        elif targeted_users >= 5:
            evidence_bonus += 3

    # --------------------------------------------------------
    # UNUSUAL LOCATION
    # --------------------------------------------------------

    elif threat == "Unusual Login Location":

        evidence_bonus += 0

    # --------------------------------------------------------
    # UNKNOWN DEVICE
    # --------------------------------------------------------

    elif threat == "Unknown / New Device":

        evidence_bonus += 0

    # --------------------------------------------------------
    # SUSPICIOUS SESSION
    # --------------------------------------------------------

    elif threat == "Suspicious Session Activity":

        action = str(
            detection.get(
                "session_action",
                ""
            )
        ).lower()

        if action == "privileged_action":
            evidence_bonus += 12

        elif action == "session_change":
            evidence_bonus += 4

    # --------------------------------------------------------
    # BEHAVIOUR CHANGE
    # --------------------------------------------------------

    elif threat == "Sudden Account Behaviour Change":

        indicator_text = str(
            detection.get(
                "indicators",
                ""
            )
        )

        indicator_count = len(
            [
                x
                for x in indicator_text.split(";")
                if x.strip()
            ]
        )

        if indicator_count >= 4:
            evidence_bonus += 10

        elif indicator_count >= 3:
            evidence_bonus += 7

        elif indicator_count >= 2:
            evidence_bonus += 4

        elif indicator_count >= 1:
            evidence_bonus += 2

    raw_score = (
        base_score
        + evidence_bonus
    )

    return {
        "base_score": base_score,
        "evidence_bonus": evidence_bonus,
        "score_contribution": raw_score
    }


# ============================================================
# REPETITION BONUS
# ============================================================
#
# Repeated detections from the same detector strengthen
# confidence, but do NOT multiply the detector's score.
#
# Maximum repetition bonus = 10 points.
# ============================================================

def calculate_repetition_bonus(
    occurrence_count
):

    count = safe_int(
        occurrence_count
    )

    if count <= 1:
        return 0

    if count == 2:
        return 3

    if count == 3:
        return 5

    if count == 4:
        return 7

    return 10


# ============================================================
# CORRELATION BONUS
# ============================================================

def calculate_correlation_bonus(
    threats
):

    threat_set = set(
        threats
    )

    bonus = 0

    correlation_reasons = []

    # --------------------------------------------------------
    # PASSWORD SPRAYING + NEW DEVICE
    # --------------------------------------------------------

    if (
        "Password Spraying" in threat_set
        and
        "Unknown / New Device" in threat_set
    ):

        bonus += 8

        correlation_reasons.append(
            "Password spraying combined with a new device"
        )

    # --------------------------------------------------------
    # PASSWORD SPRAYING + LOCATION
    # --------------------------------------------------------

    if (
        "Password Spraying" in threat_set
        and
        "Unusual Login Location" in threat_set
    ):

        bonus += 8

        correlation_reasons.append(
            "Password spraying combined with an unusual location"
        )

    # --------------------------------------------------------
    # FAILED LOGINS + NEW DEVICE
    # --------------------------------------------------------

    if (
        "Multiple Failed Login Attempts" in threat_set
        and
        "Unknown / New Device" in threat_set
    ):

        bonus += 5

        correlation_reasons.append(
            "Repeated failed logins combined with a new device"
        )

    # --------------------------------------------------------
    # FAILED LOGINS + LOCATION
    # --------------------------------------------------------

    if (
        "Multiple Failed Login Attempts" in threat_set
        and
        "Unusual Login Location" in threat_set
    ):

        bonus += 5

        correlation_reasons.append(
            "Repeated failed logins combined with an unusual location"
        )

    # --------------------------------------------------------
    # LOCATION + DEVICE
    # --------------------------------------------------------

    if (
        "Unusual Login Location" in threat_set
        and
        "Unknown / New Device" in threat_set
    ):

        bonus += 7

        correlation_reasons.append(
            "Unusual location combined with a new device"
        )

    # --------------------------------------------------------
    # SUSPICIOUS SESSION + DEVICE
    # --------------------------------------------------------

    if (
        "Suspicious Session Activity" in threat_set
        and
        "Unknown / New Device" in threat_set
    ):

        bonus += 8

        correlation_reasons.append(
            "Suspicious session activity combined with a new device"
        )

    # --------------------------------------------------------
    # SUSPICIOUS SESSION + LOCATION
    # --------------------------------------------------------

    if (
        "Suspicious Session Activity" in threat_set
        and
        "Unusual Login Location" in threat_set
    ):

        bonus += 8

        correlation_reasons.append(
            "Suspicious session activity combined with an unusual location"
        )

    # --------------------------------------------------------
    # STRONG ATTACK CHAIN
    # --------------------------------------------------------

    strong_attack_signals = {
        "Multiple Failed Login Attempts",
        "Password Spraying",
        "Unknown / New Device"
    }

    if strong_attack_signals.issubset(
        threat_set
    ):

        bonus += 8

        correlation_reasons.append(
            "Multiple authentication attack signals detected together"
        )

    # --------------------------------------------------------
    # SESSION + MULTIPLE ATTACK SIGNALS
    # --------------------------------------------------------

    attack_signals = {
        "Multiple Failed Login Attempts",
        "Password Spraying",
        "Suspicious Session Activity"
    }

    if attack_signals.issubset(
        threat_set
    ):

        bonus += 10

        correlation_reasons.append(
            "Authentication attack indicators combined with suspicious session activity"
        )

    # --------------------------------------------------------
    # BEHAVIOUR CHANGE CORROBORATION
    # --------------------------------------------------------

    if (
        "Sudden Account Behaviour Change" in threat_set
        and
        len(threat_set) >= 3
    ):

        bonus += 6

        correlation_reasons.append(
            "Behavioural change corroborates other suspicious activity"
        )

    return (
        bonus,
        correlation_reasons
    )


# ============================================================
# BUILD RISK REPORT
# ============================================================

def build_risk_report(
    failed_login_results,
    password_spraying_results,
    unusual_location_results,
    unknown_device_results,
    suspicious_session_results,
    behaviour_change_results
):

    # ========================================================
    # NORMALISE ALL DETECTORS
    # ========================================================

    detector_frames = [

        normalise_detection(
            failed_login_results,
            "Multiple Failed Login Attempts"
        ),

        normalise_detection(
            password_spraying_results,
            "Password Spraying"
        ),

        normalise_detection(
            unusual_location_results,
            "Unusual Login Location"
        ),

        normalise_detection(
            unknown_device_results,
            "Unknown / New Device"
        ),

        normalise_detection(
            suspicious_session_results,
            "Suspicious Session Activity"
        ),

        normalise_detection(
            behaviour_change_results,
            "Sudden Account Behaviour Change"
        )
    ]

    detector_frames = [
        df
        for df in detector_frames
        if not df.empty
    ]

    # ========================================================
    # NOTHING DETECTED
    # ========================================================

    if not detector_frames:

        return (

            pd.DataFrame(
                columns=[
                    "user_id",
                    "risk_score",
                    "risk_level",
                    "detector_count",
                    "detectors_triggered",
                    "reasons"
                ]
            ),

            pd.DataFrame()
        )

    # ========================================================
    # COMBINE DETECTIONS
    # ========================================================

    combined = pd.concat(
        detector_frames,
        ignore_index=True,
        sort=False
    )

    # ========================================================
    # BUILD USER REPORT
    # ========================================================

    reports = []

    detection_details = []

    for user_id, user_events in combined.groupby(
        "user_id"
    ):

        # ====================================================
        # COUNT DETECTOR OCCURRENCES
        # ====================================================

        detector_counts = (
            user_events[
                "threat"
            ]
            .value_counts()
            .to_dict()
        )

        # ====================================================
        # UNIQUE DETECTORS
        # ====================================================

        unique_detections = (
            user_events
            .drop_duplicates(
                subset=["threat"]
            )
        )

        threats = (
            unique_detections[
                "threat"
            ]
            .tolist()
        )

        # ====================================================
        # INDIVIDUAL DETECTOR SCORES
        # ====================================================

        detector_scores = []

        evidence_reasons = []

        for _, detection in (
            unique_detections.iterrows()
        ):

            threat = detection[
                "threat"
            ]

            score_data = (
                calculate_detector_score(
                    threat,
                    detection
                )
            )

            detector_scores.append(
                score_data[
                    "score_contribution"
                ]
            )

            # ================================================
            # HUMAN-READABLE EVIDENCE
            # ================================================

            if threat == "Multiple Failed Login Attempts":

                failed_attempts = safe_int(
                    detection.get(
                        "failed_attempts",
                        0
                    )
                )

                evidence_reasons.append(
                    f"{failed_attempts} failed login attempts detected"
                )

            elif threat == "Password Spraying":

                targeted_users = safe_int(
                    detection.get(
                        "targeted_users",
                        0
                    )
                )

                evidence_reasons.append(
                    f"{targeted_users} accounts targeted by password spraying"
                )

            elif threat == "Unusual Login Location":

                location = str(
                    detection.get(
                        "detected_location",
                        "unknown location"
                    )
                )

                evidence_reasons.append(
                    f"Login detected from unusual location: {location}"
                )

            elif threat == "Unknown / New Device":

                device = str(
                    detection.get(
                        "detected_device",
                        "unknown device"
                    )
                )

                evidence_reasons.append(
                    f"Previously unseen device detected: {device}"
                )

            elif threat == "Suspicious Session Activity":

                action = str(
                    detection.get(
                        "session_action",
                        "suspicious activity"
                    )
                )

                evidence_reasons.append(
                    f"Suspicious session action detected: {action}"
                )

            elif threat == "Sudden Account Behaviour Change":

                indicators = str(
                    detection.get(
                        "indicators",
                        ""
                    )
                )

                if indicators:

                    evidence_reasons.append(
                        f"Sudden behavioural change: {indicators}"
                    )

                else:

                    evidence_reasons.append(
                        "Sudden change in account behaviour detected"
                    )

        # ====================================================
        # BASE SCORE
        # ====================================================

        base_score = sum(
            detector_scores
        )

        # ====================================================
        # CORRELATION BONUS
        # ====================================================

        (
            correlation_bonus,
            correlation_reasons
        ) = calculate_correlation_bonus(
            threats
        )

        # ====================================================
        # DIMINISHING RETURNS
        # ====================================================

        sorted_scores = sorted(
            detector_scores,
            reverse=True
        )

        weighted_score = 0

        for index, score in enumerate(
            sorted_scores
        ):

            if index == 0:
                multiplier = 1.00

            elif index == 1:
                multiplier = 0.85

            elif index == 2:
                multiplier = 0.70

            elif index == 3:
                multiplier = 0.50

            elif index == 4:
                multiplier = 0.35

            else:
                multiplier = 0.20

            weighted_score += (
                score *
                multiplier
            )

        # ====================================================
        # REPETITION BONUS
        # ====================================================

        repetition_bonus = 0

        for threat, count in (
            detector_counts.items()
        ):

            bonus = calculate_repetition_bonus(
                count
            )

            repetition_bonus += bonus

            if bonus > 0:

                evidence_reasons.append(
                    f"{threat} detected {count} times; "
                    f"repeated evidence adds {bonus} risk points"
                )

        # ====================================================
        # COMBINE SCORE
        # ====================================================

        raw_score = (
            weighted_score
            + correlation_bonus
            + repetition_bonus
        )

        # ====================================================
        # STRONG EVIDENCE ADJUSTMENT
        # ====================================================

        strong_signals = 0

        if (
            "Password Spraying"
            in threats
        ):
            strong_signals += 1

        if (
            "Multiple Failed Login Attempts"
            in threats
        ):
            strong_signals += 1

        if (
            "Suspicious Session Activity"
            in threats
        ):
            strong_signals += 1

        if strong_signals >= 3:

            raw_score += 8

            evidence_reasons.append(
                "Multiple strong authentication attack signals detected"
            )

        # ====================================================
        # BEHAVIOURAL CORROBORATION
        # ====================================================

        if (
            "Sudden Account Behaviour Change"
            in threats
            and
            len(threats) >= 2
        ):

            raw_score += 5

            evidence_reasons.append(
                "Behavioural anomaly corroborates other suspicious signals"
            )

        # ====================================================
        # CAP SCORE
        # ====================================================

        risk_score = int(
            round(
                min(
                    raw_score,
                    100
                )
            )
        )

        # ====================================================
        # RISK LEVEL
        # ====================================================

        if risk_score >= HIGH_THRESHOLD:

            risk_level = "HIGH"

        elif risk_score >= LOW_THRESHOLD:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # ====================================================
        # COMBINED REASONS
        # ====================================================

        all_reasons = (
            evidence_reasons
            +
            correlation_reasons
        )

        all_reasons = list(
            dict.fromkeys(
                all_reasons
            )
        )

        # ====================================================
        # DETECTOR SUMMARY
        # ====================================================

        detectors_triggered = ", ".join(
            threats
        )

        # ====================================================
        # FINAL USER REPORT
        # ====================================================

        reports.append({

            "user_id":
                user_id,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "detector_count":
                len(threats),

            "detectors_triggered":
                detectors_triggered,

            "reasons":
                " | ".join(
                    all_reasons
                ),

            "base_score":
                round(
                    base_score,
                    2
                ),

            "correlation_bonus":
                correlation_bonus,

            "repetition_bonus":
                repetition_bonus
        })

        # ====================================================
        # TECHNICAL DETECTION DETAILS
        # ====================================================

        for _, detection in (
            unique_detections.iterrows()
        ):

            detail = detection.to_dict()

            detail[
                "user_risk_score"
            ] = risk_score

            detail[
                "user_risk_level"
            ] = risk_level

            detail[
                "detector_count"
            ] = len(
                threats
            )

            detail[
                "detector_occurrences"
            ] = detector_counts.get(
                detection["threat"],
                1
            )

            detail[
                "repetition_bonus"
            ] = calculate_repetition_bonus(
                detector_counts.get(
                    detection["threat"],
                    1
                )
            )

            detection_details.append(
                detail
            )

    # ========================================================
    # DATAFRAMES
    # ========================================================

    risk_report = pd.DataFrame(
        reports
    )

    detection_details = pd.DataFrame(
        detection_details
    )

    # ========================================================
    # SORT BY RISK
    # ========================================================

    risk_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    if not risk_report.empty:

        risk_report[
            "_risk_order"
        ] = (
            risk_report[
                "risk_level"
            ]
            .map(
                risk_order
            )
        )

        risk_report = (
            risk_report
            .sort_values(
                [
                    "_risk_order",
                    "risk_score"
                ],
                ascending=[
                    False,
                    False
                ]
            )
            .drop(
                columns=[
                    "_risk_order"
                ]
            )
            .reset_index(
                drop=True
            )
        )

    # ========================================================
    # RETURN
    # ========================================================

    return (
        risk_report,
        detection_details
    )
