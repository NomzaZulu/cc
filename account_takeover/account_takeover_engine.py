import pandas as pd


# ============================================================
# CYBERGUARD
# CREDENTIAL THEFT & ACCOUNT TAKEOVER DETECTION ENGINE
# ============================================================




# ============================================================
# INPUT SAFETY HELPERS
# ============================================================

def _prepare_events(events, required_columns=None, optional_columns=None):
    """
    Prepare organisation telemetry without requiring attack labels.

    Required columns are necessary for a detector to operate. If one of
    them is missing, the detector should return an empty result instead
    of crashing the entire analysis pipeline. Optional columns are added
    with safe defaults when unavailable.
    """

    if events is None or not isinstance(events, pd.DataFrame):
        return None, list(required_columns or [])

    events = events.copy()

    required_columns = list(required_columns or [])
    optional_columns = list(optional_columns or [])

    missing_required = [
        column
        for column in required_columns
        if column not in events.columns
    ]

    if missing_required:
        return None, missing_required

    for column in optional_columns:
        if column not in events.columns:
            events[column] = ""

    return events, []


def _empty_result(columns):
    """Return a consistent empty detector result."""
    return pd.DataFrame(columns=columns)


# ============================================================
# DETECTOR 1: MULTIPLE FAILED LOGIN ATTEMPTS
# ============================================================

def detect_multiple_failed_logins(
    events,
    threshold=5,
    window_minutes=10
):

    events, missing_columns = _prepare_events(
        events,
        required_columns=[
            "timestamp",
            "user_id",
            "login_status"
        ],
        optional_columns=["ip_address"]
    )

    if events is None:
        return _empty_result([
            "user_id",
            "threat",
            "failed_attempts",
            "window_minutes",
            "unique_source_ips",
            "source_ips",
            "first_attempt",
            "last_attempt",
            "attempts_per_minute",
            "risk"
        ])

    # ========================================================
    # VALIDATE / CONVERT TIMESTAMP
    # ========================================================

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    events = events.dropna(
        subset=[
            "timestamp",
            "user_id"
        ]
    )

    # ========================================================
    # ONLY FAILED LOGIN EVENTS
    # ========================================================

    failed = events[
        events["login_status"]
        .astype(str)
        .str.lower()
        .eq("failed")
    ].copy()

    detections = []

    # ========================================================
    # ANALYSE EACH USER
    # ========================================================

    for user_id, user_events in failed.groupby(
        "user_id"
    ):

        user_events = (
            user_events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        # ----------------------------------------------------
        # Sliding window
        # ----------------------------------------------------

        left = 0

        for right in range(
            len(user_events)
        ):

            window_start = user_events.loc[
                right,
                "timestamp"
            ]

            window_end = (
                window_start
                + pd.Timedelta(
                    minutes=window_minutes
                )
            )

            # Move through events occurring inside
            # the current window
            while (
                left <= right
                and user_events.loc[
                    left,
                    "timestamp"
                ] < window_start
            ):

                left += 1

            attempts = user_events[
                (
                    user_events["timestamp"]
                    >= window_start
                )
                &
                (
                    user_events["timestamp"]
                    <= window_end
                )
            ]

            # =================================================
            # THRESHOLD CHECK
            # =================================================

            if len(attempts) >= threshold:

                # ---------------------------------------------
                # Source IP information
                # ---------------------------------------------

                source_ips = (
                    attempts["ip_address"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                )

                unique_ip_count = len(
                    source_ips
                )

                # ---------------------------------------------
                # Time span
                # ---------------------------------------------

                first_attempt = (
                    attempts["timestamp"].min()
                )

                last_attempt = (
                    attempts["timestamp"].max()
                )

                duration_seconds = (
                    last_attempt
                    - first_attempt
                ).total_seconds()

                # ---------------------------------------------
                # Failure rate
                # ---------------------------------------------

                if duration_seconds > 0:

                    attempts_per_minute = (
                        len(attempts)
                        /
                        (duration_seconds / 60)
                    )

                else:

                    attempts_per_minute = float(
                        len(attempts)
                    )

                # ---------------------------------------------
                # Detection
                # ---------------------------------------------

                detections.append({

                    "user_id":
                        user_id,

                    "threat":
                        "Multiple Failed Login Attempts",

                    "failed_attempts":
                        len(attempts),

                    "window_minutes":
                        window_minutes,

                    "unique_source_ips":
                        unique_ip_count,

                    "source_ips":
                        ", ".join(
                            source_ips
                        ),

                    "first_attempt":
                        first_attempt,

                    "last_attempt":
                        last_attempt,

                    "attempts_per_minute":
                        round(
                            attempts_per_minute,
                            2
                        ),

                    "risk":
                        "HIGH"
                })

                # ---------------------------------------------
                # One detection per user for this detector
                # ---------------------------------------------

                break

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return pd.DataFrame(
        detections
    )

# ============================================================
# DETECTOR 2: PASSWORD SPRAYING
# ============================================================

def detect_password_spraying(
    events,
    min_users=5,
    window_minutes=10
):

    events, missing_columns = _prepare_events(
        events,
        required_columns=[
            "timestamp",
            "user_id",
            "ip_address",
            "login_status"
        ]
    )

    if events is None:
        return _empty_result([
            "ip_address",
            "threat",
            "targeted_users",
            "targeted_user_ids",
            "attempt_count",
            "first_attempt",
            "last_attempt",
            "risk"
        ])

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # Only failed login attempts
    # --------------------------------------------------------

    failed = events[
        events["login_status"]
        .astype(str)
        .str.lower()
        .eq("failed")
    ].copy()

    failed = failed.dropna(
        subset=[
            "timestamp",
            "ip_address",
            "user_id"
        ]
    )

    detections = []

    # --------------------------------------------------------
    # Analyse each source IP
    # --------------------------------------------------------

    for ip_address, ip_events in failed.groupby(
        "ip_address"
    ):

        ip_events = ip_events.sort_values(
            "timestamp"
        ).reset_index(drop=True)

        timestamps = ip_events[
            "timestamp"
        ].tolist()

        # ----------------------------------------------------
        # Sliding time window
        # ----------------------------------------------------

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            window_end = (
                window_start
                + pd.Timedelta(
                    minutes=window_minutes
                )
            )

            window_events = ip_events[
                (ip_events["timestamp"] >= window_start)
                &
                (ip_events["timestamp"] <= window_end)
            ]

            # ------------------------------------------------
            # Unique targeted accounts
            # ------------------------------------------------

            targeted_users = (
                window_events["user_id"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            unique_users = len(
                targeted_users
            )

            # ------------------------------------------------
            # Password spraying threshold
            # ------------------------------------------------

            if unique_users >= min_users:

                detections.append({

                    "ip_address": ip_address,

                    "threat": (
                        "Password Spraying"
                    ),

                    "targeted_users": unique_users,

                    "targeted_user_ids": (
                        ", ".join(
                            targeted_users
                        )
                    ),

                    "attempt_count": len(
                        window_events
                    ),

                    "first_attempt": (
                        window_events[
                            "timestamp"
                        ].min()
                    ),

                    "last_attempt": (
                        window_events[
                            "timestamp"
                        ].max()
                    ),

                    "risk": "HIGH"
                })

                # --------------------------------------------
                # Stop after first confirmed window for
                # this IP
                # --------------------------------------------

                break

    return pd.DataFrame(
        detections
    )


# ============================================================
# DETECTOR 3: UNUSUAL LOGIN LOCATION
# ============================================================

def detect_unusual_locations(
    events,
    profiles=None,
    min_history=3
):

    events, missing_columns = _prepare_events(
        events,
        required_columns=[
            "timestamp",
            "user_id",
            "location"
        ],
        optional_columns=["event_id"]
    )

    if events is None:
        return _empty_result([
            "event_id",
            "user_id",
            "threat",
            "detected_location",
            "normal_locations",
            "baseline_source",
            "historical_events",
            "timestamp",
            "risk"
        ])

    # ========================================================
    # PREPARE EVENTS
    # ========================================================

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    events = events.dropna(
        subset=[
            "timestamp",
            "user_id",
            "location"
        ]
    ).copy()

    events["location"] = (
        events["location"]
        .astype(str)
        .str.strip()
    )

    # ========================================================
    # BUILD PROFILE-BASED LOCATION BASELINE
    # ========================================================

    profile_locations = {}

    if profiles is not None:

        profiles = profiles.copy()

        if (
            "user_id" in profiles.columns
            and
            "normal_locations" in profiles.columns
        ):

            for _, profile in profiles.iterrows():

                normal_locations = [
                    location.strip()
                    for location in str(
                        profile["normal_locations"]
                    ).split("|")
                    if location.strip()
                ]

                if normal_locations:

                    profile_locations[
                        str(profile["user_id"])
                    ] = set(
                        normal_locations
                    )

    # ========================================================
    # SORT HISTORICAL EVENTS
    # ========================================================

    events = events.sort_values(
        ["user_id", "timestamp"]
    ).reset_index(
        drop=True
    )

    detections = []

    # ========================================================
    # ANALYSE EACH USER
    # ========================================================

    for user_id, user_events in events.groupby(
        "user_id"
    ):

        user_events = (
            user_events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        user_id = str(user_id)

        profile_baseline = profile_locations.get(
            user_id,
            set()
        )

        # ====================================================
        # CHECK EACH LOGIN
        # ====================================================

        for i, event in user_events.iterrows():

            current_location = (
                str(event["location"]).strip()
            )

            # ------------------------------------------------
            # MODE 1:
            # Organisation profile has a known baseline
            # ------------------------------------------------

            if profile_baseline:

                known_locations = profile_baseline

                baseline_source = (
                    "Organisation profile"
                )

            # ------------------------------------------------
            # MODE 2:
            # Learn baseline from historical events
            # ------------------------------------------------

            else:

                historical_events = (
                    user_events.iloc[:i]
                )

                historical_locations = (
                    historical_events["location"]
                    .dropna()
                    .astype(str)
                    .str.strip()
                )

                location_counts = (
                    historical_locations
                    .value_counts()
                )

                known_locations = set(
                    location_counts.index
                )

                baseline_source = (
                    "Historical user activity"
                )

            # ------------------------------------------------
            # Not enough history?
            # ------------------------------------------------

            if (
                not profile_baseline
                and
                i < min_history
            ):

                continue

            # ------------------------------------------------
            # Compare current location
            # ------------------------------------------------

            if current_location not in known_locations:

                detections.append({

                    "event_id":
                        event["event_id"],

                    "user_id":
                        user_id,

                    "threat":
                        "Unusual Login Location",

                    "detected_location":
                        current_location,

                    "normal_locations":
                        ", ".join(
                            sorted(
                                known_locations
                            )
                        ),

                    "baseline_source":
                        baseline_source,

                    "historical_events":
                        i,

                    "timestamp":
                        event["timestamp"],

                    "risk":
                        "MEDIUM"
                })

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return pd.DataFrame(
        detections
    )


# ============================================================
# DETECTOR 4: UNKNOWN / NEW DEVICE
# ============================================================

def detect_unknown_devices(
    events,
    profiles=None,
    min_history=3
):

    events, missing_columns = _prepare_events(
        events,
        required_columns=[
            "timestamp",
            "user_id",
            "device"
        ],
        optional_columns=["event_id"]
    )

    if events is None:
        return _empty_result([
            "event_id",
            "user_id",
            "threat",
            "detected_device",
            "known_devices",
            "baseline_source",
            "historical_events",
            "timestamp",
            "risk"
        ])

    # ========================================================
    # PREPARE EVENTS
    # ========================================================

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    events = events.dropna(
        subset=[
            "timestamp",
            "user_id",
            "device"
        ]
    ).copy()

    events["device"] = (
        events["device"]
        .astype(str)
        .str.strip()
    )

    # ========================================================
    # BUILD PROFILE-BASED DEVICE BASELINE
    # ========================================================

    profile_devices = {}

    if profiles is not None:

        profiles = profiles.copy()

        if (
            "user_id" in profiles.columns
            and
            "known_devices" in profiles.columns
        ):

            for _, profile in profiles.iterrows():

                known_devices = [
                    device.strip()
                    for device in str(
                        profile["known_devices"]
                    ).split("|")
                    if device.strip()
                ]

                if known_devices:

                    profile_devices[
                        str(profile["user_id"])
                    ] = set(
                        known_devices
                    )

    # ========================================================
    # SORT HISTORICAL EVENTS
    # ========================================================

    events = events.sort_values(
        ["user_id", "timestamp"]
    ).reset_index(
        drop=True
    )

    detections = []

    # ========================================================
    # ANALYSE EACH USER
    # ========================================================

    for user_id, user_events in events.groupby(
        "user_id"
    ):

        user_events = (
            user_events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        user_id = str(user_id)

        profile_baseline = profile_devices.get(
            user_id,
            set()
        )

        # ====================================================
        # CHECK EACH LOGIN
        # ====================================================

        for i, event in user_events.iterrows():

            current_device = (
                str(event["device"]).strip()
            )

            # ------------------------------------------------
            # MODE 1:
            # Organisation profile baseline
            # ------------------------------------------------

            if profile_baseline:

                known_devices = profile_baseline

                baseline_source = (
                    "Organisation profile"
                )

            # ------------------------------------------------
            # MODE 2:
            # Historical user baseline
            # ------------------------------------------------

            else:

                historical_events = (
                    user_events.iloc[:i]
                )

                historical_devices = (
                    historical_events["device"]
                    .dropna()
                    .astype(str)
                    .str.strip()
                )

                device_counts = (
                    historical_devices
                    .value_counts()
                )

                known_devices = set(
                    device_counts.index
                )

                baseline_source = (
                    "Historical user activity"
                )

            # ------------------------------------------------
            # Not enough history
            # ------------------------------------------------

            if (
                not profile_baseline
                and
                i < min_history
            ):

                continue

            # ------------------------------------------------
            # Compare current device
            # ------------------------------------------------

            if current_device not in known_devices:

                detections.append({

                    "event_id":
                        event["event_id"],

                    "user_id":
                        user_id,

                    "threat":
                        "Unknown / New Device",

                    "detected_device":
                        current_device,

                    "known_devices":
                        ", ".join(
                            sorted(
                                known_devices
                            )
                        ),

                    "baseline_source":
                        baseline_source,

                    "historical_events":
                        i,

                    "timestamp":
                        event["timestamp"],

                    "risk":
                        "MEDIUM"
                })

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return pd.DataFrame(
        detections
    )


# ============================================================
# DETECTOR 5: SUSPICIOUS SESSION ACTIVITY
# ============================================================

def detect_suspicious_sessions(
    events,
    min_session_events=3,
    rapid_action_window_minutes=5
):

    events, missing_columns = _prepare_events(
        events,
        required_columns=[
            "timestamp",
            "user_id",
            "login_status"
        ],
        optional_columns=[
            "ip_address",
            "location",
            "device"
        ]
    )

    if events is None:
        return _empty_result([
            "user_id",
            "threat",
            "indicators",
            "baseline_events",
            "recent_events",
            "baseline_failed_rate",
            "recent_failed_rate",
            "baseline_ips",
            "recent_ips",
            "baseline_locations",
            "recent_locations",
            "baseline_devices",
            "recent_devices",
            "risk"
        ])

    # ========================================================
    # PREPARE DATA
    # ========================================================

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    required_columns = [
        "event_id",
        "user_id",
        "session_id",
        "session_action",
        "timestamp"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in events.columns
    ]

    if missing_columns:

        return pd.DataFrame(
            columns=[
                "event_id",
                "user_id",
                "session_id",
                "threat",
                "session_action",
                "device",
                "location",
                "timestamp",
                "session_events",
                "privileged_actions",
                "rapid_actions",
                "risk"
            ]
        )

    events = events.dropna(
        subset=[
            "timestamp",
            "user_id",
            "session_id"
        ]
    ).copy()

    # Device and location are useful evidence but are not required
    # for session-level detection.
    if "device" not in events.columns:
        events["device"] = ""

    if "location" not in events.columns:
        events["location"] = ""

    events["session_action"] = (
        events["session_action"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    events = events.sort_values(
        [
            "user_id",
            "session_id",
            "timestamp"
        ]
    )

    detections = []

    # ========================================================
    # SESSION-LEVEL ANALYSIS
    # ========================================================

    for (
        user_id,
        session_id
    ), session_events in events.groupby(
        [
            "user_id",
            "session_id"
        ]
    ):

        session_events = (
            session_events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        if session_events.empty:
            continue

        # ----------------------------------------------------
        # Basic session information
        # ----------------------------------------------------

        session_event_count = len(
            session_events
        )

        privileged_events = session_events[
            session_events["session_action"]
            == "privileged_action"
        ]

        session_change_events = session_events[
            session_events["session_action"]
            == "session_change"
        ]

        privileged_count = len(
            privileged_events
        )

        session_change_count = len(
            session_change_events
        )

        # ----------------------------------------------------
        # Detect rapid actions
        # ----------------------------------------------------

        rapid_actions = 0

        timestamps = (
            session_events["timestamp"]
            .tolist()
        )

        for i in range(
            1,
            len(timestamps)
        ):

            time_difference = (
                timestamps[i]
                - timestamps[i - 1]
            ).total_seconds() / 60

            if time_difference <= (
                rapid_action_window_minutes
            ):

                rapid_actions += 1

        # ====================================================
        # DETERMINE SUSPICIOUS BEHAVIOUR
        # ====================================================

        suspicious_reasons = []

        # ----------------------------------------------------
        # Condition 1:
        # Privileged action
        # ----------------------------------------------------

        if privileged_count > 0:

            suspicious_reasons.append(
                "Privileged action performed"
            )

        # ----------------------------------------------------
        # Condition 2:
        # Session change
        # ----------------------------------------------------

        if session_change_count > 0:

            suspicious_reasons.append(
                "Session change detected"
            )

        # ----------------------------------------------------
        # Condition 3:
        # Rapid activity
        # ----------------------------------------------------

        if rapid_actions > 0:

            suspicious_reasons.append(
                "Multiple actions occurred within "
                f"{rapid_action_window_minutes} minutes"
            )

        # ----------------------------------------------------
        # Condition 4:
        # Multiple indicators in same session
        # ----------------------------------------------------

        indicator_count = 0

        if privileged_count > 0:
            indicator_count += 1

        if session_change_count > 0:
            indicator_count += 1

        if rapid_actions > 0:
            indicator_count += 1

        # ----------------------------------------------------
        # A single ordinary session action is not enough.
        #
        # We require either:
        #
        #   privileged action
        #
        # OR
        #
        #   multiple behavioural indicators
        #
        # ----------------------------------------------------

        suspicious = False

        if privileged_count > 0:

            suspicious = True

        elif indicator_count >= 2:

            suspicious = True

        elif (
            session_event_count >= min_session_events
            and
            rapid_actions >= 2
        ):

            suspicious = True

        if not suspicious:
            continue

        # ====================================================
        # RISK LEVEL
        # ====================================================

        risk = "MEDIUM"

        if privileged_count > 0:

            risk = "HIGH"

        elif indicator_count >= 2:

            risk = "HIGH"

        # ====================================================
        # CREATE DETECTION
        # ====================================================

        first_event = (
            session_events["timestamp"].min()
        )

        last_event = (
            session_events["timestamp"].max()
        )

        first_row = session_events.iloc[0]

        detections.append({

            "event_id":
                first_row["event_id"],

            "user_id":
                user_id,

            "session_id":
                session_id,

            "threat":
                "Suspicious Session Activity",

            "session_action":
                ", ".join(
                    sorted(
                        session_events[
                            "session_action"
                        ]
                        .dropna()
                        .unique()
                        .tolist()
                    )
                ),

            "device":
                first_row.get(
                    "device",
                    ""
                ),

            "location":
                first_row.get(
                    "location",
                    ""
                ),

            "timestamp":
                first_event,

            "session_events":
                session_event_count,

            "privileged_actions":
                privileged_count,

            "session_changes":
                session_change_count,

            "rapid_actions":
                rapid_actions,

            "reasons":
                " | ".join(
                    suspicious_reasons
                ),

            "risk":
                risk
        })

    # ========================================================
    # RETURN
    # ========================================================

    return pd.DataFrame(
        detections
    )


# ============================================================
# DETECTOR 6: SUDDEN ACCOUNT BEHAVIOUR CHANGE
# ============================================================

def detect_sudden_account_behaviour(
    events,
    minimum_events=6,
    baseline_ratio=0.5,
    activity_multiplier=2.0,
    minimum_indicators=1
):
    """
    Detect significant changes in a user's behaviour.

    The detector does NOT use:
        - scenario
        - is_anomaly

    A user's earlier activity is used as the baseline.
    Later activity is compared against that baseline.

    Indicators:
        - sudden increase in login activity
        - sudden increase in failed-login rate
        - sudden increase in IP diversity
        - sudden increase in location diversity
        - sudden increase in device diversity
    """

    events = events.copy()

    # ========================================================
    # PREPARE DATA
    # ========================================================

    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="coerce"
    )

    events = events.dropna(
        subset=[
            "timestamp",
            "user_id"
        ]
    ).copy()

    events = events.sort_values(
        [
            "user_id",
            "timestamp"
        ]
    )

    detections = []

    # ========================================================
    # ANALYSE EACH USER
    # ========================================================

    for user_id, user_events in events.groupby(
        "user_id"
    ):

        user_events = (
            user_events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        # ----------------------------------------------------
        # Need enough events
        # ----------------------------------------------------

        if len(user_events) < minimum_events:
            continue

        # ----------------------------------------------------
        # Determine baseline/recent split
        #
        # Example:
        # 10 events
        # baseline = first 5
        # recent   = last 5
        # ----------------------------------------------------

        split_index = max(
            1,
            int(
                len(user_events)
                * baseline_ratio
            )
        )

        baseline = user_events.iloc[
            :split_index
        ].copy()

        recent = user_events.iloc[
            split_index:
        ].copy()

        if baseline.empty or recent.empty:
            continue

        # ====================================================
        # ACTIVITY VOLUME
        # ====================================================

        baseline_activity = len(
            baseline
        )

        recent_activity = len(
            recent
        )

        # ====================================================
        # FAILED LOGIN RATE
        # ====================================================

        baseline_failed_rate = (
            baseline["login_status"]
            .astype(str)
            .str.lower()
            .eq("failed")
            .mean()
        )

        recent_failed_rate = (
            recent["login_status"]
            .astype(str)
            .str.lower()
            .eq("failed")
            .mean()
        )

        # ====================================================
        # IP DIVERSITY
        # ====================================================

        baseline_ips = (
            baseline["ip_address"]
            .dropna()
            .nunique()
            if "ip_address" in baseline.columns
            else 0
        )

        recent_ips = (
            recent["ip_address"]
            .dropna()
            .nunique()
            if "ip_address" in recent.columns
            else 0
        )

        # ====================================================
        # LOCATION DIVERSITY
        # ====================================================

        baseline_locations = (
            baseline["location"]
            .dropna()
            .nunique()
            if "location" in baseline.columns
            else 0
        )

        recent_locations = (
            recent["location"]
            .dropna()
            .nunique()
            if "location" in recent.columns
            else 0
        )

        # ====================================================
        # DEVICE DIVERSITY
        # ====================================================

        baseline_devices = (
            baseline["device"]
            .dropna()
            .nunique()
            if "device" in baseline.columns
            else 0
        )

        recent_devices = (
            recent["device"]
            .dropna()
            .nunique()
            if "device" in recent.columns
            else 0
        )

        indicators = []

        # ====================================================
        # INDICATOR 1
        # Sudden increase in activity
        # ====================================================

        if (
            baseline_activity > 0
            and
            recent_activity
            >= baseline_activity
            * activity_multiplier
        ):

            indicators.append(
                "Sudden increase in login activity"
            )

        # ====================================================
        # INDICATOR 2
        # Sudden increase in failed logins
        # ====================================================

        failed_rate_threshold = max(
            baseline_failed_rate
            * activity_multiplier,
            0.30
        )

        if (
            recent_failed_rate
            >= failed_rate_threshold
            and
            recent_failed_rate
            > baseline_failed_rate
        ):

            indicators.append(
                "Sudden increase in failed logins"
            )

        # ====================================================
        # INDICATOR 3
        # Increased IP diversity
        # ====================================================

        if (
            baseline_ips > 0
            and
            recent_ips
            >= baseline_ips
            * activity_multiplier
        ):

            indicators.append(
                "Sudden increase in IP diversity"
            )

        # ====================================================
        # INDICATOR 4
        # Increased location diversity
        # ====================================================

        if (
            baseline_locations > 0
            and
            recent_locations
            >= baseline_locations
            * activity_multiplier
        ):

            indicators.append(
                "Sudden increase in location diversity"
            )

        # ====================================================
        # INDICATOR 5
        # Increased device diversity
        # ====================================================

        if (
            baseline_devices > 0
            and
            recent_devices
            >= baseline_devices
            * activity_multiplier
        ):

            indicators.append(
                "Sudden increase in device diversity"
            )

        # ====================================================
        # GENERATE DETECTION
        # ====================================================

        if len(indicators) >= minimum_indicators:

            risk = "MEDIUM"

            if len(indicators) >= 3:

                risk = "HIGH"

            detections.append({

                "user_id":
                    user_id,

                "threat":
                    "Sudden Account Behaviour Change",

                "indicators":
                    "; ".join(
                        indicators
                    ),

                "baseline_events":
                    baseline_activity,

                "recent_events":
                    recent_activity,

                "baseline_failed_rate":
                    round(
                        baseline_failed_rate,
                        3
                    ),

                "recent_failed_rate":
                    round(
                        recent_failed_rate,
                        3
                    ),

                "baseline_ips":
                    baseline_ips,

                "recent_ips":
                    recent_ips,

                "baseline_locations":
                    baseline_locations,

                "recent_locations":
                    recent_locations,

                "baseline_devices":
                    baseline_devices,

                "recent_devices":
                    recent_devices,

                "risk":
                    risk
            })

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return pd.DataFrame(
        detections
    )


# ============================================================
# DIRECT ENGINE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print(
        " CYBERGUARD ACCOUNT TAKEOVER DETECTION ENGINE"
    )
    print("=" * 60)

    try:

        profiles = pd.read_csv(
            "cyberguard_organisation_profiles.csv"
        )

        events = pd.read_csv(
            "cyberguard_login_events.csv"
        )

        print(
            f"\nLoaded {len(profiles)} organisation users."
        )

        print(
            f"Loaded {len(events)} login events."
        )

        # ----------------------------------------------------
        # Detector 1
        # ----------------------------------------------------

        result_1 = detect_multiple_failed_logins(
            events
        )

        print(
            "\n[1] Multiple Failed Login Attempts"
        )

        print(
            f"Detections: {len(result_1)}"
        )

        # ----------------------------------------------------
        # Detector 2
        # ----------------------------------------------------

        result_2 = detect_password_spraying(
            events
        )

        print(
            "\n[2] Password Spraying"
        )

        print(
            f"Detections: {len(result_2)}"
        )

        # ----------------------------------------------------
        # Detector 3
        # ----------------------------------------------------

        result_3 = detect_unusual_locations(
            events,
            profiles
        )

        print(
            "\n[3] Unusual Login Location"
        )

        print(
            f"Detections: {len(result_3)}"
        )

        # ----------------------------------------------------
        # Detector 4
        # ----------------------------------------------------

        result_4 = detect_unknown_devices(
            events,
            profiles
        )

        print(
            "\n[4] Unknown / New Device"
        )

        print(
            f"Detections: {len(result_4)}"
        )

        # ----------------------------------------------------
        # Detector 5
        # ----------------------------------------------------

        result_5 = detect_suspicious_sessions(
            events
        )

        print(
            "\n[5] Suspicious Session Activity"
        )

        print(
            f"Detections: {len(result_5)}"
        )

        # ----------------------------------------------------
        # Detector 6
        # ----------------------------------------------------

        result_6 = detect_sudden_account_behaviour(
            events
        )

        print(
            "\n[6] Sudden Account Behaviour Change"
        )

        print(
            f"Detections: {len(result_6)}"
        )

        if not result_6.empty:

            print(
                "\nBehaviour change detections:"
            )

            print(
                result_6.to_string(
                    index=False
                )
            )

        # ----------------------------------------------------
        # Final summary
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print(" DETECTION SUMMARY")
        print("=" * 60)

        print(
            f"\n1. Multiple failed logins : {len(result_1)}"
        )

        print(
            f"2. Password spraying      : {len(result_2)}"
        )

        print(
            f"3. Unusual locations      : {len(result_3)}"
        )

        print(
            f"4. Unknown devices        : {len(result_4)}"
        )

        print(
            f"5. Suspicious sessions    : {len(result_5)}"
        )

        print(
            f"6. Behaviour changes      : {len(result_6)}"
        )

        print(
            "\nAll six detectors executed."
        )

    except FileNotFoundError as e:

        print(
            "\nERROR: Required CSV file was not found."
        )

        print(
            f"Missing file: {e.filename}"
        )

    except Exception as e:

        print(
            f"\nERROR: {str(e)}"
        )
