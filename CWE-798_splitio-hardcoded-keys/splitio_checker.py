import os
from typing import Any, Dict
import requests
import urllib3

urllib3.disable_warnings()

# Retrieve the fallback target key from environment variables if set
DUMMY_KEY = os.getenv("SPLIT_KEY", "SPLITIO_SDK_KEY_HERE")


def display_feature_flags(payload: Dict[str, Any]) -> None:
    """Parses and logs the feature flags retrieved from the Split.io API payload.

    Args:
        payload: The JSON response dictionary from the Split.io API.
    """
    feature_flags = payload.get("splits", [])
    print(f"[+] VALID - {len(feature_flags)} feature flags accessible")

    for flag in feature_flags[:5]:
        treatment = flag.get("defaultTreatment", "unknown")
        print(f"    - {flag['name']}: {treatment}")

    if len(feature_flags) > 5:
        print(f"    ... and {len(feature_flags) - 5} more")


def test_splitio_key(environment_name: str, sdk_key: str) -> None:
    """Validates a Split.io SDK key and lists its accessible feature flags.

    Args:
        environment_name: The descriptive name of the environment being tested.
        sdk_key: The Split.io SDK authorization key string.
    """
    print(f"\n[*] Testing Environment: {environment_name}...")

    url = "https://sdk.split.io/api/splitChanges"
    params = {"since": "-1"}
    headers = {"Authorization": f"Bearer {sdk_key}"}

    try:
        response = requests.get(url, params=params, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            display_feature_flags(response.json())
        else:
            print(f"[-] INVALID - Status Code: {response.status_code}")
    except requests.RequestException as error:
        print(f"[-] Error occurred: {str(error)}")


if __name__ == "__main__":
    mock_keys: Dict[str, str] = {
        "Production_Env": DUMMY_KEY,
        "Staging_Env": "PLACEHOLDER_STAGING_KEY",
        "Sandbox_Env": "PLACEHOLDER_SANDBOX_KEY",
    }

    for env, token in mock_keys.items():
        if "PLACEHOLDER" in token or "YOUR_" in token:
            print(f"\n[!] Skipping {env}: Replace placeholder with a valid key to test.")
            continue
        test_splitio_key(env, token)