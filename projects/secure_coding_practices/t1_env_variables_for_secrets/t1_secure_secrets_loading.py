import os

#note: need to install dotenv first
from dotenv import load_dotenv

load_dotenv()

### Goal: Eliminate hard-coded credentials to prevent accidental disclosure
### Aim:  Address A02: Cryptographic Failures (by protecting secrets) and Security Misconfiguration

def get_api_key(key_name: str) -> str:
    """
    Retrieves a secret key from environment variables.

    :param key_name: The name of the environment variable ('EXTERNAL_API_KEY').
    :return: The secret value.
    :raises EnvironmentError: If the key is not found.
    """
    secret_value = os.getenv(key_name)

    if secret_value is None:
        # Fail fast if a required secret is missing.
        raise EnvironmentError(
            f"Error: The required secret '{key_name}' was not found in environment variables or the .env file."
        )

    return secret_value

if __name__ == "__main__":
    print("Secure Secret Loading Demonstration:")

# TEST 1: SUCESS EVENT
    # Attempt to load the required key (EXTERNAL_API_KEY)
    try:
        external_api_key = get_api_key("EXTERNAL_API_KEY")
        print(f"[SUCCESS] Loaded API Key. Length: {len(external_api_key)} characters.")
        print(f"Key Value (Masked): {external_api_key[:4]}...{external_api_key[-4:]}")

# TEST 2: FAILURE EVENT (comment lines 42-44 out if test 1 will be done)
        # Simulate using a key that is not in the .env file (should fail)
        print("\nAttempting to load missing key...")
        missing_key = get_api_key("MISSING_DB_PASSWORD")

    except EnvironmentError as e:
        print(f"[FAILURE] Security check passed. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
