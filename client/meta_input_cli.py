import requests
from datetime import datetime

META_STORE_URL = "http://localhost:4000/meta/user"


def must_not_be_empty(label: str) -> str:
    while True:
        value = input(label).strip()
        if value:
            return value
        print("This field cannot be empty. Please try again.\n")


def validate_dob(label: str) -> str:
    while True:
        dob = input(label).strip()
        if not dob:
            print("DOB cannot be empty.\n")
            continue
        try:
            
            datetime.strptime(dob, "%Y-%m-%d")
            return dob
        except ValueError:
            print("Invalid DOB format. \n")


def main():
    print("Meta User Input Client")
    print("Data is entered at runtime (no hardcoded personal data)")
    print("Data is sent to Meta and stored encrypted in MongoDB\n")

    username = must_not_be_empty("Enter username / full name: ")
    address = must_not_be_empty("Enter address: ")
    dob = validate_dob("Enter DOB (YYYY-MM-DD): ")
    phone = must_not_be_empty("Enter phone: ")

    payload = {
        "username": username,
        "address": address,
        "dob": dob,
        "phone": phone
    }

    try:
        r = requests.post(META_STORE_URL, json=payload, timeout=10)

        
        try:
            body = r.json()
        except Exception:
            body = {"raw_response": r.text}

        print("\nStatus:", r.status_code)

        if r.status_code == 200:
            print("User data stored securely in Meta database (encrypted).")
            
            if isinstance(body, dict) and body.get("message"):
                print("Message:", body["message"])
        else:
            print("Failed to store user data.")
            print("Meta response:", body)

    except requests.exceptions.ConnectionError:
        print(" Cannot connect to Meta server.")
        print("   Make sure Meta server is running on http://localhost:4000")
    except requests.exceptions.Timeout:
        print("Request timed out. Meta server may be slow or not responding.")
    except Exception as e:
        print("Unexpected error:", str(e))


if __name__ == "__main__":
    main()
