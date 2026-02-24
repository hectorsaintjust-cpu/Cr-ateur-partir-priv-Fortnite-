#!/usr/bin/env python3
"""
Fortnite Private Party Generator Bot

Install with: pip install -U rebootpy

This script creates a private Fortnite party and auto-accepts join
requests (for friend join requests) using the rebootpy library.

WARNING: This uses an alt account! Risk of ban if abused.
Only use for private lobbies with friends.
"""

print("Install with: pip install -U rebootpy")

import asyncio
import json
import os
import getpass
import sys
from typing import Any, Optional

import rebootpy

# Path to device auth storage for re-use of device auths to avoid password entry
DEVICE_AUTH_FILE = "device_auths.json"


def load_device_auth(email: str) -> Optional[Any]:
    """Load saved device auth for the given email from DEVICE_AUTH_FILE.

    Returns the raw saved value or None if not found.
    """
    if not os.path.exists(DEVICE_AUTH_FILE):
        return None
    try:
        with open(DEVICE_AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get(email)
    except Exception:
        return None


def save_device_auth(email: str, device_auth: Any) -> None:
    """Save device auth for the given email to DEVICE_AUTH_FILE.

    This merges with existing file content.
    """
    data = {}
    if os.path.exists(DEVICE_AUTH_FILE):
        try:
            with open(DEVICE_AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    data[email] = device_auth
    try:
        with open(DEVICE_AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Warning: failed to save device auth: {e}")


def extract_device_auth_from_auth(auth_obj: Any) -> Optional[Any]:
    """Attempt to extract a device-auth blob from an auth object.

    rebootpy's exact attribute names may vary; try common names.
    This is a best-effort extraction for later re-use.
    """
    if not auth_obj:
        return None
    # Common attribute names to try
    candidates = ("device_auth", "device", "_device_auth", "device_auth_data", "deviceAuth")
    for attr in candidates:
        if hasattr(auth_obj, attr):
            val = getattr(auth_obj, attr)
            if val:
                return val
    # If the auth object is a mapping
    try:
        if isinstance(auth_obj, dict):
            for key in ("device_auth", "deviceAuth"):
                if key in auth_obj:
                    return auth_obj[key]
    except Exception:
        pass
    return None


async def main() -> None:
    """Main entry point: prompt for credentials, authenticate, create party.

    The function attempts to reuse saved device auth for the provided email
    to avoid entering the password in future runs.
    """
    print("\nWarning: This uses an alt account! Risk of ban if abused.")
    print("Only use for private lobbies with friends.\n")

    email = input("Epic Games email: ").strip()
    if not email:
        print("Email is required.")
        return

    # Try to load a saved device auth for this email
    saved_device_auth = load_device_auth(email)

    # Ask for password only if no saved device auth is available
    password = None
    if not saved_device_auth:
        password = getpass.getpass("Epic Games password (input hidden): ")

    auth = None
    try:
        # Prefer AdvancedAuth with device auth if we have one
        if saved_device_auth is not None:
            try:
                auth = rebootpy.AdvancedAuth(email=email, device_auth=saved_device_auth)
            except Exception:
                # Fallback to password flow if device-auth usage fails
                if password is None:
                    password = getpass.getpass("Epic Games password (input hidden): ")
                auth = rebootpy.AdvancedAuth(email=email, password=password)
        else:
            auth = rebootpy.AdvancedAuth(email=email, password=password)
    except Exception as e:
        # If AdvancedAuth fails (2FA or other flows), attempt an authorization-code flow
        print(f"Authentication attempt failed: {e}")
        print("Attempting AuthorizationCodeAuth/interactive flow if available...")
        try:
            # Some libraries provide AuthorizationCodeAuth for interactive device flows
            auth = rebootpy.AuthorizationCodeAuth(email=email)
        except Exception as e2:
            print(f"AuthorizationCodeAuth failed: {e2}")
            print("Unable to authenticate. Exiting.")
            return

    # Create the client with the prepared auth
    client = rebootpy.Client(auth=auth)

    party = None

    @client.event
    async def event_ready() -> None:
        """Called when the client is ready. Creates the private party immediately.

        This handler attempts to create a private party, set playlist to Solo,
        and ready the bot's party member slot.
        """
        nonlocal party
        try:
            print(f"Bot logged in as {client.user.display_name} ({client.user.id})")
        except Exception:
            print("Bot logged in (failed to access user object details)")

        try:
            # Create a private party with max size 16
            party = await client.party.create(
                config=rebootpy.DefaultPartyConfig(privacy=rebootpy.PartyPrivacy.PRIVATE, max_size=16)
            )

            # Set playlist to Solo (version -1 to use current/latest)
            try:
                await party.set_playlist("Solo", version=-1)
            except Exception:
                # Non-fatal: playlist detection or set may fail depending on API/version
                pass

            # Mark the bot as ready
            try:
                await party.me.set_ready(True)
            except Exception:
                pass

            print("✅ Private party created!")
            try:
                print(f"Party ID: {party.id}\nUsername: {client.user.display_name}\n")
            except Exception:
                print("Party created (could not fetch full details)")

            print("Instructions: Add this account as friend in Fortnite, send join request. Bot auto-accepts!")
            print("Press Ctrl+C to leave party.")

            # Simple flow: ask for a party code to set so friends can join easily
            try:
                loop = asyncio.get_running_loop()
                code = await loop.run_in_executor(None, input, "Enter party code to set (or press Enter to skip): ")
                code = (code or "").strip()
                if code:
                    # Try several common method names to set a party code (best-effort)
                    async def try_set_code(party_obj, code_str):
                        methods = (
                            "set_join_code",
                            "set_join_key",
                            "set_access_key",
                            "set_party_code",
                            "set_custom_key",
                            "set_privacy_key",
                            "set_code",
                            "set_invite_code",
                            "set_password",
                            "set_join_password",
                        )
                        for m in methods:
                            fn = getattr(party_obj, m, None)
                            if fn is None:
                                continue
                            try:
                                res = fn(code_str)
                                if asyncio.iscoroutine(res):
                                    await res
                                print(f"Party code set via {m}")
                                return True
                            except Exception:
                                continue
                        # Fallback: try to set on party.config if writable
                        try:
                            cfg = getattr(party_obj, "config", None)
                            if cfg is not None and hasattr(cfg, "__dict__"):
                                setattr(cfg, "code", code_str)
                                print("Party code stored on party.config.code (best-effort)")
                                return True
                        except Exception:
                            pass
                        return False

                    ok = await try_set_code(party, code)
                    if ok:
                        print(f"✅ Party code applied: {code}")
                    else:
                        print("Could not apply party code automatically. Please share the code with friends manually.")
            except Exception as e:
                print(f"Error while handling party code input: {e}")
            # Attempt to extract and save device auth for future runs
            try:
                device_blob = extract_device_auth_from_auth(auth)
                if device_blob is not None:
                    save_device_auth(email, device_blob)
            except Exception:
                pass

        except Exception as e:
            print(f"Failed to create or configure party: {e}")

    @client.event
    async def event_party_join_request(request) -> None:
        """Automatically accept incoming party join requests (friend requests).

        This will accept any incoming party join request. Keep in mind the
        obvious privacy/security implications.
        """
        try:
            await request.accept()
            try:
                user_desc = f"{request.user.display_name} ({request.user.id})"
            except Exception:
                user_desc = "<unknown user>"
            print(f"Accepted join request from {user_desc}")
        except Exception as e:
            print(f"Failed to accept join request: {e}")

    @client.event
    async def event_error(exception) -> None:
        """Global error handler to print exceptions raised by the client."""
        print(f"Error: {exception}")

    # Run the client and handle graceful shutdown
    try:
        await client.start()
    except KeyboardInterrupt:
        # User requested shutdown; attempt to leave party and logout
        print("\nShutdown requested — leaving party...")
        try:
            if party is not None:
                await party.leave()
        except Exception:
            pass
        try:
            await client.close()
        except Exception:
            pass
        print("Party left.")
    except Exception as e:
        print(f"Client runtime error: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
