from __future__ import division  # Use floating point for math calculations

import types
import math
import os

from CTFd.models import Solves, Challenges, db
from CTFd.plugins.challenges import CHALLENGE_CLASSES
from CTFd.utils.modes import get_model
from CTFd.utils.user import (
    authed,
    get_current_team
)
from CTFd.utils.scores import get_team_standings


def calculate_value(cls, challenge):
    Model = get_model()

    solve_count = (
        Solves.query.join(Model, Solves.account_id == Model.id)
        .filter(
            Solves.challenge_id == challenge.id,
            Model.hidden == False,
            Model.banned == False,
        )
        .count()
    )
    teams_count = Model.query.filter_by(hidden=False, banned=False).count()

    # If the solve count is 0 we shouldn't manipulate the solve count to
    # let the math update back to normal
    if solve_count != 0:
        # We subtract -1 to allow the first solver to get max point value
        solve_count -= 1

    # It is important that this calculation takes into account floats.
    # Hence this file uses from __future__ import division
    p0 = 0.7
    p1 = 0.96
    c0 = -math.atanh(p0)
    c1 = math.atanh(p1)
    a = lambda x: (1 - math.tanh(x)) / 2
    b = lambda x: (a((c1 - c0) * x + c0) - a(c1)) / (a(c0) - a(c1))

    def get_score(rl, rh, maxSolves, solves):
        s = max(1, maxSolves)
        f = lambda x: rl + (rh - rl) * b(x / s)
        return round(max(f(solves), f(s)))
    # value = get_score(challenge.minimum, challenge.initial, challenge.decay, solve_count)
    # https://github.com/sigpwny/ctfd-dynamic-challenges-mod/issues/1
    value = get_score(challenge.minimum, challenge.initial, teams_count, solve_count)

    if value < challenge.minimum:
        value = challenge.minimum

    challenge.value = value
    db.session.commit()
    return challenge


def load(app):
    # Make a page to show the flag if the user has the most points
    @app.route('/flag')
    def flag():
        if not authed():
            return "You must be logged in to view the flag!"

        if Solves.query.count() <= 0:
            return "No solves have been submitted yet!"
        
        team = get_current_team()

        if team is None:
            return "You must be on a team to view the flag!"
        print(f"/flag check for team: {team.id}, {team.name}")
        
        team_standings = get_team_standings()
        print(f"Current team standings: {team_standings}")

        # If the current team is the team with the most points, show the flag
        if team_standings and team_standings[0].team_id == team.id:
            return f"Congrats! You beat Kalmarunionen! Here's your flag: {os.environ.get('FLAG', 'kalmar{fake_flag}')}"
        return "You are not on the team with the most points!"
    
    if "dynamic" not in CHALLENGE_CLASSES:
        print("DynamicValueChallenge class not found, skipping plugin...")
        return
    
    # Hook the DynamicValueChallenge class and modify the calculate method
    dvc_class = CHALLENGE_CLASSES["dynamic"]
    print("hooking DynamicValueChallenge and modifying calculate method...")
    setattr(dvc_class, calculate_value.__name__, types.MethodType(calculate_value, dvc_class))

    # Recalculate the value of all challenges
    print("recalculating values for all challenges...")
    challs = Challenges.query.filter_by(type="dynamic")
    for challenge in challs:
        print(f"recalculating value for challenge {challenge.id}... current value: {challenge.value}")
        challenge = calculate_value(dvc_class, challenge)
        print(f"new value: {challenge.value}")
    print("done recalculating values for all challenges")
