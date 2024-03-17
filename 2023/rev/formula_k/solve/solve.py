import json
import math
import os
from pathlib import Path

import cv2
import numpy

DIST = 10
PADDING = 10
WIDTH = 4 * DIST + 2 * PADDING
HEIGHT = 10 * DIST + 2 * PADDING
XY_DIST = DIST / math.sqrt(2)
BLACK = [0x00, 0x00, 0x00]
WHITE = [0xFF, 0xFF, 0xFF]
RED = [0x00, 0x00, 0xFF]  # image is GBR
FPS = 60
VIDEO_PAD = FPS * 10  # 10 sec
RESULTS_DIR = Path("results")

TMP_MP4 = RESULTS_DIR / "tmp.mp4"

RESULTS_DIR.mkdir(exist_ok=True, parents=True)

ffmpeg_cmd = "ffmpeg -loglevel error"


def reset():
    return (
        cv2.VideoWriter(
            str(TMP_MP4.absolute()),
            cv2.VideoWriter_fourcc(*"mp4v"),
            FPS,
            (WIDTH, HEIGHT),
        ),
        numpy.full((HEIGHT, WIDTH, 3), 0xFF, dtype=numpy.uint8),
        "N",
        False,
        (PADDING, HEIGHT - PADDING),
    )


def turn(direction, cur_orientation):
    if cur_orientation == "N":
        return "NE" if direction == "CW" else "NW"
    elif cur_orientation == "NE":
        return "E" if direction == "CW" else "N"
    elif cur_orientation == "E":
        return "SE" if direction == "CW" else "NE"
    elif cur_orientation == "SE":
        return "S" if direction == "CW" else "E"
    elif cur_orientation == "S":
        return "SW" if direction == "CW" else "SE"
    elif cur_orientation == "SW":
        return "W" if direction == "CW" else "S"
    elif cur_orientation == "W":
        return "NW" if direction == "CW" else "SW"
    elif cur_orientation == "NW":
        return "N" if direction == "CW" else "W"


def move(loc, orientation, going_backwards):
    direction = orientation
    if going_backwards:
        direction = turn("CW", direction)
        direction = turn("CW", direction)
        direction = turn("CW", direction)
        direction = turn("CW", direction)

    if direction == "N":
        loc = (loc[0], loc[1] - DIST)
    elif direction == "NE":
        loc = (loc[0] + XY_DIST, loc[1] - XY_DIST)
    elif direction == "E":
        loc = (loc[0] + DIST, loc[1])
    elif direction == "SE":
        loc = (loc[0] + XY_DIST, loc[1] + XY_DIST)
    elif direction == "S":
        loc = (loc[0], loc[1] + DIST)
    elif direction == "SW":
        loc = (loc[0] - XY_DIST, loc[1] + XY_DIST)
    elif direction == "W":
        loc = (loc[0] - DIST, loc[1])
    elif direction == "NW":
        loc = (loc[0] - XY_DIST, loc[1] - XY_DIST)
    return loc


with open("uf2.json", "r") as f:
    track = json.load(f)

i = 0
video, field, orientation, drawing, loc = reset()

for ii, t in enumerate(track):
    if t & 0b01000000:
        # Letter done, reset
        for _ in range(VIDEO_PAD):
            video.write(field)  # Linger on last frame

        out_gif = RESULTS_DIR / f"{i:04}.gif"

        ffmpeg_cmd += f" -i {out_gif.absolute()}"
        video.release()
        os.system(
            f'ffmpeg -loglevel error -i "{TMP_MP4.absolute()}" "{out_gif.absolute()}" -y'
        )
        TMP_MP4.unlink()
        video, field, orientation, drawing, loc = reset()
        i += 1
        continue

    if t & 0b00010000:
        drawing = True
    if t & 0b00100000:
        drawing = False

    new_loc = loc
    motor_state = t & 0b00001111

    if motor_state == 0b0000:  # Going forwards
        new_loc = move(loc, orientation, False)
    elif motor_state == 0b1111:  # Going backwards
        new_loc = move(loc, orientation, True)
    elif motor_state == 0b1100:  # Turning clockwise
        orientation = turn("CW", orientation)
    elif motor_state == 0b0011:  # Turning counter-clockwise
        orientation = turn("CC", orientation)
    elif motor_state == 0b0101:  # Standing still
        continue
    else:
        raise ValueError(f"Unknown motor state at index {ii}: 0b{motor_state:08b}")

    _new_loc = (int(new_loc[0]), int(new_loc[1]))

    if drawing:
        field = cv2.line(
            field,
            (int(loc[0]), int(loc[1])),
            _new_loc,
            BLACK,
            2,
        )

    saved_field = numpy.array(field, copy=True)
    field = cv2.circle(field, _new_loc, 2, RED, 2)

    loc = new_loc

    for _ in range(10):
        video.write(field)

    field = saved_field

video.release()
TMP_MP4.unlink()

res_gif = RESULTS_DIR / "res.gif"
ffmpeg_cmd += f' -filter_complex hstack=inputs={i} "{res_gif.absolute()}" -y'
os.system(ffmpeg_cmd)
os.system(
    f'ffmpeg -loglevel error -sseof -3 -i "{res_gif.absolute()}" -update 1 -q:v 1 "{RESULTS_DIR / "res.png"}" -y'
)
