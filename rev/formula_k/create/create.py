import json
import random
import datetime

motorA_forward = 0b00000000
motorA_stop = 0b00000001
motorA_backward = 0b00000011
motorD_forward = 0b00000000
motorD_stop = 0b00000100
motorD_backward = 0b00001100

_start_drawing = 0b00010000
_stop_drawing = 0b00100000
reset = 0b01000000

forward = motorA_forward | motorD_forward
backward = motorA_backward | motorD_backward
left = motorA_backward | motorD_forward
right = motorA_forward | motorD_backward

pause = motorA_stop | motorD_stop

TICK_TIME = 5.7


def go(direction, length=1, start_drawing=False, stop_drawing=False):
    res = []
    if start_drawing:
        res += [_start_drawing | direction]
        res += [direction] * (length - 1)
    elif stop_drawing:
        res += [_stop_drawing | direction]
        res += [direction] * (length - 1)
    else:
        res += [direction] * length
    return res


def draw_K_old():
    res = []
    res += go(forward, 5, start_drawing=True)
    res += go(left)
    res += go(backward, 4)
    res += go(forward, 4, stop_drawing=True)
    res += go(right)
    res += go(forward, 5, start_drawing=True)
    res += go(backward, 10, stop_drawing=True)
    res += [reset]
    return res


def draw_K():
    res = []
    res += go(forward, 3, start_drawing=True)
    res += go(left)
    res += go(backward, 4)
    res += go(right)
    res += go(forward, 6, stop_drawing=True)
    res += go(right)
    res += go(backward, 4, start_drawing=True)
    res += go(left)
    res += go(forward, 7)
    res += go(backward, 10, stop_drawing=True)
    res += [reset]
    return res


def draw_A():
    res = []
    res += go(forward, 7, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 4)
    res += go(left)
    res += go(left)
    res += go(forward, 7)
    res += go(backward, 7, stop_drawing=True)
    res += go(backward, 3, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 4)
    res += go(right)
    res += go(right)
    res += go(backward, 3)
    res += go(backward, 7, stop_drawing=True)
    res += [reset]
    return res


def draw_L():
    res = []
    res += go(forward, 10, start_drawing=True)
    res += go(backward, 10, stop_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 4, start_drawing=True)
    res += go(backward, 4, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += [reset]
    return res


def draw_M():
    res = []
    res += go(forward, 10, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 2)
    res += go(left)
    res += go(left)
    res += go(backward, 4)
    res += go(forward, 4, stop_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 2, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 10)
    res += go(left)
    res += go(left)
    res += go(forward, 4, stop_drawing=4)
    res += go(right)
    res += go(right)
    res += [reset]
    return res


def draw_R_old():
    res = []
    res += go(forward, 5)
    res += go(right)
    res += go(forward, 5, start_drawing=True)
    res += go(right)
    res += go(forward, 5)
    res += go(right)
    res += go(forward, 5, stop_drawing=True)
    res += go(right)
    res += [reset]
    return res


def draw_R():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 4)
    res += go(right)
    res += go(backward, 5, start_drawing=True)
    res += go(left)
    res += go(forward, 4)
    res += go(left)
    res += go(left)
    res += go(forward, 6)
    res += go(left)
    res += go(left)
    res += go(forward, 4)
    res += go(right)
    res += go(right)
    res += go(backward, 10)
    res += [reset | _stop_drawing]
    return res


def draw_bl():
    res = []
    res += go(forward, 10, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 2)
    res += go(right)
    res += go(right)
    res += go(backward, 10, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 2, start_drawing=True)
    res += go(right, stop_drawing=True)
    res += go(right)
    res += [reset]
    return res


def draw_ø():
    res = []
    res += go(right)
    res += go(forward, 1, start_drawing=True)
    res += go(left)
    res += go(forward, 3)
    res += go(right)
    res += go(right)
    res += go(forward, 3)
    res += go(left)
    res += go(left)
    res += go(backward, 3)
    res += go(right)
    res += go(right)
    res += go(backward, 3)
    res += go(left)
    res += go(forward, 5)
    res += go(backward, 6, stop_drawing=True)
    res += go(left)
    res += [reset]
    return res


def draw_d():
    res = []
    res += go(left)
    res += go(left)
    res += go(backward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 10)
    res += go(backward, 6, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 4)
    res += [reset | _stop_drawing]
    return res


def draw_us():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 4, start_drawing=True)
    res += go(backward, 4, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += [reset]
    return res


def draw_6():
    res = []
    res += go(forward, 10, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 4)
    res += go(right)
    res += go(right)
    res += go(backward, 5, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 4, start_drawing=True)
    res += go(backward, 4, stop_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 5, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 4)
    res += go(right, stop_drawing=True)
    res += go(right)
    res += [reset]
    return res


def draw_5():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 3, start_drawing=True)
    res += go(left)
    res += go(forward, 1)
    res += go(left)
    res += go(forward, 3)
    res += go(left)
    res += go(forward, 1)
    res += go(left)
    res += go(forward, 3)
    res += go(right)
    res += go(right)
    res += go(forward, 5)
    res += go(left)
    res += go(left)
    res += go(backward, 4)
    res += go(forward, 5, stop_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 10)
    res += [reset]
    return res


def draw_3():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 4, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 5)
    res += go(right)
    res += go(right)
    res += go(backward, 3)
    res += go(forward, 3, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 5, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 4)
    res += go(left)
    res += go(left)
    res += go(backward, 10, stop_drawing=True)
    res += [reset]
    return res


def draw_F():
    res = []
    res += go(forward, 7, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 3)
    res += go(backward, 1, stop_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 3)
    res += go(left)
    res += go(left)
    res += go(forward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 3)
    res += go(backward, 7, stop_drawing=True)
    res += [reset]
    return res


def draw_1():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 4, start_drawing=True)
    res += go(backward, 2, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 10, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 2)
    res += go(left)
    res += go(left)
    res += go(backward, 10, stop_drawing=True)
    res += [reset]
    return res


def draw_br():
    res = []
    res += go(right)
    res += go(right)
    res += go(forward, 2)
    res += go(forward, 2, start_drawing=True)
    res += go(left)
    res += go(left)
    res += go(forward, 10)
    res += go(right)
    res += go(right)
    res += go(backward, 2)
    res += go(backward, 2, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 10)
    res += [reset]
    return res


def draw_o():
    res = []
    res += go(forward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 4)
    res += go(left)
    res += go(left)
    res += go(backward, 4)
    res += go(right)
    res += go(right)
    res += go(backward, 4)
    res += go(left, stop_drawing=True)
    res += go(left)
    res += [reset]
    return res


def draw_u():
    res = []
    res += go(forward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(forward, 4, stop_drawing=True)
    res += go(left)
    res += go(left)
    res += go(backward, 4, start_drawing=True)
    res += go(right)
    res += go(right)
    res += go(backward, 4)
    res += go(left, stop_drawing=True)
    res += go(left)
    res += [reset]
    return res


res = []
res += draw_K()
res += draw_A()
res += draw_L()
res += draw_M()
res += draw_A()
res += draw_R()
res += draw_bl()
res += draw_R()
res += draw_o()
res += draw_d()
res += draw_us()
res += draw_6()
res += draw_5()
res += draw_o()
res += draw_d()
res += draw_us()
res += draw_M()
res += draw_3()
res += draw_d()
res += draw_us()
res += draw_F()
res += draw_1()
res += draw_o()
res += draw_d()
res += draw_3()
res += draw_us()
res += draw_o()
res += draw_6()
res += draw_us()
res += draw_F()
res += draw_1()
res += draw_o()
res += draw_d()
res += draw_3()
res += draw_5()
res += draw_K()
res += draw_u()
res += draw_M()
res += draw_br()

print(f"Track time: {datetime.timedelta(seconds=len(res)*TICK_TIME)}")
with open("res.json", "w") as f:
    json.dump(res, f)
