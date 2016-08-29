__author__ = 'Nicholas Rodofile'

import sys
import time


def countdown_timer(wait_time, message="Countdown"):
    try:
        while wait_time != 0:
            wait_time -= 1
            minutes_left = wait_time/60
            seconds_left = wait_time % 60
            sys.stdout.flush()
            sys.stdout.write('\r{0}: {1} Min {2} Sec'.format(message, minutes_left, seconds_left))
            time.sleep(1)
    except KeyboardInterrupt:
        raise
    print "" #new line

def scan_countdown(wait_time):
    message = '\033[33m' + "Next Scan" + '\033[0m'
    countdown_timer(wait_time, message)


def ending_dataset(wait_time):
    print "Sleep for", wait_time/60, "Min", wait_time % 60, "Sec"
    print "============================"
    message = '\033[92m' + "Ending data collection" + '\033[0m'
    countdown_timer(wait_time, message)


def attack_countdown(wait_time):
    print "Sleep for", wait_time/60, "Min", wait_time % 60, "Sec"
    print "============================"
    message = '\033[91m' + "Next Attack" + '\033[0m'
    #countdown_timer(wait_time, message)
    time.sleep(wait_time)

if __name__ == "__main__":
    import datetime
    a = datetime.datetime.now()
    b = datetime.datetime.now() + datetime.timedelta(hours=10)
    c = datetime.datetime.now() + datetime.timedelta(hours=11)
    print a
    print b
    print c
    print (c - b).total_seconds()
