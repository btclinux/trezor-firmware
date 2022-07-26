#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math

from .pallas import Fp, Point
from ..utils import cldiv, lebs2ip, i2leosp
from .group_hash import group_hash
from ..output import render_args, render_tv
from ..rand import Rand

def sinsemilla_hash_to_point(d, m):
    return None

def sinsemilla_hash(d, m):
    return sinsemilla_hash_to_point(d, m).extract()
