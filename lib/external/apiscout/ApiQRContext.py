########################################################################
# Copyright (c) 2018
# Steffen Enders <steffen<at>enders<dot>nrw>
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout
#
#  apiscout is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import math
from operator import itemgetter


class ApiQRContext:
    """
    Class to store all context related data that is especially needed for:
    - Exports to HTML
    - Exports to PNG
    """
    data = []
    colors_format = "RGB"
    colors_white = (255, 255, 255)
    colors_dict = {
        "execution": (41, 128, 185), # 2980B9 blue
        "gui":       (241, 196, 15), # F1C40F yellow
        "file":      (95,158,160),   # cadet blue <- (46, 204, 113), # 2ECC71 bright green
        "time":      (72,61,139),    # dark slate blue <- (52, 152, 219), # 3498DB blue
        "memory":    (243, 156, 18), # F39C12 orange
        "string":    (231, 76, 60),  # E74C3C red
        "network":   (30,144,255),   # dodger blue <- (59, 216, 214), # 3BD8D6 green-blue
        "crypto":    (142, 68, 173), # 8E44AD purple
        "other":     (39, 174, 96),  # 27AE60 green
        "device":    (189,183,107),  # dark khakhi <- (250, 206, 32), # FACE20 yellow
        "system":    (255,20,147),   # deep pink <- (192, 57, 43),  # C0392B dark red
        "registry":  (26, 188, 156), # 1ABC9C light green
    }

    def __init__(self, winapi1024):
        self.data = winapi1024
        if self.dimension ** 2 != len(self.data) or int(math.log(self.dimension, 2)) != math.log(self.dimension, 2):
            raise ValueError("Vector needs to have a length for which its squareroot is a power of two")

    @property
    def dimension(self):
        return int(len(self.data) ** 0.5)

    @property
    def apis(self):
        return list(zip(map(itemgetter(0), self.data), map(itemgetter(1), self.data)))

    @property
    def colors(self):
        return list(map(lambda x: self.colors_dict[x[2]], self.data))

    @property
    def empty_vector(self):
        return [0] * len(self.data)

