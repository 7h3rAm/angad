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

import operator
import numpy as np
import math
import numbers
import os
from PIL import Image

from ApiQRContext import ApiQRContext
from ApiVector import ApiVector


class ApiQR:
    """
    Class for a two-dimensional vector where each component stands for one distinct API.
    The vector is saved one-dimensionally though.
    """
    vector = None
    context = None

    def __init__(self, winapi1024_filepath, vector=None):
        self._apivector = ApiVector(winapi1024_filepath, sort_vector=False)
        self._apivector_path = winapi1024_filepath
        self.context = ApiQRContext(self._apivector.getWinApi1024())
        if vector is None:
            self.vector = self.context.empty_vector
        else:
            self.vector = vector

    def setVector(self, vector):
        self.vector = self._apivector.decompress(vector)

    @property
    def vector_unsorted(self):
        ### @7h3rAm.PATCH: use sorted vector
        #return self.vector
        ###
        result = [None] * len(self.vector)
        with open(self._apivector_path, "r") as infile:
            translation = {
                new_index: entry[0]
                for new_index, entry in enumerate(sorted(enumerate(infile.readlines()), key=lambda entry: int(entry[1].split(";")[3].strip()), reverse=True))
            }
        for index, entry in enumerate(self.vector):
            result[translation[index]] = entry
        return result

    def exportPng(self, destination_path, scale_factor=5):
        colored_vector = list(map(self.__mapColor, self.vector_unsorted, self.context.colors))
        scaled_vector = sum(([e] * 4 ** scale_factor for e in colored_vector), [])
        transformed_vector = np.int8(self.__vectorToHilbert(scaled_vector))
        image = Image.fromarray(transformed_vector, mode=self.context.colors_format)
        image.save(destination_path, format="PNG", compress_level=0)

    def exportHtml(self, output_path, full=False):
        vector = self.vector_unsorted
        hilbert_size = int(len(vector) ** 0.5)
        result = "<br/><table>"
        result += """\
        <style>
            td.api-cell {{
                width: {:.4f}%;
            }}
            td.api-cell-white {{
                background-color: rgb({white[0]:d}, {white[1]:d}, {white[2]:d});
            }}
        </style>""".format(1.0 / hilbert_size, white=self.context.colors_white)
        for hilbert_row in self.__hilbertCurve(hilbert_size):
            result += "<tr>"
            for index in hilbert_row:
                value, raw_color = vector[index], self.context.colors[index]
                color = self.__mapColor(value, raw_color)
                if color == self.context.colors_white:
                    # result += '<td class="api-cell api-cell-white"></td>'
                    color = self.__mapColor(0.2, raw_color)
                    text = ":".join(self.context.apis[index])
                    result += '<td data-toggle="popover" data-content="{popover:s}" data-delay="200" class="api-cell" style="background-color: rgb({color[0]:d}, {color[1]:d}, {color[2]:d});"></td>'.format(popover=text, color=color)
                else:
                    text = ":".join(self.context.apis[index])
                    # rescale value to range 0.4-1.0
                    value = 0.4 + (value * (1 - 0.4))
                    color = self.__mapColor(value, raw_color)
                    result += '<td data-toggle="popover" data-content="{popover:s}" class="api-cell" style="background-color: rgb({color[0]:d}, {color[1]:d}, {color[2]:d});"></td>'.format(popover=text, color=color)
            result += "</tr>"
        result += "</table><script>$('td.api-cell').popover({trigger: 'hover'})</script>"
        if not full: return result
        this_path = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        with open(os.sep.join([this_path, "..", "data", "html_frame.html"]), "r") as f_html:
            with open(os.sep.join([this_path, "..", "data", "html_style.css"]), "r") as f_css:
                compressed_vector = self._apivector.compress(vector)
                result = f_html.read().format(vector=compressed_vector, body=result, head="<style>\n{}\n</style>".format(f_css.read()))
        with open(output_path, "w") as f_out:
            f_out.write(result)

    def __mapColor(self, value, color):
        if value is True or value == 1 or value == 1.0: return color
        if value is False or value == 0 or value == 0.0: value = 0.15
        alpha = max(min(value, 1), 0)
        return (
            int((1 - alpha) * 255 + alpha * color[0]),
            int((1 - alpha) * 255 + alpha * color[1]),
            int((1 - alpha) * 255 + alpha * color[2]),
        )

    @property
    def vector_hilbert(self):
        return self.__vectorToHilbert(self.vector_unsorted)

    def __vectorToHilbert(self, vector):
        element_size = 1
        if len(np.array(vector)[0].shape): element_size = np.array(vector)[0].shape[0]
        hilbert_indices = self.__hilbertCurve(int(len(vector) ** 0.5))
        return np.array(vector)[np.digitize(hilbert_indices.ravel(), list(range(len(vector))), right=True)]\
            .reshape(hilbert_indices.shape[0], hilbert_indices.shape[1], element_size)

    def __hilbertCurve(self, n):
        """
        Generate Hilbert curve indexing for (n, n) array. 'n' must be a power of two.
        https://github.com/znah/notebooks/blob/master/hilbert_curve.ipynb
        """
        if n == 1: return np.zeros((1, 1), np.int32)
        t = self.__hilbertCurve(n//2)
        a = np.flipud(np.rot90(t))
        b = t + t.size
        c = t + t.size*2
        d = np.flipud(np.rot90(t, -1)) + t.size*3
        return np.vstack(map(np.hstack, [[a, b], [d, c]]))

    def __add__(self, other):
        if not isinstance(other, ApiQR):
            raise ValueError("Only another ApiQR instance can be added.")
        if self.context != other.context:
            raise ValueError("Both ApiQR instances need to share the same context in order to be added together!")
        return ApiQR(vector=list(map(operator.add, self.vector, other.vector)), context=self.context)

    def __mul__(self, other):
        if not isinstance(other, numbers.Number):
            raise ValueError("An ApiQR instance can only be multiplied with numbers.")
        return ApiQR(vector=list(map(lambda x: x * other, self.vector)), context=self.context)

    def __div__(self, other):
        if not isinstance(other, numbers.Number):
            raise ValueError("An ApiQR instance can only be divided by numbers.")
        return ApiQR(vector=list(map(lambda x: 1.0 * x / other, self.vector)), context=self.context)

    def __truediv__(self, other):
        return self.__div__(other)

    def __str__(self):
        return "ApiQR {}".format(np.array(self.vector))

    def __repr__(self):
        return str(self)

