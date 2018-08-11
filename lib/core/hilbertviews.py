# -*- coding: utf-8 -*-

from lib.external.apiscout.ApiQR import ApiQR
from lib.external.apiscout import ApiVector

from lib.external.scurve.scurve import progress
from lib.external.scurve import binvis

from settings import config
from lib import utils

import pefile
import os
import re


def scurve(infile, reportsdir, curvemap=["hilbert"], curvetype=["square", "unrolled"], curvecolor=["entropy", "hilbert", "gradient"], pngsize=256, showprogress=True, byteviewanimate=True):
  filename = utils.remove_extension(utils.filename(infile))
  utils.mkdirp(reportsdir)
  imagefiles = []
  data = file(infile).read()
  print "  mode: fulldata (%d bytes)" % (len(data))
  for ctidx, ct in enumerate(curvetype):
    for ccidx, cc in enumerate(curvecolor):
      if cc == "entropy":
        csource = binvis.ColorEntropy(data, None)
      elif cc == "hilbert":
        csource = binvis.ColorHilbert(data, None)
      elif cc == "gradient":
        csource = binvis.ColorGradient(data, None)
      else:
        csource = binvis.ColorHilbert(data, None)
      pngfilename = "%s/%s.%s.%s.png" % (reportsdir, filename, ct, cc)
      imagefiles.append(pngfilename)
      print "  [%d/%d] %s" % (ccidx+1, ctidx+1, pngfilename)
      if ct == "unrolled":
        binvis.drawmap_unrolled(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
      if ct == "square":
        binvis.drawmap_square(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
  if byteviewanimate:
    utils.mkdirp(reportsdir)
    data = file(infile).read()
    chunks = utils.chunkify(data, config["byteviewanimatesize"])
    print "  mode: blockdata (%d bytes ~= %d chunks)" % (len(data), len(chunks))
    for ctidx, ct in enumerate(curvetype):
      for ccidx, cc in enumerate(curvecolor):
        outfiles = []
        for idx, chunk in enumerate(chunks):
          if cc == "entropy":
            csource = binvis.ColorEntropy(chunks[idx], None)
          elif cc == "hilbert":
            csource = binvis.ColorHilbert(chunks[idx], None)
          elif cc == "gradient":
            csource = binvis.ColorGradient(chunks[idx], None)
          else:
            csource = binvis.ColorHilbert(chunks[idx], None)
          pngfilename = "%s/%s.%s.%s.%d.png" % (reportsdir, filename, ct, cc, idx)
          outfiles.append(pngfilename)
          print "  [%d/%d] %s" % (ccidx+1, ctidx+1, pngfilename)
          if ct == "unrolled":
            binvis.drawmap_unrolled(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
          if ct == "square":
            binvis.drawmap_square(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
        giffile = "%s/%s.%s.%s.gif" % (reportsdir, filename, ct, cc)
        cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
        os.system(cli)
        print "  created gif %s for curvetype %s and curvecolor %s" % (giffile, ct, cc)
        utils.remove_files(outfiles)
        imagefiles.append(giffile)
  return imagefiles

def visualize_file(infile):
  filename = utils.remove_extension(utils.filename(infile))
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  print "[byteview] visualizing %s:" % (infile)
  print "  reportsdir: %s" % (infilerd)
  print "  curvemap: %s" % (", ".join(config["scurve"]["curvemap"]))
  print "  curvetype: %s" % (", ".join(config["scurve"]["curvetype"]))
  print "  curvecolor: %s" % (", ".join(config["scurve"]["curvecolor"]))
  return scurve(
    infile = infile,
    reportsdir = infilerd,
    curvemap = config["scurve"]["curvemap"],
    curvetype = config["scurve"]["curvetype"],
    curvecolor = config["scurve"]["curvecolor"],
    pngsize = config["scurve"]["pngsize"],
    showprogress = config["scurve"]["showprogress"],
    byteviewanimate = config["scurve"]["byteviewanimate"]
  )


def apiscout(infile, outfile, apiqr, apivector, vector, exporthtml=True):
  imagefiles = []
  pngfilename = "%s.png" % (outfile)
  apiqr.setVector(apivector.compress(vector))
  apiqr.exportPng(pngfilename)
  print "  exported vector as png %s" % (pngfilename)
  imagefiles.append(pngfilename)
  if exporthtml:
    htmlfilename = "%s.html" % (outfile)
    apiqr.setVector(apivector.compress(vector))
    apiqr.exportHtml(htmlfilename, full=True)
    print "  exported vector as html %s" % (htmlfilename)
    imagefiles.append(htmlfilename)
  return imagefiles

def visualize_imports(infile):
  imagefiles = []
  filename = utils.remove_extension(utils.filename(infile))
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  winapivector = config["apiscout"]["winapivector"]
  apivector = ApiVector.ApiVector(winapivector)
  apiqr = ApiQR(winapivector)
  try:
    pe = pefile.PE(infile)
    pe.parse_data_directories()
    currapilist = []
    regexes = [re.compile("A$"), re.compile("ExA$"), re.compile("Ex$"), re.compile("ExW$"), re.compile("W$")]
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
      for imp in entry.imports:
        if imp.name:
          api = imp.name
          for regex in regexes:
            api = regex.sub("", api)
          currapilist.append(api)
    currapilist = list(set(currapilist))
  except:
    currapilist = []
  imagefiles = []
  apis, vector = [], [0] * 1024
  for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
    for api in currapilist:
      if "!%s;" % (api) in winapi:
        apis.append(winapi)
        index = int(winapi.split(";")[-1])
        vector[index] = 1
  apis = list(set(apis))
  cvector = apivector.compress(vector)
  print "[iatview] visualizing %s:" % (infile)
  print "  reportsdir: %s" % (infilerd)
  print "  importsvector: %s" % (winapivector)
  print "  cvector: %s" % (cvector)
  print "  apis: %d" % (sum(vector))
  imagefiles += apiscout(
    infile = infile,
    outfile = "%s/%s.iv" % (infilerd, filename),
    apiqr = apiqr,
    apivector = apivector,
    vector = vector,
    exporthtml = config["scurve"]["exporthtml"]
  )
  if config["scurve"]["iatviewanimate"]:
    chunks = utils.chunkify(currapilist, config["biviewblocksize"])
    outfiles = []
    for idx, chunk in enumerate(chunks):
      apis, vector = [], [0] * 1024
      for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
        for api in chunk:
          if "!%s;" % (api) in winapi:
            apis.append(winapi)
            index = int(winapi.split(";")[-1])
            vector[index] = 1
      apis = list(set(apis))
      cvector = apivector.compress(vector)
      outfiles.append("%s/%s.iv.%d.png" % (infilerd, filename, idx))
      print "  cvector: %s" % (cvector)
      print "  apis: %d" % (sum(vector))
      outfiles += apiscout(
        infile = infile,
        outfile = "%s/%s.iv.%d" % (infilerd, filename, idx),
        apiqr = apiqr,
        apivector = apivector,
        vector = vector,
        exporthtml = config["scurve"]["exporthtml"]
      )
    giffile = "%s/%s.iv.gif" % (infilerd, filename)
    cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
    os.system(cli)
    print "  created gif %s for mode iatview" % (giffile)
    utils.remove_files(outfiles)
    imagefiles.append(giffile)
  return imagefiles

def visualize_behavior(infile):
  imagefiles = []
  filename = utils.remove_extension(utils.filename(infile))
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  winapivector = config["apiscout"]["winapivector"]
  apivector = ApiVector.ApiVector(winapivector)
  apiqr = ApiQR(winapivector)
  currapilist = []
  report = utils.file_json_open(infile)
  regexes = [re.compile("A$"), re.compile("ExA$"), re.compile("Ex$"), re.compile("ExW$"), re.compile("W$")]
  try:
    for proc in report[report.keys()[0]]["behavior"]["behavior"]["processes"]:
      for call in proc["calls"]:
        api = call["api"]
        for regex in regexes:
          api = regex.sub("", api)
        currapilist.append(api)
    currapilist = list(set(currapilist))
  except:
    currapilist = []
  outfiles = []
  apis, vector = [], [0] * 1024
  for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
    for api in currapilist:
      if "!%s;" % (api) in winapi:
        apis.append(winapi)
        index = int(winapi.split(";")[-1])
        vector[index] = 1
  apis = list(set(apis))
  cvector = apivector.compress(vector)
  print "[behaviorview] visualizing %s:" % (infile)
  print "  reportsdir: %s" % (infilerd)
  print "  importsvector: %s" % (winapivector)
  print "  cvector: %s" % (cvector)
  print "  apis: %d" % (sum(vector))
  imagefiles += apiscout(
    infile = infile,
    outfile = "%s/%s.bv" % (infilerd, filename),
    apiqr = apiqr,
    apivector = apivector,
    vector = vector,
    exporthtml = config["scurve"]["exporthtml"]
  )
  if config["scurve"]["behaviorviewanimate"]:
    chunks = utils.chunkify(currapilist, config["biviewblocksize"])
    outfiles = []
    for idx, chunk in enumerate(chunks):
      apis, vector = [], [0] * 1024
      for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
        for api in chunk:
          if "!%s;" % (api) in winapi:
            apis.append(winapi)
            index = int(winapi.split(";")[-1])
            vector[index] = 1
      apis = list(set(apis))
      cvector = apivector.compress(vector)
      outfiles.append("%s/%s.bv.%d.png" % (infilerd, filename, idx))
      print "  cvector: %s" % (cvector)
      print "  apis: %d" % (sum(vector))
      apiscout(
        infile = infile,
        outfile = "%s/%s.bv.%d" % (infilerd, filename, idx),
        apiqr = apiqr,
        apivector = apivector,
        vector = vector,
        exporthtml = config["scurve"]["exporthtml"]
      )
    giffile = "%s/%s.bv.gif" % (infilerd, filename)
    cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
    os.system(cli)
    print "  created gif %s for mode behaviorview" % (giffile)
    utils.remove_files(outfiles)
    imagefiles.append(giffile)
  return imagefiles
