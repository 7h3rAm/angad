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


def scurve(infile, reportsdir, curvemap=["hilbert"], curvetype=["square", "unrolled"], curvecolor=["entropy", "hilbert", "gradient"], pngsize=256, showprogress=False, byteviewanimate=True):
  status = {}
  status["config"] = {}
  status["config"]["infile"] = infile
  status["config"]["reportsdir"] = reportsdir
  status["config"]["curvemap"] = curvemap
  status["config"]["curvetype"] = curvetype
  status["config"]["curvecolor"] = curvecolor
  status["config"]["pngsize"] = pngsize
  status["config"]["showprogress"] = showprogress
  status["config"]["byteviewanimate"] = byteviewanimate
  status["config"]["filename"] = utils.remove_extension(utils.filename(infile))
  utils.mkdirp(status["config"]["reportsdir"])
  data = file(infile).read()
  status["config"]["filesize"] = len(data)
  status["fileview"] = []
  print "  mode: fileview (%d bytes)" % (status["config"]["filesize"])
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
      pngfilename = "%s/%s.%s.%s.png" % (status["config"]["reportsdir"], status["config"]["filename"], ct, cc)
      status["fileview"].append(pngfilename)
      print "  [%d/%d] %s" % (ccidx+1, ctidx+1, pngfilename)
      if ct == "unrolled":
        binvis.drawmap_unrolled(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
      if ct == "square":
        binvis.drawmap_square(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
  if status["config"]["byteviewanimate"]:
    utils.mkdirp(status["config"]["reportsdir"])
    chunks = utils.chunkify(data, config["byteviewblocksize"])
    status["byteviewanimate"] = []
    print "  mode: blockdata (%d bytes ~= %d chunks)" % (status["config"]["filesize"], len(chunks))
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
          pngfilename = "%s/%s.%s.%s.%d.png" % (status["config"]["reportsdir"], status["config"]["filename"], ct, cc, idx)
          outfiles.append(pngfilename)
          print "  [%d/%d] %s" % (ccidx+1, ctidx+1, pngfilename)
          if ct == "unrolled":
            binvis.drawmap_unrolled(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
          if ct == "square":
            binvis.drawmap_square(curvemap[0], pngsize, csource, pngfilename, progress.Progress(None) if showprogress else progress.Dummy())
        giffile = "%s/%s.%s.%s.gif" % (status["config"]["reportsdir"], status["config"]["filename"], ct, cc)
        cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
        os.system(cli)
        print "  created gif %s for curvetype %s and curvecolor %s" % (giffile, ct, cc)
        utils.remove_files(outfiles)
        status["byteviewanimate"].append(giffile)
  return status

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


def apiscout(infile, outfile, apiqr, apivector, defaultvector, exporthtml=True):
  imagefiles = []
  pngfilename = "%s.png" % (outfile)
  apiqr.setVector(apivector.compress(defaultvector))
  apiqr.exportPng(pngfilename)
  print "  exported defaultvector as png %s" % (pngfilename)
  imagefiles.append(pngfilename)
  if exporthtml:
    htmlfilename = "%s.html" % (outfile)
    apiqr.setVector(apivector.compress(defaultvector))
    apiqr.exportHtml(htmlfilename, full=True)
    print "  exported defaultvector as html %s" % (htmlfilename)
    imagefiles.append(htmlfilename)
  return imagefiles

def visualize_imports(infile):
  status = {}
  status["config"] = {}
  status["config"]["infile"] = infile
  filename = utils.remove_extension(utils.filename(status["config"]["infile"]))
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  winapivector = config["apiscout"]["winapivector"]
  apivector = ApiVector.ApiVector(winapivector)
  apiqr = ApiQR(winapivector)
  try:
    pe = pefile.PE(status["config"]["infile"])
    pe.parse_data_directories()
    status["config"]["currapilist"] = []
    regexes = [re.compile("A$"), re.compile("ExA$"), re.compile("Ex$"), re.compile("ExW$"), re.compile("W$")]
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
      for imp in entry.imports:
        if imp.name:
          api = imp.name
          for regex in regexes:
            api = regex.sub("", api)
          status["config"]["currapilist"].append(api)
    status["config"]["currapilist"] = list(set(status["config"]["currapilist"]))
  except:
    status["config"]["currapilist"] = []
  status["importsview"] = []
  status["config"]["importapis"], defaultvector = [], [0] * 1024
  for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
    for api in status["config"]["currapilist"]:
      if "!%s;" % (api) in winapi:
        status["config"]["importapis"].append(winapi)
        index = int(winapi.split(";")[-1])
        defaultvector[index] = 1
  status["config"]["importapis"] = list(set(status["config"]["importapis"]))
  status["config"]["cvector"] = apivector.compress(defaultvector)
  print "[iatview] visualizing %s:" % (status["config"]["infile"])
  print "  reportsdir: %s" % (infilerd)
  print "  importsvector: %s" % (winapivector)
  print "  cvector: %s" % (status["config"]["cvector"])
  print "  importapis: %d" % (sum(defaultvector))
  status["importsview"] += apiscout(
    infile = status["config"]["infile"],
    outfile = "%s/%s.iv" % (infilerd, filename),
    apiqr = apiqr,
    apivector = apivector,
    defaultvector = defaultvector,
    exporthtml = config["scurve"]["exporthtml"]
  )
  if config["scurve"]["iatviewanimate"]:
    chunks = utils.chunkify(status["config"]["currapilist"], config["biviewblocksize"])
    outfiles = []
    for idx, chunk in enumerate(chunks):
      status["config"]["importapis"], defaultvector = [], [0] * 1024
      for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
        for api in chunk:
          if "!%s;" % (api) in winapi:
            status["config"]["importapis"].append(winapi)
            index = int(winapi.split(";")[-1])
            defaultvector[index] = 1
      status["config"]["importapis"] = list(set(status["config"]["importapis"]))
      status["config"]["cvector"] = apivector.compress(defaultvector)
      outfiles.append("%s/%s.iv.%d.png" % (infilerd, filename, idx))
      print "  cvector: %s" % (status["config"]["cvector"])
      print "  importapis: %d" % (sum(defaultvector))
      outfiles += apiscout(
        infile = status["config"]["infile"],
        outfile = "%s/%s.iv.%d" % (infilerd, filename, idx),
        apiqr = apiqr,
        apivector = apivector,
        defaultvector = defaultvector,
        exporthtml = config["scurve"]["exporthtml"]
      )
    giffile = "%s/%s.iv.gif" % (infilerd, filename)
    cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
    os.system(cli)
    print "  created gif %s for mode iatview" % (giffile)
    utils.remove_files(outfiles)
    status["importsview"].append(giffile)
  return status

def visualize_behavior(infile):
  status = {}
  status["config"] = {}
  status["config"]["infile"] = infile
  filename = utils.remove_extension(utils.filename(status["config"]["infile"])).replace(".behavior", "")
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  winapivector = config["apiscout"]["winapivector"]
  apivector = ApiVector.ApiVector(winapivector)
  apiqr = ApiQR(winapivector)
  status["config"]["currapilist"] = []
  report = utils.file_json_open(infile)
  regexes = [re.compile("A$"), re.compile("ExA$"), re.compile("Ex$"), re.compile("ExW$"), re.compile("W$")]
  try:
    for proc in report["results"]["behavior"]["processes"]:
      for call in proc["calls"]:
        api = call["api"]
        for regex in regexes:
          api = regex.sub("", api)
        status["config"]["currapilist"].append(api)
    status["config"]["currapilist"] = list(set(status["config"]["currapilist"]))
  except:
    status["config"]["currapilist"] = []
  status["behaviorview"] = []
  status["config"]["behaviorapis"], defaultvector = [], [0] * 1024
  for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
    for api in status["config"]["currapilist"]:
      if "!%s;" % (api) in winapi:
        status["config"]["behaviorapis"].append(winapi)
        index = int(winapi.split(";")[-1])
        defaultvector[index] = 1
  status["config"]["behaviorapis"] = list(set(status["config"]["behaviorapis"]))
  status["config"]["cvector"] = apivector.compress(defaultvector)
  print "[behaviorview] visualizing %s:" % (infile)
  print "  reportsdir: %s" % (infilerd)
  print "  importsvector: %s" % (winapivector)
  print "  cvector: %s" % (status["config"]["cvector"])
  print "  behaviorapis: %d" % (sum(defaultvector))
  status["behaviorview"] += apiscout(
    infile = infile,
    outfile = "%s/%s.bv" % (infilerd, filename),
    apiqr = apiqr,
    apivector = apivector,
    defaultvector = defaultvector,
    exporthtml = config["scurve"]["exporthtml"]
  )
  if config["scurve"]["behaviorviewanimate"]:
    chunks = utils.chunkify(status["config"]["currapilist"], config["biviewblocksize"])
    outfiles = []
    for idx, chunk in enumerate(chunks):
      status["config"]["behaviorapis"], defaultvector = [], [0] * 1024
      for winapi in utils.file_to_list(config["apiscout"]["winapivector"]):
        for api in chunk:
          if "!%s;" % (api) in winapi:
            status["config"]["behaviorapis"].append(winapi)
            index = int(winapi.split(";")[-1])
            defaultvector[index] = 1
      status["config"]["behaviorapis"] = list(set(status["config"]["behaviorapis"]))
      status["config"]["cvector"] = apivector.compress(defaultvector)
      outfiles.append("%s/%s.bv.%d.png" % (infilerd, filename, idx))
      print "  cvector: %s" % (status["config"]["cvector"])
      print "  behaviorapis: %d" % (sum(defaultvector))
      apiscout(
        infile = infile,
        outfile = "%s/%s.bv.%d" % (infilerd, filename, idx),
        apiqr = apiqr,
        apivector = apivector,
        defaultvector = defaultvector,
        exporthtml = config["scurve"]["exporthtml"]
      )
    giffile = "%s/%s.bv.gif" % (infilerd, filename)
    cli = "convert -delay 3 %s gif:- | gifsicle --delay=%d --loop --optimize=2 --colors=256 --multifile - >%s 2>/dev/null" % (" ".join(outfiles), config["gifdelay"] if config["gifdelay"] and config["gifdelay"] >= 10 and config["gifdelay"] <= 100 else 100, giffile)
    os.system(cli)
    print "  created gif %s for mode behaviorview" % (giffile)
    utils.remove_files(outfiles)
    status["behaviorview"].append(giffile)
  return status
