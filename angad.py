# -*- coding: utf-8 -*-
#!/usr/bin/env python

from lib.core import hilbertviews
from lib.core.db import Database
from settings import config
from pprint import pprint
from lib import utils

import argparse
import sys


__progname__ = "Angad"
__version__ = 0.1
__author__ = "Ankur Tyagi (@7h3rAm)"
__email__ = "7h3rAm@gmail.com"


class Angad:
  def __init__(self, args):
    self.args = args
    self.summary = dict()

    # create db if not exists
    Database(config["misc"]["database"]).create().close()

  def create(self):
    self.summary["input"] = {}
    self.summary["views"] = {}
    self.summary["config"] = config

    utils.mkdirp(config["reportsdir"])

    if self.args.inputdir and utils.is_dir(self.args.inputdir):
      self.summary["input"]["virfiles"] = utils.file_list(self.args.inputdir, pattern="*.vir")
      self.summary["input"]["reportjson"] = utils.file_list(self.args.inputdir, pattern="*report.json")
      self.summary["input"]["behaviorjson"] = utils.file_list(self.args.inputdir, pattern="*behavior.json")

      if not len(self.summary["input"]["virfiles"]) and not len(self.summary["input"]["reportjson"]) and not len(self.summary["input"]["behaviorjson"]):
        print "[-] could not find *.vir, *report.json and *.behavior.json files in %s. cannot proceed further" % (self.summary["input"]["directory"])
        sys.exit(1)

      # extract static and behavior data from vt report
      filereport = utils.file_json_open(self.summary["input"]["reportjson"][0])
      self.summary["vtdata"] = {
        "sha256": filereport["sha256"],
        "packer": filereport["additional_info"]["peid"] if "additional_info" in filereport and "peid" in filereport["additional_info"] else None,
        "av": {
          "bitdefender": filereport["scans"]["BitDefender"]["result"],
          "kaspersky": filereport["scans"]["Kaspersky"]["result"],
          "microsoft": filereport["scans"]["Microsoft"]["result"],
          "symantec": filereport["scans"]["Symantec"]["result"],
        },
        "imphash": filereport["additional_info"]["pe-imphash"],
        "ssdeep": filereport["ssdeep"],
        "magic": filereport["additional_info"]["magic"] if "additional_info" in filereport and "magic" in filereport["additional_info"] else None,
      }

      self.summary["views"]["file"] = hilbertviews.visualize_file(self.summary["input"]["virfiles"][0])
      byteviewb64data = utils.file_to_base64(self.summary["views"]["file"]["fileview"][0]) if self.summary["views"]["file"]["fileview"] and len(self.summary["views"]["file"]["fileview"]) and self.summary["views"]["file"]["fileview"][0] else ""
      print

      self.summary["views"]["imports"] = hilbertviews.visualize_imports(self.summary["input"]["virfiles"][0])
      iatviewb64data = utils.file_to_base64(self.summary["views"]["imports"]["importsview"][0]) if self.summary["views"]["imports"]["importsview"] and len(self.summary["views"]["imports"]["importsview"]) and self.summary["views"]["imports"]["importsview"][0] else ""
      print

      self.summary["views"]["behavior"] = hilbertviews.visualize_behavior(self.summary["input"]["behaviorjson"][0])
      behaviorviewb64data = utils.file_to_base64(self.summary["views"]["behavior"]["behaviorview"][0]) if self.summary["views"]["behavior"]["behaviorview"] and len(self.summary["views"]["behavior"]["behaviorview"]) and self.summary["views"]["behavior"]["behaviorview"][0] else ""
      print

      filename = utils.remove_extension(utils.filename(self.summary["input"]["virfiles"][0]))
      self.summary["config"]["directory"] = "%s/%s" % (config["reportsdir"], filename)
      utils.mkdirp(self.summary["config"]["directory"])
      report = config["htmltemplate"].replace("{{datadir}}", config["datadir"]).replace("{{reportdir}}", self.summary["config"]["directory"]).replace("{{sha256}}", filename).replace("{{square.entropy.png}}", iatviewb64data).replace("{{iv.png}}", iatviewb64data).replace("{{bv.png}}", behaviorviewb64data)

      if not len(self.summary["views"]["behavior"]["config"]["behaviorapis"]):
        self.summary["views"]["behavior"]["config"]["cvector"] = None

      # use cvectors from import views to search for similar reports in db
      self.summary["importclusters"] = self.cluster(key="imports")
      print

      # use cvectors from behavior views to search for similar reports in db
      self.summary["behaviorclusters"] = self.cluster(key="behavior")
      print

      self.summary["config"]["scantime"] = utils.get_epoch()
      self.summary["config"]["scantimehuman"] = utils.format_epoch(self.summary["config"]["scantime"])

      self.summary["config"]["reporthtml"] = "%s/report.html" % (self.summary["config"]["directory"])
      utils.file_save(filename=self.summary["config"]["reporthtml"], data=report)
      print "[+] saved %s" % (self.summary["config"]["reporthtml"])

      self.summary["config"]["summaryjson"] = "%s/summary.json" % (self.summary["config"]["directory"])
      utils.file_json_save(filename=self.summary["config"]["summaryjson"], data=self.summary)
      print "[+] saved %s" % (self.summary["config"]["summaryjson"])

      print
      return self

  def index(self):
    # add a new row or update existing for current sha256
    db = Database(config["misc"]["database"])

    # if overwrite requested, delete existing entry from db
    if self.args.overwrite:
      db.remove_from_db(self.summary["vtdata"]["sha256"])

    db.add_to_db(
      sha256=self.summary["vtdata"]["sha256"],
      scantime=self.summary["config"]["scantime"],
      scantimehuman=self.summary["config"]["scantimehuman"],
      filepathbinary=self.summary["input"]["virfiles"][0],
      filepathbehavior=self.summary["input"]["reportjson"][0],
      importapis=",".join(self.summary["views"]["imports"]["config"]["importapis"]) if self.summary["views"]["imports"]["config"]["importapis"] and len(self.summary["views"]["imports"]["config"]["importapis"]) else None,
      importvector=self.summary["views"]["imports"]["config"]["cvector"],
      importclusters=",".join(self.summary["importclusters"]) if self.summary["importclusters"] and len(self.summary["importclusters"]) else None,
      behaviorapis=",".join(self.summary["views"]["behavior"]["config"]["behaviorapis"]) if self.summary["views"]["behavior"]["config"]["behaviorapis"] and len(self.summary["views"]["behavior"]["config"]["behaviorapis"]) else None,
      behaviorvector=self.summary["views"]["behavior"]["config"]["cvector"],
      behaviorclusters=",".join(self.summary["behaviorclusters"]) if self.summary["behaviorclusters"] and len(self.summary["behaviorclusters"]) else None,
      packer=self.summary["vtdata"]["packer"],
      avbitdefender=self.summary["vtdata"]["av"]["bitdefender"],
      avkaspersky=self.summary["vtdata"]["av"]["kaspersky"],
      avmicrosoft=self.summary["vtdata"]["av"]["microsoft"],
      avsymantec=self.summary["vtdata"]["av"]["symantec"],
      imphash=self.summary["vtdata"]["imphash"],
      ssdeep=self.summary["vtdata"]["ssdeep"],
      magic=self.summary["vtdata"]["magic"]
    )

    db.close()
    return self

  def cluster(self, key="imports"):
    key = key.lower()
    if key not in ["imports", "behavior"]:
      return None
    db = Database(config["misc"]["database"])

    vector = self.summary["views"][key]["config"]["cvector"]
    if not vector:
      return None

    # open database and search for similar reports
    matches, clusters = [], []
    if key == "imports":
      records = db.execute("SELECT sha256, importclusters, importvector FROM records WHERE sha256 NOT LIKE '%s'" % (self.summary["vtdata"]["sha256"]))
    elif key == "behavior":
      records = db.execute("SELECT sha256, behaviorclusters, behaviorvector FROM records WHERE sha256 NOT LIKE '%s'" % (self.summary["vtdata"]["sha256"]))

    for record in records:
      matchpercent = utils.similar(vector, record[2])
      if matchpercent >= config["misc"]["clusterthreshold"]:
        matches.append({
          "existinghash": self.summary["vtdata"]["sha256"],
          "currenthash": record[0],
          "clusters": record[1],
          "matchpercent": matchpercent*100
        })
        if record[1] and record[1] not in clusters:
          clusters.append(record[1])
      if self.args.verbose:
        print "[cluster][%s] %s ~= %s (%s: %.2f%%)" % (key, self.summary["vtdata"]["sha256"], record[0], record[1], matchpercent*100)

    if len(matches):
      for match in matches:
        print "[cluster][%s] %s ~= %s (%s: %.2f%%)" % (key, match["existinghash"], match["currenthash"], match["clusters"], match["matchpercent"])
    else:
      print "[cluster][%s] No matches found for sha256: %s" % (key, self.summary["vtdata"]["sha256"])

    # return clusters for current sha256
    if not len(clusters):
      if key == "imports":
        clusters = db.execute("SELECT importclusters FROM records WHERE sha256 = '%s'" % (self.summary["vtdata"]["sha256"]))
      elif key == "behavior":
        clusters = db.execute("SELECT behaviorclusters FROM records WHERE sha256 = '%s'" % (self.summary["vtdata"]["sha256"]))

      if len(clusters) and clusters[0][0] != "None":
        clusters = clusters[0][0].split(",")
      else:
        clusters = [utils.get_unique_string()]

    db.close()
    return clusters

  def process(self):
    # load existing summary.json
    if self.args.summaryjson:
      self.summary = utils.file_json_open(self.args.summaryjson)

    # or create a new summary.json
    else:
      self.create()

    # find clusters and save report to db
    self.index()

  def summarize(self):
    db = Database(config["misc"]["database"])

    # read all clusters from database
    records = db.execute("SELECT importclusters, behaviorclusters FROM records")
    print records


if __name__ == "__main__":
  header = "\n%s (v%s) - %s\n" % (__progname__, __version__, __author__)

  parser = argparse.ArgumentParser(description=header)
  parser.add_argument("-i", type=str, action="store", dest="inputdir", help="input directory with .vir and .json files")
  parser.add_argument("-s", type=str, action="store", dest="summaryjson", help="path for summary.json file")
  parser.add_argument("-o", default=False, action="store_true", dest="overwrite", help="overwrite records in db")
  parser.add_argument("-v", default=False, action="store_true", dest="verbose", help="show verbose output")

  args = parser.parse_args()

  if not args.inputdir and not args.summaryjson:
    print "[-] need inputdir or summary.json to proceed further"
    parser.print_help()
    sys.exit(1)
  else:
    print header
    angad = Angad(args)
    angad.process()
