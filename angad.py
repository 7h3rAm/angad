# -*- coding: utf-8 -*-

#!/usr/bin/env python

from lib.core import hilbertviews
from settings import config
from lib import utils

import argparse
import sys


__progname__ = "Angad"
__version__ = 0.1
__author__ = "Ankur Tyagi (@7h3rAm)"
__email__ = "7h3rAm@gmail.com"


if __name__ == "__main__":
  header = "%s (v%s) - %s" % (__progname__, __version__, __author__)

  parser = argparse.ArgumentParser(description=header)
  parser.add_argument("-i", type=str, action="store", dest="inputdir", help="input directory with .vir and .json files")
  parser.add_argument("-v", action="store_true", help="show verbose output")

  args = parser.parse_args()

  if not args.inputdir:
    print "[-] need inputdir to proceed further"
    parser.print_help()
    sys.exit(1)

  print header

  utils.mkdirp(config["reportsdir"])

  if args.inputdir and utils.is_dir(args.inputdir):
    virfiles = utils.file_list(args.inputdir, pattern="*.vir")
    jsonfiles = utils.file_list(args.inputdir, pattern="*.json")
    if not len(virfiles) and not len(jsonfiles):
      print "[-] could not find .vir and .json files in %s. cannot proceed further" % (args.inputdir)
      sys.exit(1)

    byteviewfile = hilbertviews.visualize_file(virfiles[0])
    byteviewb64data = utils.file_to_base64(byteviewfile[0]) if byteviewfile and len(byteviewfile) and byteviewfile[0] else ""
    iatviewfile = hilbertviews.visualize_imports(virfiles[0])
    iatviewb64data = utils.file_to_base64(iatviewfile[0]) if iatviewfile and len(iatviewfile) and iatviewfile[0] else ""
    behaviorviewfile = hilbertviews.visualize_behavior(jsonfiles[0])
    behaviorviewb64data = utils.file_to_base64(behaviorviewfile[0]) if behaviorviewfile and len(behaviorviewfile) and behaviorviewfile[0] else ""

  filename = utils.remove_extension(utils.filename(virfiles[0]))
  infilerd = "%s/%s" % (config["reportsdir"], filename)
  utils.mkdirp(infilerd)
  report = config["htmltemplate"].replace("{{datadir}}", config["datadir"]).replace("{{reportdir}}", infilerd).replace("{{sha256}}", filename).replace("{{square.entropy.png}}", byteviewb64data).replace("{{iv.png}}", iatviewb64data).replace("{{bv.png}}", behaviorviewb64data)
  with open("%s/report.html" % (infilerd), "w") as fp:
    fp.write(report)
  print "[+] saved %s/report.html" % (infilerd)
  print
