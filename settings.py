# -*- coding: utf-8 -*-

import os

config = {
  "scurve": {
    "curvemap": ["hilbert"],
    "curvetype": ["square"],
    "curvecolor": ["entropy"],
    "pngsize": 256,
    "exporthtml": False,
    "showprogress": False,
    "byteviewanimate": False,
    "iatviewanimate": False,
    "behaviorviewanimate": False
  },

  "apiscout": {
    "winapivector": "%s/data/winapi1024v1.txt" % (os.path.abspath(os.path.join(os.path.dirname(__file__))))
  },

  "gifdelay": 100,
  "byteviewblocksize": 40000,
  "biviewblocksize": 20,
  "datadir": "%s/data" % (os.path.abspath(os.path.join(os.path.dirname(__file__)))),
  "reportsdir": "%s/reports" % (os.path.abspath(os.path.join(os.path.dirname(__file__)))),
  "htmltemplate": open("%s/data/report-template.html" % (os.path.abspath(os.path.join(os.path.dirname(__file__))))).read(),

  "misc": {
    "database": "angad.sqlite",
    "saveimages": False,
    "clusterthreshold": 0.9,
    "vectors": [
      "A8gAgAFAIA3gA7IA4EAACA7CQA4QA8QABA3EA6FAEA5CA3IA69BAEAABAABA10",
      "AAgAAgAAwAgAFQIAQMwysA5JA3gEQAgACA3BgCQLAAQACFCgIAIAELJBIA5QBL}AEAiA3GAEQA58EgIASwA6BABAABAgA6QAKIA",
      "ErkAAQIABBpe,QIgUIwytA5JzhgAOYAm.aBhMwBq]Ot+twChA,]gIABLBAYCiVMswMAZACAA?BjBEIQAAgAIwj-aBCQNA5QAIAD,-eQoiQkQmBAH]DA3ngACAAQAEEAALI-kAE^acSzABCAABhSBEAREgBhgEQCXoYI+",
      "AARogzQx/,wIiQcwCuABj.RJDlujHYQgv*AC,_fe@LO-}TIcIA3IasLJBgCAntMwNLFAEAAYhlADAQABgEAxAQCAAQAAIA3wAMAz_kYitAQhAFA10BD_^/fDMBn.-_mADwgASgDTkAAEgPFNDHAgbBhIAGToaKQ"
    ]
  }
}
