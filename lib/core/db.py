# -*- coding: utf-8 -*-

from settings import config
from lib import utils

import sqlite3


class Database:
  def __init__(self, filename):
    self.filename = filename
    self.conn = sqlite3.connect(self.filename)
    self.cur = self.conn.cursor()
    self.schema = """CREATE TABLE IF NOT EXISTS records (
      sha256 TEXT PRIMARY KEY,
      scantime INT,
      scantimehuman TEXT,
      filepathbinary TEXT,
      filepathbehavior TEXT,
      importapis TEXT,
      importvector TEXT,
      importclusters TEXT,
      behaviorapis TEXT,
      behaviorvector TEXT,
      behaviorclusters TEXT,
      packer TEXT,
      avbitdefender TEXT,
      avkaspersky TEXT,
      avmicrosoft TEXT,
      avsymantec TEXT,
      imphash TEXT,
      ssdeep TEXT,
      magic TEXT
    )"""

  def open(self):
    self.conn = sqlite3.connect(self.filename)
    self.cur = self.conn.cursor()

  def create(self):
    self.cur.execute(self.schema)
    return self

  def execute(self, query):
    try:
      result = self.cur.execute(query)
    except:
      import traceback
      traceback.print_exc()
      result = None
    if result:
      return result.fetchall()
    else:
      return None

  def commit(self):
    self.conn.commit()
    return self

  def close(self):
    self.conn.close()
    return self

  def add_to_db(self, sha256, scantime, scantimehuman, filepathbinary, filepathbehavior, importapis=None, importvector=None, importclusters=None, behaviorapis=None, behaviorvector=None, behaviorclusters=None, packer=None, avbitdefender=None, avkaspersky=None, avmicrosoft=None, avsymantec=None, imphash=None, ssdeep=None, magic=None):
    self.execute("INSERT OR IGNORE INTO records VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (sha256, scantime, scantimehuman, filepathbinary, filepathbehavior, importapis, importvector, importclusters, behaviorapis, behaviorvector, behaviorclusters, packer, avbitdefender, avkaspersky, avmicrosoft, avsymantec, imphash, ssdeep, magic))
    self.commit()
    return self

  def remove_from_db(self, sha256):
    self.execute("DELETE FROM records WHERE sha256 = '%s'" % (sha256))
    self.commit()
    return self

  def indb(self, sha256):
    return bool(len(self.execute("SELECT sha256 FROM records WHERE sha256 = '%s'" % (sha256))))

  def recordcount(self):
    return len(self.execute("SELECT sha256 FROM records"))
