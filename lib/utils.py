# -*- coding: utf-8 -*-

from difflib import SequenceMatcher
import fnmatch
import base64
import codecs
import errno
import json
import time
import uuid
import os

def chunkify(inlist, blocksize):
  return list(inlist[i:i+blocksize] for i in range(0, len(inlist), blocksize))

def filename(filepath):
  return filepath.split("/")[-1]

def file_open(filename):
  if filename and filename != "" and is_file(filename):
    with codecs.open(filename, mode="r", encoding="utf-8") as fo:
      return fo.read()

def file_save(filename, data, mode="w"):
  if filename and filename != "":
    mkdirp(os.path.dirname(filename))
    try:
      with codecs.open(filename, mode, encoding="utf-8") as fo:
        fo.write(data)
    except Exception as ex:
      with open(filename, mode) as fo:
        fo.write(data)

def file_json_open(filename):
  if filename and filename != "":
    return dict(json.loads(file_open(filename)))

def file_json_string(filename):
  if filename and filename != "":
    return json.dumps(file_open(filename))

def file_json_save(filename, data):
  if filename and filename != "":
    # save json data to file
    with open(filename, "w") as jsonfile:
      return json.dump(data, jsonfile)

def file_to_list(filename):
  lines = []
  with open(filename) as fp:
    lines = [x.strip() for x in fp.readlines()]
  return lines if len(lines) else None

# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def file_search(search_dir="./", regex="*"):
  matches = []
  for root, dirnames, filenames in os.walk(search_dir):
    for filename in fnmatch.filter(filenames, regex):
      if os.path.exists(os.path.join(root, filename)):
        matches.append(os.path.join(root, filename))
  return matches

# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
def file_list(directory, pattern="*.*"):
  if directory and directory != "":
    matches = []
    for root, dirnames, filenames in os.walk(directory):
      for filename in fnmatch.filter(filenames, pattern):
        if os.path.exists(os.path.join(root, filename)):
          if os.path.join(root, filename) not in matches:
            matches.append(os.path.join(root, filename))
    return matches

def file_basename(filename):
  if filename and filename != "":
    return os.path.basename(filename) if is_file(filename) else None

def file_dirname(filename):
  if filename and filename != "":
    return os.path.dirname(filename) if is_file(filename) else None

def is_dir(path):
  if path and path != "":
    return os.path.isdir(path)

def is_file(filename):
  if filename and filename != "":
    return os.path.isfile(filename)

def list_common(list1, list2):
  return list(set(list1).intersection(list2))

# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdirp(path):
  if path and path != "":
    try:
      os.makedirs(path)
    except OSError as exc: # Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
        pass
      else: raise

def remove_extension(filename):
  return ".".join(filename.split(".")[0:-1])

def remove_files(fileslist):
  for f in fileslist:
    try:
      os.remove(f)
    except:
      continue

def file_to_base64(filename):
  if is_file(filename):
    with open(filename) as fp:
      return "data:image/png;base64,%s" % (base64.b64encode(fp.read()))

def get_epoch():
  return int(time.time())

def format_epoch(epoch, formatstr="%d/%b/%Y %H:%M:%S %Z"):
  return time.strftime(formatstr, time.localtime(epoch))

def similar(a, b):
  if a and b:
    return SequenceMatcher(None, a, b).ratio()
  else:
    return 0

def get_unique_string():
  return uuid.uuid4().hex.upper()
