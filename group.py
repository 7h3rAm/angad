#!/usr/bin/env python

import sys

maxreports = 10

templatereport = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Angad: v0.1</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  </head>
  <body>
    <div class="container">
      <br/>
      <table class="table table-striped table-hover">
        <tr>
          <td colspan="5" class="text-center"><h3>Angad (v0.1): {{familyname}}</h3></td>
        </tr>

        <tr>
          <td><p class="lead text-muted">#</p></td>
          <td><p class="lead text-info">SHA256</p></td>
          <td><p class="lead text-warning">ByteView</p></td>
          <td><p class="lead text-success">IATView</p></td>
          <td><p class="lead text-primary">BehaviorView</p></td>
        </tr>

{{rows}}

      </table>
    </div>
  </body>
</html>
"""

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print "USAGE: %s <list.family>" % (sys.argv[0])
    sys.exit(1)

  listfile = sys.argv[1]

  templaterow = """        <tr>
          <td><h5>{{idx}}.</h5></td>
          <td><h4><a href="https://www.virustotal.com/en/file/{{sha256}}/analysis/" target="_blank">{{sha256}}</a></h4></td>
          <td><img class="img-rounded center-block" alt="" src="{{byteview}}" style="width:128px;height:128px;" /></td>
          <td><img class="img-rounded center-block" alt="" src="{{iatview}}" style="width:128px;height:128px;" /></td>
          <td><img class="img-rounded center-block" alt="" src="{{behaviorview}}" style="width:128px;height:128px;" /></td>
        </tr>
"""

  with open(listfile) as fp:
    lines = fp.readlines()

  family = listfile.split(".")[1]

  rows = []
  for idx, line in enumerate(lines[:maxreports]):
    sha256 = line.strip()
    rows.append(templaterow.replace("{{idx}}", str(idx+1)).replace("{{sha256}}", sha256).replace("{{byteview}}", "/media/ankur/ubuntu500g/warehouse/projects/angad/reports/%s/%s.square.entropy.png" % (sha256, sha256)).replace("{{iatview}}", "/media/ankur/ubuntu500g/warehouse/projects/angad/reports/%s/%s.iv.png" % (sha256, sha256)).replace("{{behaviorview}}", "/media/ankur/ubuntu500g/warehouse/projects/angad/reports/%s/%s.bv.png" % (sha256, sha256)))

  with open("report.%s.html" % (family), "w") as fp:
    fp.write(templatereport.replace("{{familyname}}", family).replace("{{rows}}", "".join(rows)))
