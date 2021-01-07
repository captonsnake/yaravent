import yara
import os
import string
import sys
import argparse
from dicttoxml import dicttoxml
from multiprocessing import Process
import Evtx.Evtx as evtx
from Evtx.Views import evtx_chunk_xml_view

class Args():
    def __init__(self, parsed):
        self.depth = parsed.depth
        self.rulesDir = parsed.yara
        self.logsDir = parsed.logs
        self.resultsDir = parsed.results
        self.write_misses = parsed.misses
        self.recurs = parsed.recursive
        try:
            self.maxLog = parsed.max
        except:
            self.maxLog = None
        self.force = parsed.force
    def __str__(self):
        return(f"depth = {self.depth}, yara = {self.rulesDir}, logs = {self.logsDir}, results = {self.resultsDir}, missed = {self.write_misses}")
    def __repr__(self):
        return self.__str__()


class Rules():
    def __init__(self, args):
        self.root = args.rulesDir
        self.args = args
        self.rules = []
        self.files = []
    
    def parseRules(self):
        self._get_rules(self.root)
        for f in self.files:
            try:
                self.rules.append(yara.compile(filepath=f))
            except Exception as e:
                print(f"Problem loading yara file = {f}", file=sys.stderr)
                print(e, file=sys.stderr)
                pass

    def _get_rules(self, root):
        for dp, _, fn in os.walk(self.root):
            for f in fn:
                if f.endswith(".yara") or f.endswith(".yar"):
                    self.files.append(os.path.join(dp, f))
            if not self.args.recurs:
                break

class Logs():
    def __init__(self, args):
        self.root = args.logsDir
        self.args = args
        self.logs = []
    
    def parseLogFiles(self):
        skip = []
        if not self.args.force:
            for f in os.listdir(self.args.resultsDir):
                f = f.replace(".misses", "").replace(".hits", "")
                skip.append(f)
        for dp, _, fn in os.walk(self.root):
            for f in fn:
                if len(self.logs) >= self.args.maxLog:
                    break
                if f.endswith('.evtx') and f not in skip:
                    self.logs.append(os.path.join(dp, f))
            break

def write_hit(f, match, xmlRecord):
    f.write("<match>")
    f.write("<rule>")
    f.write(dicttoxml(match, attr_type=False, root=False).decode("utf-8"))
    f.write("</rule>")
    f.write(xmlRecord)
    f.write("</match>")

def write_misses(f, xmlRecord):
    f.write("<miss>")
    f.write(xmlRecord)
    f.write("</miss>")

def scan(log, rules, args):
    log_name = os.path.basename(log)
    hits = os.path.join(args.resultsDir, log_name + ".hits")
    misses = os.path.join(args.resultsDir, log_name + ".misses")

    hitsFn = open(hits, "w")
    hitsFn.write('<?xml version="1.0"?>')
    if args.write_misses:
        missesFn = open(misses, "w")
        missesFn.write('<?xml version="1.0"?>')
    
    with evtx.Evtx(log) as curlog:
                for record in curlog.records():
                    xmlRecord = record.xml()
                    for rule in rules:
                        matches = rule.match(data=xmlRecord)
                        if matches:
                            write_hit(hitsFn, matches, xmlRecord)
                        if matches and args.write_misses:
                            missesFn.write(xmlRecord)
    hitsFn.close()
    if args.write_misses:
        missesFn.close()


def main():

    parser = argparse.ArgumentParser(description="Scans Event logs agains yara rules")
    parser.add_argument('-y', '--yara', metavar='path', required=True, help="Directory of the yara rules")
    parser.add_argument('-l', '--logs', metavar='path', required=True, help="Directory containing the evtx files")
    parser.add_argument('-r', '--results', metavar='path', required=True, help="Directory to store the results")
    parser.add_argument('-d', '--depth', metavar='N', type=int, default=2, help="Recussion depth when looking for scans")
    parser.add_argument('-m', '--misses', action='store_true', help="Write a misses file containing all missed events")
    parser.add_argument('-f', '--force', action="store_true", help="Force scans against all logs")
    parser.add_argument('-R', '--recursive', action="store_true", help="Recursively search for yara rules")
    parser.add_argument('-M', '--max', metavar='N', type=int, help="Set a maximum number of logs to scan")
    parsed = parser.parse_args()
    args = Args(parsed)

    if not os.path.exists(args.resultsDir):
        os.makedirs(args.resultsDir)

    rules = Rules(args)
    rules.parseRules()

    if not rules.rules:
        print("No rules loaded", file=sys.stderr)
        exit()

    logs = Logs(args)
    logs.parseLogFiles()
    print(logs.logs)
    exit()
    if not logs.logs:
        print("No logs loaded", file=sys.stderr)
        exit()

    for log in logs.logs:
        p = Process(target=scan, args=(log, rules.rules, args))
        p.start()


if __name__ == "__main__":
    main()