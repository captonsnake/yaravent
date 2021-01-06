import yara
import os
import string
import sys
import argparse
from multiprocessing import Process
import Evtx.Evtx as evtx

class Args():
    def __init__(self, parsed):
        self.depth = parsed.depth
        self.rulesDir = parsed.yara
        self.logsDir = parsed.logs
        self.resultsDir = parsed.results
        self.write_matches = parsed.misses
    def __str__(self):
        return(f"depth = {self.depth}, yara = {self.rulesDir}, logs = {self.logsDir}, results = {self.resultsDir}, missed = {self.write_matches}")
    def __repr__(self):
        return self.__str__()


class Rules():
    def __init__(self, args):
        self.root = args.rulesDir
        self.maxDepth = args.depth
        self.depth = 0
        self.rules = []
        self.files = []
    
    def parseRules(self):
        self._get_rules(self.root)
        for f in self.files:
            try:
                self.rules.append(yara.compile(filepath=f))
            except:
                #TODO: Log error
                pass

    def _get_rules(self, root):
        # TODO handle externals in yara
        self.depth += 1
        for dp, dn, fn in os.walk(self.root):
            for f in fn:
                if f.endswith(".yara") or f.endswith(".yar"):
                    self.files.append(os.path.join(dp, f))
            if self.depth < self.maxDepth:
                for d in dn:
                    self._get_rules(d)
            else:
                return

class Logs():
    def __init__(self, args):
        self.root = args.logsDir
        self.logs = []
    
    def parseEventFiles(self):
        # TODO test if already scanned?
        for dp, _, fn in os.walk(self.root):
            for f in fn:
                if f.endswith('.evtx'):
                    self.logs.append(os.path.join(dp, f))

def scan(log, rules, args):
    log_name = os.path.basename(log)
    hits = os.path.join(args.resultsDir, log_name + ".hits")
    misses = os.path.join(args.resultsDir, log_name + ".misses")

    hitsFn = open(hits, "a")
    missesFn = open(misses, "a")

    with evtx.Evtx(log) as curlog:
            for record in curlog.records():
                xmlRecord = record.xml()
                for rule in rules:
                    matches = rule.match(data=xmlRecord)
                    if matches:
                        for match in matches:
                            hitsFn.write(xmlRecord)
                    if matches and args.write_matches:
                        missesFn.write(xmlRecord)


def main():

    parser = argparse.ArgumentParser(description="Scans Event logs agains yara rules")
    parser.add_argument('-y', '--yara', metavar='path', type=ascii, required=True, help="Directory of the yara rules")
    parser.add_argument('-l', '--logs', metavar='path', type=ascii, required=True, help="Directory containing the evtx files")
    parser.add_argument('-r', '--results', metavar='path', type=ascii, required=True, help="Directory to store the results")
    parser.add_argument('-d', '--depth', metavar='N', type=int, default=2, help="Recussion depth when looking for scans")
    parser.add_argument('-m', '--misses', action='store_true', help="Will write a misses file containing all missed events")
    parsed = parser.parse_args()
    args = Args(parsed)
    print(args)
    rules = Rules(args)
    rules.parseRules()

    logs = Logs(args)
    logs.parseEventFiles()

    for log in logs.logs:
        p = Process(target=scan, args=(log, rules.rules, args))
        p.start()


if __name__ == "__main__":
    main()