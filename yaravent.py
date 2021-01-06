import yara
import os
import string
import sys
from multiprocessing import Process
import Evtx.Evtx as evtx

class Args():
    def __init__(self):
        self.threads = 4
        self.depth = 2
        self.rulesDir = "./yara"
        self.logsDir = "./logs"
        self.resultsDir = "./"


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

class Scan():
    def __init__(self, rules, log, args):
        self.rules = rules
        self.log = log
        self.resultDir = args.resultsDir

    def scan(self):
        with evtx.Evtx(self.log) as log:
            for record in log.records():
                xmlRecord = record.xml()
                for rule in self.rules.rules:
                    matches = rule.match(data=xmlRecord)
                    if matches:
                        print(matches)

        
def main():
    args = Args()
    
    rules = Rules(args)
    rules.parseRules()

    logs = Logs(args)
    logs.parseEventFiles()
    processes = []
    for log in logs.logs:
        scan = Scan(rules, log, args)
        p = Process(target=scan.scan())
        processes.append(p)
        p.start()

    for process in processes:
        process.join()
    #scan with yara rules
    #write results

if __name__ == "__main__":
    main()