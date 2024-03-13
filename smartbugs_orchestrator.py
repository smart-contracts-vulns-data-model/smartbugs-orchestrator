#! /usr/bin/env python3

import argparse, json, sys, shutil, importlib
sys.path.append('./smartbugs')
from pathlib import Path
import copy
import sb.smartbugs as smartbugs
import sb.settings as settings
import sb.errors as errors
import sb.colors as colors

URL = "https://smart-contracts-vulns-data-model.github.io/smart-vulnerabilities/main?vulnerability="
MODELPATH = "./smart-vulnerabilities/src/data/out.json"
SMARTRESPATH = "results"
TOOLS = ["confuzzius", "conkas", "ethainter", "ethor", "honeybadger", "madmax", "maian", "manticore", "mythril", "osiris", "oyente", "pakala", "securify", "sfuzz", "slither", "solhint", "teether", "vandal", "smartcheck"]

def load_model():
    with open(MODELPATH, "r") as f:
        data_model = f.read()
    return json.loads(data_model)
MODEL = load_model()

def parse_args():
    parser = argparse.ArgumentParser(
                        prog='SmartBugs Orchestrator',
                        add_help=False,
                        description='Orchestrate SmartBugs tools prioritizing them and enrich output')

    input = parser.add_argument_group("input options")
    input.add_argument("-f", "--files",
        metavar="PATTERN",
        nargs="+",
        type=str,
        help=f"glob pattern specifying the files to analyse [default: None]")
    input.add_argument("-t", "--tools",
        metavar="TOOL",
        nargs="+",
        type=str,
        help=f"tools to run on the contracts (default: Best tools)")

    exec = parser.add_argument_group("execution options")
    exec.add_argument("--processes",
        type=int,
        metavar="N",
        default=1,
        help=f"number of parallel processes [default: 1]")
    exec.add_argument("--timeout",
        type=int,
        metavar="N",
        help=f"timeout for each task in seconds [default: None]")
    exec.add_argument("--cpu-quota",
        type=int,
        metavar="N",
        help=f"cpu quota for docker containers [default: None]")
    exec.add_argument("--mem-limit",
        type=str,
        metavar="MEM",
        help=f"memory quota for docker containers, like 512m or 1g [default: None]")

    info = parser.add_argument_group("information options")
    info.add_argument("-h", "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help message and exit")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    arguments = vars(parser.parse_args())
    arguments["sarif"] = True
    arguments["runid"] = "sbo"

    return arguments

class ToolEvaluator():
    _scored_tools = {}

    def __init__(self) -> None:
        for tool in MODEL["tools"]:
            if tool["name"] in TOOLS:
                self._scored_tools[tool["id"]] = {
                        "vulns": set(),
                        "name": tool["name"]
                        }

    def _reset_scores(self):
        for k in self._scored_tools.keys():
            self._scored_tools[k]["vulns"] = set()

    # Returns the tool that is connected with the highest number of vulns
    # depth: "the n-th best tool(s)"
    def best_tools(self, depth = 0) -> list:
        for vuln in MODEL["vulnerabilities"]:
            for tool in vuln["tools"]:
                if self._scored_tools.get(tool):
                    self._scored_tools[tool]["vulns"].add(vuln["id"])
            for vuln1 in MODEL["vulnerabilities"]:
                if vuln["id"] in vuln1["parent_vulnerabilities"]:
                    for tool in vuln["tools"]:
                        if self._scored_tools.get(tool):
                            self._scored_tools[tool]["vulns"].add(vuln1["id"])
        sorted_tools = sorted(self._scored_tools.items(), key=lambda x: len(x[1]["vulns"]), reverse=True)
        best_tools = []
        max_ = -1
        i = 0
        for tool in sorted_tools:
            if len(tool[1]["vulns"]) > max_:
                max_ = len(tool[1]["vulns"])
                best_tools.append([tool[1]["name"]])
            elif len(tool[1]["vulns"]) == max_:
                best_tools[i].append(tool[1]["name"])
            else:
                i += 1
                max_ = len(tool[1]["vulns"])
                best_tools.append([tool[1]["name"]])
        self._reset_scores()
        if depth >= len(best_tools): return []
        else: return best_tools[depth]

class SmartBugsRunner():
    options = settings.Settings()
    results = {}

    def __init__(self) -> None:
        self._reset_options()

    def dump_results(self, file):
        to_dump = copy.deepcopy(self.results)
        for result in [x for xs in to_dump.values() for x in xs]:
            sbos = result["sbo"]
            for sbo in sbos:
                if not sbo.get("id"): continue
                sbo["url"] = URL + sbo["id"]
                del sbo["id"]
                sbo["level"] = Level(sbo["level"]).body["name"]
                categories = []
                for category in sbo["categories"]:
                    categories.append(Category(category).body["name"])
                sbo["categories"] = categories
                attacks = []
                for attack in sbo["attacks"]:
                    attacks.append(Attack(attack).body["name"])
                sbo["attacks"] = attacks
                for ref in sbo["references"]:
                    ref["ref_id"] = Reference(ref["ref_id"]).body["name"]
                cwes = []
                for cwe in sbo["cwes"]:
                    cwes.append(CWE(cwe).body["name"])
                sbo["cwes"] = cwes
                swcs = []
                for swc in sbo["swcs"]:
                    swcs.append(SWC(swc).body["name"])
                sbo["swcs"] = swcs
                tools = []
                for tool in sbo["tools"]:
                    tools.append(Tool(id_=tool).body["name"])
                sbo["tools"] = tools
                mitigations = []
                for mitigation in sbo["mitigations"]:
                    mitigations.append(Mitigation(mitigation).body["name"])
                sbo["mitigations"] = mitigations
                parents = []
                for parent in sbo["parent_vulnerabilities"]:
                    parents.append(Vulnerability(id_=parent).body["name"])
                sbo["parent_vulnerabilities"] = parents
                enablings = []
                for enabling in sbo["enabling_vulnerabilities"]:
                    enablings.append(Vulnerability(id_=enabling).body["name"])
                sbo["enabling_vulnerabilities"] = enablings
                impactants = []
                for impactant in sbo["impacting_vulnerabilities"]:
                    impactants.append(Vulnerability(id_=impactant).body["name"])
                sbo["impacting_vulnerabilities"] = impactants
        with open(file, 'w') as outfile:
            json.dump(to_dump, outfile, indent=2)

    def set_files(self, files):
        self.options.files = []
        if isinstance(files, list):
            for f in files:
                self.options.files.append((None, f))
        else: self.options.files = [(None, files)]

    def set_tools(self, tools):
        if isinstance(tools, list): self.options.tools = tools
        else: self.options.tools = [tools]

    def run(self):
        results = {}
        smartbugs.main(self.options)
        files = list(Path(".").rglob("*.sarif"))
        for file in files:
            tool = ""
            for t in TOOLS:
                if t in str(file):
                    tool = t
            with open(file, "r") as f:
                content = f.read()
            content = json.loads(content)
            for run in content["runs"]:
                results[tool] = run["results"]
        for tool, result in results.items():
            for res in result:
                if res.get("sbo"):
                    tmp = []
                    for v1 in res["sbo"]:
                        v = Vulnerability(v1)
                        tmp.append(v.body)
                    res["sbo"] = tmp
        shutil.rmtree(SMARTRESPATH, ignore_errors=True)
        return results

    def run_tools(self):
        found = False
        if self.options.tools[0] == "None":
            print(colors.success("No inputted tools"))
            return found
        print(colors.success(f"Running input tools..."))
        results = self.run()
        for tool, res in results.items():
            if res:
                print(colors.success(f"{tool} found something!"))
                found = True
        self.results.update(results)
        self._reset_options()
        if not found:
            print(colors.warning("Nothing found by input tools"))
        else:
            print(colors.success(f"Finished running input tools"))
        return found

    def run_best_tools(self):
        print(colors.success(f"Running best tools..."))
        depth = 0
        while True:
            self._reset_options()
            te = ToolEvaluator()
            best_tools = te.best_tools(depth)
            print(colors.success(f"Trying {best_tools}..."))
            self.set_tools(best_tools)
            results = self.run()
            found = False
            for tool, res in results.items():
                if res:
                    print(colors.success(f"{tool} found something!"))
                    found = True
            self.results.update(results)
            if not found:
                print(colors.warning(f"Nothing found by {best_tools} with depth {depth}"))
                depth += 1
            else:
                print(colors.success(f"Finished running best tools"))
                self._reset_options()
                return True
            if not best_tools:
                print(colors.success(f"No vulnerabilities found"))
                return False

    def run_impacting(self):
        print(colors.success(f"Running tools spotting impacting vulns..."))
        vulns_found = False
        blind = set()
        found = set()
        impacting = set()
        for tool, result in self.results.items():
            for res in result:
                if not res.get("sbo"): continue
                for v1 in res["sbo"]:
                    v = Vulnerability(body = v1)
                    tmp = v.get_impacting_vulns()
                    converted_impacting = []
                    for e in tmp:
                        converted_impacting.append(Vulnerability(id_ = e).body["name"])
                    if converted_impacting:
                        print(colors.success(f"The vulnerability {v.body['name']} is impacted by: {converted_impacting}"))
                        impacting.update(tmp)
                        blind.update(tmp)
        if impacting:
            to_run = set()
            for tool in TOOLS:
                t = Tool(name=tool)
                connected = t.get_connected_vulns()
                for c in connected:
                    if c in impacting:
                        to_run.add(tool)
                        found.add(c)
            blind = blind - found
            if to_run:
                converted_found = []
                for e in found:
                    converted_found.append(Vulnerability(id_ = e).body["name"])
                print(colors.success(f"Trying {to_run} tools to spot {converted_found} impacting vulns"))
                self.set_tools(list(to_run))
                results = self.run()
                self.results.update(results)
                vulns_found = False
                impacting_found = False
                for tool, result in results.items():
                    if result:
                        print(colors.success(f"{tool} found something!"))
                        for r in result:
                            for v in r["sbo"]:
                                if v["id"] in found:
                                    print(colors.success(f"{tool} found the impacting vuln {v['name']}"))
                                    impacting_found = True
                        vulns_found = True
                if not vulns_found: print(colors.warning(f"Nothing found by {to_run}"))
                elif not impacting_found: print(colors.warning(f"No impacting vulns found by {to_run}"))
        if blind:
            converted_blind = []
            for b in blind:
                converted_blind.append(Vulnerability(id_ = b).body["name"])
            print(colors.error(f"These vulnerabilities can't be spotted by any supported tool: {converted_blind}"))
        print(colors.success(f"Finished running tools spotting impacting vulns"))
        return vulns_found

    def run_impactant(self):
        print(colors.success(f"Running tools spotting impacted vulns..."))
        vulns_found = False
        blind = set()
        found = set()
        impactant = set()
        for tool, result in self.results.items():
            for res in result:
                if not res.get("sbo"): continue
                for v1 in res["sbo"]:
                    v = Vulnerability(body = v1)
                    tmp = v.get_impactant_vulns()
                    converted_impactant = []
                    for e in tmp:
                        converted_impactant.append(Vulnerability(id_ = e).body["name"])
                    if converted_impactant:
                        print(colors.success(f"The vulnerability {v.body['name']} is impactant on: {converted_impactant}"))
                        impactant.update(tmp)
                        blind.update(tmp)
        if impactant:
            to_run = set()
            for tool in TOOLS:
                t = Tool(name=tool)
                connected = t.get_connected_vulns()
                for c in connected:
                    if c in impactant:
                        to_run.add(tool)
                        found.add(c)
            blind = blind - found
            if to_run:
                converted_found = []
                for e in found:
                    converted_found.append(Vulnerability(id_ = e).body["name"])
                print(colors.success(f"Trying {to_run} tools to spot {converted_found} impacted vulns"))
                self.set_tools(list(to_run))
                results = self.run()
                self.results.update(results)
                vulns_found = False
                impactant_found = False
                for tool, result in results.items():
                    if result:
                        print(colors.success(f"{tool} found something!"))
                        for r in result:
                            for v in r["sbo"]:
                                if v["id"] in found:
                                    print(colors.success(f"{tool} found the impacted vuln {v['name']}"))
                                    impactant_found = True
                        vulns_found = True
                if not vulns_found: print(colors.warning(f"Nothing found by {to_run}"))
                elif not impactant_found: print(colors.warning(f"No impacted vulns found by {to_run}"))
        if blind:
            converted_blind = []
            for b in blind:
                converted_blind.append(Vulnerability(id_ = b).body["name"])
            print(colors.error(f"These vulnerabilities can't be spotted by any supported tool: {converted_blind}"))
        print(colors.success(f"Finished running tools spotting impacted vulns"))
        return vulns_found

    def run_enabling(self):
        print(colors.success(f"Running tools spotting enabling vulns..."))
        vulns_found = False
        blind = set()
        found = set()
        enabling = set()
        for tool, result in self.results.items():
            for res in result:
                if not res.get("sbo"): continue
                for v1 in res["sbo"]:
                    v = Vulnerability(body = v1)
                    tmp = v.get_enabling_vulns()
                    converted_enabling = []
                    for e in tmp:
                        converted_enabling.append(Vulnerability(id_ = e).body["name"])
                    if converted_enabling:
                        print(colors.success(f"The vulnerability {v.body['name']} is enabled by: {converted_enabling}"))
                        enabling.update(tmp)
                        blind.update(tmp)
        if enabling:
            to_run = set()
            for tool in TOOLS:
                t = Tool(name=tool)
                connected = t.get_connected_vulns()
                for c in connected:
                    if c in enabling:
                        to_run.add(tool)
                        found.add(c)
            blind = blind - found
            if to_run:
                converted_found = []
                for e in found:
                    converted_found.append(Vulnerability(id_ = e).body["name"])
                print(colors.success(f"Trying {to_run} tools to spot {converted_found} enabling vulns"))
                self.set_tools(list(to_run))
                results = self.run()
                self.results.update(results)
                vulns_found = False
                enabling_found = False
                for tool, result in results.items():
                    if result:
                        print(colors.success(f"{tool} found something!"))
                        for r in result:
                            for v in r["sbo"]:
                                if v["id"] in found:
                                    print(colors.success(f"{tool} found the enabling vuln {v['name']}"))
                                    enabling_found = True
                        vulns_found = True
                if not vulns_found: print(colors.warning(f"Nothing found by {to_run}"))
                elif not enabling_found: print(colors.warning(f"No enabling vulns found by {to_run}"))
        if blind:
            converted_blind = []
            for b in blind:
                converted_blind.append(Vulnerability(id_ = b).body["name"])
            print(colors.error(f"These vulnerabilities can't be spotted by any supported tool: {converted_blind}"))
        print(colors.success(f"Finished running tools spotting enabling vulns"))
        return vulns_found

    def run_enabled(self):
        print(colors.success(f"Running tools spotting enabled vulns..."))
        vulns_found = False
        blind = set()
        found = set()
        enabled = set()
        for tool, result in self.results.items():
            for res in result:
                if not res.get("sbo"): continue
                for v1 in res["sbo"]:
                    v = Vulnerability(body = v1)
                    tmp = v.get_enabled_vulns()
                    converted_enabled = []
                    for e in tmp:
                        converted_enabled.append(Vulnerability(id_ = e).body["name"])
                    if converted_enabled:
                        print(colors.success(f"The vulnerability {v.body['name']} enables: {converted_enabled}"))
                        enabled.update(tmp)
                        blind.update(tmp)
        if enabled:
            to_run = set()
            for tool in TOOLS:
                t = Tool(name=tool)
                connected = t.get_connected_vulns()
                for c in connected:
                    if c in enabled:
                        to_run.add(tool)
                        found.add(c)
            blind = blind - found
            if to_run:
                converted_found = []
                for e in found:
                    converted_found.append(Vulnerability(id_ = e).body["name"])
                print(colors.success(f"Trying {to_run} tools to spot {converted_found} enabled vulns"))
                self.set_tools(list(to_run))
                results = self.run()
                self.results.update(results)
                vulns_found = False
                enabled_found = False
                for tool, result in results.items():
                    if result:
                        print(colors.success(f"{tool} found something!"))
                        for r in result:
                            for v in r["sbo"]:
                                if v["id"] in found:
                                    print(colors.success(f"{tool} found the enabled vuln {v['name']}"))
                                    enabled_found = True
                        vulns_found = True
                if not vulns_found: print(colors.warning(f"Nothing found by {to_run}"))
                elif not enabled_found: print(colors.warning(f"No enabled vulns found by {to_run}"))
        if blind:
            converted_blind = []
            for b in blind:
                converted_blind.append(Vulnerability(id_ = b).body["name"])
            print(colors.error(f"These vulnerabilities can't be spotted by any supported tool: {converted_blind}"))
        print(colors.success(f"Finished running tools spotting enabled vulns"))
        return vulns_found

    def _reset_options(self):
        self.options = settings.Settings()
        self.options.update(parse_args())

class Vulnerability():
    body = {}

    def __init__(self, name = "", body = {}, id_ = "") -> None:
        if body: self.body = body
        elif name: self.body = self._get_body_by_name(name)
        elif id_: self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for vuln in MODEL["vulnerabilities"]:
            if vuln["id"] == id_:
                return vuln
        return {}

    def _get_body_by_name(self, name):
        for vuln in MODEL["vulnerabilities"]:
            if vuln["name"] == name:
                return vuln
        return {}

    def get_impacting_vulns(self):
        return self.body["impacting_vulnerabilities"]
    
    def get_enabling_vulns(self):
        return self.body["enabling_vulnerabilities"]
    
    def get_parent_vulns(self):
        return self.body["parent_vulnerabilities"]

    def get_son_vulns(self):
        sons = []
        for vuln in MODEL["vulnerabilities"]:
            if vuln["id"] != self.body["id"]:
                if self.body["id"] in vuln["parent_vulnerabilities"]:
                    sons.append(vuln["id"])
        return sons

    def get_enabled_vulns(self):
        enabled = []
        for vuln in MODEL["vulnerabilities"]:
            if vuln["id"] != self.body["id"]:
                if self.body["id"] in vuln["enabling_vulnerabilities"]:
                    enabled.append(vuln["id"])
        return enabled

    def get_impactant_vulns(self):
        impactant = []
        for vuln in MODEL["vulnerabilities"]:
            if vuln["id"] != self.body["id"]:
                if self.body["id"] in vuln["impacting_vulnerabilities"]:
                    impactant.append(vuln["id"])
        return impactant

class Tool():
    body = {}
    
    def __init__(self, name = None, id_ = None) -> None:
        if name: self.body = self._get_body_by_name(name)
        elif id_: self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for tool in MODEL["tools"]:
            if tool["id"] == id_:
                return tool
        return {}

    def _get_body_by_name(self, name):
        for tool in MODEL["tools"]:
            if tool["name"] == name:
                return tool
        return {}

    def get_connected_vulns(self):
        vulns = []
        for vuln in MODEL["vulnerabilities"]:
            if self.body.get("id") in vuln["tools"]:
                vulns.append(vuln["id"])
        return vulns

class Level():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for level in MODEL["levels"]:
            if level["id"] == id_:
                return level
        return {}

class Category():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for category in MODEL["categories"]:
            if category["id"] == id_:
                return category
        return {}

class Attack():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for attack in MODEL["attacks"]:
            if attack["id"] == id_:
                return attack
        return {}

class Reference():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for reference in MODEL["references"]:
            if reference["id"] == id_:
                return reference
        return {}

class CWE():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for cwe in MODEL["cwes"]:
            if cwe["id"] == id_:
                return cwe
        return {}

class SWC():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for swc in MODEL["swcs"]:
            if swc["id"] == id_:
                return swc
        return {}

class Mitigation():
    body = {}
    
    def __init__(self, id_) -> None:
        self.body = self._get_body_by_id(id_)

    def _get_body_by_id(self, id_):
        for mitigation in MODEL["mitigations"]:
            if mitigation["id"] == id_:
                return mitigation
        return {}

if __name__ == "__main__":
    print(colors.success(f"Welcome to SmartBugs Orchestrator!"))

    runner = SmartBugsRunner()

    # Start the analysis running input tools or tools that are capable of finding the highest number of vulns until something is found
    if not runner.run_tools():
        if not runner.run_best_tools():
            exit(0)

    # Expand the analysis searching for enabled vulns and run tools that are capable of spotting them -> Alert blind spots
    runner.run_enabled()

    # Expand the analysis searching for impactant vulns and run tools that are capable of spotting them -> Alert blind spots
    runner.run_impactant()
 
    # Expand the analysis searching for enabling rels with vulns and run tools that are capable of spotting them -> Alert blind spots
    runner.run_enabling()

    # Expand the analysis searching for impacting rels with vulns and run tools that are capable of spotting them -> Alert blind spots
    runner.run_impacting()

    # Dump results to file
    runner.dump_results("data.json")
