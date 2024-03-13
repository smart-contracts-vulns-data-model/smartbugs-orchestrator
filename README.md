# Smartbugs Orchestrator

Orchestrate SmartBugs tools prioritizing them and enrich output.

PoC for the paper "SoK: A Unified Data Model for Smart Contract Vulnerability Taxonomies"

## Features

- Supported
    - Some features and supported tools by SmartBugs
    - Best tools choosing by vulnerabilities coverage
    - Alert blind spots
    - Depends on and Enables
    - Mitigations
    - Tools already tried aren't rerun on the same input file
- Enabled
    - Similarity with famous attack
    - Scoring
    - Mitigations prioritization based on Scoring
    - Tools orchestation based on precision in spotting vulnerabilities
    - Mitigation applicability (Type of, Consequence of)

## Limitations

- As for now, the tool works only if files in input are the same contract in all supported formats

## Installation

### Requirements

- Linux
- [Docker](https://docs.docker.com/install)
- [Python3](https://www.python.org) (version 3.6 and above, 3.10+ recommended)

### Unix/Linux

1. Install [Docker](https://docs.docker.com/install) and [Python3](https://www.python.org).

   Make sure that the user running SmartBugs is allowed to interact with the Docker daemon, by adding the user to the `docker` group:

   ```bash
   sudo usermod -a -G docker $USER
   ```
   For adding another user, replace `$USER` by the respective user-id. The group membership becomes active with the next log-in.

2. Clone [SmartBugs's Orchestrator repository](https://gitlab.com/sapienza-phd/projects/smart-contracts/smartbugs-orchestrator) and its submodules:

   ```bash
   git clone --recurse-submodules git@github.com:smart-contracts-vulns-data-model/smartbugs-orchestrator.git
   ```

3. Install Python dependencies in a virtual environment and activate it:

   ```bash
   smartbugs/install/setup-venv.sh
   virtualenv venv && . venv/bin/activate
   ```

## Usage

SmartBugs Orchestrator provides a command-line interface. Run it without arguments for a short description.

```console
$ python smartbugs_orchestrator.py
Welcome to SmartBugs Orchestrator!
usage: SmartBugs Orchestrator [-f PATTERN [PATTERN ...]] [-t TOOL [TOOL ...]] [--processes N] [--timeout N]
                              [--cpu-quota N] [--mem-limit MEM] [-h]

Orchestrate SmartBugs tools prioritizing them and enrich output

input options:
  -f PATTERN [PATTERN ...], --files PATTERN [PATTERN ...]
                        glob pattern specifying the files to analyse [default: None]; may be prefixed by 'DIR:' for
                        search relative to DIR
  -t TOOL [TOOL ...], --tools TOOL [TOOL ...]
                        tools to run on the contracts (default: Best tools)

execution options:
  --processes N         number of parallel processes [default: 1]
  --timeout N           timeout for each task in seconds [default: None]
  --cpu-quota N         cpu quota for docker containers [default: None]
  --mem-limit MEM       memory quota for docker containers, like 512m or 1g [default: None]

information options:
  -h, --help            show this help message and exit
```

**Example:** To analyse the ReturnValue sample in the `smartbugs/samples` directory use the command

```console
python smartbugs-orchestrator.py -f samples/ReturnValue* --processes 2 --mem-limit 4g --timeout 600
```

The options tell SmartBugs and the orchestrator to run two processes in parallel, with a memory limit of 4GB and max. 10 minutes computation time per task.
Results are placed in the local file `data.json`.

Here's the output of a sample run analyzing SimpleDAO contract; instead in `./data.json` actual vulnerabilities spotted are reported:

```console
$ python smartbugs_orchestrator.py -f ./smartbugs/samples/SimpleDAO.* --processes 4
Welcome to SmartBugs Orchestrator!
No inputted tools
Running best tools...
Trying ['slither']...
Collecting files ...
3 files to analyse
Assembling tasks ...
1 tasks to execute
Starting task 1/1: slither and ./smartbugs/samples/SimpleDAO.sol
1/1 completed, ETC 0:00:00
Analysis completed in 0:00:04.
slither found something!
Finished running best tools
Running tools spotting enabled vulns...
The vulnerability Function Default Visibility enables: ['High Gas Consumption Function Type']
The vulnerability Function Default Visibility enables: ['High Gas Consumption Function Type']
The vulnerability Function Default Visibility enables: ['High Gas Consumption Function Type']
The vulnerability Low Level Calls enables: ['Mishandled Exception']
Trying {'confuzzius', 'securify', 'sfuzz'} tools to spot ['Mishandled Exception'] enabled vulns
Collecting files ...
3 files to analyse
Assembling tasks ...
4 tasks to execute
Starting task 1/4: securify and ./smartbugs/samples/SimpleDAO.sol
Starting task 2/4: securify and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 3/4: sfuzz and ./smartbugs/samples/SimpleDAO.sol
Starting task 4/4: confuzzius and ./smartbugs/samples/SimpleDAO.sol
1/4 completed, ETC 0:00:07
2/4 completed, ETC 0:00:04
3/4 completed, ETC 0:00:03
4/4 completed, ETC 0:00:00
Analysis completed in 0:02:03.
sfuzz found something!
sfuzz found the enabled vuln Mishandled Exception
sfuzz found the enabled vuln Mishandled Exception
sfuzz found the enabled vuln Mishandled Exception
confuzzius found something!
confuzzius found the enabled vuln Mishandled Exception
These vulnerabilities can't be spotted by any supported tool: ['High Gas Consumption Function Type']
Finished running tools spotting enabled vulns
Running tools spotting impacted vulns...
The vulnerability Reentrancy is impactant on: ['Assert / Require / Revert Violation']
The vulnerability Reentrancy is impactant on: ['Assert / Require / Revert Violation']
The vulnerability Reentrancy is impactant on: ['Assert / Require / Revert Violation']
The vulnerability Reentrancy is impactant on: ['Assert / Require / Revert Violation']
The vulnerability Reentrancy is impactant on: ['Assert / Require / Revert Violation']
Trying {'slither', 'smartcheck', 'mythril'} tools to spot ['Assert / Require / Revert Violation'] impacted vulns
Collecting files ...
3 files to analyse
Assembling tasks ...
4 tasks to execute
Starting task 1/4: mythril-0.23.15 and ./smartbugs/samples/SimpleDAO.sol
Starting task 2/4: smartcheck and ./smartbugs/samples/SimpleDAO.sol
Starting task 3/4: mythril-0.23.15 and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 4/4: mythril-0.23.15 and ./smartbugs/samples/SimpleDAO.hex
1/4 completed, ETC 0:00:04
2/4 completed, ETC 0:00:12
3/4 completed, ETC 0:00:08
4/4 completed, ETC 0:00:00
Analysis completed in 0:00:50.
mythril found something!
mythril found the impacted vuln Assert / Require / Revert Violation
mythril found the impacted vuln Assert / Require / Revert Violation
Finished running tools spotting impacted vulns
Running tools spotting enabling vulns...
The vulnerability Mishandled Exception is enabled by: ['Unchecked External Call', 'Low Level Calls']
The vulnerability Mishandled Exception is enabled by: ['Unchecked External Call', 'Low Level Calls']
The vulnerability Mishandled Exception is enabled by: ['Unchecked External Call', 'Low Level Calls']
The vulnerability Mishandled Exception is enabled by: ['Unchecked External Call', 'Low Level Calls']
The vulnerability Unprotected Ether Withdrawal (Unauthorized Transfer) is enabled by: ['Wrong Logic']
Trying {'ethainter', 'conkas', 'vandal', 'smartcheck', 'slither', 'mythril'} tools to spot ['Low Level Calls', 'Unchecked External Call'] enabling vulns
Collecting files ...
3 files to analyse
Assembling tasks ...
4 tasks to execute
Starting task 1/4: vandal and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 2/4: conkas and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 3/4: ethainter and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 4/4: conkas and ./smartbugs/samples/SimpleDAO.sol
1/4 completed, ETC 0:00:02
2/4 completed, ETC 0:00:01
3/4 completed, ETC 0:00:01
4/4 completed, ETC 0:00:00
Analysis completed in 0:00:06.
vandal found something!
vandal found the enabling vuln Unchecked External Call
conkas found something!
conkas found the enabling vuln Unchecked External Call
These vulnerabilities can't be spotted by any supported tool: ['Wrong Logic']
Finished running tools spotting enabling vulns
Running tools spotting impacting vulns...
The vulnerability Assert / Require / Revert Violation is impacted by: ['Reentrancy']
The vulnerability Assert / Require / Revert Violation is impacted by: ['Reentrancy']
Trying {'ethor', 'osiris', 'conkas', 'securify', 'vandal', 'mythril', 'oyente', 'confuzzius', 'sfuzz'} tools to spot ['Reentrancy'] impacting vulns
Collecting files ...
3 files to analyse
Assembling tasks ...
5 tasks to execute
Starting task 1/5: osiris and ./smartbugs/samples/SimpleDAO.rt.hex
Starting task 2/5: osiris and ./smartbugs/samples/SimpleDAO.sol
Starting task 3/5: oyente and ./smartbugs/samples/SimpleDAO.sol
Starting task 4/5: ethor-2023 and ./smartbugs/samples/SimpleDAO.rt.hex
1/5 completed, ETC 0:00:08
Starting task 5/5: oyente and ./smartbugs/samples/SimpleDAO.rt.hex
2/5 completed, ETC 0:00:06
3/5 completed, ETC 0:00:05
4/5 completed, ETC 0:00:02
5/5 completed, ETC 0:00:00
Analysis completed in 0:00:14.
osiris found something!
osiris found the impacting vuln Reentrancy
oyente found something!
oyente found the impacting vuln Reentrancy
ethor found something!
ethor found the impacting vuln Reentrancy
Finished running tools spotting impacting vulns
```
