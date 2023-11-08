import json, requests, random, string
from slugify import slugify
from datetime import datetime
from time import sleep

from .logger import logger as log

# file deepcode ignore SSLVerificationBypass: Nessus self-signed certificate

class _Scan():

    nessus_server = ""
    headers = {}

    export_types = {
        "nessus":"",
        "csv":"",
        "html":"vuln_by_host;compliance_exec;remediations;",
        "pdf":"vuln_by_host;compliance_exec;remediations;",
    }

    def __init__(self, nessus_server: str, headers: dict, folder_map: dict, policy_map: dict, name: str = "", targets: str = "", id: str = "", folder: str = ""):
        self.id = id
        self.metadata = json.loads('''{
            "uuid":"ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40",
            "settings":{
                "emails":"",
                "attach_report":"no",
                "filter_type":"and",
                "filters":[],
                "launch":"ONETIME",
                "launch_now":false,
                "enabled":false,
                "timezone":"Europe/Madrid",
                "starttime":"20231001T170000",
                "rrules":"FREQ=ONETIME",
                "live_results":"",
                "name":"NO NAME",
                "description":"",
                "folder_id":0,
                "scanner_id":"1",
                "policy_id":"0",
                "text_targets":""
            }
        }''')
        self.nessus_server = nessus_server
        self.headers = headers
        self.folder_map = folder_map
        self.policy_map = policy_map
        self.metadata["settings"]["text_targets"] = targets
        self.metadata["settings"]["name"] = name
        self.metadata["settings"]["folder_id"] = self.folder_map[folder] if folder in self.folder_map else 0
        log.success("Scan object created: " + str(name) + " " + str(targets))

    def set_name(self, name: str):
        self.metadata["settings"]["name"] = name
        log.debug("Name updated: " + name)

    def set_description(self, description: str):
        self.metadata["settings"]["description"] = description
        log.debug("Description updated: " + description)

    def set_target(self, target: str):
        self.metadata["settings"]["text_targets"] = target
        log.debug("Target updated: " + target)

    def set_folder(self, folder: str):
        if folder in self.folder_map:
            self.metadata["settings"]["folder_id"] = self.folder_map[folder]
        else:
            raise Exception("[!] Invalid folder name: " + folder)
        log.debug("Folder updated: " + folder)
        
    def set_policy(self, policy: str):
        if policy in self.policy_map:
            self.metadata["settings"]["policy_id"] = self.policy_map[policy]
        else:
            raise Exception("[!] Invalid policy name: " + policy)
        log.debug("Policy updated: " + policy)
    
    def set_launch_now(self, launch: bool):
        if launch in [True, False]:
            self.metadata["settings"]["launch_now"] = launch
        else:
            raise Exception("[!] Invalid launch_now value: %s\n Value must be True or False", launch)
        log.debug("Launch now: " + str(launch))
        
    def set_live_results(self, live_results: bool):
        if live_results in [True, False]:
            self.metadata["settings"]["live_results"] = live_results
        else:
            raise Exception("[!] Invalid live_results value: %s\n Value must be True or False", live_results)
        log.debug("Live results: " + str(live_results))
    
    def set_program_scan(self, enabled: bool, date: str):
        if enabled in [True, False]:
            self.metadata["settings"]["enabled"] = enabled
        else:
            raise Exception("[!] Invalid enabled value: %s\n Value must be True or False", enabled)
        
        if datetime.strptime(date, "%Y%m%dT%H%M%S"):
            self.metadata["settings"]["starttime"] = date
        else:
            raise Exception("[!] Invalid date format: %s\n Format must be YYYYMMDDTHHMMSS, example: 20231001T170000", date)
        log.debug("Program scan: " + str(enabled) + " " + date)
        
    def get_name(self):
        return self.metadata["settings"]["name"]
    
    def get_target(self):
        return self.metadata["settings"]["text_targets"]
    
    def get_folder(self):
        return self.metadata["settings"]["folder_id"]
    
    def get_policy(self):
        return self.metadata["settings"]["policy_id"]
    
    def get_description(self):
        return self.metadata["settings"]["description"]

    def get_metadata(self):
        return self.metadata
        
    def get_status(self):
        if self.id:
            x = json.loads(requests.get(f"{self.nessus_server}/scans/{self.id}", headers=self.headers, verify=False).text)
            res = {}
            res["status"] = x["info"]["status"]
            res["scan_start"] = x["info"]["scan_start"] if res["status"] != "empty" else None
            res["scan_end"] = x["info"]["scan_end"] if res["status"] == "completed" else None 
            res["name"] = x["info"]["name"]
            return res
        else:
            return "Scan not posted yet"
    
    def post(self):
        if not self.metadata["settings"]["text_targets"]:
            raise Exception("[!] No targets provided")
        x = json.loads(requests.post(f"{self.nessus_server}/scans", headers=self.headers, json = self.metadata, verify=False).text)
        if self.metadata["settings"]["launch_now"]:
            log.info("Scan launched: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        else:
            log.info("Scan saved: " + str(x["scan"]["id"]) + " (" + self.metadata["settings"]["name"] + ")")
        self.id = x["scan"]["id"]

    def dump(self):
        return {
            "id":self.id,
            "nessus_server":self.nessus_server,
            "metadata":self.metadata,
        }

    def get_reports(self, path: str):
        if not self.id:
            log.error("Scan not posted yet")
            return
        if self.get_status()["status"] != "completed":
            log.error("Scan not completed yet")
            return

        for t in self.export_types:
            data = json.loads('{"format":"csv","reportContents":{"csvColumns":{"id":true,"cve":true,"cvss":true,"risk":true,"hostname":true,"protocol":true,"port":true,"plugin_name":true,"synopsis":true,"description":true,"solution":true,"see_also":true,"plugin_output":true,"stig_severity":true,"cvss3_base_score":true,"cvss_temporal_score":true,"cvss3_temporal_score":true,"vpr_score":true,"risk_factor":true,"references":true,"plugin_information":true,"exploitable_with":true}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}')
            data["format"] = t

            if t in ["html", "pdf"]:
                data = json.loads('{"format":"", "chapters": "vuln_by_plugin"}')
                data["format"] = t
                # data = json.loads('{"format":"html", "chapters": "vuln_by_host;compliance_exec;remediations;"}')                

            res = json.loads(requests.post(f"{self.nessus_server}/scans/{self.id}/export", headers=self.headers, json = data, verify=False).text)
            if "token" in res:
                log.debug("Export in progress: " + res["token"])
                status = json.loads(requests.get(f"{self.nessus_server}/tokens/{res['token']}/status", headers=self.headers, verify=False).text)
                while status["status"] != "ready":
                    if status["status"] == "error":
                        log.error("Error exporting scan type " + t + ": " + status)
                        quit()
                    sleep(0.5)
                    log.debug(status)
                    status = json.loads(requests.get(f"{self.nessus_server}/tokens/{res['token']}/status", headers=self.headers, verify=False).text)
                if t == "pdf":
                    t_headers = self.headers
                    t_headers["Accept-Encoding"] = "gzip, deflate"
                    t_headers["Connection"] = "keep-alive"
                    t_headers["Accept"] = "*/*"
                else: t_headers = self.headers

                report_url = f"{self.nessus_server}/tokens/{res['token']}/download"
                filename = ''.join(random.choice(string.ascii_letters) for i in range(6))
                report_path = f"{path}/{slugify(self.metadata['settings']['name'], lowercase=False)}_{filename}.{t}"

                r = requests.get(report_url, headers=t_headers, verify=False)
                if r.status_code == 200:
                    with open(report_path, "wb") as f:
                        f.write(r.content)
                        log.debug("Report downloaded: " + report_path)
            else:
                log.error("Error exporting scan: " + res["error"])
                raise Exception("[!] Error exporting scan: " + res["error"])
        
        log.success("Reports exported to " + path)
        return path
