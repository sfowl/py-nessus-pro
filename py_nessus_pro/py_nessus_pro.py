import json, requests, re
from datetime import datetime
from selenium import webdriver
from bs4 import BeautifulSoup

from .logger import logger as log
from py_nessus_pro.scan import _Scan

# file deepcode ignore SSLVerificationBypass: Nessus self-signed certificate
requests.packages.urllib3.disable_warnings() 

class PyNessusPro:
    
    nessus_server = ""
    headers = {}
    config = {}
    folder_map = {}
    policy_map = {}
    scans = []

    def __init__(self, nessus_server, username, password):
        self.nessus_server = nessus_server if not self.nessus_server else self.nessus_server
        if not self.headers:
            self.headers = {
                "Content-Type" : "application/json", 
                "User-Agent":"Mozilla/5.0 Gecko/20100101 Firefox/114.0"
            }

            r = requests.get(self.nessus_server, headers=self.headers, verify=False)
            html = r.text
            
            soup = BeautifulSoup(html, 'html.parser')
            script_urls = []
            for script in soup.find_all('script', src=True):
                script_urls.append(script['src'])
            options = webdriver.ChromeOptions()
            options.add_argument('ignore-certificate-errors')
            options.add_argument('headless')
            options.page_load_strategy = 'eager'
            options.headless = True
            driver = webdriver.Chrome(options=options)
            driver.get(self.nessus_server)
            for script_url in script_urls:
                driver.execute_script(f'var xhr = new XMLHttpRequest(); xhr.open("GET", "{script_url}", false); xhr.send(null); eval(xhr.responseText);')
                token = driver.execute_script('return _Utils.getApiToken();')
                if token:
                    break
            driver.quit()
            
            r = requests.post(f"{self.nessus_server}/session", headers=self.headers, data=f'{{"username":"{username}","password":"{password}"}}', verify=False)
            if r.status_code == 200:
                self.headers["X-Cookie"] = "token=" + json.loads(r.text)["token"]
                self.headers["X-API-Token"] = token
                log.info("Successfully logged in")
            else:
                raise Exception("[!] Login failed")
        
        if len(self.folder_map) == 0:
            folders = json.loads(requests.get(f"{self.nessus_server}/folders", headers=self.headers, verify=False).text)
            if not folders["folders"]:
                raise Exception("[!] No folders found.")
            for folder in folders["folders"]:
                self.folder_map[folder["name"]] = folder["id"]
            log.info("Found %d custom folders." % (len(self.folder_map) - 2))

        if len(self.policy_map) == 0:
            policies = json.loads(requests.get(f"{self.nessus_server}/policies", headers=self.headers, verify=False).text)
            if policies["policies"]:
                for policy in policies["policies"]:
                    self.policy_map[policy["name"]] = policy["id"]
                log.info("Found %d custom policies." % len(self.policy_map))
            else:
                log.info("No policies found")

        if not self.scans:
            scans_list = json.loads(requests.get(f"{self.nessus_server}/scans", headers=self.headers, verify=False).text)
            for scan in scans_list["scans"]:
                if scan["folder_id"] != 2:
                    self.scans.append(_Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, id = scan["id"], name = scan["name"], folder_id = scan["folder_id"]))

    def new_scan(self, name = "", target = "", folder = 0):
        self.scans.append(_Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, name = name, target = target, folder = folder))
        log.info("Created new scan")
        return len(self.scans) - 1
    
    def list_scans(self):
        scans = []
        for scan in self.scans:
            scans.append(str(scan.id) + " - " + scan.get_name())
        return scans
    
    def get_scan_launch_ids(self):
        ids = []
        for scan in self.scans:
            if scan.id:
                ids.append(scan.id)
        return ids
    
    def get_scan_ids(self):
        return range(len(self.scans))
    
    def get_scan_metadata(self, scan_id):
        return self.scans[scan_id].get_metadata()
    
    def get_scan_status(self, scan_id):
        return self.scans[scan_id].get_status()

    def set_scan_name(self, scan_id, name):
        self.scans[scan_id].set_name(name)

    def set_scan_description(self, scan_id, description):
        self.scans[scan_id].set_description(description)

    def set_scan_folder(self, scan_id, folder):
        self.scans[scan_id].set_folder(folder)

    def set_scan_policy(self, scan_id, policy):
        self.scans[scan_id].set_policy(policy)

    def set_scan_target(self, scan_id, target):
        self.scans[scan_id].set_target(target)

    def set_scan_launch_now(self, scan_id, launch_now):
        self.scans[scan_id].set_launch_now(launch_now)

    def set_scan_live_results(self, scan_id, live_results):
        self.scans[scan_id].set_live_results(live_results)

    def set_scan_program_scan(self, scan_id, enabled, date):
        self.scans[scan_id].set_program_scan(enabled, date)

    def post_scan(self, scan_id):
        self.scans[scan_id].post()

    def dump_scans(self):
        scans = []
        for scan in self.scans:
            scans.append(scan.dump())
        return scans

    def get_scan_reports(self, scan_id, path = ""):
        return self.scans[scan_id].get_reports()
    
    def get_status_by_name(self, name):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_reports_by_name(self, name, path = ""):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "path":self.scans[id].get_reports(path)})
        return res
    
    def get_scans_before(self, before):
        res = []
        ids = self.search_scans(before = before)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_scans_after(self, after):
        res = []
        ids = self.search_scans(after = after)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def search_scans(self, name = "", after = "", before = ""):
        results = []
        for i, scan in enumerate(self.scans):
            if name:
                name = re.sub(r'(?<!\.)\*', '.*', name)
                if re.compile(name, re.IGNORECASE).search(scan.get_name()):
                    if after:
                        after_millis = datetime.strptime(after, "%Y-%m-%d_%H:%M:%S").timestamp()
                        if after_millis < scan.get_status()["scan_start"]:
                            if before:
                                before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                                if before_millis > scan.get_status()["scan_start"]:
                                    results.append(i)
                            else:
                                results.append(i)
                    else:
                        results.append(i)
            elif after:
                after_millis = datetime.strptime(after, "%Y-%m-%d_%H:%M:%S").timestamp()
                if after_millis < scan.get_status()["scan_start"]:
                    if before:
                        before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                        if before_millis > scan.get_status()["scan_start"]:
                            results.append(i)
                    else:
                        results.append(i)  
            elif before:
                before_millis = datetime.strptime(before, "%Y-%m-%d_%H:%M:%S").timestamp()
                if before_millis > scan.get_status()["scan_start"]:
                    results.append(i)                 

        return results
    
    def create_folder(self, folder_name):
        if folder_name in self.folder_map:
            log.warn("Folder already exists")
            return self.folder_map[folder_name]
        else:
            r = requests.post(f"{self.nessus_server}/folders", headers=self.headers, data=f'{{"name":"{folder_name}"}}', verify=False)
            if r.status_code == 200:
                self.folder_map[folder_name] = json.loads(r.text)["id"]
                log.success("Folder created")
                return self.folder_map[folder_name]
            else:
                raise Exception("[!] Folder creation failed")

