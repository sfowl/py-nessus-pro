import json, requests, re, sys
import typing
from datetime import datetime
from loguru import logger

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

    def __init__(self, nessus_server: str, username: str, password: str, auth_with_selenium: bool = False, log_level: str = "warning"):
        if log_level:
            if log_level in ["debug", "info", "success", "warning", "warn", "error", "critical"]:
                logger.remove()
                logger.add(sys.stderr, level = log_level.upper())

            else:
                logger.info("Invalid log level. log_level must be one of the following: [debug, info, success, warning, warn, error, critical]")
                logger.error("Invalid log level, using default (warning)")

        self.nessus_server = nessus_server if not self.nessus_server else self.nessus_server
        if not self.headers:
            self.headers = {
                "Content-Type" : "application/json", 
                "User-Agent":"Mozilla/5.0 Gecko/20100101 Firefox/114.0"
            }

        if auth_with_selenium:
            # Requires local chrome and chromedriver, if not available they will be installed
            # This auth method is more reliable though heavyweight, and can be slow on first run
            self._authenticate_with_selenium(username, password)
        else:
            self._authenticate(username, password)

        if len(self.folder_map) == 0:
            folders = json.loads(requests.get(f"{self.nessus_server}/folders", headers=self.headers, verify=False).text)
            if not folders.get("folders", None):
                logger.warning("No folders found.")
            for folder in folders["folders"]:
                self.folder_map[folder["name"]] = folder["id"]
            logger.info("Found %d custom folders." % (len(self.folder_map) - 2))

        if len(self.policy_map) == 0:
            policies = json.loads(requests.get(f"{self.nessus_server}/policies", headers=self.headers, verify=False).text)
            if policies.get("policies", None):
                for policy in policies["policies"]:
                    self.policy_map[policy["name"]] = policy["id"]
                logger.info("Found %d custom policies." % len(self.policy_map))
            else:
                logger.info("No policies found")

        if not self.scans:
            scans_list = json.loads(requests.get(f"{self.nessus_server}/scans", headers=self.headers, verify=False).text)
            if scans_list.get("scans", None):
                for scan in scans_list["scans"]:
                    if scan["folder_id"] != 2:
                        folder = next((key for key, value in self.folder_map.items() if value == scan["folder_id"]), None)
                        self.scans.append(_Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, id=scan["id"], name=scan["name"], folder=folder))

    def _get_api_token(self) -> typing.Optional[str]:
        url = self.nessus_server + "/nessus6.js"
        req = self._session.get(url, verify=False)
        # regular expression to find UUID used for api key
        token_regex = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        match = re.search(token_regex, req.text)
        if match:
            api_token = match.group()
        else:
            logger.error(f"Unable to get token in response from {url}")
            return None

        return api_token

    def _get_cookie_token(self, username: str, password: str) -> str:
        data = {"username": username, "password": password}
        url = self.nessus_server + "/session"
        logger.info("POST")
        req = self._session.post(url, data, verify=False)
        logger.info("POST W")
        cookie_token = req.json().get("token")
        return cookie_token

    def _authenticate(self, username: str, password: str):
        logger.debug("Authenticating without selenium")
        self._session = requests.Session()
        self._session.verify = False
        cookie_token = self._get_cookie_token(username, password)
        self.headers["X-Cookie"] = f"token={cookie_token}"
        api_token = self._get_api_token()
        if api_token:
            self.headers["X-API-Token"] = api_token
        logger.info("Successfully logged in")

    def _authenticate_with_selenium(self, username: str, password: str):
        try:
            from selenium import webdriver
            from bs4 import BeautifulSoup
        except ImportError as e:
            logger.error(
                f"Failed to import {e}. Install or use auth_with_selenium=False"
            )
            sys.exit(1)
        logger.debug("Authenticating with selenium")
        r = requests.get(self.nessus_server, headers=self.headers, verify=False)
        html = r.text

        soup = BeautifulSoup(html, "html.parser")
        script_urls = []
        for script in soup.find_all("script", src=True):
            script_urls.append(script["src"])
        options = webdriver.ChromeOptions()
        options.add_argument("ignore-certificate-errors")
        options.add_argument("headless=new")
        options.add_argument("disable-gpu")
        options.add_argument("no-sandbox")
        options.page_load_strategy = "eager"
        options.headless = True
        driver = webdriver.Chrome(options=options)
        driver.get(self.nessus_server)
        for script_url in script_urls:
            driver.execute_script(
                f'var xhr = new XMLHttpRequest(); xhr.open("GET", "{script_url}", false); xhr.send(null); eval(xhr.responseText);'
            )
            token = driver.execute_script("return _Utils.getApiToken();")
            if token:
                break
        driver.quit()

        r = requests.post(
            f"{self.nessus_server}/session",
            headers=self.headers,
            data=f'{{"username":"{username}","password":"{password}"}}',
            verify=False,
        )
        if r.status_code == 200:
            self.headers["X-Cookie"] = "token=" + json.loads(r.text)["token"]
            self.headers["X-API-Token"] = token
            logger.info("Successfully logged in")
        else:
            raise Exception("[!] Login failed")

    def new_scan(self, name: str = "", targets: str = "", folder: str = "", create_folder: bool = True):
        if folder:
            if not folder in self.folder_map and create_folder:
               self.create_folder(folder)
        self.scans.append(_Scan(self.nessus_server, self.headers, self.folder_map, self.policy_map, name = name, targets = targets, folder = folder))
        logger.info("Created new scan")
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
    
    def get_scan_metadata(self, scan_id: int):
        return self.scans[scan_id].get_metadata()
    
    def get_scan_status(self, scan_id: int):
        return self.scans[scan_id].get_status()

    def set_scan_name(self, scan_id: int, name: str):
        self.scans[scan_id].set_name(name)

    def set_scan_description(self, scan_id: int, description: str):
        self.scans[scan_id].set_description(description)

    def set_scan_folder(self, scan_id: int, folder: str):
        self.scans[scan_id].set_folder(folder)

    def set_scan_policy(self, scan_id: int, policy: str):
        self.scans[scan_id].set_policy(policy)

    def set_scan_target(self, scan_id: int, target: str):
        self.scans[scan_id].set_target(target)

    def set_scan_launch_now(self, scan_id: int, launch_now: bool):
        self.scans[scan_id].set_launch_now(launch_now)

    def set_scan_live_results(self, scan_id: int, live_results: str):
        self.scans[scan_id].set_live_results(live_results)

    def set_scan_program_scan(self, scan_id: int, enabled: bool, date: str):
        self.scans[scan_id].set_program_scan(enabled, date)

    def post_scan(self, scan_id: int):
        self.scans[scan_id].post()

    def dump_scans(self):
        scans = []
        for scan in self.scans:
            scans.append(scan.dump())
        return scans

    def get_scan_reports(self, scan_id: int, path: str = ""):
        return self.scans[scan_id].get_reports(path)
    
    def get_status_by_name(self, name: str):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_reports_by_name(self, name: str, path: str):
        res = []
        ids = self.search_scans(name)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "path":self.scans[id].get_reports(path)})
        return res
    
    def get_scans_before(self, before: str):
        res = []
        ids = self.search_scans(before = before)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def get_scans_after(self, after: str):
        res = []
        ids = self.search_scans(after = after)
        for id in ids:
            res.append({"id": id, "name":self.scans[id].get_name(), "status":self.scans[id].get_status()})
        return res
    
    def search_scans(self, name: str = "", after: str = "", before: str = ""):
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
    
    def create_folder(self, folder_name: str):
        if folder_name in self.folder_map:
            logger.warn("Folder already exists")
            return self.folder_map[folder_name]
        else:
            r = requests.post(f"{self.nessus_server}/folders", headers=self.headers, data=f'{{"name":"{folder_name}"}}', verify=False)
            if r.status_code == 200:
                self.folder_map[folder_name] = json.loads(r.text)["id"]
                logger.success("Folder created")
                return self.folder_map[folder_name]
            else:
                logger.error("[!] Folder creation failed")

    def import_policy(self, policy_file):
        with open(policy_file, "r") as f:
            headers = self.headers.copy()
            headers.pop("Content-Type")
            r = requests.post(f"{self.nessus_server}/file/upload", headers=headers, files={"Filedata":f}, verify=False)
            if r.status_code == 200:
                logger.info("Policy uploaded")
                filename = json.loads(r.text)["fileuploaded"]
                r = requests.post(f"{self.nessus_server}/policies/import", headers=self.headers, data=f'{{"file":"{filename}"}}', verify=False)
                if r.status_code == 200:
                    policy_id = json.loads(r.text)["id"]
                    policy_name = json.loads(r.text)["name"]
                    self.policy_map[policy_name] = policy_id
                    logger.success(f"Policy imported, {policy_name}")
                else:
                    logger.error("Policy import failed")
            else:
                logger.error("Policy import failed")
    
    def import_scan(self, scan_path, folder_name = ""):
        with open(scan_path, "r") as f:
            headers = self.headers.copy()
            headers["Content-Type"] = "multipart/form-data"
            r = requests.post(f"{self.nessus_server}/file/upload", headers=headers, files={"Filedata":f}, verify=False)
            if r.status_code == 200:
                logger.info("Scan uploaded")
                filename = json.loads(r.text)["fileuploaded"]
                if folder_name:
                    if folder_name in self.folder_map:
                        folder_id = self.folder_map[folder_name]
                    else:
                        logger.info("Folder not found, creating it")
                        folder_id = self.create_folder(folder_name)
                else:
                    folder_id = 2
                r = requests.post(f"{self.nessus_server}/scans/import", headers=self.headers, data=f'{{"file":"{filename}", "folder_id":{folder_id}}}', verify=False)
                if r.status_code == 200:
                    scan_name = json.loads(r.text)["name"]
                    logger.success(f"Scan imported, {scan_name}")
                else:
                    logger.error("Scan import failed")
            else:
                logger.error("Scan import failed")

