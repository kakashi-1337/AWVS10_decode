"""
Site tree data structures matching AWVS10's scheme/variation model.
A "scheme" = a page + its input parameters + observed value variations.
"""
from urllib.parse import urlparse, parse_qs, urlencode
import random
import string


class InputParam:
    def __init__(self, name, value="", input_type="URL encoded GET", flags=0):
        self.name = name
        self.value = value
        self.input_type = input_type
        self.flags = flags

    def to_dict(self):
        return {
            "name": self.name,
            "value": self.value,
            "type": self.input_type,
            "flags": self.flags,
        }


class Variation:
    """A set of input values observed for a scheme during crawling."""

    def __init__(self, values=None):
        self.values = values or {}

    def to_dict(self):
        return dict(self.values)


class Scheme:
    """
    Matches AWVS10's scheme object. Represents a page + inputs.
    The JS runtime receives this as the 'scheme' context variable.
    """

    INPUT_FLAG_REFLECTION_TESTS = 0x80
    INPUT_FLAG_IS_FILE = 0x4
    INPUT_FLAG_IS_PASSWORD = 0x10
    INPUT_FLAG_NUMERIC = 0x40
    INPUT_FLAG_HAS_NAME = 0x100
    INPUT_FLAG_CAN_BE_ARRAY = 0x200

    def __init__(self, url, method="GET"):
        self.url = url
        self.method = method
        self.inputs = []
        self.variations = []
        self._current_variation = 0
        self._internal_id = "".join(random.choices(string.hexdigits[:16], k=12))

        parsed = urlparse(url)
        self.path = parsed.path or "/"
        self.hash = ""

    @property
    def inputCount(self):
        return len(self.inputs)

    @property
    def variationCount(self):
        return len(self.variations)

    @property
    def internalId(self):
        return self._internal_id

    def getInputName(self, i):
        return self.inputs[i].name if i < len(self.inputs) else ""

    def getInputTypeStr(self, i):
        return self.inputs[i].input_type if i < len(self.inputs) else ""

    def getInputValue(self, i):
        return self.inputs[i].value if i < len(self.inputs) else ""

    def setInputValue(self, i, value):
        if i < len(self.inputs):
            self.inputs[i].value = value

    def inputHasFlag(self, i, flag):
        if i < len(self.inputs):
            return bool(self.inputs[i].flags & flag)
        return False

    def loadVariation(self, idx):
        if idx < len(self.variations):
            self._current_variation = idx
            var = self.variations[idx]
            for i, inp in enumerate(self.inputs):
                if inp.name in var.values:
                    inp.value = var.values[inp.name]

    def selectVariationsForInput(self, input_idx):
        return list(range(len(self.variations))) if self.variations else [0]

    def randomizeValues(self):
        for inp in self.inputs:
            if not inp.value:
                inp.value = "".join(random.choices(string.ascii_lowercase, k=5))

    def populateRequest(self, job_dict):
        """Fill a request dict with this scheme's current params."""
        if self.method == "GET":
            params = {inp.name: inp.value for inp in self.inputs if inp.input_type == "URL encoded GET"}
            job_dict["getVar"] = urlencode(params)
        elif self.method == "POST":
            params = {inp.name: inp.value for inp in self.inputs if inp.input_type == "URL encoded POST"}
            job_dict["postData"] = urlencode(params)

        cookies = {inp.name: inp.value for inp in self.inputs if inp.input_type == "Cookie"}
        if cookies:
            job_dict["cookies"] = cookies

        headers = {inp.name: inp.value for inp in self.inputs if inp.input_type == "HTTP Header"}
        if headers:
            job_dict["headers"] = headers

    def add_input(self, name, value="", input_type="URL encoded GET", flags=0):
        self.inputs.append(InputParam(name, value, input_type, flags))

    def add_variation(self, values):
        self.variations.append(Variation(values))

    def to_js_object(self):
        """Serialize for the Node.js runtime."""
        return {
            "path": self.path,
            "hash": self.hash,
            "internalId": self._internal_id,
            "inputCount": len(self.inputs),
            "variationCount": len(self.variations),
            "inputs": [inp.to_dict() for inp in self.inputs],
            "variations": [v.to_dict() for v in self.variations],
            "_currentVariation": self._current_variation,
        }

    @classmethod
    def from_url(cls, url, method="GET"):
        """Create a scheme from a URL, extracting query params as inputs."""
        scheme = cls(url, method)
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for name, values in params.items():
            val = values[0] if values else ""
            flags = (cls.INPUT_FLAG_HAS_NAME |
                     cls.INPUT_FLAG_REFLECTION_TESTS |
                     cls.INPUT_FLAG_CAN_BE_ARRAY)
            if val.isdigit():
                flags |= cls.INPUT_FLAG_NUMERIC
            scheme.add_input(name, val, "URL encoded GET", flags)
            if values:
                scheme.add_variation({name: val})

        return scheme

    @classmethod
    def from_api_endpoint(cls, url, method="GET"):
        """Create a scheme from a discovered API endpoint with synthesized inputs."""
        scheme = cls(url, method)
        parsed = urlparse(url)
        path = parsed.path or "/"

        API_FLAGS = (cls.INPUT_FLAG_REFLECTION_TESTS |
                     cls.INPUT_FLAG_CAN_BE_ARRAY |
                     cls.INPUT_FLAG_HAS_NAME)

        params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in params.items():
            val = values[0] if values else ""
            flags = API_FLAGS
            if val.isdigit():
                flags |= cls.INPUT_FLAG_NUMERIC
            scheme.add_input(name, val, "URL encoded GET", flags)
            if values:
                scheme.add_variation({name: val})

        path_parts = path.split('/')
        for part in path_parts:
            if part.startswith(':') or (part.startswith('{') and part.endswith('}')):
                param_name = part.strip(':{}')
                scheme.add_input(param_name, "1", "URL encoded GET",
                                 API_FLAGS | cls.INPUT_FLAG_NUMERIC)
                scheme.add_variation({param_name: "1"})

        if not scheme.inputs:
            if method in ("POST", "PUT", "PATCH"):
                scheme.add_input("id", "1", "JSON body",
                                 API_FLAGS | cls.INPUT_FLAG_NUMERIC)
                scheme.add_input("name", "test", "JSON body", API_FLAGS)
                scheme.add_input("value", "test", "JSON body", API_FLAGS)
                scheme.add_variation({"id": "1", "name": "test", "value": "test"})
            else:
                scheme.add_input("id", "1", "URL encoded GET",
                                 API_FLAGS | cls.INPUT_FLAG_NUMERIC)
                scheme.add_variation({"id": "1"})

        scheme.add_input("Authorization", "Bearer test", "HTTP Header", API_FLAGS)

        return scheme

    @classmethod
    def from_form(cls, action_url, method, params):
        """Create a scheme from a discovered form."""
        scheme = cls(action_url, method.upper())
        input_type = "URL encoded POST" if method.upper() == "POST" else "URL encoded GET"

        for p in params:
            flags = (cls.INPUT_FLAG_HAS_NAME |
                     cls.INPUT_FLAG_REFLECTION_TESTS |
                     cls.INPUT_FLAG_CAN_BE_ARRAY)
            ptype = p.get("type", "text").lower()
            if ptype == "file":
                flags |= cls.INPUT_FLAG_IS_FILE
            if ptype == "password":
                flags |= cls.INPUT_FLAG_IS_PASSWORD
            if p.get("value", "").isdigit():
                flags |= cls.INPUT_FLAG_NUMERIC

            scheme.add_input(p["name"], p.get("value", ""), input_type, flags)

        return scheme


class SiteFile:
    """A discovered page/file in the site tree."""

    def __init__(self, url, status=200, content_type=""):
        self.url = url
        self.status = status
        self.content_type = content_type
        self.schemes = []
        self.children = []
        self.flags = 0
        self._id = "".join(random.choices(string.hexdigits[:16], k=8))

    def add_scheme(self, scheme):
        self.schemes.append(scheme)

    def to_js_object(self):
        return {
            "url": self.url,
            "status": self.status,
            "contentType": self.content_type,
            "flags": self.flags,
            "id": self._id,
            "schemes": [s.to_js_object() for s in self.schemes],
            "children": [c.to_js_object() for c in self.children],
        }


class SiteTree:
    """Root of the crawled site tree."""

    def __init__(self, target_url):
        self.target = target_url
        self.root = SiteFile(target_url)
        self.all_files = {}
        self.all_directories = set()
        self.all_schemes = []

    def add_url(self, url, status=200, content_type=""):
        parsed = urlparse(url)
        path = parsed.path or "/"

        directory = "/".join(path.split("/")[:-1]) + "/"
        self.all_directories.add(directory)

        site_file = SiteFile(url, status, content_type)
        self.all_files[url] = site_file

        scheme = Scheme.from_url(url)
        site_file.add_scheme(scheme)
        self.all_schemes.append(scheme)

        return site_file

    def add_form(self, action_url, method, params):
        scheme = Scheme.from_form(action_url, method, params)
        self.all_schemes.append(scheme)

        if action_url in self.all_files:
            self.all_files[action_url].add_scheme(scheme)
        else:
            sf = SiteFile(action_url)
            sf.add_scheme(scheme)
            self.all_files[action_url] = sf

        return scheme

    def add_api_endpoint(self, url, method="GET"):
        scheme = Scheme.from_api_endpoint(url, method)
        self.all_schemes.append(scheme)

        parsed = urlparse(url)
        directory = "/".join(parsed.path.split("/")[:-1]) + "/"
        self.all_directories.add(directory)

        if url not in self.all_files:
            sf = SiteFile(url)
            sf.add_scheme(scheme)
            self.all_files[url] = sf
        else:
            self.all_files[url].add_scheme(scheme)

        return scheme

    def to_js_object(self):
        return {
            "target": self.target,
            "files": {url: f.to_js_object() for url, f in self.all_files.items()},
            "directories": list(self.all_directories),
            "schemeCount": len(self.all_schemes),
        }
