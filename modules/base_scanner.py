from abc import ABC, abstractmethod

class VulnerabilityScanner(ABC):
    """
    Abstract Base Class for all vulnerability scanners.
    Enforces a standard interface for all scanning modules.
    """
    def __init__(self, target_url, session):
        """
        Initialize the scanner.
        :param target_url: The URL to scan.
        :param session: A requests.Session object to maintain state (cookies, etc.)
        """
        self.target_url = target_url
        self.session = session
        self.vulnerabilities = []

    @abstractmethod
    def scan(self):
        """
        Perform the scan.
        Must be implemented by child classes.
        :return: A list of findings (dictionaries).
        """
        pass

    def add_finding(self, finding_type, description, severity, url=None, payload=None, evidence=None, poc=None):
        """
        Helper to add a finding to the list with extended metadata.
        """
        finding = {
            "type": finding_type,
            "description": description,
            "severity": severity,
            "url": url if url else self.target_url, # Default to target_url if not specific
            "payload": payload,
            "evidence": evidence,
            "poc": poc
        }
        self.vulnerabilities.append(finding)
