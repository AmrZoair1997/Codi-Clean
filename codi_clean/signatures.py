"""Names of well-documented Mac adware, malware and unwanted programs.

Matched against launch item labels, app names, folder names and browser
extension names. A name match is a strong hint, not proof: the description
shown to the person says what the family is known to do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Signature:
    family: str
    category: str       # "malware", "adware" or "pup" (potentially unwanted program)
    severity: str       # "high" or "medium"
    description: str
    pattern: "re.Pattern[str]"


def _sig(pattern: str, family: str, category: str, severity: str, description: str) -> Signature:
    return Signature(family, category, severity, description, re.compile(pattern, re.I))


SIGNATURES = (
    _sig(r"shlayer", "Shlayer", "malware", "high",
         "Trojan downloader, usually disguised as a Flash Player or video codec update; installs adware."),
    _sig(r"(?:adobe[ ._-]?)?flash[ ._-]?player", "Fake Flash Player", "malware", "high",
         "Adobe Flash was discontinued in 2020, so any Flash Player installer is almost certainly a disguised trojan."),
    _sig(r"silver[ ._-]?sparrow|verx\.updater|init_verx", "Silver Sparrow", "malware", "high",
         "Malware that checks in with a remote server for instructions; found on ~30,000 Macs in 2021."),
    _sig(r"xcsset", "XCSSET", "malware", "high",
         "Malware spread through Xcode projects; steals browser data and screenshots."),
    _sig(r"keranger", "KeRanger", "malware", "high",
         "Ransomware that encrypts files and demands payment."),
    _sig(r"pirrit", "Pirrit", "adware", "high",
         "Aggressive adware that injects ads into web pages and can route browsing through its own proxy."),
    _sig(r"bundlore", "Bundlore", "adware", "high",
         "Adware installer that bundles unwanted apps and browser extensions."),
    _sig(r"\badload\b", "AdLoad", "adware", "high",
         "Adware loader that keeps itself running and redirects searches and browsing to ad pages."),
    _sig(r"genieo", "Genieo", "adware", "high",
         "Browser hijacker that changes your homepage and search engine and injects ads."),
    _sig(r"vsearch", "VSearch", "adware", "high",
         "Adware that injects ads and pop-ups into web pages."),
    _sig(r"mughthesec", "Mughthesec", "adware", "high",
         "Adware bundler that installs unwanted apps and changes browser settings."),
    _sig(r"conduit|search[ ._-]?protect", "Conduit", "adware", "medium",
         "Browser hijacker toolbar that takes over the search engine and homepage."),
    _sig(r"spigot", "Spigot", "adware", "medium",
         "Installs browser extensions that redirect searches through its own servers."),
    _sig(r"search[ ._-]?(?:baron|marquis|mine|pulse)", "Search hijacker", "adware", "high",
         "Browser hijacker that sends your searches through tracking redirect sites."),
    _sig(r"maxofferdeal", "MaxOfferDeal", "adware", "high",
         "Ad-injecting browser extension from the AdLoad family."),
    _sig(r"weknow", "WeKnow", "adware", "medium",
         "Browser hijacker that replaces the search engine."),
    _sig(r"safe[ ._-]?finder|chumsearch", "Safe Finder", "adware", "medium",
         "Browser hijacker that redirects searches through its own pages."),
    _sig(r"crossrider", "Crossrider", "adware", "medium",
         "Adware platform that installs ad-injecting browser extensions."),
    _sig(r"installcore", "InstallCore", "pup", "medium",
         "Bundling installer that adds extra unwanted programs during installs."),
    _sig(r"mackeeper|zeobit", "MacKeeper", "pup", "medium",
         "Aggressively marketed 'cleaner'; many security vendors classify it as a potentially unwanted program."),
    _sig(r"advanced[ ._-]?mac[ ._-]?cleaner", "Advanced Mac Cleaner", "pup", "high",
         "Scareware 'cleaner' that reports fake problems to sell a licence; often installed by adware."),
    _sig(r"mac[ ._-]?auto[ ._-]?fixer", "Mac Auto Fixer", "pup", "high",
         "Scareware 'cleaner' that reports fake problems to sell a licence."),
    _sig(r"smart[ ._-]?mac[ ._-]?booster", "Smart Mac Booster", "pup", "high",
         "Scareware 'optimizer' that shows exaggerated problems to sell a licence."),
    _sig(r"mac[ ._-]?cleanup[ ._-]?pro", "Mac Cleanup Pro", "pup", "high",
         "Scareware 'cleaner' distributed through adware bundles."),
)


def match(*texts: str) -> Optional[Signature]:
    for text in texts:
        if not text:
            continue
        for sig in SIGNATURES:
            if sig.pattern.search(text):
                return sig
    return None
