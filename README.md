# Codi Clean

A local macOS tool, run from the terminal, that cleans cache junk and checks for
malware, adware and spyware. Before anything is removed, Codi shows where an item
is and what it does, and asks you to confirm.

```
codi
```

```
   1  Cache files                  find caches, browser ad/tracker junk, logs and old installers
   2  Malware & Spyware            scan, explain each find, quarantine what you confirm
   3  General check-up & summary   read-only health check of this Mac
   4  Quarantine                   review, restore or permanently delete quarantined items
   q  Quit
```

You can also run one option directly: `codi cache`, `codi malware`, `codi checkup`,
`codi quarantine`.

## Quick start

Codi needs **macOS** and **Python 3.8 or newer** (`python3 --version` to check).
It has no dependencies to install.

```
git clone https://github.com/AmrZoair1997/Codi-Clean.git
cd Codi-Clean
chmod +x codi
./codi
```

To run it from anywhere, link the launcher into a folder on your `PATH`:

```
ln -s "$PWD/codi" /usr/local/bin/codi
```

> **Please read first:** Codi can move and permanently delete files. It always asks
> before it does, and it never touches macOS system folders, but review every item
> before you confirm. Back up your Mac (Time Machine) before your first cleanup.
> Codi is a learning project, not a replacement for a full antivirus product.

## What each option does

**1. Cache files.** Measures app caches in `~/Library/Caches` (Apple's own caches are
left alone), per-profile browser web data from Chrome, Brave, Edge, Vivaldi and Arc
(service-worker storage, compiled scripts and GPU caches, much of it from ads and
trackers), app logs, developer caches (Xcode, npm, Gradle, Cargo, pip) and installers
in Downloads older than 14 days. Each item shows its size, a short description and
its location. You choose items by number or pick "all". Chosen items go to the
**Trash**, so Finder's *Put Back* can restore them. Cookies and logins are never
touched. Caches of apps that are currently open are flagged and left out of "all".

**2. Malware & Spyware.** Checks:

- **Startup items** (`LaunchAgents` and `LaunchDaemons`): known adware names,
  programs in temporary or hidden folders, scripts that download or decode things,
  unsigned programs, and leftovers that point to deleted apps.
- **Apps** in `/Applications` and `~/Applications`: known adware and scareware names,
  and apps with no signature or only an ad-hoc one.
- **Downloads and Desktop**: installers with known-bad names, such as fake Flash Player installers.
- **Hidden programs**: unsigned programs in hidden folders, `/Users/Shared` and the temp folders.
- **Browser extensions and browser policies**: known adware extensions, and
  configuration profiles that lock your search engine or homepage.
- **ClamAV**, if installed: antivirus signatures on Downloads, Desktop, startup items
  and the programs they start.
- **Zero Breach Toolkit**, optional: Codi asks first, then runs the audited toolkit
  from `../Zero-Breach-Toolkit-main` offline and unchanged, to look for mercenary
  spyware (Pegasus, Candiru, Predator...).

Each finding shows why it was flagged, what it is, who signed it, where it was
downloaded from, its size and location. Codi then asks whether to quarantine it.

**3. General check-up.** Read-only. Shows disk space, SIP, Gatekeeper, FileVault,
firewall, XProtect version, automatic security updates, Full Disk Access, startup
items, how much junk could be cleaned, and Codi's history. It ends with suggestions.

**4. Quarantine.** Lists quarantined items. `r 2` restores item 2 to its original
place. `p 2` or `p all` deletes permanently, but only after you type `DELETE`.

## Safety rules

- **Nothing is removed without your confirmation.**
- Malware is **quarantined, not deleted**. It moves to `~/.codi/quarantine`, a
  private folder only you can read, and loses its permission to run. A manifest
  records its original path and SHA-256 hash, so it can be restored. Purging is the
  only permanent step.
- Before quarantining a startup item that belongs to you, Codi stops it if it is running.
- **Codi never asks for admin rights** and refuses to run under `sudo`. For system
  startup items, it prints the exact `sudo` commands so you can decide yourself.
- Codi never moves macOS system locations (`/System`, `/usr`, `/Library/Apple`...),
  your top-level folders (Documents, Desktop, Library...) or its own data.
- Spyware matches from Zero Breach are evidence. Codi links to expert help
  (Access Now, Amnesty Security Lab) instead of encouraging you to delete them.
- **Fully offline.** It uses only the Python standard library and built-in macOS
  tools (`codesign`, `mdls`, `launchctl`, `csrutil`...), plus ClamAV if you have it.
- A clean result means nothing known was found where Codi could look. It is not a guarantee.

## Tips

- Without **Full Disk Access** for Terminal, macOS hides browser folders and some
  others from Codi; it tells you when. You can grant access in System Settings >
  Privacy & Security > Full Disk Access, and turn it off again after a scan.
- Optional antivirus engine: `brew install clamav`, then run `freshclam` to download
  its virus definitions. Set `CODI_ZERO_BREACH` to use a Zero Breach copy in another folder.

## Files

```
codi                 launcher (runs python3 -I codi.py)
codi.py              entry point
codi_clean/
  cli.py             menu and commands
  cache.py           option 1
  malware.py         option 2: checks, review, quarantine prompts
  signatures.py      known adware/malware/PUP names and descriptions
  describe.py        "what is this file": kind, signature, download source
  zerobreach.py      runs Zero Breach offline and reads its JSON report
  checkup.py         option 3
  quarantine.py      option 4 and the quarantine store
  state.py           remembers the last scan for the check-up
  fsutil.py          sizes, protected paths, Trash, running macOS tools
tests/test_codi.py   unit tests (temporary folders only)
```

Run the tests: `python3 -I -m unittest discover -s tests`

Zero Breach Toolkit is © archivegenocide.com, Apache 2.0. Codi calls it unchanged
and does not redistribute it.

## License

MIT. See [LICENSE](LICENSE). The software is provided as is, without warranty.
