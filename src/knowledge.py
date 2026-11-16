"""Plain-English knowledge about Windows events and MITRE ATT&CK techniques.

explain_event() turns one parsed event into a sentence a non-specialist can follow,
plus the reasons (if any) that the event looks suspicious."""
import re

# Severity levels, from least to most concerning
ROUTINE, NOTABLE, SUSPICIOUS = "routine", "notable", "suspicious"

LOGON_TYPES = {
    "2": "at the keyboard", "3": "over the network", "4": "by a scheduled task",
    "5": "by a service", "7": "by unlocking the screen", "8": "over the network with a plain-text password",
    "9": "with alternate credentials (runas /netonly)", "10": "by Remote Desktop", "11": "with cached credentials",
}

# (name, what it means, default severity), keyed by event ID.
SECURITY_EVENTS = {
    1102: ("Security log cleared", "Someone erased the Security event log.", SUSPICIOUS),
    4624: ("Successful logon", "An account signed in.", ROUTINE),
    4625: ("Failed logon", "Someone tried to sign in and got the password or user name wrong.", NOTABLE),
    4634: ("Logoff", "An account signed out.", ROUTINE),
    4648: ("Logon with explicit credentials", "A program signed in using a user name and password it supplied itself.", NOTABLE),
    4662: ("Directory object accessed", "An account read or changed an object in Active Directory.", ROUTINE),
    4663: ("Object accessed", "A program accessed a file, folder or registry key.", ROUTINE),
    4672: ("Admin rights assigned at logon", "An account signed in with administrator-level privileges.", NOTABLE),
    4688: ("Process started", "A program was started.", ROUTINE),
    4697: ("Service installed", "A new Windows service was installed.", NOTABLE),
    4698: ("Scheduled task created", "A new scheduled task was created.", NOTABLE),
    4720: ("User account created", "A new user account was created.", NOTABLE),
    4724: ("Password reset", "Someone reset another account's password.", NOTABLE),
    4728: ("Added to a security group", "An account was added to a global security group.", NOTABLE),
    4732: ("Added to a local group", "An account was added to a local group, such as Administrators.", NOTABLE),
    4765: ("SID history added", "Extra security identifiers were attached to an account.", SUSPICIOUS),
    4768: ("Kerberos ticket requested", "An account asked the domain controller for a sign-in ticket.", ROUTINE),
    4769: ("Kerberos service ticket requested", "An account asked for a ticket to use a specific service.", ROUTINE),
    4771: ("Kerberos pre-authentication failed", "A sign-in to the domain failed, usually because of a wrong password.", NOTABLE),
    4776: ("Credential validation", "The computer checked an account's password (NTLM).", ROUTINE),
    4794: ("DSRM password change attempt", "Someone tried to set the Directory Services Restore Mode administrator password on a domain controller.", SUSPICIOUS),
    5140: ("Network share accessed", "Someone connected to a shared folder over the network.", ROUTINE),
    5145: ("Network share file checked", "Someone accessed a file or pipe on a shared folder.", ROUTINE),
    5156: ("Network connection allowed", "The firewall allowed a network connection.", ROUTINE),
}

SYSMON_EVENTS = {
    1: ("Process started", "A program was started.", ROUTINE),
    2: ("File time changed", "A program changed a file's creation time.", NOTABLE),
    3: ("Network connection", "A program made a network connection.", ROUTINE),
    4: ("Sysmon started", "The Sysmon monitoring service started.", ROUTINE),
    5: ("Process ended", "A program exited.", ROUTINE),
    7: ("DLL loaded", "A program loaded a code library (DLL).", ROUTINE),
    8: ("Code injected into another program", "One program started running code inside another program.", SUSPICIOUS),
    10: ("Program opened another program", "One program opened another program's memory.", ROUTINE),
    11: ("File created", "A program created a file.", ROUTINE),
    12: ("Registry key created or deleted", "A program created or deleted a registry key.", ROUTINE),
    13: ("Registry value set", "A program changed a registry value.", ROUTINE),
    16: ("Sysmon configuration changed", "Sysmon's monitoring settings were changed.", NOTABLE),
    18: ("Named pipe connected", "A program connected to a named pipe (a channel between programs).", ROUTINE),
    22: ("DNS lookup", "A program looked up a domain name.", ROUTINE),
}

OTHER_EVENTS = {
    ("Eventlog", 1102): SECURITY_EVENTS[1102],
    ("Eventlog", 104): ("Event log cleared", "Someone erased a Windows event log.", SUSPICIOUS),
    ("Service Control Manager", 7045): ("Service installed", "A new Windows service was installed.", NOTABLE),
    ("PowerShell", 4104): ("PowerShell script ran", "PowerShell recorded the script it was about to run.", NOTABLE),
    ("Bits-Client", 3): ("Background download job created", "A BITS background transfer job was created.", NOTABLE),
    ("Bits-Client", 59): ("Background download started", "A BITS transfer started.", NOTABLE),
    ("Bits-Client", 60): ("Background download finished", "A BITS transfer finished.", NOTABLE),
    ("Windows Defender", 1116): ("Malware detected", "Microsoft Defender detected malware.", SUSPICIOUS),
    ("Windows Defender", 1117): ("Malware action taken", "Microsoft Defender acted on detected malware.", SUSPICIOUS),
}

# MITRE ATT&CK techniques: (name, plain-English meaning)
TECHNIQUES = {
    # Older technique IDs that Sysmon rule sets still use
    "T1031": ("Modify Existing Service", "changing a Windows service so it runs attacker code"),
    "T1033": ("System Owner/User Discovery", "checking which account it is running as"),
    "T1050": ("New Service", "installing a service so attacker code runs with system rights"),
    "T1060": ("Registry Run Keys", "making a program start automatically at sign-in"),
    "T1085": ("Rundll32", "using rundll32.exe, a trusted Windows program, to run attacker code"),
    "T1086": ("PowerShell", "running attacker commands through PowerShell"),
    "T1088": ("Bypass User Account Control", "getting admin rights without the usual Windows prompt"),
    "T1117": ("Regsvr32", "using regsvr32.exe, a trusted Windows program, to run attacker code"),
    "T1170": ("Mshta", "using mshta.exe, a trusted Windows program, to run attacker scripts"),
    "T1003": ("OS Credential Dumping", "stealing passwords or password hashes from Windows"),
    "T1003.001": ("LSASS Memory", "stealing passwords from the memory of LSASS, the process that handles Windows sign-ins"),
    "T1003.006": ("DCSync", "pretending to be a domain controller to copy every password hash in the domain"),
    "T1021": ("Remote Services", "using remote access services to move to other computers"),
    "T1012": ("Query Registry", "reading registry settings to learn about the system"),
    "T1016": ("System Network Configuration Discovery", "looking up the computer's network settings"),
    "T1018": ("Remote System Discovery", "looking for other computers on the network"),
    "T1027": ("Obfuscated Files or Information", "hiding code by encoding or scrambling it"),
    "T1036": ("Masquerading", "disguising a malicious program as something legitimate"),
    "T1053": ("Scheduled Task", "using scheduled tasks to run attacker code automatically"),
    "T1055": ("Process Injection", "hiding attacker code inside another, trusted program"),
    "T1059": ("Command and Scripting Interpreter", "running attacker commands through a shell or script engine"),
    "T1059.001": ("PowerShell", "running attacker commands through PowerShell"),
    "T1070": ("Indicator Removal", "deleting logs or other evidence"),
    "T1070.001": ("Clear Windows Event Logs", "erasing Windows event logs to hide activity"),
    "T1047": ("Windows Management Instrumentation", "using WMI to run commands, often on other computers"),
    "T1049": ("System Network Connections Discovery", "listing the computer's network connections"),
    "T1057": ("Process Discovery", "listing the programs that are running"),
    "T1078": ("Valid Accounts", "signing in with a real, stolen account"),
    "T1082": ("System Information Discovery", "collecting details about the computer"),
    "T1083": ("File and Directory Discovery", "browsing files and folders to find valuable data"),
    "T1087": ("Account Discovery", "listing user accounts to pick targets"),
    "T1098": ("Account Manipulation", "changing an account to keep access, for example by resetting a password"),
    "T1110": ("Brute Force", "guessing passwords"),
    "T1110.003": ("Password Spraying", "trying one common password against many accounts"),
    "T1112": ("Modify Registry", "changing registry settings to hide or keep access"),
    "T1130": ("Install Root Certificate", "installing a trusted certificate so malicious software or traffic looks legitimate"),
    "T1134": ("Access Token Manipulation", "borrowing another account's security token to gain its rights"),
    "T1134.005": ("SID-History Injection", "adding hidden admin identifiers to an account"),
    "T1178": ("SID-History Injection", "adding hidden admin identifiers to an account"),
    "T1053.003": ("Cron", "scheduling a program to run again and again on Linux"),
    "T1059.004": ("Unix Shell", "running attacker commands in a Linux shell"),
    "T1070.003": ("Clear Command History", "erasing the shell history to hide commands"),
    "T1070.004": ("File Deletion", "deleting files to remove evidence or competitors"),
    "T1090": ("Proxy", "relaying traffic through a hacked machine to hide its source"),
    "T1098.004": ("SSH Authorized Keys", "adding the attacker's SSH key so they can log back in"),
    "T1489": ("Service Stop", "stopping other programs or services"),
    "T1496": ("Resource Hijacking", "using the victim's computer to mine cryptocurrency"),
    "T1105": ("Ingress Tool Transfer", "downloading attacker tools onto the computer"),
    "T1135": ("Network Share Discovery", "looking for shared folders on the network"),
    "T1140": ("Deobfuscate/Decode Files", "decoding hidden attacker code before running it"),
    "T1187": ("Forced Authentication", "tricking Windows into sending password hashes to the attacker"),
    "T1197": ("BITS Jobs", "abusing Windows' background download service to fetch or run files"),
    "T1218": ("Signed Binary Proxy Execution", "using a trusted Windows program to run attacker code"),
    "T1548.002": ("Bypass User Account Control", "getting admin rights without the usual Windows prompt"),
    "T1543.003": ("Windows Service", "installing a service so attacker code runs with system rights"),
    "T1547": ("Boot or Logon Autostart", "making attacker code start automatically at boot or sign-in"),
    "T1550.002": ("Pass the Hash", "signing in with a stolen password hash instead of the password"),
    "T1555": ("Credentials from Password Stores", "stealing saved passwords, for example from a password manager"),
    "T1558": ("Steal or Forge Kerberos Tickets", "stealing or forging domain sign-in tickets"),
    "T1021.002": ("SMB/Windows Admin Shares", "using hidden admin shares to copy files to or run code on other computers"),
    "T1574": ("Hijack Execution Flow", "tricking a program into loading attacker code, for example a planted DLL"),
    "T1569.002": ("Service Execution", "running attacker code by starting a Windows service"),
}

KNOWN_TOOLS = {
    "mimikatz": "a tool that steals Windows passwords and password hashes",
    "mimilsa": "a file written by Mimikatz to capture passwords as users sign in",
    "keefarce": "a tool that steals saved passwords from the KeePass password manager",
    "psexec": "a tool for running commands on other computers, often used to spread through a network",
    "procdump": "a tool attackers use to copy LSASS memory so they can extract passwords",
    "meterpreter": "a remote-control backdoor from the Metasploit hacking toolkit",
    "rubeus": "a tool for stealing and forging Kerberos sign-in tickets",
    "sharphound": "a tool that maps Active Directory to find paths to domain admin",
    "bloodhound": "a tool that maps Active Directory to find paths to domain admin",
    "lazagne": "a tool that recovers passwords saved on a computer",
    "cobaltstrike": "a commercial attack framework popular with real attackers",
}

# Folders any user can write to, so attackers like to drop tools there
USER_WRITABLE = [r"\users\public", r"\appdata\local\temp", r"\windows\temp", r"\downloads", r"\programdata"]

# Active Directory permissions used to replicate password data (DCSync)
REPLICATION_GUIDS = ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                     "89e95b76-444d-4c62-991a-0facbeda640c"]

SUSPICIOUS_POWERSHELL = ["frombase64string", "-enc", "downloadstring", "invoke-expression", "iex ",
                         "invoke-mimikatz", "get-credential", "net.webclient", "gzipstream"]

# Background downloads from these are normal Windows behavior
TRUSTED_DOWNLOADS = re.compile(r"https?://[^/]*(microsoft\.com|windowsupdate\.com|msftconnecttest\.com|office\.net|msft[\w-]*\.azureedge\.net)/", re.I)

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def file_name(path):
    """C:\\Users\\Public\\KeeFarce.exe -> KeeFarce.exe"""
    return re.split(r"[\\/]", str(path).strip())[-1] if path else ""


def source_key(provider):
    """Shortens a provider name for lookups and display."""
    return str(provider).replace("_", " ").replace("Microsoft-Windows-", "") or "Unknown"


def event_info(event_id, provider):
    """Returns (name, meaning, severity) for an event, or a generic entry if unknown."""
    source = source_key(provider)
    try:
        number = int(event_id)
    except (TypeError, ValueError):
        number = None
    if source == "Sysmon" and number in SYSMON_EVENTS:
        return SYSMON_EVENTS[number]
    if (source, number) in OTHER_EVENTS:
        return OTHER_EVENTS[(source, number)]
    if source == "Security-Auditing" and number in SECURITY_EVENTS:
        return SECURITY_EVENTS[number]
    if event_id in (None, "", "-"):
        label = "Log entry"
    else:
        label = f"{source} event {event_id}" if provider else str(event_id)
    return label, "", ROUTINE


def technique_text(technique_id):
    name, meaning = TECHNIQUES.get(technique_id, (None, None))
    if name:
        return f"{name} ({technique_id}): {meaning}"
    return f"MITRE ATT&CK technique {technique_id}"


def _sentence(number, source, f):
    """A one-line, plain-English description of what this specific event says happened."""
    user = f.get("TargetUserName") or f.get("SubjectUserName") or ""
    image = file_name(f.get("Image") or f.get("NewProcessName") or f.get("Application"))
    if source == "Sysmon":
        if number == 1:
            parent = file_name(f.get("ParentImage"))
            text = f"{image} was started" + (f" by {parent}" if parent else "")
            folder = str(f.get("Image", "")).rsplit("\\", 1)[0]
            return text + (f" from {folder}" if folder and folder != f.get("Image") else "")
        if number == 3:
            return f"{image} connected to {f.get('DestinationIp', '?')}:{f.get('DestinationPort', '?')}"
        if number == 7:
            return f"{image} loaded {file_name(f.get('ImageLoaded'))} from {str(f.get('ImageLoaded', '')).rsplit(chr(92), 1)[0]}"
        if number == 8:
            return f"{file_name(f.get('SourceImage'))} injected code into {file_name(f.get('TargetImage'))}"
        if number == 10:
            return f"{file_name(f.get('SourceImage'))} opened the memory of {file_name(f.get('TargetImage'))}"
        if number == 11:
            return f"{image} created the file {f.get('TargetFilename', '?')}"
        if number in (12, 13):
            return f"{image} changed the registry key {f.get('TargetObject', '?')}"
        if number == 5:
            return f"{image} exited"
    if number == 4624:
        how = LOGON_TYPES.get(str(f.get("LogonType")), "")
        where = f.get("IpAddress") or f.get("WorkstationName") or ""
        where = f" from {where}" if where not in ("", "-", "::1", "127.0.0.1") else ""
        return f"{user} signed in {how}{where}".strip()
    if number == 4625:
        return f"Failed sign-in for {user}" + (f" from {f.get('IpAddress')}" if f.get("IpAddress") not in (None, "", "-") else "")
    if number in (4771, 4768) and f.get("TargetUserName"):
        status = " (failed)" if str(f.get("Status", "0x0")).lower() not in ("0x0", "0") else ""
        return f"Domain sign-in ticket requested for {f['TargetUserName']} from {f.get('IpAddress', '?')}{status}"
    if number == 4794:
        return f"{f.get('SubjectUserName', 'Someone')} tried to set the DSRM administrator password on {f.get('Workstation', 'a domain controller')}"
    if number in (1102, 104):
        return f"{f.get('SubjectUserName', 'Someone')} cleared the event log"
    if number == 4688:
        return f"{image} was started by {f.get('SubjectUserName', '?')}"
    if number == 4662:
        return f"{f.get('SubjectUserName', '?')} accessed an Active Directory object"
    if number == 4672:
        return f"{f.get('SubjectUserName', '?')} signed in with administrator privileges"
    if number in (5140, 5145):
        target = f.get("RelativeTargetName") or ""
        return f"{f.get('SubjectUserName', '?')} accessed {f.get('ShareName', 'a share')}{(chr(92) + target) if target else ''} from {f.get('IpAddress', '?')}"
    if source == "Bits-Client" and (f.get("name") or f.get("string")):
        job = f.get("name") or f.get("string")
        return f"Background transfer job '{job}'" + (f" for {f['url']}" if f.get("url") else " was created")
    if source == "Windows Defender" and number == 1116 and f.get("Threat Name"):
        return (f"Defender detected {f['Threat Name']} in {file_name(f.get('Process Name')) or 'a program'}"
                + (f" run by {f['Detection User']}" if f.get("Detection User") else ""))
    if source == "Windows Defender" and number == 1117 and f.get("Threat Name"):
        return f"Defender acted against {f['Threat Name']} (action: {f.get('Action Name', '?')})"
    if source == "PowerShell" and number == 4104:
        return "PowerShell ran a script: " + " ".join(str(f.get("ScriptBlockText", "")).split())[:80]
    return ""


def explain_event(event):
    """Explains one parsed event.

    event is a dict with event_id, provider, fields (dict) and message (str).
    Returns a dict with name, meaning, sentence, severity, reasons and techniques."""
    event_id, provider = event.get("event_id"), event.get("provider", "")
    fields = event.get("fields") or {}
    name, meaning, severity = event_info(event_id, provider)
    source = source_key(provider)
    try:
        number = int(event_id)
    except (TypeError, ValueError):
        number = None

    reasons, techniques = [], []
    text_blob = " ".join(str(v) for v in fields.values()).lower() + " " + str(event.get("message", "")).lower()

    # Sysmon detection rules often tag events with ATT&CK technique IDs. (Other logs use
    # "RuleName" for things like firewall rules, which aren't detections.)
    rule = str(fields.get("RuleName", "")).strip() if source == "Sysmon" else ""
    for technique_id in TECHNIQUE_ID.findall(rule):
        techniques.append(technique_id)
        reasons.append(f"A detection rule tagged this as {technique_text(technique_id)}.")
    if rule and rule.lower() not in ("-", "undefined") and not TECHNIQUE_ID.search(rule):
        reasons.append(f"A detection rule flagged it: \"{rule}\".")

    for tool, description in KNOWN_TOOLS.items():
        if tool in text_blob:
            reasons.append(f"It mentions {tool.capitalize()}, {description}.")
    if source == "Windows Defender" and fields.get("Threat Name"):
        severity_name = fields.get("Severity Name", "")
        reasons.insert(0, f"Microsoft Defender identified it as malware ({fields['Threat Name']}"
                          + (f", severity: {severity_name}" if severity_name else "") + ").")

    for key in ("Image", "ImageLoaded", "SourceImage", "TargetFilename", "NewProcessName"):
        value = str(fields.get(key, "")).lower()
        if value.startswith("\\\\"):
            reasons.append(f"{file_name(fields[key])} ran from a network share ({fields[key].rsplit(chr(92), 1)[0]}) "
                           "instead of from the computer itself, which is unusual for normal software.")
            break
        folder = next((d for d in USER_WRITABLE if d in value), None)
        if folder:
            reasons.append(f"{file_name(fields[key])} is in {fields[key].rsplit(chr(92), 1)[0]}, a folder any user can "
                           "write to. Attackers often drop their tools there.")
            break

    target = file_name(fields.get("TargetImage")).lower()
    if source == "Sysmon" and number in (8, 10) and target == "lsass.exe":
        reasons.append("LSASS holds the passwords of signed-in users, so touching its memory is how credential "
                       "dumping tools work.")
        techniques.append("T1003.001")
    if source == "Sysmon" and number == 8:
        reasons.append("Legitimate programs rarely run code inside other programs. This is a common way to hide "
                       "malware or steal data from the target.")
        techniques.append("T1055")
    if number == 4662 and any(guid in text_blob for guid in REPLICATION_GUIDS):
        reasons.append("It used the directory replication permissions that DCSync attacks use to copy password hashes.")
        techniques.append("T1003.006")
    if number in (1102, 104):
        reasons.append("Attackers clear logs to hide what they did.")
        techniques.append("T1070.001")
    if number == 4794:
        reasons.append("The DSRM password gives a hidden local admin account on the domain controller, so setting it "
                       "is a known way to keep access.")
        techniques.append("T1098")
    url = str(fields.get("url", ""))
    if source == "Bits-Client" and url and not TRUSTED_DOWNLOADS.search(url):
        reasons.append(f"A background (BITS) transfer used {url[:60]}. BITS jobs are a known way to download or run "
                       "files quietly, and this isn't a normal Microsoft download.")
        techniques.append("T1197")
    if source == "PowerShell" and any(word in text_blob for word in SUSPICIOUS_POWERSHELL):
        reasons.append("The script is encoded or downloads code, which is typical of malicious PowerShell.")
        techniques.append("T1059.001")

    if reasons:
        severity = SUSPICIOUS
    message = str(event.get("message", ""))
    blocked = "contains malicious content" in message
    if blocked:
        reasons.append("Antivirus blocked this script because it contained malicious code.")
    sentence = _sentence(number, source, fields)
    if blocked:
        sentence = "PowerShell blocked a script that contained malicious content"
    elif not sentence and message and not meaning:
        # Unknown event type: use the first sentence of its own message
        sentence = re.split(r"(?<=\.)\s", message, maxsplit=1)[0].strip()
    sentence = sentence or name
    return {
        "name": name, "meaning": meaning, "sentence": sentence, "severity": severity,
        "reasons": reasons, "techniques": list(dict.fromkeys(techniques)),
    }


def explained(event):
    """explain_event(), computed once per event and cached on it (big logs are explained twice)."""
    if "info" not in event:
        event["info"] = explain_event(event)
    return event["info"]
