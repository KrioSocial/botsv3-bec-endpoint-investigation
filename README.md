# Business Email Compromise and Endpoint Takeover at Frothly

**Analyst:** Arun
**Dataset:** Splunk Boss of the SOC v3 (Frothly / Taedonggang scenario)
**Date of incident:** 20 August 2018
**Tooling:** Splunk Enterprise, Splunk Stream, Sysmon, Office 365 management and Azure AD sign in logs, CyberChef, VirusTotal

---

## Summary

A Frothly employee opened what appeared to be a folder of birthday party photos shared on the company's own SharePoint. It was a Windows shortcut file carrying an embedded command. Two seconds after it opened, an obfuscated PowerShell payload executed, disabled the machine's script logging and antimalware interface, and opened an encrypted channel to an external server. Within eight minutes the attacker had bypassed User Account Control, created a hidden local administrator account, and installed a scheduled task for persistence. Roughly forty minutes later they dropped a network reconnaissance and brute force tool onto the host, confirmed malicious by 28 of 69 vendors on VirusTotal.

Eighty minutes after the initial execution, a rule appeared in Frothly's Exchange Online tenant under the same user's identity. It was named "SOX" so it would read as a routine compliance rule. Its actual function was to blind copy mail to an external webmail address controlled by the attacker.

The user's account had no multifactor authentication enforced at the moment the rule was created.

I chose this thread out of BOTSv3 because it starts the way a real ticket starts, with something small and ambiguous, and it forces you to work outward rather than being handed a compromised hostname. Nobody told me which machine to look at. Finding that was the investigation.

---

## Why I started where I started

The obvious entry point into this dataset is the mail traffic, so that is where I began, with a deliberately simple question: did anything arrive from outside the company?

```spl
index=botsv3 sourcetype="stream:smtp" NOT sender_email="*@froth.ly*" subject="*"
| table _time sender_email subject
```

The `NOT sender_email="*@froth.ly*"` filter is the whole idea. Internal mail is noise for this question. I want anything crossing the boundary. The `subject="*"` clause matters more than it looks, because SMTP is a conversation protocol and a large proportion of those events are handshake level records with no message content attached. Filtering to events that actually carry a subject cuts the volume down to something a person can read.

That surfaced a message from `hyunki1984@naver.com`, display name HyunKi Kim, subject "All your datas belong to us". Naver is a South Korean webmail provider. Nothing about that is proof of anything on its own, but an external consumer webmail address sending a message with that subject line into a brewery's corporate mail flow is worth pulling on.

Four minutes later the same subject appeared again, this time prefixed "Fw:" and sent by `ghoppy@froth.ly`. Grace Hoppy had received it and forwarded it internally.

---

## The taunt, and the click that never happened

The body of the original message was encoded with base64, which is normal for mail with mixed content and not itself suspicious. Decoded, it read:

> Gracie,
>
> We brought your data and imported it: hxxps://pastebin[.]com/sdBUkwsE Also, you should not be too hard Bruce. He good man

The HTML version carried the same text plus a tracking pixel pointing at Naver's read receipt service, which would tell the sender the moment the message was opened.

<img width="1381" height="797" alt="Screenshot 2026-09-22 at 20 41 09" src="https://github.com/user-attachments/assets/8a8db897-1ad0-48f5-b255-6b512d308e1c" />

> Screenshot of the expanded raw SMTP event showing sender_email, subject and the message body. Crop to the readable fields rather than the whole event.

Two things stood out immediately. First, this is not a lure. There is no attachment and no credential harvesting page. It claims data has **already** been taken and posted publicly, which means it is either an extortion attempt or an act of intimidation, and either way it implies a compromise that happened before this email was sent. Second, the line about Bruce is social engineering aimed at a named colleague, which suggests the sender knows something about Frothly's internal relationships.

I did not open the Pastebin link. It is evidence, not a page to browse to. Instead I asked the only question that actually matters for triage: did anyone at Frothly go there?

```spl
index=botsv3 source="stream:dns" "pastebin"
index=botsv3 source="stream:http" "pastebin"
```

Both came back empty. That is a stronger negative than it might appear. DNS resolution happens regardless of whether the connection is encrypted, so if anyone had visited that link over HTTPS there would still be a lookup for `pastebin.com` in the stream data. There is none.

One result did surface when I widened the keyword search across the whole index, and it is worth showing because ruling it out correctly is part of the work:

<img width="1470" height="797" alt="Screenshot 2026-09-22 at 20 41 45" src="https://github.com/user-attachments/assets/a8fc4e72-9678-49f5-b9d2-7bc4b338b651" />

That event matched my keyword but is not related. The domain is `pastebin.brewertalk.com`, a subdomain of an unrelated forum, not `pastebin.com`. The response was NXDOMAIN, so the name does not resolve and nothing was reached. The source is an AWS Lambda function's own DNS resolution, not a user workstation. I recorded it as a false positive rather than quietly discarding it, because an analyst who only reports the hits they liked is not reporting accurately.

**Finding:** the extortion email was delivered and forwarded internally, and no host in the environment resolved or requested the linked resource.

---

## Pivoting on the indicator rather than guessing

At this point I had a confirmed bad indicator and no compromised host. The mistake here would be to start guessing at machines. The correct move is to take the one thing I know is attacker controlled, the email address itself, and ask where else it appears in the environment.

```spl
index=botsv3 "hyunki1984" | stats count by sourcetype
```

This is the single most important query in the investigation, and it is worth explaining why. An address used once to send a message is a nuisance. An address that also appears inside an administrative configuration log is a compromise. Searching a known indicator across every data source, rather than the source you happen to be looking at, is what turns a phishing ticket into an incident.

<img width="1470" height="797" alt="Screenshot 2026-09-22 at 20 42 49" src="https://github.com/user-attachments/assets/b100d17d-91de-4d2d-b135-33fdadd7461b" />


The results:

| Sourcetype | Count | What it means |
|---|---|---|
| `ms:o365:reporting:messagetrace` | 84 | Mail flow records, expected |
| `stream:smtp` | 2 | The two messages already reviewed |
| `o365:management:activity` | 1 | Tenant level activity |
| `ms:o365:management` | 1 | **Administrative configuration change** |

One event in the administrative log. That is the one to open.

---

## The mail rule

```spl
index=botsv3 sourcetype="ms:o365:management" "hyunki1984"
```

A single event, timestamped 12:21:40, with `Operation: New-TransportRule`, `Workload: Exchange`, `ResultStatus: True`, performed under `UserId: fyodor@froth.ly` inside the `frothly.onmicrosoft.com` tenant.

The `Parameters` array is where the rule's actual behaviour lives, and expanding it gave the finding:

```
Name:                  BlindCopyTo
Value:                 hyunki1984@naver.com

Name:                  Name
Value:                 SOX

Name:                  Mode
Value:                 Enforce

Name:                  StopRuleProcessing
Value:                 False

Name:                  RuleErrorAction
Value:                 Ignore
```

<img width="1470" height="797" alt="Screenshot 2026-09-22 at 20 45 25" src="https://github.com/user-attachments/assets/0e4c2c2a-070a-4655-98cb-0de5013bbdbe" />

Reading the configuration rather than just the fact of it:

**`BlindCopyTo`** silently copies mail to an external address. The recipients see nothing. There is no forwarding indicator in the mailbox, no bounce, no trace in the user's sent items.

**`Name: SOX`** is the detail I find most telling. Sarbanes Oxley is financial compliance legislation, and organisations routinely run mail rules named after compliance frameworks. An administrator reviewing a list of transport rules and seeing one called SOX is far more likely to assume it belongs there than one called anything overtly odd. This is deliberate camouflage, and it is the same instinct that later named a scheduled task "Updater".

**`StopRuleProcessing: False`** and **`Mode: Enforce`** mean the rule is live and does not interrupt the normal processing of other rules. Mail flows exactly as it did before. Nothing appears broken to anyone.

**`RuleErrorAction: Ignore`** means if the rule fails for a given message, it fails silently rather than generating an error that might be noticed.

Every one of those settings is chosen to avoid attention. This is persistence and exfiltration built to survive a casual review.

---

## A lead that did not hold, and why I dropped it

The rule creation event recorded `ClientIP: 199.66.91.253`. The tempting move is to treat that as attacker infrastructure and start building a case around it. I checked it first:

```spl
index=botsv3 199.66.91.253 | stats count by userPrincipalName
```

Kevin Lagerfield (`klagerfield@froth.ly`) signed in successfully from the same address, on the same day, from a similar client. That makes it an ordinary shared egress address, almost certainly Frothly's office network or VPN concentrator, not something an attacker uniquely controls.

So I dropped it. The IP address tells you nothing incriminating on its own, and building a narrative on it would have been wrong. The evidence for compromise is the rule's configuration, which stands entirely on its own regardless of where it came from.

I am including this because knowing when to abandon a lead is part of the job, and because an investigation that only shows the paths that worked is not showing you how someone thinks.

---

## Reconstructing the account's activity

With the rule confirmed, I pulled the full sign in history for the account to understand the context around 12:21:40.

```spl
index=botsv3 sourcetype="ms:aad:signin" userPrincipalName="fyodor@froth.ly"
| table _time ipAddress deviceInformation loginStatus mfaRequired
| sort _time
```

<img width="1468" height="791" alt="Screenshot 2026-09-22 at 20 46 34" src="https://github.com/user-attachments/assets/bb9f6152-7c0b-4cab-a269-cfd6caea604b" />


Eighty two sign in events across the day, moving between several addresses and client types. Two observations were worth recording and one was worth flagging as a control failure.

**Two failures immediately preceding sustained success.** At 12:17:08 and 12:17:18 the account recorded `Failure`, then from 12:17:30 onward a continuous run of successes from the same client, running through the rule creation at 12:21:40. Two failed attempts followed twelve seconds later by success, four minutes before a malicious administrative action, is a soft signal. It is equally consistent with a mistyped password. I noted it without drawing a conclusion from it.

**MFA was not enforced.** The `mfaRequired` field reads `false` for the overwhelming majority of the day's sign ins, including the session that created the rule. It flips to `true` only for a narrow block later in the afternoon from a different client. That pattern is characteristic of legacy authentication paths falling outside conditional access policy, which is one of the most common real world gaps in Office 365 tenants. It is a finding in its own right, independent of anything else in this incident.

---

## Searching the endpoint, and finding nothing

The natural next question is whether something on the user's machine created that rule. I scoped Sysmon process creation on `FYODOR-L` to the ten minutes surrounding it.

```spl
index=botsv3 host="FYODOR-L" sourcetype="xmlwineventlog" "<EventID>1</EventID>"
earliest="08/20/2018:12:15:00" latest="08/20/2018:12:25:00"
| rex field=_raw "Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| table _time Image CommandLine ParentImage
```

Three processes. `RuntimeBroker.exe -Embedding` twice and `taskhostw.exe USER` once. All three are ordinary Windows background activity.

That result is genuinely useful, and it is also where I made a mistake worth admitting. My first reading was that the endpoint was not involved and the compromise was purely at the cloud identity layer, with the attacker acting through Exchange Online directly. That conclusion was reasonable given the evidence in front of me, and it was wrong. The error was not in the logic, it was in the window. I had scoped the search to the moment of the symptom rather than the span of the intrusion, which is a bounded search answering a narrower question than the one I actually had.

So I removed the time constraint entirely and looked at the whole day.

---

## The attack chain

```spl
index=botsv3 host="FYODOR-L" sourcetype="xmlwineventlog" "<EventID>1</EventID>"
| rex field=_raw "Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| table _time Image CommandLine ParentImage
| sort _time
```

158 process creation events. Reading down the CommandLine column in chronological order, an entire intrusion is laid out in plain text.

<img width="1385" height="796" alt="Screenshot 2026-09-22 at 20 49 55" src="https://github.com/user-attachments/assets/d2691bfd-a5bf-4f50-9a65-73476756ba94" />

<img width="1384" height="130" alt="Screenshot 2026-09-22 at 20 50 40" src="https://github.com/user-attachments/assets/cede6cf0-e197-4e00-8aee-6d9465d86346" />


### 11:01:41 and 11:01:44, execution

```
powershell.exe -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUA...
```

Two executions three seconds apart carrying an identical payload. The flag combination is the first thing to read. `-enc` passes the command as base64 so it never appears in plain text in any command line log. `-w 1` hides the window. `-noP` skips profile loading. Each of those has a legitimate administrative use. Together, they are a combination seen almost exclusively in malicious PowerShell, and the presence of that combination is worth alerting on before anyone decodes anything.

### 11:07:03, discovery

```
whoami.exe /groups
```

Run twice in consecutive seconds. The attacker is checking which groups the current user belongs to, which is how you decide whether you need to escalate.

### 11:07:05, privilege escalation

```
consent.exe 4684 324 00000241F5831DB0
fodhelper.exe
powershell.exe -NoP -NonI -W Hidden -c $x=$((gp HKCU:Software\Mi...
```

`fodhelper.exe` is a Windows binary that auto elevates without prompting. The known abuse of it involves writing a command into a registry key under the current user's hive that fodhelper reads on launch, causing an attacker controlled command to run elevated with no UAC prompt shown to the user. The PowerShell immediately after it uses `gp`, the alias for `Get-ItemProperty`, to read from exactly that part of the registry. The sequence is the technique.

### 11:08:17 and 11:08:35, persistence

```
net.exe user /add svcvnc Password123!
net.exe localgroup administrators svcvnc /add
```

A new local account called `svcvnc`, granted local administrator eighteen seconds later. The name is chosen to read as a service account for VNC remote access software. It is a backdoor with a known password that does not require re exploiting anything to reuse.

### 11:09:44, persistence again

```
schtasks.exe /Create /F /RU system /SC DAILY /ST 18:45 /TN Updater
/TR "powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString(
[Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\""
```

This one is worth reading closely. A scheduled task named "Updater" runs daily at 18:45 as SYSTEM. What it runs is a hidden PowerShell command that reads a value out of the registry at `HKLM:\Software\Microsoft\Network debug`, decodes it from base64, and executes it.

The payload is not stored as a file anywhere. It lives in a registry value under a path constructed to look like Windows networking configuration. There is nothing on disk for file based antivirus to scan. This is a second, independent persistence mechanism running alongside the backdoor account, and it is meaningfully more sophisticated than the first.

The naming is the same instinct as "SOX" on the mail rule. An administrator scanning a list of scheduled tasks and seeing "Updater" moves on.

### 11:43:10, tooling

```
C:\Windows\Temp\hdoor.exe
```

Execution from `C:\Windows\Temp` is a signal on its own. It is a writable directory that legitimate software has very little reason to execute from.

### 12:07:04, masquerading

```
C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe
```

Read that filename carefully. It is `iexeplorer.exe`, not `iexplore.exe`. The extra letter is the point. The binary is also nested inside a folder structure imitating an extracted open source archive. Both choices are there to survive a glance.

---

## Decoding the payload

Recording that a command was encoded is weaker evidence than showing what it does, so I decoded the base64 from the 11:01:41 execution. PowerShell's `-enc` expects UTF-16LE, so the decode is From Base64 followed by Decode Text as UTF-16LE in CyberChef.

<img width="1470" height="795" alt="Screenshot 2026-09-22 at 20 58 16" src="https://github.com/user-attachments/assets/c302f8ef-2395-4b84-af32-9cca9194d840" />

The decoded script does four distinct things.

**It blinds the host's defences first.** Before anything else, it reaches into PowerShell's internals to set `EnableScriptBlockLogging` and `EnableScriptBlockInvocationLogging` to zero, and sets `amsiInitFailed` to true on `System.Management.Automation.AmsiUtils`. AMSI is the interface that allows Windows Defender and other products to inspect script content at runtime. Disabling it before doing anything else is a deliberate ordering choice, and it explains a great deal about why the rest of this chain went unnoticed. The variable names throughout are randomly cased and the method names are broken up with string concatenation, both to defeat pattern matching on the script text itself.

**It disguises its traffic.** It constructs a WebClient with an Internet Explorer 11 user agent string, inherits the system proxy and its credentials, and sets the certificate validation callback to always return true, so it will connect to a server presenting an invalid or self signed certificate without complaint.

**It contacts a hardcoded server.** A base64 string in the script decodes, again as UTF-16LE, to `https://45.77.53.176:443`. It requests `/admin/get.php` with a fixed cookie value attached.

**It decrypts and executes in memory.** The script block assigned to `$R` is an implementation of RC4, recognisable from its key scheduling and pseudorandom generation loops. The response from the server is treated as a four byte initialisation vector followed by ciphertext, decrypted with a hardcoded key, and piped directly into `IEX`. The second stage never touches disk.

That single script demonstrates impairing defences, encrypted command and control, and downloading a further payload, and it does all three before the host has had a chance to log anything useful about it.

---

## Confirming the malware independently

Rather than take the filename at face value, I pulled the hash Sysmon recorded at process creation.

```spl
index=botsv3 host="FYODOR-L" sourcetype="xmlwineventlog" "hdoor.exe"
| rex field=_raw "<EventID>(?<EventID>[^<]+)"
| search EventID=1
| rex field=_raw "Data Name='Hashes'>(?<Hashes>[^<]+)"
| table _time Hashes
```

```
MD5=586EF56F4D8963DD546163AC31C865D7
SHA256=99925199059EE049F7AEDA8904C2F5BDFBA86671FD7A5989BD60B72F26EF737C
```

Submitting the SHA256 to VirusTotal returned **28 of 69 vendors flagging the file as malicious**, with a popular threat label of `hacktool.bruteforce` and categories of hacktool, trojan and PUA.

<img width="1470" height="798" alt="Screenshot 2026-09-22 at 20 59 49" src="https://github.com/user-attachments/assets/787bb17e-90fb-425e-bc8c-92d7d7205e0b" />


The capability description matters as much as the score. This is not a simple backdoor. It performs port scanning, banner grabbing and host discovery, enumerates users, groups and shares through NetAPI32, and runs automated dictionary attacks against IPC$ shares and SQL Server instances. It is a tool for moving sideways through a network once you already have a foothold.

That changes the assessment. The presence of this binary means the intrusion was not intended to stop at one workstation.

---

## How it actually started

By this point I had the full chain from 11:01:41 onward, but not what caused it. The first PowerShell execution did not appear from nothing, so I read the `ParentImage` column on that earliest event.

The parent was `browser_broker.exe`, which had itself launched two seconds earlier at 11:01:39. Pulling its full command line gave the answer directly:

```spl
index=botsv3 host="FYODOR-L" sourcetype="xmlwineventlog" "browser_broker.exe" "IOAVHost"
| rex field=_raw "Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| table _time CommandLine
```

```
C:\Windows\system32\browser_broker.exe -IOAVHost 2781761e-28e0-4109-99fe-b9d127c57afe
|C:\Users\FyodorMalteskesko\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe
\TempState\Downloads\BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk
|https://frothly-my.sharepoint.com/personal/bgist_froth_ly/Documents/Birthday%20Pictures
/BRUCE%20BIRTHDAY%20HAPPY%20HOUR%20PICS.lnk
```

<img width="1470" height="797" alt="Screenshot 2026-09-22 at 21 02 27" src="https://github.com/user-attachments/assets/55b37176-72ef-415b-a955-29d1ea437154" />

`browser_broker.exe -IOAVHost` is the Windows mechanism invoked when a user opens a downloaded file directly from the browser. The `(1)` suffix on the filename means this was the second copy downloaded, so the file had been fetched at least once before.

Three things make this the answer:

**It is a `.lnk` file, not an image.** A Windows shortcut carries a target command. A user double clicking something presented as a folder of party photos executes whatever the shortcut's author put in that field. Two seconds later, PowerShell ran.

**It was hosted on Frothly's own SharePoint.** The URL is `frothly-my.sharepoint.com`, under the personal document library of `bgist_froth_ly`, in a folder named "Birthday Pictures". This is not an unfamiliar external domain a security aware user would hesitate over. It is the company's own file sharing platform, under a colleague's account, which means either that account was already compromised or the file was placed there by someone with access to it.

**The timing connects it to mail traffic I had already seen.** Returning to the SMTP data, `bgist@froth.ly` sent a message titled "Wild Birthday Extravaganza!!!" at 10:58:43, which drew replies from three separate employees at 10:59:22, 11:00:32 and 11:01:20. The `.lnk` file was opened at 11:01:39, nineteen seconds after the last reply in that thread.

<img width="1470" height="796" alt="Screenshot 2026-09-22 at 21 05 13" src="https://github.com/user-attachments/assets/ad5a562c-f32a-4995-acbe-96f0b81e2c61" />

I want to be precise about the limit of that last point. I have the thread, I have the SharePoint URL under the same sender's account, and I have a nineteen second gap between the last reply and the file opening. What I don't have is the body of that email confirming it contained this specific link. The connection is strongly supported by timing, sender and hosting location, and it is correlational rather than proven. I have written it that way.

---

## A second stage download

One further artefact sits in the timeline and is worth recording separately:

```spl
index=botsv3 host="FYODOR-L" sourcetype="stream:http" "logos.png"
| table _time uri_path status bytes
```

`/images/logos.png` requested at 11:47:16 with a 200 response and a size of **5,542,317 bytes**.

A logo image is typically tens of kilobytes. This is 5.4 megabytes. The extension does not match the payload, which is the same masquerading technique as `iexeplorer.exe` and the SOX rule name applied to a network transfer.

The timing places it after `hdoor.exe` executed at 11:43:10, so this is not the initial delivery. It is a later transfer into an already compromised host, which fits the download cradle behaviour in the decoded loader script.

<img width="1470" height="796" alt="Screenshot 2026-09-22 at 21 06 40" src="https://github.com/user-attachments/assets/607c92cc-b35c-42c9-ad68-e7c22e0a7bfc" />


---

## Timeline

All times as displayed in Splunk.

| Time | Event | Source |
|---|---|---|
| 10:55:14 | `bgist@froth.ly` sends "Draft Financial Plan for Brewery FY2019" | `stream:smtp` |
| 10:58:43 | `bgist@froth.ly` sends "Wild Birthday Extravaganza!!!" | `stream:smtp` |
| 10:59:22 to 11:01:20 | Three employees reply to the thread | `stream:smtp` |
| **11:01:39** | **`BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk` opened from Edge downloads, sourced from Frothly SharePoint** | Sysmon EID 1 |
| 11:01:41 | Obfuscated PowerShell executes, parent is `browser_broker.exe` | Sysmon EID 1 |
| 11:01:44 | Identical payload executes a second time | Sysmon EID 1 |
| 11:07:03 | `whoami.exe /groups` run twice | Sysmon EID 1 |
| 11:07:05 | `fodhelper.exe` UAC bypass, followed by registry read | Sysmon EID 1 |
| 11:08:17 | Local account `svcvnc` created | Sysmon EID 1 |
| 11:08:35 | `svcvnc` added to local administrators | Sysmon EID 1 |
| 11:09:44 | Scheduled task "Updater" created, runs daily as SYSTEM from a registry stored payload | Sysmon EID 1 |
| 11:11:00, 11:15:27 | Further hidden PowerShell executions | Sysmon EID 1 |
| 11:43:10 | `hdoor.exe` executes from `C:\Windows\Temp` | Sysmon EID 1 |
| 11:47:16 | 5.4 MB file retrieved as `/images/logos.png` | `stream:http` |
| 12:07:04 | `iexeplorer.exe` executes from a nested Temp directory | Sysmon EID 1 |
| 12:17:08, 12:17:18 | Two failed sign ins for `fyodor@froth.ly` | `ms:aad:signin` |
| 12:17:30 onward | Continuous successful session, MFA not required | `ms:aad:signin` |
| **12:21:40** | **`New-TransportRule` creates "SOX", blind copying mail to `hyunki1984@naver.com`** | `ms:o365:management` |
| 15:15:00 | Extortion email arrives from `hyunki1984@naver.com` | `stream:smtp` |
| 15:19:34 | Grace Hoppy forwards it internally | `stream:smtp` |

The ordering is the point. The endpoint was compromised at 11:01. The mail rule was created eighty minutes later. The email claiming the data was already taken arrived nearly four hours after that. The taunt was not the attack, it was the victory lap.

---

## Indicators

| Type | Value |
|---|---|
| Compromised host | `FYODOR-L` |
| Compromised identity | `fyodor@froth.ly` |
| Attacker email | `hyunki1984@naver.com` |
| C2 server | `45.77.53.176:443` |
| C2 path | `/admin/get.php` |
| C2 cookie | `PthAVgs=bKQxpuOd5LPCjyfRC1BxPqQ8FWI=` |
| RC4 key | `1AB<Yk6Z4#+vVu%o5}8&M-9UL~l\|>0gP` |
| Malicious file | `BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk` |
| Hosting URL | `frothly-my.sharepoint.com/personal/bgist_froth_ly/Documents/Birthday Pictures/` |
| Malware | `C:\Windows\Temp\hdoor.exe` |
| MD5 | `586EF56F4D8963DD546163AC31C865D7` |
| SHA256 | `99925199059EE049F7AEDA8904C2F5BDFBA86671FD7A5989BD60B72F26EF737C` |
| Masqueraded binary | `C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe` |
| Backdoor account | `svcvnc` (local administrator) |
| Scheduled task | `Updater`, daily 18:45, runs as SYSTEM |
| Registry payload store | `HKLM:\Software\Microsoft\Network debug` value `debug` |
| Malicious mail rule | `SOX`, BlindCopyTo `hyunki1984@naver.com` |
| Second stage transfer | `/images/logos.png`, 5,542,317 bytes |

---

## MITRE ATT&CK

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing Link | T1566.002 | `.lnk` hosted on internal SharePoint, opened from Edge |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell at 11:01:41 |
| Execution | Malicious File | T1204.002 | User opened the `.lnk` |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | AMSI and ScriptBlockLogging disabled |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 command line, randomised casing, string concatenation |
| Defense Evasion | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | `fodhelper.exe` with registry write |
| Defense Evasion | Masquerading | T1036 | `iexeplorer.exe`, "Updater" task, "SOX" rule, `logos.png` |
| Discovery | System Owner/User Discovery | T1033 | `whoami.exe /groups` |
| Discovery | Network Service Discovery | T1046 | `hdoor.exe` scanning capability |
| Discovery | Network Share Discovery | T1135 | `NetShareEnum` usage in `hdoor.exe` |
| Persistence | Create Account: Local Account | T1136.001 | `svcvnc` |
| Persistence | Scheduled Task | T1053.005 | "Updater" running as SYSTEM |
| Persistence | Email Forwarding Rule | T1114.003 | `New-TransportRule` with BlindCopyTo |
| Privilege Escalation | Account Manipulation | T1098 | `svcvnc` added to local administrators |
| Credential Access | Brute Force | T1110 | `hdoor.exe` dictionary attacks against IPC$ and SQL |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS to `45.77.53.176/admin/get.php` |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 | RC4 with hardcoded key |
| Command and Control | Ingress Tool Transfer | T1105 | Second stage retrieved in memory, plus `logos.png` |
| Collection | Email Collection | T1114 | Blind copy of mail to attacker address |

---

## Assessment

**Severity: high.** This is a full compromise of a workstation with two independent persistence mechanisms, an encrypted channel to attacker infrastructure, administrator level access on the host, and a covert mail exfiltration channel operating at the tenant level. The presence of a network scanning and brute force tool indicates intent to move further into the environment, and the scope of what was actually reached beyond this host has not been established here.

**Containment, in order of priority:**

1. Remove the `SOX` transport rule and audit every other transport rule in the tenant for unexpected `BlindCopyTo` or redirect parameters.
2. Revoke all active sessions and tokens for `fyodor@froth.ly`, then reset credentials. A password reset alone does not invalidate an existing session token.
3. Isolate `FYODOR-L` from the network. It should be treated as untrusted until rebuilt, not cleaned.
4. Disable and remove the `svcvnc` account and the `Updater` scheduled task, and delete the registry value at `HKLM:\Software\Microsoft\Network debug`.
5. Block `45.77.53.176` at the perimeter and search all hosts for connections to it.
6. Audit the `bgist_froth_ly` SharePoint account. The malicious file was hosted there, so that account is either compromised or was used to stage the payload.
7. Identify everyone who received the "Wild Birthday Extravaganza" thread and check each of their hosts for the same execution chain. The scanning tool suggests this was not meant to stay on one machine.

---

## Recommendations

**Enforce MFA without legacy exceptions.** The account that created the malicious rule was authenticated without multifactor at that moment, while the same account required it from a different client later the same day. That inconsistency is the gap. Conditional access should cover legacy authentication paths rather than leaving them as an implicit exemption.

**Alert on transport rule creation.** `New-TransportRule` is a low volume event in most tenants. Any rule containing `BlindCopyTo`, `RedirectMessageTo` or `ForwardTo` with an external recipient should generate an alert on creation, regardless of who created it. This single detection would have caught the exfiltration channel at 12:21:40 rather than never.

**Detect the PowerShell flag combination, not just the contents.** `-enc` together with hidden window and no profile is a combination with almost no legitimate administrative use. Alerting on that pattern does not require decoding anything and would have fired at 11:01:41, before privilege escalation and before persistence.

**Alert on local account creation and privileged group changes.** `net user /add` followed within seconds by `net localgroup administrators /add` is a high confidence, low noise detection on a standard workstation. Two commands, eighteen seconds apart, and it is a positive.

**Monitor scheduled task creation running as SYSTEM.** Particularly tasks whose action is a scripting interpreter rather than a binary, which is what separates "Updater" from a genuine updater.

**Restrict execution from user writable directories.** Application control policies preventing execution from `C:\Windows\Temp` and user profile temporary paths would have blocked `hdoor.exe` and `iexeplorer.exe` regardless of whether either was recognised as malicious.

**Treat internally hosted files as untrusted.** The delivery vector succeeded partly because the file came from the company's own SharePoint under a colleague's account, which defeats the usual instinct to be cautious about external links. Awareness training that only covers external senders does not address this. `.lnk` files in particular have almost no legitimate reason to be shared between colleagues and can reasonably be blocked at the platform level.

---

## Notes on method and limitations

**The scoping error is the most useful thing I learned here.** My first search of the endpoint covered ten minutes around the mail rule and came back clean, and I initially concluded the endpoint was not involved. The conclusion was wrong because the window was wrong. The compromise had happened eighty minutes earlier. A negative result from a bounded search only answers the bounded question, and the correct response was to widen the aperture rather than accept the finding. I have kept that mistake in the write up because the correction is the lesson.

**Sourcetype names in this dataset do not match current add on expectations.** BOTSv3 ships pre indexed with 2018 era sourcetypes. Sysmon data is tagged as the generic `xmlwineventlog` rather than a name containing "sysmon", which means the Microsoft Sysmon Add on's extraction rules never fire against it even when the add on is installed. The raw XML contains every field, but none of it is searchable as extracted fields. I used inline `rex` against `_raw` throughout instead of rewriting `props.conf`, which is less efficient at scale but the right trade for a single investigation. Beginning every new thread with `| stats count by sourcetype` against the host, rather than trusting a sourcetype name from a walkthrough, saved considerable time once I started doing it.

**Field presence in the sidebar is not the same as field existence.** At one point a table returned empty columns for `sender_email` and `subject`, and Splunk's field sidebar did not list either. Both fields existed with real values in the raw events. The sidebar surfaces a subset it considers interesting rather than everything present, and the empty table was caused by many SMTP events being connection level records with no message content rather than by the fields being absent.

**What I could not establish.** I did not confirm the body of the "Wild Birthday Extravaganza" email, so the link between that thread and the `.lnk` file rests on sender, hosting location and a nineteen second timing gap rather than direct proof. I did not verify whether the C2 callback to `45.77.53.176` succeeded or was blocked, which would sharpen the impact assessment. I did not check whether endpoint protection generated any detection across the intrusion on this host. I also did not establish how the attacker obtained access to the `bgist_froth_ly` SharePoint account in the first place, which is the question one step further back than where this investigation ends.

---

## Reproducing this

Splunk Enterprise, the BOTSv3 dataset from [github.com/splunk/botsv3](https://github.com/splunk/botsv3), and the Windows, Sysmon, Stream and CIM add ons. Every query above is copy pasteable. Set the time picker to **All time** before running anything, since the data is from August 2018 and the default range returns nothing.
