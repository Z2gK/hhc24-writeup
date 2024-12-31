# Act 3 - Elf Stack

The Elf Stack challenge has an easy (Silver) and a hard (Gold) mode. Both modes require the player to answer a series of questions based on information in the provided log files which capture a malware incident at North Pole.

The logs are provided in two files: `log_chunk_1.log.zip` and `log_chunk_2.log.zip`. Configuration files to set up an ELK (Elasticsearch, Logstash, Kibana) environment are also provided in `elf-stack-siem-with-logs.zip`, though the player is free to choose any other analysis tool to complete the challenge.

The number of events in each log file can be determined using the  Linux `wc` tool. There are 1,162,269 and 1,180,877 lines in `log_chunk_1.log` and `log_chunk_2.log` respectively, giving a total of 2,343,146 events.

Here, both the ELK query languages Kibana Query Language (KQL) and Elasticsearch Query Language (ES|QL) have been used to facilitate log analysis.

## Easy Mode

There are 15 questions for easy mode.

Q1: How many unique values are there for the event_source field in all logs?  
Answer: 5

The `event_source` field records the log source. This ES|QL query counts the number of distinct values for the field and returns 5 as the answer:  
`FROM .ds-logs-* | STATS COUNT_DISTINCT(event_source)`

Q2: Which event_source has the fewest number of events related to it?  
Answer: `AuthLog`

The ES|QL query here counts the number of logs from each `event_source`. The `AuthLog` source has 269 events, the least amongst the 4 source.  
`FROM .ds-logs-* | STATS COUNT(*) by event_source`

Q3: Using the event_source from the previous question as a filter, what is the field name that contains the name of the system the log event originated from?  
Answer: `hostname`

For this question, one can examine a log sample from the source `AuthLog` by filtering out events from this source using this  query:  
`FROM .ds-logs-* | WHERE event_source == "AuthLog"`

This is a sample event from the source:
`{ "@timestamp": "2024-09-16T15:48:01.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.OpcodeDisplayNameText": "Unknown", "event.hostname": "kringleSSleigH", "event.message": "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "event.service": "CRON[6715]:", "event.timestamp": "2024-09-16T18:48:01.232Z", "event_source": "AuthLog", "host.ip": "172.18.0.5", "hostname": "kringleSSleigH", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }`

In the sample here, the field name `hostname` contains the name of the system (`kringleSSleigH`) the event originated from.

Q4: Which event_source has the second highest number of events related to it?  
Answer: NetflowPmacct

Results from the query in Easy Q2 can be used for this question. The source `NetflowPmacct` comes in second with 34,679 events.


Q5: Using the event_source from the previous question as a filter, what is the name of the field that defines the destination port of the Netflow logs?  
Answer: `event.port_dst`

Similar to Q3, one can examine a log sample from the source `NetflowPmacct` using this query:  
`FROM .ds-logs-* | WHERE event_source == "NetflowPmacct"`


This is a sample event from the source:  
```
{ "@timestamp": "2024-09-15T14:37:46.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccessCheckResults": null, "event.AccessCheckResults_READ_CONTROL": null, 
...
"event.Workstation": null, "event.WorkstationName": null, "event.additional_info": null, "event.bytes": 626, "event.dst_host": "", "event.event_type": "purge", "event.host": null, "event.hostname": null, "event.http_protocol": null, "event.ip": null, "event.ip_dst": "172.24.25.25", "event.ip_proto": "tcp", "event.ip_src": "35.190.59.101", "event.message": null, "event.method": null, "event.packets": 1, "event.param1": null, "event.param10": null, "event.param11": null, "event.param2": null, "event.param3": null, "event.param4": null, "event.param5": null, "event.param6": null, "event.param7": null, "event.param8": null, "event.param9": null, "event.port_dst": 51894, "event.port_src": 443, "event.protocol": null, "event.response_size": null, "event.service": null, "event.serviceGuid": null, "event.src_host": "", "event.status_code": null, "event.timestamp": null, "event.timestamp_end": "0000-00-00T00:00:00-00:00", "event.timestamp_start": "2024-09-15T10:37:46-04:00", "event.updateGuid": null, "event.updateRevisionNumber": null, "event.updateTitle": null, "event.url": null, "event.user_identifier": null, "event_source": "NetflowPmacct", "host.ip": "172.18.0.5", "hostname": "kringleconnect", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

The field name `event.port_dst` for the destination port can be found from inspection.

Q6: Which event_source is related to email traffic?  
Answer: `SnowGlowMailPxy`

Similar to the approach in the previous question, the fields for each source can be examined using log samples. Events from `SnowGlowMailPxy` appear to contain email body, sender and recipient addresses etc and is related to email traffic.

Q7: Looking at the event source from the last question, what is the name of the field that contains the actual email text?  
Answer: `event.Body`

The player can examine a log sample from the source `SnowGlowMailPxy` using this query:  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy"`

This log sample shows the email text contained in the `event.Body` field:
```
{ "@timestamp": "2024-09-16T15:49:13.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccessCheckResults": null, 
...
"event.BindType": null, "event.Body": "Dear elf_user06,\n\nI regret to inform you that we are currently experiencing unforeseen disruptions within our supply chain, impacting our production timelines significantly. This unexpected setback may cause delays in the delivery of our products to our customers.\n\nWe are actively working on resolving these issues and are in close communication with our elves to mitigate any further disruptions. Please rest assured that our team is focused on finding alternative solutions and minimizing the impact on our business operations.\n\nI will keep you updated with any developments and appreciate your understanding during this challenging time.\n\nBest regards,\n\nelf_user10\n", "event.CallerProcessId": null, "event.CallerProcessName": null, "event.CalloutId": 
...
"event.user_identifier": null, "event_source": "SnowGlowMailPxy", "host.ip": "172.18.0.5", "hostname": "SecureElfGwy", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q8: Using the 'GreenCoat' event_source, what is the only value in the hostname field?  
Answer: `SecureElfGwy`

This query here lists all hostnames in the `GreenCoat` log. The only value in the hostname field is `SecureElfGwy`.  
`FROM .ds-logs-* | WHERE event_source == "GreenCoat" | STATS COUNT(*) by hostname`

Q9: Using the 'GreenCoat' event_source, what is the name of the field that contains the site visited by a client in the network?  
Answer: `event.url`

The player can examine a log sample from the source `GreenCoat` using this query:  
`FROM .ds-logs-* | WHERE event_source == "GreenCoat"`

The name of the site visited (`www.tumblr.com` in this case) can be found in the `event.url` field:
```
{ "@timestamp": "2024-09-16T15:35:13.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.OpcodeDisplayNameText": "Unknown", "event.additional_info": "outgoing via 172.24.25.25", "event.host": "SnowSentry", "event.http_protocol": "HTTP/1.1", "event.ip": "172.24.25.93", "event.method": "CONNECT", "event.protocol": "HTTPS", "event.response_size": 0, "event.status_code": 200, "event.timestamp": "2024-09-16T15:35:13.000Z", "event.url": "www.tumblr.com:443", "event.user_identifier": "elf_user03", "event_source": "GreenCoat", "host.ip": "172.18.0.5", "hostname": "SecureElfGwy", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" } 
```

Q10: Using the 'GreenCoat' event_source, which unique URL and port (URL:port) did clients in the TinselStream network visit most?  
Answer: `pagead2.googlesyndication.com:443`

The event count for each URL and port can be found using this query:  
`FROM .ds-logs-* | WHERE event_source == "GreenCoat" | STATS COUNT(event.url) BY event.url`

The query result can then be sorted by event count to reveal the URL:port that is visited most.

Q11: Using the 'WindowsEvent' event_source, how many unique Channels is the SIEM receiving Windows event logs from?  
Answer: 5

The number of unique channels can be found by counting the number of distinct values for the `event.Channel` field using this query:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" | STATS COUNT_DISTINCT(event.Channel)`

Q12: What is the name of the event.Channel (or Channel) with the second highest number of events?  
Answer: `Microsoft-Windows-Sysmon/Operational`

The event count for each channel can be found using the query here. `Microsoft-Windows-Sysmon/Operational` comes up second highest with 17,713 events.  
```FROM .ds-logs-* | WHERE event_source == "WindowsEvent" | STATS count(*) BY `event.Channel` | SORT `count(*)` DESC```

Q13: Our environment is using Sysmon to track many different events on Windows systems. What is the Sysmon Event ID related to loading of a driver?  
Answer: 6

The Sysmon Event ID for the loading of a driver can be found by googling.

Q14: What is the Windows event ID that is recorded when a new service is installed on a system?  
Answer: 4697

The Windows event ID for the installation of a new service can be found by googling.

Q15: Using the WindowsEvent event_source as your initial filter, how many user accounts were created?  
Answer: 0

The Windows event ID for user account creation is 4720. This query counts for such events and returns 0 when executed:
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND event.EventID == 4720 | STATS count(*)`


## Hard Mode

There are 24 questions for hard mode.

Q1: What is the event.EventID number for Sysmon event logs relating to process creation?  
Answer: 1

The event ID for process creation can be found by googling.

Q2: How many unique values are there for the 'event_source' field in all of the logs?  
Answer: 5

This value can be found from Easy mode Q1 of this challenge.

Q3: What is the event_source name that contains the email logs?  
Answer: `SnowGlowMailPxy`

The answer can be found from Easy mode Q6 of this challenge.

Q4: The North Pole network was compromised recently through a sophisticated phishing attack sent to one of our elves. The attacker found a way to bypass the middleware that prevented phishing emails from getting to North Pole elves. As a result, one of the Received IPs will likely be different from what most email logs contain. Find the email log in question and submit the value in the event 'From:' field for this email log event.  
Answer: `kriskring1e@northpole.local`

There are two fields that record the received IPs in the email logs: `event.ReceivedIP1` and `event.ReceivedIP2`. The one different Received IP can be identified by listing the unique IPs and their counts using this query:  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" | STATS count(*) BY event.ReceivedIP2`

The result show that all except one event have the IP `172.24.25.20`. The odd event has the IP `34.30.110.62`. A second query can be run to examine this particular event:  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" AND event.ReceivedIP2 == "34.30.110.62"`

This is the event with the different Received IP. The value in the "From" field is `kriskring1e@northpole.local`.  
```
{ "@timestamp": "2024-09-15T14:36:09.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.Body": "We need to store the updated naughty and nice list somewhere secure. I posted it here http://hollyhaven.snowflake/howtosavexmas.zip. Act quickly so I can remove the link from the internet! I encrypted it with the password: n&nli$t_finAl1\n\nthx!\nkris\n- Sent from the sleigh. Please excuse any Ho Ho Ho's.", "event.From": "kriskring1e@northpole.local", "event.Message-ID": "<F3483D7F-3DBF-4A92-813D-4D9738479E50@SecureElfGwy.northpole.local>", "event.OpcodeDisplayNameText": "Unknown", "event.ReceivedIP1": "172.24.25.25", "event.ReceivedIP2": "34.30.110.62", "event.Received_Time": "2024-09-15T10:36:09-04:00", "event.Return-Path": "fr0sen@hollyhaven.snowflake", "event.Subject": "URGENT!", "event.To": "elf_user02@northpole.local", "event_source": "SnowGlowMailPxy", "host.ip": "172.18.0.5", "hostname": "SecureElfGwy", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q5: Our ElfSOC analysts need your help identifying the hostname of the domain computer that established a connection to the attacker after receiving the phishing email from the previous question. You can take a look at our GreenCoat proxy logs as an event source. Since it is a domain computer, we only need the hostname, not the fully qualified domain name (FQDN) of the system.  
A: SleighRider

The user probably clicked on the link in the email and established a connection to the attacker. Hence the event can be filtered out using the URL in the email:  
`FROM .ds-logs-* | WHERE event_source == "GreenCoat" AND `event.url`=="http://hollyhaven.snowflake/howtosavexmas.zip"`

```
{ "@timestamp": "2024-09-15T14:36:26.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.OpcodeDisplayNameText": "Unknown", "event.additional_info": "outgoing via 172.24.25.25", "event.host": "SleighRider", "event.http_protocol": "HTTP/1.1", "event.ip": "172.24.25.12", "event.method": "GET", "event.protocol": "HTTP", "event.response_size": 1098, "event.status_code": 200, "event.timestamp": "2024-09-15T14:36:26.000Z", "event.url": "http://hollyhaven.snowflake/howtosavexmas.zip", "event.user_identifier": "elf_user02", "event_source": "GreenCoat", "host.ip": "172.18.0.5", "hostname": "SecureElfGwy", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

The hostname of the domain computer is `SleighRider`.

Q6: What was the IP address of the system you found in the previous question?  
Answer: 172.24.25.12

The IP address for `SleighRider` can be found in the event filtered out in Q5.

Q7: A process was launched when the user executed the program AFTER they downloaded it. What was that Process ID number (digits only please)?  
Answer: 10014

The event filtered out in Hard mode Q5 shows the downloading of the malicious file at `2024-09-15T14:36:26Z`. The user may have run the downloaded executable shortly after and it is reasonable to search the logs for process creation events (Event ID 1) within 2 minutes of downloading using this query.  
` FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND event.Hostname == "SleighRider.northpole.local" AND @timestamp >= "2024-09-15T14:36:26.000Z" AND @timestamp <= "2024-09-15T14:38:26.000Z" AND event.EventID == 1`

6 events are filtered out and it can be seen that one of them runs the executable `C:\Users\elf_user02\Downloads\howtosavexmas\howtosavexmas.pdf.exe` whose name is very similar to the zip file downloaded. This event, copied below, has process ID 10014:

```
{ "@timestamp": "2024-09-15T14:37:50.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccountName": "SYSTEM", "event.AccountType": "User", "event.Category": "Process Create (rule: ProcessCreate)", "event.Channel": "Microsoft-Windows-Sysmon/Operational", "event.CommandLine": "\"C:\\Users\\elf_user02\\Downloads\\howtosavexmas\\howtosavexmas.pdf.exe\" ", "event.Company": "-", "event.CurrentDirectory": "C:\\Users\\elf_user02\\Downloads\\howtosavexmas\\", "event.Description": "-", "event.Domain": "NT AUTHORITY", "event.EventID": 1, "event.EventTime": "2024-09-15T14:37:50.000Z", "event.EventType": "INFO", "event.FileVersion": "-", "event.Hashes": "MD5=790F0E0E9DBF7E9771FF9F0F7DE9804C,SHA256=7965DB6687032CB6A3D875DF6A013FA61B9804F98618CE83688FBA546D5EC892,IMPHASH=B4C6FFF030479AA3B12625BE67BF4914", "event.Hostname": "SleighRider.northpole.local", "event.Image": "C:\\Users\\elf_user02\\Downloads\\howtosavexmas\\howtosavexmas.pdf.exe", "event.IntegrityLevel": "High", "event.Keywords": "-9223372036854775808", "event.LogonGuid": "{face0b26-426d-660c-650f-7d0500000000}", "event.LogonId": "0x57d0f65", "event.MoreDetails": "Process Create:", "event.OpcodeDisplayNameText": "Info", "event.OpcodeValue": 0, "event.OriginalFileName": "-", "event.ParentCommandLine": "C:\\Windows\\Explorer.EXE", "event.ParentImage": "C:\\Windows\\explorer.exe", "event.ParentProcessGuid": "{face0b26-e149-6606-9300-000000000700}", "event.ParentProcessId": 5680, "event.ParentUser": "NORTHPOLE\\elf_user02", "event.ProcessGuid": "{face0b26-426e-660c-eb0f-000000000700}", "event.ProcessID": 10014, "event.ProcessId": 8096, "event.Product": "-", "event.ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", "event.RecordNumber": 723, "event.RuleName": "-", "event.Severity": "INFO", "event.SeverityValue": 2, "event.SourceModuleName": "inSysmon", "event.SourceModuleType": "im_msvistalog", "event.SourceName": "Microsoft-Windows-Sysmon", "event.Task": 1, "event.TerminalSessionId": 1, "event.ThreadID": 6340, "event.User": "NORTHPOLE\\elf_user02", "event.UserID": "S-1-5-18", "event.Version": 5, "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "SleighRider.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q8: Did the attacker's payload make an outbound network connection? Our ElfSOC analysts need your help identifying the destination TCP port of this connection.  
Answer: 8443

Since the outbound network connection was made by the executable `howtosavexmas.pdf.exe`, querying for a similar string in the the application name fields should filter out this event:
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND event.Hostname == "SleighRider.northpole.local" AND (event.Application LIKE "*howtosavexmas*" OR event.ApplicationInformation_ApplicationName LIKE "*howtosavexmas")`

Only one event is filtered out and the destination port (8443) is recorded in the `event.NetworkInformation_DestinationPort` field:  
```
{ "@timestamp": "2024-09-15T14:37:50.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.Application": "\\device\\harddiskvolume3\\users\\elf_user02\\downloads\\howtosavexmas\\howtosavexmas.pdf.exe", "event.ApplicationInformation_ApplicationName": "\\device\\harddiskvolume3\\users\\elf_user02\\downloads\\howtosavexmas\\howtosavexmas.pdf.exe", "event.ApplicationInformation_ProcessID": 8096, "event.Category": "Filtering Platform Connection", "event.Channel": "Security", "event.DestAddress": "103.12.187.43", "event.DestPort": 8080, "event.Direction": "%%14593", "event.EventID": 5156, "event.EventTime": "2024-09-15T14:37:50.000Z", "event.EventType": "AUDIT_SUCCESS", "event.FilterInformation_FilterRunTimeID": 0, "event.FilterInformation_LayerName": "Connect", "event.FilterInformation_LayerRunTimeID": 48, "event.FilterRTID": 0, "event.Hostname": "SleighRider.northpole.local", "event.Keywords": "-9214364837600034816", "event.LayerName": "%%14611", "event.LayerRTID": 48, "event.MoreDetails": "The Windows Filtering Platform has permitted a connection.", "event.NetworkInformation_DestinationAddress": "103.12.187.43", "event.NetworkInformation_DestinationPort": 8443, "event.NetworkInformation_Direction": "Outbound", "event.NetworkInformation_Protocol": 6, "event.NetworkInformation_SourceAddress": "172.24.25.12", "event.NetworkInformation_SourcePort": 64543, "event.OpcodeDisplayNameText": "Info", "event.OpcodeValue": 0, "event.ProcessID": 4, "event.Protocol": 6, "event.ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}", "event.RecordNumber": 734596,
...
"event.Version": 1, "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "SleighRider.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

The timestamp of this event is `2024-09-15T14:37:50.000Z` which is consistent with the timestamp of the process creation event in Hard mode Q7.

Q9: The attacker escalated their privileges to the SYSTEM account by creating an inter-process communication (IPC) channel. Submit the alpha-numeric name for the IPC channel used by the attacker.  
Answer: ddpvccdbr

For this question, KQL is used as it allows the user to search across multiple fields. Since "pipes" channels for IPC, querying for this string could be helpful:  
`event_source: "WindowsEvent" AND event.Hostname: "SleighRider.northpole.local"  AND *pipe*`

Indeed 4 events are filtered out, all occurring at `2024-09-15T14:38:22.000Z`. One of them is copied here, logging the creation of `\pipe\ddpvccdbr`:  
```
{ "@timestamp": [ "2024-09-15T14:38:22.000Z" ], "@version": [ "1" ], "data_stream.dataset": [ "generic" ], "data_stream.namespace": [ "default" ], "data_stream.type": [ "logs" ], "event_source": [ "WindowsEvent" ], "event.AccountName": [ "elf_user02" ], "event.AccountType": [ "User" ], "event.Channel": [ "System" ], "event.Domain": [ "NORTHPOLE" ], "event.EventID": [ 7045 ], "event.EventTime": [ "2024-09-15T14:38:22.000Z" ], "event.EventType": [ "INFO" ], "event.Hostname": [ "SleighRider.northpole.local" ], "event.ImagePath": [ "cmd.exe /c echo ddpvccdbr &gt; \\\\.\\pipe\\ddpvccdbr" ], "event.Keywords": [ "-9187343239835811840" ], "event.MoreDetails": [ "A service was installed in the system." ], "event.OpcodeDisplayNameText": [ "Info" ], "event.ProcessID": [ 628 ], "event.ProviderGuid": [ "{555908D1-A6D7-4695-8E1E-26931D2012F4}" ], "event.RecordNumber": [ 1571 ], "event.ServiceAccount": [ "LocalSystem" ], "event.ServiceFileName": [ "cmd.exe /c echo ddpvccdbr > \\\\.\\pipe\\ddpvccdbr" ], "event.ServiceName": [ "ddpvccdbr" ], "event.ServiceStartType": [ "demand start" ], "event.ServiceType": [ "user mode service" ], "event.Severity": [ "INFO" ], 
...
```

Q10: The attacker's process attempted to access a file. Submit the full and complete file path accessed by the attacker's process.  
Answer: `C:\Users\elf_user02\Desktop\kkringl315@10.12.25.24.pem`

The event ID for file creation is 4663 and this can be used as a filter. Furthermore, this has to take place after the running of the malicious executable, and hence the timestamp filter here.  
```
FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND event.Hostname == "SleighRider.northpole.local" AND @timestamp >= "2024-09-15T14:37:50Z" AND event.EventID == 4663 AND `event.ProcessName` LIKE "*howtosavexmas*"
```

2 events are filtered out and one of them shows the unusual access of a `.pem` file:
```
{ "@timestamp": "2024-09-16T14:45:48.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccessCheckResults": null, "event.AccessCheckResults_READ_CONTROL": null, "event.AccessCheckResults_ReadAttributes": null,
...
"event.ObjectClass": null, "event.ObjectDN": null, "event.ObjectGUID": null, "event.ObjectName": "C:\\Users\\elf_user02\\Desktop\\kkringl315@10.12.25.24.pem", "event.ObjectServer": "Security", "event.ObjectType": "File",
...
"event.ProcessGuid": "{face0b26-426e-660c-eb0f-000000000700}", "event.ProcessID": 10014,
...
"event.ProcessName": "C:\\Users\\elf_user02\\Downloads\\howtosavexmas\\howtosavexmas.pdf.exe"
...
"WindowsEvent", "host.ip": "172.18.0.5", "hostname": "SleighRider.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q11: The attacker attempted to use a secure protocol to connect to a remote system. What is the hostname of the target server?  
Answer: KringleSSleigH

The `.pem` file from the previous question accessed by the attacker is likely the private key for the SSH service on a server with IP address `10.12.25.24`. The search can start in sources other than `WindowsEvent` since the target server is likely to run Linux. A KQL query for this IP address across fields may be helpful:  
`NOT event_source: "WindowsEvent" AND *10.12.25.24*`

This query results in 17 events - 14 are from `AuthLog` and the remainder from `NetFlowPmacct`. A number of `AuthLog` events record SSH connection to the host `kringleSSleigH`, as shown in a sample here:
```
{ "@timestamp": [ "2024-09-15T10:55:37.000Z" ], "@version": [ "1" ], "data_stream.dataset": [ "generic" ], "data_stream.namespace": [ "default" ], "data_stream.type": [ "logs" ], "event_source": [ "AuthLog" ], "event.hostname": [ "kringleSSleigH" ], "event.message": [ "Connection from 34.30.110.62 port 39728 on 10.12.25.24 port 22 rdomain \"\"" ], "event.OpcodeDisplayNameText": [ "Unknown" ], "event.service": [ "sshd[6013]:" ], "event.timestamp": [ "2024-09-15T13:55:37.345Z" ], "host.ip": [ "172.18.0.5" ], "hostname": [ "kringleSSleigH" ], "log.syslog.facility.code": [ 1 ], "log.syslog.facility.name": [ "user-level" ], "log.syslog.facility.name.text": [ "user-level" ], "log.syslog.severity.code": [ 5 ], "log.syslog.severity.name": [ "notice" ], "log.syslog.severity.name.text": [ "notice" ], "tags": [ "match" ], "type": [ "syslog" ], "_id": "778ce349bbac7b003ed1a5f55efb670abe537766", "_index": ".ds-logs-generic-default-2024.12.16-000001", "_score": null }
```

Q12: The attacker created an account to establish their persistence on the Linux host. What is the name of the new account created by the attacker?  
Answer: ssdh

Record of account creation should be found in the authentication log. The query here can help by listing the description of all events in a single column.  
`FROM .ds-logs-* | WHERE event_source == "AuthLog" AND event.hostname == "kringleSSleigH" | STATS count(*) BY event.message`

92 unique event descriptions (found in `event.message` field) are listed. Looking through the list, it is noted that there are several failed logins with different usernames, which is evidence of a brute force attack on the host. Then there are some events relating to user and group creation and password change for a user `ssdh`. This is the new account created by the attacker. The event copied below records the creation of this account. This can be found using the query here:  
`FROM .ds-logs-* | WHERE event_source == "AuthLog" AND event.hostname == "kringleSSleigH" AND event.message LIKE "*ssdh*"`

```
{ "@timestamp": "2024-09-16T14:59:46.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.OpcodeDisplayNameText": "Unknown", "event.hostname": "kringleSSleigH", "event.message": "new user: name=ssdh, UID=1002, GID=1002, home=/home/ssdh, shell=/bin/bash, from=/dev/pts/6", "event.service": "useradd[6207]:", "event.timestamp": "2024-09-16T17:59:46.121Z", "event_source": "AuthLog", "host.ip": "172.18.0.5", "hostname": "kringleSSleigH", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q13: The attacker wanted to maintain persistence on the Linux host they gained access to and executed multiple binaries to achieve their goal. What was the full CLI syntax of the binary the attacker executed after they created the new user account?  
Answer: `/usr/sbin/usermod -a -G sudo ssdh`

Authentication events on this host should capture some commands run by the attacker. By filtering out and examining the events AFTER the creation of the new account (at `2024-09-16T14:59:46.000Z`), the actual command can be identified. This query filters out 185 events and the single event of interest reads ` kkringl315 : TTY=pts/5 ; PWD=/opt ; USER=root ; COMMAND=/usr/sbin/usermod -a -G sudo ssdh` in the `event.message` field.  
`FROM .ds-logs-* | WHERE event_source == "AuthLog" AND hostname == "kringleSSleigH" AND @timestamp >= "2024-09-16T14:59:46.000Z" | KEEP @timestamp, event.message`

Q14: The attacker enumerated Active Directory using a well known tool to map our Active Directory domain over LDAP. Submit the full ISO8601 compliant timestamp when the first request of the data collection attack sequence was initially recorded against the domain controller.  
Answer: 2024-09-16T11:10:12-04:00

The domain controller's FQDN is `"dc01.northpole.local` and the LDAP unecrypted port is 389. Using this filter and sorting the events by timestamp, the earliest such event can be identified.  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND hostname == "dc01.northpole.local" AND event.ServicePort == 389 | SORT @timestamp ASC`

```
{ "@timestamp": "2024-09-16T15:10:12.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccessCheckResults": null,
...
"event.ClientAddress": null, "event.ClientCreationTime": null, "event.ClientIPaddress": "172.24.25.22:24273", "event.ClientName": null,
...
"event.DCName": null, "event.DSName": null, "event.DSType": null, "event.Date": "2024-09-16T11:10:12-04:00", "event.DeletedRule_RuleID": null, "event.DeletedRule_RuleName": null, "event.Description": "The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without requesting signing (integrity verification), or performed a simple bind over a clear text (non-SSL/TLS-encrypted) LDAP connection.",
...
"event.ServiceIpAddress": "172.24.25.153", "event.ServiceName": "dc01.northpole.local", "event.ServiceName_ServiceID": null, "event.ServicePort": 389, "event.ServicePrincipalNames": null,
...
```

This event occured at `2024-09-16T11:10:12-04:00`.

Q15: The attacker attempted to perform an ADCS ESC1 attack, but certificate services denied their certificate request. Submit the name of the software responsible for preventing this initial attack.  
Answer: KringleGuard

Using the `WindowsEvent` source and the domain controller's hostname as the starting point, the types of events can be listed using this query:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND hostname == "dc01.northpole.local" | STATS count(*) BY event.Category`

50 different values (including nulls) for the `event.Category` field are listed and the results show only one event with description "Certification Services - Certificate Request Denied". This event can then be filtered out using this query:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND hostname == "dc01.northpole.local" AND event.Category == "Certification Services - Certificate Request Denied"`

```
{ "@timestamp": "2024-09-16T15:14:12.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AdditionalInformation_CallerComputer": null, "event.AdditionalInformation_RequestedUPN": "administrator@northpole.local", "event.AdditionalInformation_RequesterComputer": "10.12.25.24", "event.CallerComputer": null, "event.Category": "Certification Services - Certificate Request Denied", "event.CertificateInformation_CertificateAuthority": "elf-dc01-SeaA", "event.CertificateInformation_CertificateTemplate": null, "event.CertificateInformation_RequestedTemplate": "Administrator", "event.CertificateTemplateInformation_CertificateTemplateName": null, "event.Computer": "dc01.northpole.local", "event.Date": "2024-09-16T11:14:12-04:00", "event.Description": "A certificate request was made for a certificate template, but the request was denied because it did not meet the criteria.", "event.Details_ModificationType": null, "event.Details_NewSecuritySettings": null, "event.EventID": 4888, "event.Keywords": "Audit Failure", "event.LevelText": "Information", "event.LogName": "Security", "event.ModifierInformation_Computer": null, "event.ModifierInformation_UserName": null, "event.OpcodeDisplayNameText": "Unknown", "event.ReasonForRejection": "KringleGuard EDR flagged the certificate request.", "event.Source": "Microsoft-Windows-Security-Auditing", "event.User": "N/A", "event.UserInformation_UPN": null, "event.UserInformation_UserName": "elf_user@northpole.local", "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "dc01.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

A more detailed description can be found in the `event.ReasonForRejection` field, i.e. "KringleGuard EDR flagged the certificate request". Hence the name of the EDR software is KringleGuard.

Q16: We think the attacker successfully performed an ADCS ESC1 attack. Can you find the name of the user they successfully requested a certificate on behalf of?  
Answer: nutcrakr

Using the same query from the previous question, the certificate issuance event can be filtered out by going through the descriptions in the `event.Category` field. There is one description which reads "Certification Services - Certificate Issuance" with only one event tagged. This event can be similary filtered out using this query:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND hostname == "dc01.northpole.local" AND event.Category == "Certification Services - Certificate Issuance"`

The name of the user can be found in the `event.UserInformation_UPN`, i.e. `nutcrakr@northpole.local`.  
```
{ "@timestamp": "2024-09-16T15:15:12.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AdditionalInformation_CallerComputer": "172.24.25.153", "event.AdditionalInformation_RequestedUPN": null, "event.AdditionalInformation_RequesterComputer": "10.12.25.24", "event.CallerComputer": null, "event.Category": "Certification Services - Certificate Issuance", "event.CertificateInformation_CertificateAuthority": "elf-dc01-SeaA", "event.CertificateInformation_CertificateTemplate": "ElfUsers", "event.CertificateInformation_RequestedTemplate": null, "event.CertificateTemplateInformation_CertificateTemplateName": null, "event.Computer": "dc01.northpole.local", "event.Date": "2024-09-16T11:15:12-04:00", "event.Description": "A certificate was issued to a user.", "event.Details_ModificationType": null, "event.Details_NewSecuritySettings": null, "event.EventID": 4886, "event.Keywords": "Audit Success", "event.LevelText": "Information", "event.LogName": "Security", "event.ModifierInformation_Computer": null, "event.ModifierInformation_UserName": null, "event.OpcodeDisplayNameText": "Unknown", "event.ReasonForRejection": null, "event.Source": "Microsoft-Windows-Security-Auditing", "event.User": "N/A", "event.UserInformation_UPN": "nutcrakr@northpole.local", "event.UserInformation_UserName": "elf_user@northpole.local", "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "dc01.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q17: One of our file shares was accessed by the attacker using the elevated user account (from the ADCS attack). Submit the folder name of the share they accessed.  
Answer: WishLists

The Windows event ID for network file share access is 5140. Starting with the `WindowsEvent` logs and filtering by the username `nutcrakr`, 7 events are found using this KQL query:  
`event_source: "WindowsEvent" AND "nutcrakr" AND event.EventID: "5140"`

The last event records the name of the file share `WishLists` in fields such as `event.ShareName`, `event.ShareInformation_SharePath` and `event.ShareInformation_ShareName`.  
```
{ "@timestamp": [ "2024-09-16T15:18:43.000Z" ], "@version": [ "1" ], "data_stream.dataset": [ "generic" ], "data_stream.namespace": [ "default" ], "data_stream.type": [ "logs" ], "event_source": [ "WindowsEvent" ], "event.AccessList": [ "%%4416\r\n\t\t\t\t" ], "event.AccessMask": [ "0x1" ], "event.AccessRequestInformation": [ "," ], "event.AccessRequestInformation_Accesses": [ "ReadData (or ListDirectory)" ], "event.AccessRequestInformation_AccessMask": [ "0x1" ], "event.Category": [ "File Share" ], "event.Channel": [ "Security" ], "event.EventID": [ 5140 ], "event.EventTime": [ "2024-09-16T15:18:43.000Z" ], "event.EventType": [ "AUDIT_SUCCESS" ], "event.Hostname": [ "dc01.northpole.local" ], "event.IpAddress": [ "34.30.110.62" ], "event.IpPort": [ "53378" ], "event.Keywords": [ "-9214364837600034816" ], "event.MoreDetails": [ "A network share object was accessed." ], "event.NetworkInformation": [ "," ], "event.NetworkInformation_ObjectType": [ "File" ], "event.NetworkInformation_SourceAddress": [ "34.30.110.62" ], "event.NetworkInformation_SourcePort": [ 53378 ], "event.ObjectType": [ "File" ], "event.OpcodeDisplayNameText": [ "Info" ], "event.OpcodeValue": [ 0 ], "event.ProcessID": [ 4 ], "event.ProviderGuid": [ "{54849625-5478-4994-A5BA-3E3B0328C30D}" ], "event.RecordNumber": [ 498420 ], "event.Severity": [ "INFO" ], "event.SeverityValue": [ 2 ], "event.ShareInformation_ShareName": [ "\\\\*\\WishLists" ], "event.ShareInformation_SharePath": [ "\\??\\C:\\WishLists" ], "event.ShareLocalPath": [ "\\??\\C:\\WishLists" ], "event.ShareName": [ "\\\\*\\WishLists" ], "event.SourceModuleName": [ "inSecurityEvent" ], "event.SourceModuleType": [ "im_msvistalog" ], "event.SourceName": [ "Microsoft-Windows-Security-Auditing" ], "event.Subject_AccountDomain": [ "NORTHPOLE" ], "event.Subject_AccountName": [ "nutcrakr" ], "event.Subject_LogonID": [ "0xD8FDB3" ], "event.Subject_SecurityID": [ "S-1-5-21-3699322559-1991583901-1175093138-1112" ], "event.SubjectDomainName": [ "NORTHPOLE" ], "event.SubjectLogonId": [ "0xd8fdb3" ], "event.SubjectUserName": [ "nutcrakr" ], "event.SubjectUserSid": [ "S-1-5-21-3699322559-1991583901-1175093138-1112" ], "event.Task": [ 12808 ], "event.ThreadID": [ 5692 ], "event.Version": [ 1 ], "host.ip": [ "172.18.0.5" ], "hostname": [ "dc01.northpole.local" ], "log.syslog.facility.code": [ 1 ], "log.syslog.facility.name": [ "user-level" ], "log.syslog.facility.name.text": [ "user-level" ], "log.syslog.severity.code": [ 5 ], "log.syslog.severity.name": [ "notice" ], "log.syslog.severity.name.text": [ "notice" ], "tags": [ "match" ], "type": [ "syslog" ], "_id": "82b195229ccd0033eb11df25e6af34a5530a0ecf", "_index": ".ds-logs-generic-default-2024.12.16-000001", "_score": null }
```

Q18: The naughty attacker continued to use their privileged account to execute a PowerShell script to gain domain administrative privileges. What is the password for the account the attacker used in their attack payload?  
Answer: fR0s3nF1@k3_s

For this question, the Linux command line tool `grep` seems more effective in exploring the filtered events. The two log files first need to be combined into one (in this case, it is `log_chunk_all.log`). Then two case-insensitive grep searches using the attacker's username `nutcrackr` and `powershell` are performed:
`$ cat log_chunk_all.log | grep -iF "nutcrakr" | grep -iF "powershell"`

121 lines of events are filtered out, two of which show the password `fR0s3nF1@k3_s` for the account in the `Payload` field:  
```
<134>1 2024-09-16T11:33:12-04:00 SleighRider.northpole.local WindowsEvent - - - {"ContextInfo": " Severity = Informational\r\n Host Name = Default Host\r\n Host Version = 5.1.19041.1\r\n Host ID = 4571e982-1bfd-4d83-97f2-ce85d3e41b9d\r\n Host Application = powershell\r\n Engine Version = 5.1.19041.1\r\n Runspace ID = dd0ca0e4-fdfe-49be-ada7-2931df92cca6\r\n Pipeline ID = 1\r\n Command Name = Set-StrictMode\r\n Command Type = Cmdlet\r\n Script Name = \r\n Command Path = \r\n Sequence Number = 30\r\n User = NORTHPOLE\\elf_user02\r\n Connected User = \r\n Shell ID = Microsoft.PowerShell\r\n", "UserData": "", "Payload": "Add-Type -AssemblyName System.DirectoryServices\n$ldapConnString = \"LDAP://CN=Domain Admins,CN=Users,DC=northpole,DC=local\"\n$username = \"nutcrakr\"\n$pswd = 'fR0s3nF1@k3_s'\n$nullGUID = [guid]'00000000-0000-0000-0000-000000000000'\n$propGUID = [guid]'00000000-0000-0000-0000-000000000000'\n$IdentityReference = (New-Object System.Security.Principal.NTAccount(\"northpole.local\\$username\")).Translate([System.Security.Principal.SecurityIdentifier])\n$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None\n$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference, ([System.DirectoryServices.ActiveDirectoryRights] \"GenericAll\"), ([System.Security.AccessControl.AccessControlType] \"Allow\"), $propGUID, $inheritanceType, $nullGUID\n$domainDirEntry = New-Object System.DirectoryServices.DirectoryEntry $ldapConnString, $username, $pswd\n$secOptions = $domainDirEntry.get_Options()\n$secOptions.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl\n$domainDirEntry.RefreshCache()\n$domainDirEntry.get_ObjectSecurity().AddAccessRule($ACE)\n$domainDirEntry.CommitChanges()\n$domainDirEntry.dispose()\n$ldapConnString = \"LDAP://CN=Domain Admins,CN=Users,DC=northpole,DC=local\"\n$domainDirEntry = New-Object System.DirectoryServices.DirectoryEntry $ldapConnString, $username, $pswd\n$user = New-Object System.Security.Principal.NTAccount(\"northpole.local\\$username\")\n$sid=$user.Translate([System.Security.Principal.SecurityIdentifier])\n$b=New-Object byte[] $sid.BinaryLength\n$sid.GetBinaryForm($b,0)\n$hexSID=[BitConverter]::ToString($b).Replace('-','')\n$domainDirEntry.Add(\"LDAP://<SID=$hexSID>\")\n$domainDirEntry.CommitChanges()\n$domainDirEntry.dispose()", "Provider_Name": "Microsoft-Windows-PowerShell", "Provider_Guid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "EventID": 4103,
...
```

Q19: The attacker then used remote desktop to remotely access one of our domain computers. What is the full ISO8601 compliant UTC EventTime when they established this connection?  
Answer: 2024-09-16T15:35:57.000Z

Such events are captured in the `WindowsEvent` log and the `event.LogonType` field can be used as a filter. Remote connections have a `LogonType` value of 10:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent" AND event.LogonType == 10`

3 events are filtered out and the earliest one has a timestamp value of `"2024-09-16T15:35:57.000Z`:  
```
{ "@timestamp": "2024-09-16T15:35:57.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.ActivityID": "{D72392BD-843F-0000-1F93-23D73F84DA01}",
...
"event.LogonType": 10, "event.MoreDetails": "Group membership information.\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\nThis event is generated when the Audit Group Membership subcategory is configured. The Logon ID field can be used to correlate this event with the corresponding user logon event as well as to any other security audit events generated during this logon session.", "event.NetworkInformation_SourceNetworkAddress": null,
...
"event.SubjectUserName": "DC01$", "event.SubjectUserSid": "S-1-5-18", "event.Subject_AccountDomain": "NORTHPOLE", "event.Subject_AccountName": "DC01$", "event.Subject_LogonID": "0x3E7", "event.Subject_SecurityID": "S-1-5-18", "event.TargetDomainName": "NORTHPOLE", "event.TargetLinkedLogonId": null, "event.TargetLogonId": "0xdd425e", "event.TargetOutboundDomainName": null, "event.TargetOutboundUserName": null, "event.TargetUserName": "nutcrakr", "event.TargetUserSid": "S-1-5-21-3699322559-1991583901-1175093138-1112", "event.Task": 12554, "event.ThreadID": 1124, "event.TransmittedServices": null, "event.Version": 0, "event.VirtualAccount": null, "event.WorkstationName": null, "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "dc01.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

Q20: The attacker is trying to create their own naughty and nice list! What is the full file path they created using their remote desktop connection?  
Answer: `C:\WishLists\santadms_only\its_my_fakelst.txt`

File paths are typically recorded as part of the command line. There are fields that record this information, such as `event.TargetFilename` and `event.CommandLine`, and their values can be listed using this query:  
`FROM .ds-logs-* | WHERE event_source == "WindowsEvent"| STATS count(*) BY event.CommandLine`

This is the one event that has a suspicious looking command relating to file creation:  
```
{ "@timestamp": "2024-09-16T15:36:28.000Z", "@version": "1", "data_stream.dataset": "generic", "data_stream.namespace": "default", "data_stream.type": "logs", "event.AccountName": "SYSTEM", "event.AccountType": "User", "event.Category": "Process Create (rule: ProcessCreate)", "event.Channel": "Microsoft-Windows-Sysmon/Operational", "event.CommandLine": "\"C:\\Windows\\system32\\NOTEPAD.EXE\" C:\\WishLists\\santadms_only\\its_my_fakelst.txt", "event.Company": "Microsoft Corporation", "event.CurrentDirectory": "C:\\WishLists\\santadms_only\\", "event.Description": "Notepad", "event.Domain": "NT AUTHORITY", "event.EventID": 1, "event.EventTime": "2024-09-16T15:36:28.000Z", "event.EventType": "INFO", "event.FileVersion": "10.0.17763.1697 (WinBuild.160101.0800)", "event.Hashes": "MD5=5394096A1CEBF81AF24E993777CAABF4,SHA256=A28438E1388F272A52559536D99D65BA15B1A8288BE1200E249851FDF7EE6C7E,IMPHASH=C8922BE3DCDFEB5994C9EEE7745DC22E", "event.Hostname": "dc01.northpole.local", "event.Image": "C:\\Windows\\System32\\notepad.exe", "event.IntegrityLevel": "Medium", "event.Keywords": "-9223372036854775808", "event.LogonGuid": "{f151dc49-500d-660c-5e42-dd0000000000}", "event.LogonId": "0xdd425e", "event.MoreDetails": "Process Create:", "event.OpcodeDisplayNameText": "Info", "event.OpcodeValue": 0, "event.OriginalFileName": "NOTEPAD.EXE", "event.ParentCommandLine": "C:\\Windows\\Explorer.EXE", "event.ParentImage": "C:\\Windows\\explorer.exe", "event.ParentProcessGuid": "{f151dc49-500f-660c-5902-000000000900}", "event.ParentProcessId": 1364, "event.ParentUser": "NORTHPOLE\\nutcrakr", "event.ProcessGuid": "{f151dc49-502c-660c-8702-000000000900}", "event.ProcessID": 6468, "event.ProcessId": 9152, "event.Product": "Microsoft® Windows® Operating System", "event.ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", "event.RecordNumber": 641, "event.RuleName": "-", "event.Severity": "INFO", "event.SeverityValue": 2, "event.SourceModuleName": "inSysmon", "event.SourceModuleType": "im_msvistalog", "event.SourceName": "Microsoft-Windows-Sysmon", "event.Task": 1, "event.TerminalSessionId": 2, "event.ThreadID": 4816, "event.User": "NORTHPOLE\\nutcrakr", "event.UserID": "S-1-5-18", "event.Version": 5, "event_source": "WindowsEvent", "host.ip": "172.18.0.5", "hostname": "dc01.northpole.local", "log.syslog.facility.code": 1, "log.syslog.facility.name": "user-level", "log.syslog.facility.name.text": "user-level", "log.syslog.severity.code": 5, "log.syslog.severity.name": "notice", "log.syslog.severity.name.text": "notice", "tags": "match", "type": "syslog" }
```

The actual command executed, i.e. `"C:\Windows\system32\NOTEPAD.EXE\" C:\WishLists\santadms_only\its_my_fakelst.txt"`, can be found in the `event.CommandLine` field. It attempted to create an alternative naughty and nice list in the file named `its_my_fakelst.txt`.

Q21: The Wombley faction has user accounts in our environment. How many unique Wombley faction users sent an email message within the domain?  
Answer: 4

In the email log (from the source `SnowGlowMailPxy`) the sender's email address is recorded in the `event.From` field. This query lists all unique sender email addresses (571 altogether) from this event source:  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" | STATS count(*) BY event.From`

It is observed that some addresses are of the form `wcubNNN@northpole.local`, where `NNN` is a 3-digit number. These are addresses that belong to the Wombley faction. The number of unique users within this faction can be using the query below. There are 4 such users.  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" AND event.From LIKE "wcub*" | STATS count(*) BY event.From`

Q22: The Alabaster faction also has some user accounts in our environment. How many emails were sent by the Alabaster users to the Wombley faction users?  
Answer: 22 

Similar, the Alabaster faction users can be identified by their email addresses, which are of the form `asnowballNNN@northpole.local`, where `NNN` is a 3-digit number. The query below counts the number of events where Alabaster faction users have sent emails to those in the Wombley faction. There are 22 in total.  
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" AND event.To LIKE "wcub*" AND event.From LIKE "asnowball*" | STATS count(*)`


Q23: Of all the reindeer, there are only nine. What's the full domain for the one whose nose does glow and shine? To help you narrow your search, search the events in the 'SnowGlowMailPxy' event source.  
Answer: rud01ph.glow

The query below uses the string processing function `DISSECT` in ES|QL to extract the domain for all sender addresses. There are 41 unique domains. Browsing through the entire list, it can be noted that `rud01ph.glow` is the domain for Rudolph the red-nosed reindeer.
`FROM .ds-logs-* | WHERE event_source == "SnowGlowMailPxy" | DISSECT event.From """%{name}@%{domain}""" | STATS count(*) BY domain`

Q24: With a fiery tail seen once in great years, what's the domain for the reindeer who flies without fears? To help you narrow your search, search the events in the 'SnowGlowMailPxy' event source.  
A: c0m3t.halleys

Using the query results from the previous question, the domain `c0m3t.halleys` can be spotted in the list. It is named after Halley's comet, which can be observed from Earth once every 76 years. "Comet" is also the name of one of the nine reindeers.
