# domain_metric_pusher


Simple job which performs WHOIS lookups for a list of domains provided in the "config" file and pushes the expiry date and if other settings match configuration as metrics to Prometheus through Pushgateway.

Flags:
```bash
usage: domain_metric_pusher [<flags>]

Flags:
  -h, --[no-]help             Show context-sensitive help (also try --help-long and --help-man).
      --config="domains.yml"  Domain exporter configuration file. ($CONFIG)
      --template="whois.textfsm"  
                              Registry whois output FSM template file. ($CONFIG)
      --pushgateway="http://localhost:9091"  
                              host:port where Pushgateway lives ($CONFIG)
      --[no-]debug-whois      print whois output and skip pushing metrics ($CONFIG)
      --log.level=info        Only log messages with the given severity or above. One of: [debug, info, warn, error]
      --log.format=logfmt     Output format of log messages. One of: [logfmt, json]
      --[no-]version          Show application version.
```

### Example Domain Config
See domains.yml. Note that the non-date data is expected to be as it is presented in the WHOIS response. For example, status can be "ok", "Registered", etc.

### Example textFSM Template
See whois.textfsm and https://github.com/google/textfsm/wiki/TextFSM

### Example Prometheus Alerts


```yaml
- name: DomainMetricsAlerts
  rules:
    - alert: DomainWhoisDataNotInSync
      expr: domain_state_desired == 0
      for: 0m
      labels:
        severity: warning
      annotations:
        summary: Domain {{ $labels.domain }} WHOIS data is not as expected in domain_metrics_pusher
        description: Domain {{ $labels.domain }} WHOIS data is not as expected in domain_metrics_pusher. Misconfiguration or failure/hijack attempt at registrar/registry?

    - alert: DomainExpiring
      expr: domain_expiration_seconds{} < time() + 60 * 60 * 24 * 30
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: domain {{ $labels.domain }} is going to expire in less than 30 days. Renew?! 
        description: domain {{ $labels.domain }} is going to expire in less than 30 days. Renew?! Expiration timestamp is {{ $value }} 

    - alert: DomainMetricExporterOverdue
      expr: domain_information_last_successfully_parsed{} < time() - 60 * 60 * 26
      for: 0m
      labels:
        severity: warning
      annotations:
        summary: domain_metric_pusher has not ran successfully in the prescribed timeframe. Check the service. 
        description: domain_metric_pusher has not ran successfully in the prescribed timeframe. Check the service. Last successful run at {{ $value }} 

```

### Example systemd timer and unit

```
# /etc/systemd/system/domain_metric_pusher.timer
[Unit]
Description=daily domain_metric_pusher run
Documentation=

[Timer]
OnCalendar=daily
AccuracySec=2h

[Install]
WantedBy=timers.target
```
```
# /etc/systemd/system/domain_metric_pusher.service
[Unit]
Description=domain_metric_pusher
Documentation=https://github.com/wwijkander/domain_metric_pusher
After=network-online.target
Requires=local-fs.target
After=local-fs.target

[Service]
Restart=on-failure
Type=simple
User=prometheus
Group=prometheus
ExecStart=/opt/domain_metric_pusher/domain_metric_pusher --config="/opt/domain_metric_pusher/domains.yml" --template="/opt/domain_metric_pusher/whois.textfsm"
TimeoutStopSec=20s
SendSIGKILL=no
CapabilityBoundingSet=CAP_SET_UID
LimitNOFILE=65000
LockPersonality=true
NoNewPrivileges=true
MemoryDenyWriteExecute=true
PrivateDevices=true
PrivateTmp=true
ProtectHome=true
RemoveIPC=true
RestrictSUIDSGID=true
#SystemCallFilter=@signal @timer
ReadOnlyPaths=/opt/domain_metric_pusher
PrivateUsers=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
SyslogIdentifier=domain_metric_pusher

[Install]
WantedBy=multi-user.target
```

### FAQ

##### Why did I get a negative amount of days until expiry?

The WHOIS resposne probably doesn't parse correctly. Please create an issue with the response and we'll add the format.


