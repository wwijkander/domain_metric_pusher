package main

import (
	"io/ioutil"
	"log"
	"path"
	"testing"
	"time"
)

var ()

func TestParsing(t *testing.T) {
	cases := []struct {
		configDomain ConfigDomain
		date         time.Time
	}{
		{configDomain: ConfigDomain{Domain: "google.cn", Status: []string{"clientDeleteProhibited", "serverDeleteProhibited", "serverUpdateProhibited", "clientTransferProhibited", "serverTransferProhibited"}, Nameservers: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}, Dnssec: "unsigned", Registrar: "厦门易名科技股份有限公司"}, date: time.Date(2025, 3, 17, 12, 48, 36, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "google.jp", Status: []string{"DomainTransferLocked", "AgentChangeLocked"}, Nameservers: []string{"ns2.google.com", "ns1.google.com", "ns3.google.com", "ns4.google.com"}}, date: time.Date(2025, 5, 31, 0, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "google.com", Status: []string{"clientUpdateProhibited", "clientDeleteProhibited", "serverDeleteProhibited", "serverUpdateProhibited", "clientTransferProhibited", "serverTransferProhibited"}, Nameservers: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}, Dnssec: "unsigned", Registrar: "MarkMonitor Inc."}, date: time.Date(2020, 9, 14, 4, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "ietf.org", Status: []string{"clientDeleteProhibited", "serverDeleteProhibited", "clientTransferProhibited"}, Nameservers: []string{"NS1.HKG1.AFILIAS-NST.INFO", "NS1.YYZ1.AFILIAS-NST.INFO", "NS1.SEA1.AFILIAS-NST.INFO", "NS1.MIA1.AFILIAS-NST.INFO", "NS1.AMS1.AFILIAS-NST.INFO", "NS0.AMSL.COM"}, Dnssec: "signedDelegation", Registrar: "Network Solutions, LLC"}, date: time.Date(2020, 3, 12, 5, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "ficora.fi", Status: []string{"Registered"}, Nameservers: []string{"ns2.traficom.fi [87.239.125.187] [2a00:13f0:0:1002:125:184:0:3]", "ns-secondary.funet.fi [128.214.248.132] [2001:708:10:55::53]", "nsp.dnsnode.net", "ns2.z.fi", "ns1.z.fi", "ns1.traficom.fi [87.239.125.186] [2a00:13f0:0:1002:125:184:0:2]"}, Dnssec: "no", Registrar: "Liikenne- ja viestintävirasto Traficom"}, date: time.Date(2029, 8, 31, 0, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "yolo.im", Nameservers: []string{"ns-145-a.gandi.net", "ns-191-c.gandi.net", "ns-181-b.gandi.net"}}, date: time.Date(2022, 06, 05, 00, 59, 59, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "com", Status: []string{"OK"}, Registrar: "PDR Ltd. d/b/a PublicDomainRegistry.com"}, date: time.Date(2018, 7, 3, 19, 6, 9, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "io"}, date: time.Date(2018, 12, 21, 17, 35, 22, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "nic.cz", Status: []string{"Sponsoring registrar change forbidden"}, Nameservers: []string{"d.ns.nic.cz (193.29.206.1, 2001:678:1::1)", "b.ns.nic.cz (194.0.13.1, 2001:678:10::1)", "a.ns.nic.cz (194.0.12.1, 2001:678:f::1)"}, Dnssec: "AUTO-ZHHWRIDCGH9F46ZDG2K2VC284", Registrar: "REG-CZNIC"}, date: time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "maxexperiencia.com.br", Status: []string{"published"}, Nameservers: []string{"a.auto.dns.br", "b.auto.dns.br"}, Dnssec: "33150 ECDSA-SHA-256 5B797E534DEEBAAAD1BDE59F6B06E5AE65580E8E67F8C64152AE6A9A735FF97A"}, date: time.Date(2025, 7, 29, 0, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "foo.rs", Status: []string{"Active"}, Nameservers: []string{"ns1.foodns.net - 91.185.193.152", "ns2.foodns.net - 91.185.193.152"}, Dnssec: "no", Registrar: "Loopia d.o.o."}, date: time.Date(2024, 8, 26, 17, 1, 7, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "alcom.ax", Status: []string{"Registered"}, Nameservers: []string{"ns1.aland.net", "ns3.alcom.fi", "ns2.aland.net", "ns4.alcom.fi"}, Registrar: "Ålands Telekommunikation Ab"}, date: time.Date(2026, 4, 11, 0, 0, 0, 0, time.UTC)},
	}

	template, err := ioutil.ReadFile("./whois.textfsm")
	if err != nil {
		log.Fatalln(err)
	}

	for i := range cases {
		w := path.Join("testdata", cases[i].configDomain.Domain)
		ans, err := ioutil.ReadFile(w)
		if err != nil {
			t.Errorf("problem on %s: %v", cases[i].configDomain.Domain, err)
		}

		domainConsistency, parsedDate := parse(cases[i].configDomain, ans, template)
		if parsedDate.IsZero() || err != nil {
			t.Errorf("%s got %v (error=%v) ", cases[i].configDomain.Domain, parsedDate, err)
		}

		if domainConsistency == 0 {
			t.Errorf("Parsed domain whois data is not as expected test case")
		}

		answerDate := cases[i].date
		if !answerDate.Equal(parsedDate) {
			t.Errorf("cases[%d]: parsedDate=%v answerDate=%v", i, parsedDate, answerDate)
		}
	}
}
