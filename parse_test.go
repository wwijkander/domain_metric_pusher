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
		{configDomain: ConfigDomain{Domain: "google.cn"}, date: time.Date(2019, 3, 17, 12, 48, 36, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "google.jp"}, date: time.Date(2021, 5, 31, 0, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "google.com"}, date: time.Date(2020, 9, 14, 4, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "ietf.org"}, date: time.Date(2020, 3, 12, 5, 0, 0, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "unisportstore.fi"}, date: time.Date(2019, 3, 20, 17, 13, 49, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "yolo.im"}, date: time.Date(2022, 06, 05, 00, 59, 59, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "com"}, date: time.Date(2018, 7, 3, 19, 6, 9, 0, time.UTC)},
		{configDomain: ConfigDomain{Domain: "io"}, date: time.Date(2018, 12, 21, 17, 35, 22, 0, time.UTC)},
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
