package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"log/slog"

	"github.com/alecthomas/kingpin/v2"
	"github.com/domainr/whois"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/sirikothe/gotextfsm"
	"gopkg.in/yaml.v2"
)

var (
	configFile   = kingpin.Flag("config", "Domain exporter configuration file.").Default("domains.yml").Envar("CONFIG").String()
	templateFile = kingpin.Flag("template", "Registry whois output FSM template file.").Default("whois.textfsm").Envar("CONFIG").String()
	pushGateway  = kingpin.Flag("pushgateway", "host:port where Pushgateway lives").Default("http://localhost:9091").Envar("CONFIG").String()
	debugWhois   = kingpin.Flag("debug-whois", "print whois output and skip pushing metrics").Envar("CONFIG").Bool()

	domainExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "domain_expiration_seconds",
			Help: "Epoch timestamp when the WHOIS record states this domain will expire",
		},
		[]string{"domain"},
	)
	stateConsistent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "domain_state_desired",
			Help: "That the domain is in the configured desired state in registry",
		},
		[]string{"domain"},
	)
	parsedSuccessfully = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "domain_information_last_successfully_parsed",
			Help: "Last epoch time that the desired domain information was looked up successfully",
		},
	)

	formats = []string{
		"2006-01-02",
		"2006-01-02T15:04:05Z",
		"02-Jan-2006",
		"2006.01.02",
		"Mon Jan 2 15:04:05 MST 2006",
		"02/01/2006",
		"2006-01-02 15:04:05 MST",
		"2006/01/02",
		"Mon Jan 2006 15:04:05",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05",
		"2.1.2006 15:04:05", // fi.
		"02/01/2006 15:04:05",
		"02.01.2006", // ax.
	}

	config promlog.Config
	logger log.Logger
)

type Config struct {
	Domains []ConfigDomain `yaml:"domains"`
}

type ConfigDomain struct {
	Domain      string   `yaml:"domain"`
	Status      []string `yaml:"status,omitempty"`
	Nameservers []string `yaml:"nameservers,omitempty"`
	Dnssec      string   `yaml:"dnssec,omitempty"`
	Registrar   string   `yaml:"registrar,omitempty"`
}

func main() {
	flag.AddFlags(kingpin.CommandLine, &config)
	kingpin.Version(version.Print("domain_metric_pusher"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true}))
	slog.SetDefault(logger)

	log.Println("Starting domain_metric_pusher", "version", version.Info())
	log.Println("Build context", version.BuildContext())

	prometheus.Register(domainExpiration)
	prometheus.Register(stateConsistent)
	prometheus.Register(parsedSuccessfully)

	config := Config{}

	templateFilename, err := filepath.Abs(*templateFile)
	if err != nil {
		log.Fatalln(err)
	}

	template, err := ioutil.ReadFile(templateFilename)
	if err != nil {
		log.Fatalln(err)
	}

	filename, err := filepath.Abs(*configFile)
	if err != nil {
		log.Fatalln(err)
	}

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalln(err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalln(err)
	}
	for _, domain := range config.Domains {
		req, err := whois.NewRequest(domain.Domain)
		if err != nil {
			log.Fatalln(err)
		}

		res, err := whois.DefaultClient.Fetch(req)
		if err != nil {
			log.Fatalln(err)
		}

		if *debugWhois {
			log.Printf("DEBUG: WHOIS output for : %s\n%s", domain.Domain, res.Body)
		}

		domainConsistency, date := parse(domain, res.Body, template)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("Domain %s expires at date %v", domain.Domain, date)
		if domainConsistency == 1 {
			log.Printf("Domain %s: all other domain settings as expected", domain.Domain)
		}

		domainExpiration.WithLabelValues(domain.Domain).Set(float64(date.Unix()))
		stateConsistent.WithLabelValues(domain.Domain).Set(domainConsistency)
	}
	parsedSuccessfully.SetToCurrentTime()
	log.Println("Successfully collected all data")
	if !*debugWhois {
		if err := push.New(*pushGateway, "domain_metrics_pusher").
			Collector(domainExpiration).
			Collector(stateConsistent).
			Collector(parsedSuccessfully).
			//Grouping("", "").
			Push(); err != nil {
			log.Fatalln("Could not push metrics to Pushgateway:", err)
		}
		log.Println("Successfully pushed all data to Pushgateway, done!")
	}
	return
}

func parse(configDomain ConfigDomain, res []byte, template []byte) (float64, time.Time) {
	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(string(template))
	if err != nil {
		log.Fatalf("Error while parsing template '%s'\n", err.Error())
	}
	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(string(res), fsm, true)
	if err != nil {
		log.Fatalf("Error while parsing input '%s'\n", err.Error())
	}

	var rawDate string
	var parametersConsistent float64
	parametersConsistent = 1
	for _, v := range parser.Dict {
		//fmt.Printf("Parsed output: %v\n", v)
		rawDate = v["expiryDate"].(string)
		//rawDate = strings.TrimSpace(rawDate)
		if len(rawDate) < 1 {
			log.Fatalf("Domain %s: don't know how to parse domain WHOIS output", configDomain.Domain)
		}

		configStatus := configDomain.Status
		actualStatus := v["status"].([]string)
		slices.Sort(configStatus)
		slices.Sort(actualStatus)
		if len(configStatus) > 0 && !slices.Equal(configStatus, actualStatus) {
			parametersConsistent = 0
			log.Printf("Domain %s WHOIS status %s is not the same as configured expected status %s", configDomain.Domain, actualStatus, configStatus)

		}
		if len(configDomain.Dnssec) > 0 && configDomain.Dnssec != v["dnssec"].(string) {
			parametersConsistent = 0
			log.Printf("Domain %s WHOIS dnssec status %s is not the same as configured expected dnssec status %s", configDomain.Domain, v["dnssec"].(string), configDomain.Dnssec)

		}
		if len(configDomain.Registrar) > 0 && configDomain.Registrar != v["registrar"].(string) {
			parametersConsistent = 0
			log.Printf("Domain %s WHOIS registrar %s is not the same as configured expected registrar %s", configDomain.Domain, v["registrar"].(string), configDomain.Registrar)

		}
		configNameservers := configDomain.Nameservers
		actualNameservers := v["nServer"].([]string)
		slices.Sort(configNameservers)
		slices.Sort(actualNameservers)
		if len(configNameservers) > 0 && !slices.Equal(configNameservers, actualNameservers) {
			parametersConsistent = 0
			log.Printf("Domain %s WHOIS nameservers %s is not the same as configured expected nameservers  %s", configDomain.Domain, actualNameservers, configNameservers)

		}
	}

	return parametersConsistent, parseDate(rawDate, configDomain.Domain)
}

func parseDate(rawDate string, domain string) time.Time {
	for _, format := range formats {
		if date, err := time.Parse(format, rawDate); err == nil {
			return date
		}

	}
	log.Fatalf("Domain %s: unable to parse raw date to timestamp: %s\n", domain, rawDate)
	return time.Time{}
}
