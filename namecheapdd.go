package main

import (
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	log "github.com/Sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

// Config represents the parsed config file.
type Config struct {
	Domains        map[string]Domain
	IntervalTime   int    `yaml:"interval_time"`
	IpRetrievalUrl string `yaml:"ip_retrieval_url"`
}

// The Domain struct is used to represent single domains, which are
// unmarshalled from our config file.
type Domain struct {
	Host     string
	Domain   string
	Password string
	Ttl      int
}

// The NamecheapXmlResponse struct is used to unmarshall the XML response
// we get from Namecheap after an update. We're only interested in the
// error count, and the first error, because we just want to know if the update
// was successful or not.
type NamecheapXmlResponse struct {
	ErrCount int
	Errors   struct {
		Err1 string
	} `xml:"errors"`
}

// The parsed configuration.
var config Config

// the external IP address, usually retrieved from an external service.
var externalIpAddress string

// IsPrivateIP is used to check whether an IP address is
// contained in an RFC1918 network.
var isPrivateIP func(string) bool = createPrivateIpChecker()

// A shared lock between the updating goroutines.
var lock bool

// The URL of Namecheap's update service.
const namecheapUpdateUrl string = "https://dynamicdns.park-your-domain.com/update"

// CheckNamecheapResponse takes the XML response of the update, and returns the
// error count and first error message.
func checkNamecheapResponse(response []byte) error {
	var ret error = nil
	res := NamecheapXmlResponse{}
	err := xml.Unmarshal([]byte(response), &res)
	if err != nil {
		log.Errorf("error while parsing namecheap response after update.\n%v", err)
		ret = err
	}
	if res.ErrCount > 0 {
		ret = errors.New(res.Errors.Err1)
	}
	return ret
}

// Creates and returns a function that can check if an IP address is in RFC1918 range.
func createPrivateIpChecker() func(string) bool {
	var rfc1918Networks []net.IPNet
	var rfc1918Addresses = map[string]int{
		"10.0.0.0":    8,
		"172.16.0.0":  12,
		"192.168.0.0": 16,
	}
	cidrLength := 32

	for ip, cidrMask := range rfc1918Addresses {
		addr := net.ParseIP(ip)
		mask := net.CIDRMask(cidrMask, cidrLength)

		rfc1918Networks = append(rfc1918Networks, net.IPNet{IP: addr, Mask: mask})
	}

	return func(ip string) bool {
		found := false
		for _, network := range rfc1918Networks {
			if network.Contains(net.ParseIP(ip)) {
				found = true
			}
		}
		return found
	}
}

// Retrieve the external IP address from an external service. We assume that the service
// returns an unformatted IP address after a GET.
func getIp(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error while retrieving external IP address.\n%v", err)
	}
	ipAddress, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return "", fmt.Errorf("error while reading response for external IP address.\n%v", err)
	}
	if net.ParseIP(string(ipAddress)) != nil {
		return string(ipAddress), nil
	} else {
		return "", fmt.Errorf("Couldn't parse external IP address. Does %s return an IP address?", url)
	}
}

// ParseConfig unmarshalls the configuration YAML file into our Config struct.
// We also do some simple validation, checking whether required fields exist.
func parseConfig(file []byte) Config {
	err := yaml.Unmarshal(file, &config)
	if err != nil {
		log.Fatalf("error while parsing YAML.\n%v", err)
	}

	if config.Domains == nil {
		log.Fatal("missing \"domains\" key in config.yaml.")
	}

	for name, domain := range config.Domains {
		switch {
		case domain.Domain == "":
			log.Fatalf("missing domain for %s.", name)
		case domain.Host == "":
			log.Fatalf("missing host for %s.", name)
		case domain.Password == "":
			log.Fatalf("missing password for %s.", name)
		case domain.Ttl == 0:
			domain.Ttl = 60
		}
	}

	if config.IpRetrievalUrl == "" {
		config.IpRetrievalUrl = "https://dynamicdns.park-your-domain.com/getip"
	}
	if config.IntervalTime == 0 {
		config.IntervalTime = 5
	}

	return config
}

// Prepare the URL we use to update a domain. We take "externalIpAddress" and add
// some query parameters to it.
func prepareUrl(domain Domain) string {
	u, err := url.Parse(namecheapUpdateUrl)
	if err != nil {
		log.Fatalf("unrecoverable error while parsing %s.", namecheapUpdateUrl)
	}

	q := u.Query()
	q.Set("host", domain.Host)
	q.Set("domain", domain.Domain)
	q.Set("password", domain.Password)
	q.Set("ip", externalIpAddress)
	u.RawQuery = q.Encode()

	return u.String()
}

// UpdateDns checks if our current external IP address differs from the
// DNS entry of the given domain. If this is the case, we update the
// domain to our current external IP address.
func updateDns(name string, domain Domain) bool {
	var changed bool
	var fqdn string

	log.Debugf("checking %s.", name)
	externalIpAddress, err := getIp(config.IpRetrievalUrl)
	if err != nil {
		log.Error(err)
		return false
	}
	if isPrivateIP(externalIpAddress) {
		log.Error("retrieved IP address is private.")
		return false
	}
	log.Debugf("found current IP address %s", externalIpAddress)

	if domain.Host == "@" {
		fqdn = domain.Domain
	} else {
		fqdn = domain.Host + "." + domain.Domain
	}
	domainIpAddresses, err := net.LookupHost(fqdn)
	if err != nil {
		log.Errorf("error while querying current IP address.\n%v", err)
		return false
	}

	if len(domainIpAddresses) > 1 || len(domainIpAddresses) < 1 {
		changed = true
	} else {
		changed = domainIpAddresses[0] != externalIpAddress
	}
	log.Debugf("found domain IP address(es) %s", domainIpAddresses)

	if changed {
		log.Infof("DNS for %s needs an update.", name)
		res, err := http.Get(prepareUrl(domain))
		if err != nil {
			log.Error("error while updating DNS.")
			return false
		}
		response, err := ioutil.ReadAll(res.Body)
		res.Body.Close()

		err = checkNamecheapResponse(response)
		if err != nil {
			log.Errorf("error while updating DNS.\n%v", err)
			return false
		}
		log.Info("successfully updated DNS.")
		return true
	} else {
		log.Debug("DNS is already up to date.")
		return false
	}
}

func init() {
	lock = false

	// define command line options
	debug := flag.Bool("debug", false, "enable debug logging")
	configFile := flag.String("config", "/etc/namecheapdd.yaml", "the location of the configuration file")
	flag.Parse()

	filename, _ := filepath.Abs(*configFile)
	rawConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	config = parseConfig(rawConfig)
}

func main() {
	for name, domain := range config.Domains {
		updateTicker := time.NewTicker(time.Minute * time.Duration(config.IntervalTime))
		log.Infof("starting scheduled checks for %s.", name)
		go func(name string, domain Domain) {
			for _ = range updateTicker.C {
				// wait till the lock is released
				for lock {
					time.Sleep(time.Second)
				}
				// acquire lock
				lock = true
				log.Debugf("checking if we need to update %s.", name)
				// run the update routine, which returns false if anything the domain
				// was updated
				updated := updateDns(name, domain)
				// release lock
				lock = false
				// if the domain was updated we don't want to check again for the
				// duration of the TTL
				if updated {
					// sleep for the duration of the domain's configured
					// ttl, default is 60 minutes
					time.Sleep(time.Minute * time.Duration(domain.Ttl))
				}
			}
		}(name, domain)
	}

	for {
		time.Sleep(time.Second * 5)
	}
}
