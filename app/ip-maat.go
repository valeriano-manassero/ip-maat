package main

import  (
	"./util"
	"encoding/json"
	"net"
	"time"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	LOGSTASH_HOST := os.Getenv("LOGSTASH_HOST")
	LOGSTASH_PORT, _ := strconv.Atoi(os.Getenv("LOGSTASH_PORT"))
	CRON_SECONDS, _ := strconv.Atoi(os.Getenv("CRON_SECONDS"))

	regexp_ip := "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
	regexp_subnet := regexp_ip + "\\/(3[0-1]|[1-2][0-9]|[1-9])"

	for {
		spamhaus := util.Feed{"spamhaus", "https://www.spamhaus.org/drop/drop.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_subnet + ".*"},
				{3, "^" + regexp_ip + ".*"}}}
		firehol := util.Feed{"firehol", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			10, []util.FeedAnalyzer{{3, "^" + regexp_subnet + ".*"},
				{3, "^" + regexp_ip + ".*"}}}
		alienvault_com := util.Feed{"alienvault.com", "https://reputation.alienvault.com/reputation.generic",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + " # Scanning Host.*"},
				{3, "^" + regexp_ip + " # Malicious Host.*"}}}
		badips_com := util.Feed{"badips.com", "https://www.badips.com/get/list/any/2?age=7d", 10,
			[]util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		bambenekconsulting_com := util.Feed{"bambenekconsulting.com", "http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		blocklist_de := util.Feed{"blocklist.de", "http://lists.blocklist.de/lists/all.txt", 10,
			[]util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		botscout := util.Feed{"badips", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		bruteforceblocker := util.Feed{"bruteforceblocker", "http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		cinsscore_com := util.Feed{"cinsscore.com", "http://cinsscore.com/list/ci-badguys.txt", 10,
			[]util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		cruzit := util.Feed{"cruzit", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cruzit_web_attacks.ipset",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		dshield_org := util.Feed{"dshield.org", "http://feeds.dshield.org/top10-2.txt", 10,
			[]util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		emergingthreats_net := util.Feed{"emergingthreats.net", "http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		feodotracker := util.Feed{"feodotracker", "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		malwaredomainlist := util.Feed{"malwaredomainlist", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomainlist.ipset",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		myip := util.Feed{"myip", "https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt", 10,
			[]util.FeedAnalyzer{{3, "^deny from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		nothink_org := util.Feed{"nothink.org", "http://www.nothink.org/blacklist/blacklist_malware_irc.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		cybersweat_shop := util.Feed{"cybersweat.shop", "http://cybersweat.shop/iprep/iprep_ramnode.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		proxylists_net := util.Feed{"proxylists.net", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_1d.ipset",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + ".*"}}}
		proxyrss_com := util.Feed{"proxyrss.com", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyrss_1d.ipset",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + ".*"}}}
		spys_ru := util.Feed{"spys.ru", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyspy_1d.ipset",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + ".*"}}}
		ransomwaretracker := util.Feed{"ransomwaretracker", "http://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		rosinstrument_com := util.Feed{"rosinstrument.com", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ri_web_proxies_30d.ipset",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		rutgers_edu := util.Feed{"rutgers.edu", "http://report.rutgers.edu/DROP/attackers",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		sblam_com := util.Feed{"sblam.com", "http://sblam.com/blacklist.txt",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		socks_proxy_net := util.Feed{"socks-proxy.net", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + ".*"}}}
		sslproxies_org := util.Feed{"sslproxies.org", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_1d.ipset",
			10, []util.FeedAnalyzer{{1, "^" + regexp_ip + ".*"}}}
		talosintelligence_com := util.Feed{"talosintelligence.com", "http://www.talosintelligence.com/feeds/ip-filter.blf",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		turris_cz := util.Feed{"turris.cz", "https://www.turris.cz/greylist-data/greylist-latest.csv",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		zeustracker := util.Feed{"zeustracker", "https://zeustracker.abuse.ch/blocklist.php?download=badips",
			10, []util.FeedAnalyzer{{3, "^" + regexp_ip + ".*"}}}
		torproject_org := util.Feed{"torproject.org", "https://check.torproject.org/exit-addresses",
			10, []util.FeedAnalyzer{{1, "^ExitAddress ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}

		var active_feeds = []util.Feed{spamhaus, firehol, alienvault_com, badips_com, bambenekconsulting_com, blocklist_de, botscout,
			bruteforceblocker, cinsscore_com, cruzit, dshield_org, emergingthreats_net, feodotracker, malwaredomainlist,
			myip, nothink_org, cybersweat_shop, proxylists_net, proxyrss_com, spys_ru, ransomwaretracker,
			rosinstrument_com, rutgers_edu, sblam_com, socks_proxy_net, sslproxies_org, talosintelligence_com,
			turris_cz, zeustracker, torproject_org}
		ips := make(map[string]util.IPAnalysis)
		subnets := make(map[string]util.SUBNETAnalysis)
		for _, active_feed := range active_feeds {
			log.Printf("[INFO] Importing data feed %s\n", active_feed.Name)
			feed_results_ips, feed_results_subnets, err := active_feed.Fetch()
			if err == nil {
				for k, e := range feed_results_ips {
					if _, ok := ips[k]; ok {
						ip := ips[k]
						ip.Score = ip.Score + e.Score
						ip.Lists = append(ip.Lists, e.Lists[0])
						ips[k] = ip
					} else {
						ips[k] = e
					}
				}
				for k, e := range feed_results_subnets {
					if _, ok := subnets[k]; ok {
						subnet := subnets[k]
						subnet.Score = subnet.Score + e.Score
						subnet.Lists = append(subnet.Lists, e.Lists[0])
						subnets[k] = subnet
					} else {
						subnets[k] = e
					}
				}
				log.Printf("[INFO] Imported %d ips and %d subnets from data feed %s\n", len(feed_results_ips),
					len(feed_results_subnets), active_feed.Name)
			} else {
				log.Printf("[ERROR] Importing data feed %s\n failed : %s", active_feed.Name, err)
			}
		}

		conn_string := strings.Join([]string{LOGSTASH_HOST, strconv.Itoa(LOGSTASH_PORT)}, ":")
		log.Printf("[INFO] Connecting to Logstash (%s)\n", conn_string)
		conn, err := net.Dial("tcp", conn_string)
		if err != nil {
			log.Printf("[ERROR] Logstash (%s) connection failed: %s\n", conn_string, err)
		} else {
			for _, v := range ips {
				jsonMessage, _ := json.Marshal(v)
				conn.Write([]byte(string(jsonMessage) + string("\n")))
			}
			for _, v := range subnets {
				jsonMessage, _ := json.Marshal(v)
				conn.Write([]byte(string(jsonMessage) + string("\n")))
			}
			conn.Close()
			log.Printf("[INFO] Logstash (%s) data pushed\n", conn_string)
		}

		log.Printf("[INFO] Sleeping for %d seconds\n", CRON_SECONDS)
		time.Sleep(time.Second * time.Duration(CRON_SECONDS))
	}
}