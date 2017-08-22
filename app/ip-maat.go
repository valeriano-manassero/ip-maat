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

	for {
		alienvault_com := util.Feed{"alienvault.com","https://reputation.alienvault.com/reputation.generic",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) # Scanning Host.*"},
				{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) # Malicious Host.*"}}}
		badips_com := util.Feed{"badips.com","https://www.badips.com/get/list/any/2?age=7d",10,
			[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		bambenekconsulting_com := util.Feed{"bambenekconsulting.com","http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		blocklist_de := util.Feed{"blocklist.de","http://lists.blocklist.de/lists/all.txt",10,
			[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		botscout := util.Feed{"badips","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset",
			10, []util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		bruteforceblocker := util.Feed{"bruteforceblocker","http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		cinsscore_com := util.Feed{"cinsscore.com","http://cinsscore.com/list/ci-badguys.txt",10,
			[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		cruzit := util.Feed{"cruzit","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cruzit_web_attacks.ipset",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		dshield_org := util.Feed{"dshield.org","http://feeds.dshield.org/top10-2.txt",10,
			[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		emergingthreats_net := util.Feed{"emergingthreats.net","http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		feodotracker := util.Feed{"feodotracker","https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		malwaredomainlist := util.Feed{"malwaredomainlist","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomainlist.ipset",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		myip := util.Feed{"myip","https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt",10,
			[]util.FeedAnalyzer{{3, "^deny from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		nothink_org := util.Feed{"nothink.org","http://www.nothink.org/blacklist/blacklist_malware_irc.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		cybersweat_shop := util.Feed{"cybersweat.shop","http://cybersweat.shop/iprep/iprep_ramnode.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		proxylists_net := util.Feed{"proxylists.net","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_1d.ipset",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		proxyrss_com := util.Feed{"proxyrss.com","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyrss_1d.ipset",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		spys_ru := util.Feed{"spys.ru","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyspy_1d.ipset",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		ransomwaretracker := util.Feed{"ransomwaretracker","http://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		rosinstrument_com := util.Feed{"rosinstrument.com","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ri_web_proxies_30d.ipset",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		rutgers_edu := util.Feed{"rutgers.edu","http://report.rutgers.edu/DROP/attackers",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		sblam_com := util.Feed{"sblam.com","http://sblam.com/blacklist.txt",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		socks_proxy_net := util.Feed{"socks-proxy.net","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		sslproxies_org := util.Feed{"sslproxies.org","https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_1d.ipset",
			10,[]util.FeedAnalyzer{{1, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		talosintelligence_com := util.Feed{"talosintelligence.com","http://www.talosintelligence.com/feeds/ip-filter.blf",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		turris_cz := util.Feed{"turris.cz","https://www.turris.cz/greylist-data/greylist-latest.csv",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		zeustracker := util.Feed{"zeustracker","https://zeustracker.abuse.ch/blocklist.php?download=badips",
			10,[]util.FeedAnalyzer{{3, "^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}
		torproject_org := util.Feed{"torproject.org","https://check.torproject.org/exit-addresses",
			10,[]util.FeedAnalyzer{{1, "^ExitAddress ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*"}}}

		var active_feeds = []util.Feed {alienvault_com, badips_com, bambenekconsulting_com, blocklist_de, botscout,
			bruteforceblocker, cinsscore_com, cruzit, dshield_org, emergingthreats_net, feodotracker, malwaredomainlist,
			myip, nothink_org, cybersweat_shop, proxylists_net, proxyrss_com, spys_ru, ransomwaretracker,
			rosinstrument_com, rutgers_edu, sblam_com, socks_proxy_net, sslproxies_org, talosintelligence_com,
			turris_cz, zeustracker, torproject_org}
		ips := make(map[string]util.IPAnalysis)
		for _, active_feed := range active_feeds {
			log.Printf("[INFO] Importing data feed %s\n", active_feed.Name)
			feed_results, err := active_feed.Fetch()
			if err == nil {
				for k, e := range feed_results {
					if _, ok := ips[k]; ok {
						ip := ips[k]
						ip.Score = ip.Score + e.Score
						ip.Lists = append(ip.Lists, e.Lists[0])
						ips[k] = ip
					} else {
						ips[k] = e
					}
				}
				log.Printf("[INFO] Imported %d ips from data feed %s\n", len(feed_results), active_feed.Name)
			} else {
				log.Printf("[ERROR] Importing data feed %s\n failed : %s", active_feed.Name, err)
			}
		}

		jsonMessage, _ := json.Marshal(ips)
		conn_string := strings.Join([]string{LOGSTASH_HOST, strconv.Itoa(LOGSTASH_PORT)}, ":")
		log.Printf("[INFO] Connecting to Logstash (%s)\n", conn_string)
		conn, err := net.Dial("tcp", conn_string)
		if err != nil {
			log.Printf("[ERROR] Logstash (%s) connection failed: %s\n", conn_string, err)
		} else {
			conn.Write([]byte(string(jsonMessage) + "\n"))
			conn.Close()
			log.Printf("[INFO] Logstash (%s) data pushed\n", conn_string)
		}

		log.Printf("[INFO] Sleeping for %d seconds\n", CRON_SECONDS)
		time.Sleep(time.Second * time.Duration(CRON_SECONDS))
	}
}