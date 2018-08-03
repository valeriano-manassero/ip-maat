# valerianomanassero/ip-maat
IP Maat is a Dockerized microservice (PYTHON VERSION) that generates and mantains a blacklist based on various public IP blacklists.

The application merges these blacklists and outputs an updated malicious IP rank to a selected Logstash via TCP.

The image is based on a CentOS 7 image.


## Recommended Options

**Environment**

- LOGSTASH_HOST - The host where Logstash is listening
- LOGSTASH_PORT - The port where Logstash is listening
- CRON_SECONDS - Number of seconds between list regenaeration 

## Docker example usage

```
docker run -d -e "LOGSTASH_HOST=logstash"-e "LOGSTASH_PORT=9563" -e "CRON_SECONDS=3600" valerianomanassero/ip-maat
```
## Logstash example config file
```
input {
        tcp {
                port => 9563
                codec => json{ }
                tags => "ip-maat"
        }
}
filter {
        if "ip-maat" in [tags] {
                geoip {
                        source => "[ip]"
                        target => "geoip"
                        database => "/usr/share/logstash/GeoLite2/GeoLite2-City.mmdb"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                geoip {
                        source => "[ip]"
                        target => "geoip"
                        database => "/usr/share/logstash/GeoLite2/GeoLite2-ASN.mmdb"
                }
                mutate {
                        convert => [ "[geoip][coordinates]", "float"]
                }
        }
}
output {
        if "ip-maat" in [tags] {
                elasticsearch {
                        hosts => ["elasticsearch:9200"]
                        index => "logstash-ip-maat-%{+YYYY.MM.dd}"
                }
        }
}
```
