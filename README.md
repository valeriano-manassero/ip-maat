# valerianomanassero/ip-maat
IP Maat is a Dockerized microservice that generates and mantains a blacklist based on various public IP blacklists.

The application merges these blacklists and outputs an updated malicious IP and Subnets rank to a selected Logstash via TCP.

The image is based on Golang/Alpine image.

## Recommended Options

**Environment**

- LOGSTASH_HOST - The host where Logstash is listening
- LOGSTASH_PORT - The port where Logstash is listening
- CRON_SECONDS - Number of seconds between list regenaeration 

## Docker example usage

```
docker run -d -e "LOGSTASH_HOST=logstash"-e "LOGSTASH_PORT=9563" -e "CRON_SECONDS=3600" valerianomanassero/ip-maat:<VERSION>
```
## Logstash example config file
```
input {
        tcp {
                port => 9563
                codec => json_lines{ }
                tags => "ip-maat"
        }
}
filter {
        if "ip-maat" in [tags] {
                if [IP] {
                        geoip {
                                source => "[IP]"
                                target => "geoip"
                        }
                }
        }
}
output {
        if "ip-maat" in [tags] {
                elasticsearch {
                        hosts => ["elasticsearch:9200"]
                        index => "ip-maat-%{+YYYY.MM.dd}"
                }
        }
}
```
## Elasticsearch template query
```
PUT /_template/ip-maat
{
  "template": "ip-maat-*",
  "order": 0,
  "version": 1,
  "mappings": {
    "_default_": {
      "_all": {
        "enabled": false
      },
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "@version": {
          "type": "keyword"
        },
        "geoip": {
          "properties": {
            "as_org": {
              "type": "keyword"
            },
            "asn": {
              "type": "integer"
            },
            "country_code2": {
              "type": "keyword"
            },
            "country_name": {
              "type": "keyword"
            }
          }
        },
        "IP": {
          "type": "ip"
        },
        "SUBNET": {
          "type": "keyword"
        },
        "PrefixLength": {
          "type": "byte"
        },
        "Lists": {
          "type": "keyword"
        },
        "Score": {
          "type": "byte"
        },
        "tags": {
          "type": "text"
        }
      }
    }
  },
  "aliases": {}
}
```

## Scores

Finding a useful score threshold can be a trivial task.
I usually use following thresholds:
* < 6  not so bad IP/subnet
* \>= 6 and < 9 Bad IP/subnet
* \>= 9 VERY Bad IP/subnet