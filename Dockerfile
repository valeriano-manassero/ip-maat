FROM centos:7

MAINTAINER Valeriano Manassero https://github.com/valeriano-manassero

ENV LOGSTASH_HOST logstash
ENV LOGSTASH_PORT 9563
ENV CRON_SECONDS 3600

RUN mkdir -p /opt/project
WORKDIR /opt/project
COPY app/ /opt/project/

COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh
CMD ["/docker-entrypoint.sh"]