FROM scratch
COPY domain_metric_pusher /domain_metric_pusher
ENTRYPOINT ["/domain_metric_pusher"]
