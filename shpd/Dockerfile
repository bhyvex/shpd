FROM debian:jessie
RUN apt-get update && apt-get install -y ca-certificates
ADD static /static
ADD shpd /bin/shpd
EXPOSE 8080
ENTRYPOINT ["/bin/shpd"]
CMD ["-h"]
