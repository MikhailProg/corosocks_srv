FROM alpine:latest as builder
RUN apk add --no-cache gcc make libc-dev
COPY ./src/ /usr/src/corosocks/
WORKDIR /usr/src/corosocks
RUN make

FROM alpine:latest as runner
WORKDIR /srv/corosocks
COPY --from=builder /usr/src/corosocks/corosocks_srv .
EXPOSE 1080
CMD ["./corosocks_srv"]
