You need `nc` from package `netcat-openbsd`, not `nc` from `netcat-traditional` or `netcat`.
If you can't nc to work, then create a Dockerfile and alias it to `nc`, like so:
  > FROM alpine:latest
  > RUN apk add --no-cache netcat-openbsd
  > ENTRYPOINT [ "nc" ]
  $ docker build -t nc .
  $ alias nc='docker run --rm nc'
   
   
How to run the challenge locally?
  $ docker compose up -d
  $ nc 127.0.0.1 1336  <-- spawn game
  (you should see this output)
  > Waiting for players to ready up.
  >   bash <(curl -s http://127.0.0.1:1337)
  > Press wasd when connected, then r when ready.
  (press "w/a/s/d" or "r", then wait for another player to run the `bash <(curl ...)` command)
  Play snake!

How to connect remotely?
  Select a beautiful IPv6 in the range: 2a01:4f8:1c1c:d3ed::/64
  E.g. `2a01:4f8:1c1c:d3ed:$(($RANDOM%10000)):dead:beef:abcd`
  Now spawn a game by connecting to port 1336:
  $ nc 2a01:4f8:1c1c:d3ed:RANDOMHERE:dead:beef:abcd 1336
  Tell your friends and have them connect:
  $ bash <(curl -s http://[2a01:4f8:1c1c:d3ed:RANDOMHERE:dead:beef:abcd]:1337)
  Play snake!


IPv6: I'm not getting any output?
  Make sure IPv6 is working (this might be the fault of your ISP, sorry consider changing ISP or giving them a call telling them we ran out of IPv4 addresses years ago!)
  How to check if IPv6 is working? You can use this website:
  $ curl -vs https://ipv6.xn--sb-lka.org/  # (<-- NOT PART OF CHALLENGE)
  If it returns your IP then IPv6 is working
  If it returns _any kind of error messages_ ("Network is unreachable" / "Unable to connect" / "Site unavailable") this means _your_ IPv6 is not working - and unfortunately we can't help with that.
