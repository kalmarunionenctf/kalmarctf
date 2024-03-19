#!/usr/bin/env bash
shopt -s nullglob  # make sure `for blah in /*` doesn't match `.`

# Kill it after 10 min
{
    sleep 10m
    kill $$
} &

# https://stackoverflow.com/a/13322667
#read -r _{,} _ _ _ _ SERVER_IP _ < <(ip r g 1)

# On remote we are spawning game.sh using socat, like this:
# socat -6 TCP-LISTEN:1336,fork SYSTEM:'echo "game spawned at http://$SOCAT_SOCKADDR:1337" ; timeout 15m /game.sh'
# But locally you should probably just run it directly, setting SERVER_IP="127.0.0.1"
SERVER_IP="${SOCAT_SOCKADDR:1:-1}"  # IPv6 without [ ]
[ -z "$SERVER_IP" ] && exit 1

GAME_DIR="/tmp/actungdebash.${SERVER_IP}"
PLAYERS_DIR="$GAME_DIR/players"

# PORTS:
# 1336: spawn game (`socat -6 TCP-LISTEN:1336,fork SYSTEM:'echo "game spawned at http://$SOCAT_SOCKADDR:1337" ; timeout 15m /game.sh'`)
# 1337: web interface
# 1338: get state
# 1339: input

get() {
  cat "$1" 2>/dev/null
}

game_state() {
  # prints lobby or game canvas
  if [ -f "$GAME_DIR/lobby" ]; then
    printf "\033cWaiting for players to ready up.\n\n\t\x1b[1mbash <(curl -s http://[%s]:1337)\x1b[0m\n\nPress \x1b[4mwasd\x1b[0m when connected, then \x1b[4mr\x1b[0m when ready.\n\n\n" "$SERVER_IP"
    for player in "$PLAYERS_DIR"/*;
    do
      local player_info="$(get "$player/color") $(get "$player/name")"
      if [ "$(get "$player/input")" == "r" ]
      then
        echo -e "  ✅ READY               $player_info"
      else
        echo -e "  ⌛ not ready yet       $player_info"
      fi
    done
  else
    printf '\033c'
    for y in {0..19};
    do
      # ${arr[@]:s:n} 	Retrieve n elements starting at index s
      printf "%s%s" "${canvas[@]:y*20:20}" "\n"
    done
    printf "\n"
  fi
}

client_server() {
  while true ; do printf 'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ndraw() { while :; do timeout 1s nc -dN %s 1338; sleep 1; done }\ninput() { S="$RANDOM"; while :; do read -sn1 c && printf "$S $(whoami)%s $c" | timeout 1s nc -N %s 1339; done }\ndraw & input ; fg\n' "$SERVER_IP" "$RANDOM" "$SERVER_IP" | timeout 1s nc -Nl "$SERVER_IP" 1337 > /dev/null; done
}

state_server() {
  while true ; do printf "\n%s\n" "$(cat "$GAME_DIR/screen")" | timeout 1s nc -Nl "$SERVER_IP" 1338 > /dev/null; done
}

harden() {
  result="$(echo "$1"      | tr -d 'fl g')"     # harden: don't need "flag" (but "a" is valid)
  result="$(echo "$result" | tr -d 'zxcݍbnm')"  # harden: don't need the lowest row of keyboard
  result="$(echo "$result" | tr -d '!\\|,^`=?_@#¤{%}&-')"  # harden: don't need these special chars
  echo "$result"
}

input_server() {
  while true
  do
    local input=$(timeout 1s nc -dl "$SERVER_IP" 1339)
    if [ -z "${input}" ]; then
      continue
    fi
    IFS=' ' read -a input_parts <<< "$input"
    local secret=$(echo "${input_parts[0]}" | sha256sum | head -c 12)
    local name="${input_parts[1]}"
    local direction=$(harden "${input_parts[-1]}")
    if [[ "$direction" =~ ^(w|a|s|d|r)(.*)$ ]]
    then
      Q="${BASH_REMATCH[0]}"
      # Allow new players to join while in lobby:
      if [ -f "$GAME_DIR/lobby" ]; then
        if mkdir "$PLAYERS_DIR/$secret" 2>/dev/null; then
          echo -n "$name" > "$PLAYERS_DIR/$secret/name"
          echo -n "$1" > "$PLAYERS_DIR/$secret/color"
          shift  # pop arg1 ($1) = next color is now first
        fi
      fi
      if [[ "$Q" -gt "quit" ]]
      then
        rm "$PLAYERS_DIR/$secret"
      fi
      # Ignore errors if dead people try moving (`$secret/` doesn't exist when dead)
      2>/dev/null echo -n "$direction" > "$PLAYERS_DIR/$secret/input"
    fi
  done
}

game() {
  rm $GAME_DIR/lobby 2>/dev/null
  # GAME LOOP: Keep running until a single player left
  while [ "$(ls $PLAYERS_DIR | wc -l)" -gt 1 ]
  do
    sleep 1
    # MOVE PLAYERS
    local playerstring=""
    for player in "$PLAYERS_DIR"/*;
      do
        local name=$(get "$player/name")
        local input=$(get "$player/input")
        local color=$(get "$player/color")
        local x=$(get "$player/x" || printf 5)
        local y=$(get "$player/y" || printf 5)

        case "$input" in
          "w")
            y=$((y - 1))
            ;;
          "a")
            x=$((x - 1))
            ;;
          "s" | "r")
            y=$((y + 1))
            ;;
          "d")
            x=$((x + 1))
            ;;
        esac
        # Allow 'border wrap', modern snake style
        # x=$((x < 0 ? 19 : x > 19 ? 0 : x))
        # y=$((y < 0 ? 19 : y > 19 ? 0 : y))

        # check if square is already colored
        local oob_x=$((x < 0 ? 1 : x > 19 ? 1 : 0))
        local oob_y=$((y < 0 ? 1 : y > 19 ? 1 : 0))
        if [ "$((oob_x+oob_y))" -gt 0 ] || [ "${canvas[$((y*20 + x))]}" != "⬜" ]
        then
          # kill thme player!
          rm -r "$player"
          canvas[$((y*20 + x))]="💀"
          continue
        fi
        # Save new state:
        canvas[$((y*20 + x))]="$color"
        printf "$x" > "$player/x"
        printf "$y" > "$player/y"
        playerstring="$playerstring$color <$name>\n"
      done

    # PRINT MAP
    printf "$(game_state)\n$playerstring\n" | tee "$GAME_DIR/screen"
  done
}

create_field() {
  canvas=( )
  for _ in {1..400}
  do
    canvas+=( "⬜" );
  done

  for player in "$PLAYERS_DIR"/*;
  do
    # assign random empty start location not too close to edge
    while true
    do
      local x=$((2 + RANDOM % 16))
      local y=$((2 + RANDOM % 16))

      if [ "${canvas[$((y*20 + x))]}" = "⬜" ]; then
        canvas[$((y*20 + x))]="$(get $player/color)"
        echo -n "$x" > "$player/x"
        echo -n "$y" > "$player/y"
        break
      fi
    done
  done
}

lobby() {
  touch $GAME_DIR/lobby
  while true
  do
    printf '\n%s\n' "$(game_state)" | tee "$GAME_DIR/screen"
    local num_players=$(ls $PLAYERS_DIR | wc -l)
    local num_ready=$(find "$PLAYERS_DIR" -type f -name input -exec cat {} \; | tr 'r' '\n' | wc -l)
    if [ "$num_players" -gt 1 ] && [ "$num_players" == "$num_ready" ]
    then
      break
    fi
    sleep 1
  done
}

win() {
  for player in "$PLAYERS_DIR"/*;
  do
    local player_info="$(get "$player/color") $(get "$player/name")"
    echo -e "\x1b[3;3H🏁 Congratulations \x1b[1m$player_info \x1b[5m🏆\x1b[0m You have won the game! 🏁" | tee "$GAME_DIR/screen"
  done
  sleep 8
}


while true
do
  rm -r $PLAYERS_DIR 2>/dev/null
  mkdir -p $PLAYERS_DIR
  touch "$GAME_DIR/screen"
  client_server &
  state_server &
  input_server "🟩" "🟥" "🟦" "⬛" "🟪" "🟧" &
  lobby
  create_field
  game
  win
  kill $!
done
