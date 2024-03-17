#!/usr/bin/env bash
# Initial version of the ppu-gcc wrapper


  # -e 's/-Wl,--eh-frame-hdr//g' \
  # -e 's/-Wl,-znoexecstack//g' \
  # -e 's/-Wl,--gc-sections//g' \
  # -e 's/-Wl,-zrelro,-znow//g' \
  # -e 's/-Wl,-O1//g' \
  # -e 's/-Wl,--strip-all//g' \
  # -e 's/-Wl,-Bdynamic//g' \
  # -e 's/-Wl,-Bstatic//g' \
  # -e 's/-Wl,--as-needed//g' \
FILTERED_ARGS=$(sed \
  -e 's/-lpthread//g' \
  -e 's/-lutil//g' \
  -e 's/-lexecinfo//g' \
  -e 's/-lmemstat//g' \
  -e 's/-lkvm//g' \
  -e 's/-lprocstat//g' \
  -e 's/-ldevstat//g' \
  \
  -e 's/-lc//g' \
  <<< $@)

# mkdir -p /app/kalmarctf/o-files
# tr -s '[:blank:]' '\n' <<< $@ | grep -E '\.o$' | xargs -i cp '{}' /app/kalmarctf/o-files

# echo -e "Running ppu-gcc with\n" $FILTERED_ARGS > /app/kalmarctf/game2/args.txt

ppu-gcc $FILTERED_ARGS -v -Wl,--verbose > /app/kalmarctf/gcc-log-rust.txt
# echo $FILTERED_ARGS
