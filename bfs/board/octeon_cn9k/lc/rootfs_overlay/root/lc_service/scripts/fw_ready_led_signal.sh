#!/bin/sh
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -eu

# Turn on Blue LED1 using GPIO:20 signal

base="$(cat /sys/class/gpio/gpiochip448/base)"
ac=$((base + 20))
gpiodir="/sys/class/gpio/gpio${ac}"

if [ ! -f "$gpiodir/value" ]; then
  echo "$ac" >/sys/class/gpio/export
fi

if [ ! -f "$gpiodir/value" ]; then
  echo >&2 "$0: could not turn on Blue LED1 from GPIO pin"
  exit 1
fi

echo out >"$gpiodir/direction"
echo 1 >"$gpiodir/value"
sleep 1
