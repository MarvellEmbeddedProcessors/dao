#!/bin/bash
# SPDX-License-Identifier: Marvell-MIT
# Copyright (c) 2025 Marvell.

set -eu

# Send the "all clear" signal to the GPIO.

base="$(cat /sys/class/gpio/gpiochip448/base)"
ac=$((base + 15))
gpiodir="/sys/class/gpio/gpio${ac}"

if [ ! -f "$gpiodir/value" ]; then
  echo "$ac" >/sys/class/gpio/export
fi

if [ ! -f "$gpiodir/value" ]; then
  echo >&2 "$0: could not export MCU 'all clear' GPIO pin"
  exit 1
fi

echo out >"$gpiodir/direction"
echo 1 >"$gpiodir/value"
sleep 1
echo 0 >"$gpiodir/value"
