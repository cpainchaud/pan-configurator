#!/usr/bin/env bash


if [ "$#" -ne 1 ]; then
  echo ""
  echo "ERROR: | Usage: $0 MGMT_IP_ADDRESS" >&2
  echo ""
  exit 1
fi


MGMTIP=$1

php api_test_filters.php in=api://${MGMTIP} \
&& php api_test_mergers.php in=api://${MGMTIP}