#!/bin/bash
mv pop pop.0
kill -USR1 `cat this.pid`
sleep 1
