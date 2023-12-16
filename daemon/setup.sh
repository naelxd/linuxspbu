#!/bin/bash

case "$1" in
  start)
    g++ -std=c++17 backup.cpp -o backup_program
    sudo systemctl daemon-reload
    sudo systemctl enable mybackup.service
    sudo systemctl start mybackup.service
    ;;
  restart)
    sudo systemctl restart mybackup.service
    ;;
  config)
    vi backup.conf
    ;;
  log)
    grep "Backup" /var/log/syslog
    ;;
  stop)
    sudo systemctl stop mybackup.service
    ;;
  *)
    echo "Usage: $0 {start|restart|config|log|stop}"
    exit 1
    ;;
esac
exit 0
