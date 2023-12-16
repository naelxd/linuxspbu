#!/bin/bash

# Read configuration from backup.conf
backupconf_dir="/root/linux/daemon/backup.conf"
backupbin_dir="/root/linux/daemon/"
source_directory=$(grep 'source_directory' $backupconf_dir | cut -d'=' -f2 | tr -d '"')
backup_directory=$(grep 'backup_directory' $backupconf_dir | cut -d'=' -f2 | tr -d '"')
backup_frequency=$(grep 'backup_frequency' $backupconf_dir | cut -d'=' -f2)

# Call the C++ binary with source_directory and backup_directory as arguments
cd $backupbin_dir
./backup_program $source_directory $backup_directory

# Log the backup activity to the system log
logger "Backup completed for $source_directory to $backup_directory"

# Sleep for the specified backup_frequency
sleep $backup_frequency

# Repeat the process
exec "$0"
