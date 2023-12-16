1. Make /etc/systemd/system/mybackup.servie
2. Paste in this file
```
[Unit]
Description=My script
After=network.target

[Service]
Type=simple
ExecStart=/путь_к_вашему_скрипту/backup.sh

[Install]
WantedBy=multi-user.target
```
3. Run commands
```
sudo systemctl daemon-reload
sudo systemctl enable mybackup.service
```
-------------------------------
Command for checking logs
```
grep "Backup" /var/log/syslog
```
Command for checking running scriph.sh in background
```
ps aux | grep script.sh
```


