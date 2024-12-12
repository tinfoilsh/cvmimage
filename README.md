# Azure CVM Provisioning

## Create scratch ramdisk

```bash
sudo mkdir /mnt/ramdisk
sudo mount -o size=128G -t tmpfs none /mnt/ramdisk
```

# Copy provisioning service
```bash
scp azure-provisioning.py tinfoil-gpu:/usr/local/azure-provisioning.py
scp azure-provisioning.service tinfoil-gpu:/etc/systemd/system/azure-provisioning.service
```

## Remove guest agent and enable provisioning updater
```bash
sudo apt -y remove walinuxagent
rm -rf /var/lib/walinuxagent
rm -rf /etc/ walinuxagent.conf
rm -rf /var/log/ walinuxagent.log

sudo systemctl daemon-reload
sudo systemctl enable --now azure-provisioning
```
