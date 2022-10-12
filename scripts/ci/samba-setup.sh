#!/bin/sh

if [ "$USE_DOCKER" != "true" ]; then
	# Remove previous samba config and stop all services
	sudo systemctl stop smbd
	sudo systemctl disable smbd
	sudo systemctl mask smbd

	sudo systemctl stop nmbd
	sudo systemctl disable nmbd
	sudo systemctl mask nmbd

	# Enable the AD-DC samba service
	sudo systemctl unmask samba-ad-dc
	sudo systemctl enable samba-ad-dc
	sudo systemctl stop samba-ad-dc
fi

sudo rm /etc/samba/smb.conf

# Remove other samba data
for DIR in $(/usr/sbin/smbd -b | awk '/LOCKDIR|STATEDIR|CACHEDIR|PRIVATE_DIR/{print $2}'); do
	sudo rm -rf "$DIR"/*
done

sudo rm -f /etc/krb5.conf

# Configure the domain
sudo /usr/bin/samba-tool domain provision \
	--realm="example.com" \
	--domain="EXAMPLE" \
	--adminpass="secret123!" \
	--use-rfc2307 \
	--server-role=dc \
	--dns-backend=SAMBA_INTERNAL

sudo cp /var/lib/samba/private/krb5.conf /etc

# Sort resolver
if ! grep -q "nameserver 127.0.0.1" /etc/resolv.conf; then
	sudo mv /etc/resolv.conf /etc/resolv.conf.tmp
	echo "search example.com" | sudo tee /etc/resolv.conf
	echo "nameserver 127.0.0.1" | sudo tee -a /etc/resolv.conf
	grep "^nameserver" /etc/resolv.conf.tmp | sudo tee -a /etc/resolv.conf
fi

# Allow non TLS LDAP connections to Samba
sudo sed -i 's/\[global\]/\[global\]\n\tldap server require strong auth = no/' /etc/samba/smb.conf

# Start the domain controller
if [ "$USE_DOCKER" != "true" ]; then
	sudo systemctl start samba-ad-dc
else
	/usr/sbin/samba
fi
