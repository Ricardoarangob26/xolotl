#!/bin/sh
# Xolotl — recolector de estado de un servidor Linux. SOLO LECTURA.
#
# No instala, no cambia ni reinicia nada. No copia secretos: ni llaves, ni contenido de
# /etc/shadow (solo los NOMBRES de cuentas sin contraseña), ni historiales, ni variables de entorno.
# Con sudo ve más (sshd -T, sudoers, procesos de cada puerto); sin sudo igual sirve para los
# paquetes y la mayoría de las comprobaciones.
#
#   sudo sh xolotl-collect.sh > xolotl-$(hostname -s).txt
#
# La salida es texto plano en secciones "===XOLOTL nombre===" que lee scan_host.

LC_ALL=C
export LC_ALL
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

sec() { printf '\n===XOLOTL %s===\n' "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }
# Corta comandos que podrían colgarse (find en discos grandes, systemctl en hosts raros).
lim() { if has timeout; then timeout 60 "$@"; else "$@"; fi; }

sec meta
echo "version=1"
echo "fecha=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
echo "hostname=$(hostname 2>/dev/null)"
echo "fqdn=$(hostname -f 2>/dev/null)"
echo "uid=$(id -u)"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
echo "uptime_s=$(cut -d. -f1 /proc/uptime 2>/dev/null)"

sec os_release
cat /etc/os-release 2>/dev/null
sec debian_version
cat /etc/debian_version 2>/dev/null
sec redhat_release
cat /etc/redhat-release 2>/dev/null

# ── Paquetes: lo que decide las vulnerabilidades ──
if has dpkg-query; then
  sec pkgs_deb
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' 2>/dev/null | grep '^ii'
fi
if has rpm; then
  sec pkgs_rpm
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null | grep -v '^gpg-pubkey'
fi
if has apk; then
  sec pkgs_apk
  apk info -v 2>/dev/null
fi

sec kernels_installed
if has rpm; then rpm -q kernel kernel-core 2>/dev/null | grep -v 'not installed'; fi
if has dpkg-query; then dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null | awk '$1=="ii"{print $2}'; fi
sec reboot_required
[ -f /var/run/reboot-required ] && echo "yes"
if has needs-restarting; then needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo "yes"; fi

# ── Red ──
sec listening
if has ss; then ss -H -tulpn 2>/dev/null || ss -tulpn 2>/dev/null; elif has netstat; then netstat -tulpn 2>/dev/null; fi

# ── SSH ──
sec sshd_effective
if has sshd && [ "$(id -u)" = "0" ]; then sshd -T 2>/dev/null; fi
sec sshd_config
grep -hEv '^\s*(#|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null

# ── Cuentas (sin secretos) ──
sec passwd
cut -d: -f1,3,4,6,7 /etc/passwd 2>/dev/null
sec empty_passwords
if [ -r /etc/shadow ]; then awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null; else echo "__sin_permiso__"; fi
sec sudoers_nopasswd
if [ -r /etc/sudoers ]; then grep -hE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; else echo "__sin_permiso__"; fi
sec group_privileged
getent group docker wheel sudo adm 2>/dev/null
sec login_defs
grep -E '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|UMASK|ENCRYPT_METHOD)' /etc/login.defs 2>/dev/null

# ── Endurecimiento ──
sec selinux
if has getenforce; then getenforce 2>/dev/null; fi
sec apparmor
if has aa-enabled; then aa-enabled 2>/dev/null; elif [ -f /sys/module/apparmor/parameters/enabled ]; then cat /sys/module/apparmor/parameters/enabled; fi
sec firewall
for s in firewalld ufw nftables iptables netfilter-persistent; do
  if has systemctl; then printf '%s=%s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"; fi
done
if has ufw && [ "$(id -u)" = "0" ]; then ufw status 2>/dev/null | head -1; fi
if has nft && [ "$(id -u)" = "0" ]; then printf 'nft_rules=%s\n' "$(nft list ruleset 2>/dev/null | grep -c .)"; fi
if has iptables && [ "$(id -u)" = "0" ]; then printf 'iptables_rules=%s\n' "$(iptables -S 2>/dev/null | grep -vc '^-P')"; fi
sec sysctl
for k in kernel.randomize_va_space net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
         net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter fs.suid_dumpable \
         kernel.kptr_restrict kernel.dmesg_restrict fs.protected_symlinks fs.protected_hardlinks; do
  printf '%s=%s\n' "$k" "$(sysctl -n "$k" 2>/dev/null)"
done
sec services_enabled
if has systemctl; then lim systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}'; fi
sec services_active
for s in auditd chronyd chrony systemd-timesyncd ntpd dnf-automatic.timer unattended-upgrades apt-daily-upgrade.timer fail2ban \
         telnet.socket rsh.socket rlogin.socket tftp.socket vsftpd xinetd avahi-daemon cups snmpd rpcbind nfs-server smb docker containerd; do
  if has systemctl; then printf '%s=%s/%s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)" "$(systemctl is-enabled "$s" 2>/dev/null)"; fi
done
sec time_sync
if has timedatectl; then timedatectl show -p NTPSynchronized --value 2>/dev/null; fi
sec auto_updates
grep -hs '^\s*APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/* 2>/dev/null
grep -hs '^\s*apply_updates' /etc/dnf/automatic.conf 2>/dev/null
sec mounts
grep -E ' (/tmp|/var/tmp|/dev/shm|/home) ' /proc/mounts 2>/dev/null

# ── Archivos ──
sec suid
lim find /usr /bin /sbin /opt /srv /home /var -xdev -type f -perm -4000 2>/dev/null
sec world_writable_etc
lim find /etc -xdev -type f -perm -0002 2>/dev/null
sec cron_writable
lim find /etc/cron* /var/spool/cron -xdev -type f -perm -0002 2>/dev/null

# ── Contenedores ──
sec docker
if has docker && [ "$(id -u)" = "0" ]; then docker ps --format '{{.Image}}\t{{.Names}}\t{{.Ports}}' 2>/dev/null; fi

sec fin
echo ok
