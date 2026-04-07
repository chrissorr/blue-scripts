# Blue Team 5-Minute Scripts

## Overview
Simple scripts for quickly securing Debian boxes during competition.

- Safe by default
- Most support **--dry-run**
- Changes are mostly reversible

## Scripts

### Core Hardening
- **harden_debian.sh** - system audit + cleanup
- **harden_firewall.sh** - UFW rules
- **harden_ssh.sh** - SSH lockdown + key audit
- **harden_sudo.sh** - remove bad sudo access
- **harden_sysctl.sh** - kernel hardening

### Apache Hardening
- **harden_apache.sh** - general hardening of apache service

### Active Response
- **triage.sh** - provides prioritized report for needed actions
- **kill_sessions.sh** - kill attacker SSH sessions
- **remove_users.sh** - remove unauthorized users
- **rotate_creds.sh** - rotate passwords
- **proc_monitor.sh** - flag suspicious/unexpected processes
- **log_monitor.sh** - highlight suspicious logs

## Recommended Order

    sudo ./kill_sessions.sh
    sudo ./remove_users.sh
    sudo ./rotate_creds.sh
    sudo ./harden_firewall.sh
    sudo ./harden_ssh.sh
    sudo ./harden_sudo.sh
    sudo ./harden_sysctl.sh
    sudo ./harden_debian.sh

## Before Running

Update these in the scripts:
- **ALLOWED_USERS**
- **TEAM_PUBKEYS**
- **AUTHORIZED_SUDO_USERS**
- **PROTECTED_USERS**
- **ROTATE_USERS**
- **EXTRA_INBOUND_PORTS**

Make sure:
- Grey team is not blocked
- Required ports are allowed

## Dry Run

    sudo ./script.sh --dry-run

## Reverting Changes

### Firewall

    ufw --force reset
    ufw disable

### SSH

    rm /etc/ssh/sshd_config.d/99-blueteam-hardening.conf
    systemctl restart sshd

### Sysctl

    rm /etc/sysctl.d/99-blueteam.conf
    sysctl --system

### Sudo

    rm /etc/sudoers.d/99-blueteam-hardening
    visudo -c

Backups:

    /root/sudoers_backups/

### Disabled Tools (**harden_debian.sh**)

    mv /usr/bin/<tool>.disabled /usr/bin/<tool>

### **ld.so.preload**

    cp /root/harden_backups/ld.so.preload.bak /etc/ld.so.preload

## Notes

- User removal is not easily reversible
- Home directories are archived to **/root/evidence/**
- Password rotation only shows once, save the output
- Firewall mistakes can break scoring
- SSH mistakes can lock you out

## Useful Outputs

Snapshots:

    /root/system_snapshot/

Compare snapshots:

    diff old new