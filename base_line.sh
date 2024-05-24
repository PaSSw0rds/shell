# ;; yum install lrzsz policycoreutils policycoreutils-python -y


# [个人密钥] 
# ;bdhigr5qqj72qd4peoi3bgvmnu
PUB_Ed25519_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG39zvVLS7XBrAK4XugwqYsowak9w2N4Xrq5bzWky6zJ root@gan.guangchuan"
# ;x4mbikqfxqjamj4wapurs7y2ye
PUB_RSA_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKWRi4TFgQIvVb38NbvKRjvO1+3YSUpJwN/DdOsZGoBFQxp8nYrnw2NNbO8HN1TykF6sEMVaoGMNqzDqR9DPXoJIAuIuDyj8Wwq1xgX9lsrURWLo7ib9CJwCUwmCjbuwtbnt/aIRjeaHwhZMbPBmPyUGsbKK2AYrE7rkhdHDw5DoKQo9r9TZNGmjFkN8VixrwmjN91+GzPhWrcb+05PEbzAAx1nUNw2WgG86HKx9ahebiv0GyXuCRNvG9Mhkw5w67VOxMXhVtI9fKe43l5cQOIoPHPafWfXfzDXityBSxkbd5taIL3KYkvl8SQR8/iAZxz69NzLaasxn2jKMwyh6Wl root@gan.guangchuan"
# [配置备份目录]
BACKUPDIR=/var/log/.backups
if [ ! -d ${BACKUPDIR} ]; then mkdir -vp ${BACKUPDIR}; fi

# [配置记录目录]
HISDIR=/var/log/.history
if [ ! -d ${HISDIR} ]; then mkdir -vp ${HISDIR}; fi

## 名称: err 、info 、warning
## 用途：全局Log信息打印函数
## 参数: $@
function err() {
    printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[31mERROR: $@ \033[0m\n"
}
function info() {
    printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[32mINFO: $@ \033[0m\n"
}
function warning() {
    printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[33mWARNING: $@ \033[0m\n"
}

#系统用户及其终端核查配置
function userManager() {
    info "[-] 锁定或者删除多余的系统账户以及创建低权限用户"
    # cat /etc/passwd | cut -d ":" -f 1 | tr '\n' ' '
    defaultuser=(root bin daemon adm lp sync shutdown halt mail operator games ftp nobody systemd-network dbus polkitd sshd postfix chrony ntp rpc rpcuser nfsnobody)
    for i in $(cat /etc/passwd | cut -d ":" -f 1,7); do
        flag=0
        name=${i%%:*}
        terminal=${i##*:}
        if [[ "${terminal}" == "/bin/bash" || "${terminal}" == "/bin/sh" ]]; then
            warning "${i} 用户，shell终端为 /bin/bash 或者 /bin/sh"
        fi
        for j in ${defaultuser[@]}; do
            if [[ "${name}" == "${j}" ]]; then
                flag=1
                break
            fi
        done
        if [[ $flag -eq 0 ]]; then
            warning "${i} 非默认用户"
        fi
    done
    cp -a /etc/shadow ${BACKUPDIR}/shadow-${EXECTIME}.bak
    passwd -l adm 2 &>/dev/null &>/dev/null
    passwd -l daemon 2 &>/dev/null &>/dev/null
    passwd -l bin 2 &>/dev/null &>/dev/null
    passwd -l sys 2 &>/dev/null &>/dev/null
    passwd -l lp 2 &>/dev/null &>/dev/null
    passwd -l uucp 2 &>/dev/null &>/dev/null
    passwd -l nuucp 2 &>/dev/null &>/dev/null
    passwd -l smmsplp 2 &>/dev/null &>/dev/null
    passwd -l mail 2 &>/dev/null &>/dev/null
    passwd -l operator 2 &>/dev/null &>/dev/null
    passwd -l games 2 &>/dev/null &>/dev/null
    passwd -l gopher 2 &>/dev/null &>/dev/null
    passwd -l ftp 2 &>/dev/null &>/dev/null
    passwd -l nobody 2 &>/dev/null &>/dev/null
    passwd -l nobody4 2 &>/dev/null &>/dev/null
    passwd -l noaccess 2 &>/dev/null &>/dev/null
    passwd -l listen 2 &>/dev/null &>/dev/null
    passwd -l webservd 2 &>/dev/null &>/dev/null
    passwd -l rpm 2 &>/dev/null &>/dev/null
    passwd -l dbus 2 &>/dev/null &>/dev/null
    passwd -l avahi 2 &>/dev/null &>/dev/null
    passwd -l mailnull 2 &>/dev/null &>/dev/null
    passwd -l nscd 2 &>/dev/null &>/dev/null
    passwd -l vcsa 2 &>/dev/null &>/dev/null
    passwd -l rpc 2 &>/dev/null &>/dev/null
    passwd -l rpcuser 2 &>/dev/null &>/dev/null
    passwd -l nfs 2 &>/dev/null &>/dev/null
    passwd -l sshd 2 &>/dev/null &>/dev/null
    passwd -l pcap 2 &>/dev/null &>/dev/null
    passwd -l ntp 2 &>/dev/null &>/dev/null
    passwd -l haldaemon 2 &>/dev/null &>/dev/null
    passwd -l distcache 2 &>/dev/null &>/dev/null
    passwd -l webalizer 2 &>/dev/null &>/dev/null
    passwd -l squid 2 &>/dev/null &>/dev/null
    passwd -l xfs 2 &>/dev/null &>/dev/null
    passwd -l gdm 2 &>/dev/null &>/dev/null
    passwd -l sabayon 2 &>/dev/null &>/dev/null
    passwd -l named 2 &>/dev/null &>/dev/null

}

function passwdManager() {
    info "[-] 配置满足策略的root管理员密码"
    TMPASSWD=$(openssl rand -base64 10)
    echo ${TMPASSWD} | passwd --stdin root
    warning "[!] ROOT 用户密码为 【${TMPASSWD}】, 请注意保存! "
    warning "[!] ROOT 用户密码为 【${TMPASSWD}】, 请注意保存! "
    warning "[!] ROOT 用户密码为 【${TMPASSWD}】, 请注意保存! "
    read -r -p "按任意键以继续… " input
    case $input in
    *)
        sleep 3
        ;;
    esac

    info "[-] 为ROOT注册密钥"
    mkdir -p /root/.ssh
    touch /root/.ssh/authorized_keys
    echo ${PUB_RSA_KEY} >>/root/.ssh/authorized_keys
    echo ${PUB_Ed25510_KEY} >>/root/.ssh/authorized_keys

    info "[-] 用户口令复杂性策略设置 (密码过期周期0~90、到期前15天提示、密码长度至少8、复杂度设置至少有一个大小写、数字、特殊字符、密码三次不能一样、尝试次数为三次)"
    cp /etc/login.defs ${BACKUPDIR}/login.defs.bak
    cp /etc/pam.d/password-auth ${BACKUPDIR}/password-auth.bak
    cp /etc/pam.d/system-auth ${BACKUPDIR}/system-auth.bak

    egrep -q "^\s*PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MIN_DAYS  0/" /etc/login.defs || echo "PASS_MIN_DAYS  0" >>/etc/login.defs
    egrep -q "^\s*PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MAX_DAYS  90/" /etc/login.defs || echo "PASS_MAX_DAYS  90" >>/etc/login.defs
    egrep -q "^\s*PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$/\PASS_WARN_AGE  15/" /etc/login.defs || echo "PASS_WARN_AGE  15" >>/etc/login.defs
    egrep -q "^\s*PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$/\PASS_MIN_LEN  8/" /etc/login.defs || echo "PASS_MIN_LEN  8" >>/etc/login.defs

    egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri '/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=  minlen=15 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=1 enforce_for_root/g;}' /etc/pam.d/password-auth
    egrep -q "^password\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri '/^password\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=3/g;}' /etc/pam.d/password-auth

    egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri '/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=  minlen=15 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=1 enforce_for_root/g;}' /etc/pam.d/system-auth
    egrep -q "^password\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri '/^password\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=3/g;}' /etc/pam.d/system-auth

    info "[-] 存储用户密码的文件，其内容经过sha512加密，所以非常注意其权限"
    # 解决首次登录配置密码时提示"passwd: Authentication token manipulation error"
    touch /etc/security/opasswd && chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd
}

function fileManager() {
    info "[-] 设置或恢复重要目录和文件的权限(设置日志文件非全局可写)"
    chmod 600 ~/.ssh/authorized_keys
    chmod 755 /etc
    chmod 755 /etc/passwd
    chmod 755 /etc/shadow
    chmod 755 /etc/security
    chmod 644 /etc/group
    chmod 644 /etc/services
    chmod 750 /etc/rc*.d
    chmod 755 /var/log/messages
    chmod 775 /var/log/spooler
    chmod 775 /var/log/cron
    chmod 775 /var/log/secure
    chmod 775 /var/log/maillog
    chmod 775 /var/log/mail 2 &>/dev/null &>/dev/null
    chmod 775 /var/log/localmessages 2 &>/dev/null &>/dev/null

    info "[-] 删除潜在威胁文件 "
    find / -maxdepth 3 -name hosts.equiv | xargs rm -rf
    find / -maxdepth 3 -name .netrc | xargs rm -rf
    find / -maxdepth 3 -name .rhosts | xargs rm -rf

    rpm -q acl >/dev/null
    if [ $? -eq 0 ]; then
        info "[-] 设置日志目录的默认权限为0600，日志轮替配置文件和审计配置文件为0644"
        chmod -R 0600 /var/log
        chmod 0644 /etc/rsyslog.conf
        chmod 0644 /etc/audit/auditd.conf
        setfacl -d -m u::rw- /var/log
    else
        err "[!] ACL软件包未安装"
    fi

    info "[-] 设置日志轮替为每日分割，且最大180次分割。"
    #egrep -q "weekly$" /etc/logrotate.conf && sed -i '/weekly/ s/.*/daily/' /etc/logrotate.conf
    egrep -q "^\s?*weekly\s+.+$" /etc/logrotate.conf && sed -ri "s|^(#)?weekly.*|daily|" /etc/logrotate.conf
    egrep -q "^\s?*rotate\s+.+$" /etc/logrotate.conf && sed -ri "s|^(#)?rotate.*|rotate 180|" /etc/logrotate.conf
    info "[-] 追加nginx日志分割。"
    tmp="
    /TRS/APP/nginx/logs/*.log {
        olddir /TRS/APP/nginx/logs/history
        daily
        create
        copytruncate
        rotate 360
        compress
        notifempty
        dateext
        sharedscripts
        missingok
        postrotate
            nginx -s reopen
        endscript
        lastaction
            find /TRS/APP/nginx/logs/history -type f -mtime -1 -exec md5sum {} >> /TRS/APP/nginx/logs/md5s.txt \;
        endscript
        su root root
    }
    "
    echo "$tmp" >>/etc/logrotate.d/nginx

    info "[-] 设置审计日志分割"
    egrep -q "^\s?*max_log_file_action\s+.+$" /etc/audit/auditd.conf && sed -ri "s|^(#)?max_log_file_action.*|max_log_file_action=ignore|" /etc/audit/auditd.conf
    kill -HUP $(pidof auditd)
    mkdir -p /var/log/.history/audit
    tmp="
    /var/log/audit/audit.log {
        olddir /var/log/.history/audit
        daily
        create
        copytruncate
        rotate 360
        compress
        notifempty
        dateext
        sharedscripts
        missingok
        lastaction
            find /var/log/.history/audit -type f -mtime -1 -exec md5sum {} >> /var/log/.history/audit/md5s.txt \;
        endscript
        su root root
    }
    "
    echo "$tmp" >>/etc/logrotate.d/audit
}

function sshManager() {
    info "[-] sshd 服务安全加固设置"
    cp /etc/ssh/sshd_config ${BACKUPDIR}/sshd_config.bak
    # 严格模式
    #sudo egrep -q "^\s*StrictModes\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*StrictModes\s+.+$/StrictModes yes/" /etc/ssh/sshd_config || echo "StrictModes yes" >>/etc/ssh/sshd_config
    # 默认的监听端口更改
    #if [ -e ${SSHPORT} ]; then export SSHPORT=20211; fi
    #sudo egrep -q "^\s*Port\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*Port\s+.+$/Port ${SSHPORT}/" /etc/ssh/sshd_config || echo "Port ${SSHPORT}" >>/etc/ssh/sshd_config
    # 禁用X11转发以及端口转发
    sudo egrep -q "^\s*X11Forwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11Forwarding\s+.+$/X11Forwarding no/" /etc/ssh/sshd_config || echo "X11Forwarding no" >>/etc/ssh/sshd_config
    sudo egrep -q "^\s*X11UseLocalhost\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11UseLocalhost\s+.+$/X11UseLocalhost yes/" /etc/ssh/sshd_config || echo "X11UseLocalhost yes" >>/etc/ssh/sshd_config
    sudo egrep -q "^\s*AllowTcpForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowTcpForwarding\s+.+$/AllowTcpForwarding no/" /etc/ssh/sshd_config || echo "AllowTcpForwarding no" >>/etc/ssh/sshd_config
    sudo egrep -q "^\s*AllowAgentForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowAgentForwarding\s+.+$/AllowAgentForwarding no/" /etc/ssh/sshd_config || echo "AllowAgentForwarding no" >>/etc/ssh/sshd_config
    # 关闭禁用用户的 .rhosts 文件  ~/.ssh/.rhosts 来做为认证: 缺省IgnoreRhosts yes
    egrep -q "^(#)?\s*IgnoreRhosts\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*IgnoreRhosts\s+.+$/IgnoreRhosts yes/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >>/etc/ssh/sshd_config
    # 禁止root远程登录（推荐配置-根据需求配置）
    #egrep -q "^\s*PermitRootLogin\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^\s*PermitRootLogin\s+.+$/PermitRootLogin no/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >>/etc/ssh/sshd_config
}
function loginManager() {
    info "[-] 用户远程连续登录失败10次锁定帐号5分钟包括root账号"
    if [ ! -f "/etc/pam.d/sshd" ]; then
        err "[!] /etc/pam.d/sshd 文件不存在, 请手动上传此PAM策略文件!"
        sleep 2
    else
        cp /etc/pam.d/sshd ${BACKUPDIR}/sshd.bak
    fi

    cp /etc/pam.d/login ${BACKUPDIR}/login.bak

    # 远程登陆
    sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/sshd
    sed -ri '2a auth required pam_tally2.so deny=10 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/sshd
    # 宿主机控制台登陆(可选)
    # sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/login
    # sed -ri '2a auth required pam_tally2.so deny=10 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/login

    info "[-] 设置登录超时时间为10分钟 "
    egrep -q "^\s*(export|)\s*TMOUT\S\w+.*$" /etc/profile && sed -ri "s/^\s*(export|)\s*TMOUT.\S\w+.*$/export TMOUT=600\nreadonly TMOUT/" /etc/profile || echo -e "export TMOUT=600\nreadonly TMOUT" >>/etc/profile
    egrep -q "^\s*.*ClientAliveInterval\s\w+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*.*ClientAliveInterval\s\w+.*$/ClientAliveInterval 600/" /etc/ssh/sshd_config || echo "ClientAliveInterval 600" >>/etc/ssh/sshd_config

    info "[*] 某些三级等保还需要配置 /etc/hosts.allow 和 /etc/hosts.deny 请手动配置!"
    sleep 2
}
function Optimizationn() {
    info "[-] 正在进行操作系统内核参数优化设置......."

    # (1) 系统内核参数的配置(/etc/sysctl.conf)
    info "[-] 系统内核参数的配置/etc/sysctl.conf"

    # /etc/sysctl.d/99-kubernetes-cri.conf
    egrep -q "^(#)?net.ipv4.ip_forward.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.ipv4.ip_forward.*|net.ipv4.ip_forward = 1|g" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
    # egrep -q "^(#)?net.bridge.bridge-nf-call-ip6tables.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.bridge.bridge-nf-call-ip6tables.*|net.bridge.bridge-nf-call-ip6tables = 1|g" /etc/sysctl.conf || echo "net.bridge.bridge-nf-call-ip6tables = 1" >> /etc/sysctl.conf
    # egrep -q "^(#)?net.bridge.bridge-nf-call-iptables.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.bridge.bridge-nf-call-iptables.*|net.bridge.bridge-nf-call-iptables = 1|g" /etc/sysctl.conf || echo "net.bridge.bridge-nf-call-iptables = 1" >> /etc/sysctl.conf
    egrep -q "^(#)?net.ipv6.conf.all.disable_ipv6.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.ipv6.conf.all.disable_ipv6.*|net.ipv6.conf.all.disable_ipv6 = 1|g" /etc/sysctl.conf || echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf
    egrep -q "^(#)?net.ipv6.conf.default.disable_ipv6.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.ipv6.conf.default.disable_ipv6.*|net.ipv6.conf.default.disable_ipv6 = 1|g" /etc/sysctl.conf || echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.conf
    #egrep -q "^(#)?net.ipv6.conf.lo.disable_ipv6.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.ipv6.conf.lo.disable_ipv6.*|net.ipv6.conf.lo.disable_ipv6 = 1|g" /etc/sysctl.conf || echo "net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.conf
    egrep -q "^(#)?net.ipv6.conf.all.forwarding.*" /etc/sysctl.conf && sed -ri "s|^(#)?net.ipv6.conf.all.forwarding.*|net.ipv6.conf.all.forwarding = 1|g" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.conf
    egrep -q "^(#)?vm.max_map_count.*" /etc/sysctl.conf && sed -ri "s|^(#)?vm.max_map_count.*|vm.max_map_count = 262144|g" /etc/sysctl.conf || echo "vm.max_map_count = 262144" >>/etc/sysctl.conf

    tee -a /etc/sysctl.conf <<'EOF'
# 调整提升服务器负载能力之外,还能够防御小流量的Dos、CC和SYN攻击
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
# net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_fin_timeout = 60
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_fastopen = 3

# 优化TCP的可使用端口范围及提升服务器并发能力(注意一般流量小的服务器上没必要设置如下参数)
#net.ipv4.tcp_keepalive_time = 1200
#net.ipv4.tcp_max_syn_backlog = 8192
#net.ipv4.tcp_max_tw_buckets = 5000
#net.ipv4.ip_local_port_range = 1024 65535

# 优化核套接字TCP的缓存区
net.core.netdev_max_backlog = 8192
net.core.somaxconn = 8192
net.core.rmem_max = 12582912
net.core.rmem_default = 6291456
net.core.wmem_max = 12582912
net.core.wmem_default = 6291456
EOF
    # (2) Linux 系统的最大进程数和最大文件打开数限制
    info "[-] Linux 系统的最大进程数和最大文件打开数限制 "
    egrep -q "^\s*ulimit -HSn\s+\w+.*$" /etc/profile && sed -ri "s/^\s*ulimit -HSn\s+\w+.*$/ulimit -HSn 65535/" /etc/profile || echo "ulimit -HSn 65535" >>/etc/profile
    egrep -q "^\s*ulimit -HSu\s+\w+.*$" /etc/profile && sed -ri "s/^\s*ulimit -HSu\s+\w+.*$/ulimit -HSu 65535/" /etc/profile || echo "ulimit -HSu 65535" >>/etc/profile
    sed -i "/# End/i *  soft  nofile  65535" /etc/security/limits.conf
    sed -i "/# End/i *  hard  nofile  65535" /etc/security/limits.conf
    sed -i "/# End/i *  soft  nproc   65535" /etc/security/limits.conf
    sed -i "/# End/i *  hard  nproc   65535" /etc/security/limits.conf
    sysctl -p
}

# function lvsmanager () {
#   echo "\n分区信息:"
#   sudo df -Th
#   sudo lsblk
#   echo -e "\n 磁盘信息："
#   sudo fdisk -l
#   echo -e "\n PV物理卷查看："
#   sudo pvscan
#   echo -e "\n vgs虚拟卷查看："
#   sudo vgs
#   echo -e "\n lvscan逻辑卷扫描:"
#   sudo lvscan
#   echo -e "\n 分区扩展"
#   echo "CentOS \n lvextend -L +24G /dev/centos/root"
#   echo "lsblk"
#   echo -e "Centos \n # xfs_growfs /dev/mapper/centos-root"
# }

function historyManager() {
    info "[-] 用户终端执行的历史命令记录 "
    egrep -q "^HISTSIZE\W\w+.*$" /etc/profile && sed -ri "s/^HISTSIZE\W\w+.*$/\#HISTORY WILL BE LOAD IN profile.d THIS LINE MAKE NO SENSE!!!!!!/" /etc/profile
    #egrep -q "^HISTSIZE\W\w+.*$" /etc/profile && sed -ri "s/^HISTSIZE\W\w+.*$/HISTSIZE=101/" /etc/profile || echo "HISTSIZE=101" >> /etc/profile
    sudo tee /etc/profile.d/history-record.sh <<'EOF'
# 历史命令执行记录文件路径
LOGTIME=$(date +%Y%m%d-%H-%M-%S)
export HISTDIR="/var/log/.history/${USER}"
export HISTFILE="/var/log/.history/${USER}/${LOGTIME}.history"
readonly HISTFILE
readonly HISTDIR
if [ ! -d ${HISTDIR} ];then
  mkdir ${HISTDIR}
fi
if [ ! -f ${HISTFILE} ];then
  touch ${HISTFILE}
fi
chmod 600 /var/log/.history/${USER}/${LOGTIME}.history
# 历史命令执行文件大小记录设置
USER_IP=$(who -u am i 2>/dev/null| awk '{print $NF}'|sed -e 's/[()]//g')
HISTSIZE=65535
HISTFILESIZE=128
HISTTIMEFORMAT="${USER_IP} - [%F/%T] - $(whoami) - "
shopt -s histappend
PROMPT_COMMAND="history -a"
readonly HISTTIMEFORMAT
EOF
}

function createNoRoot() {
    info "[-] 新建用户"
    useradd -G root -c "Create By Gan GuangChuan TRS(R)(C)" toor
    TMPASSWD=$(openssl passwd ",./<>?")
    echo toor:${TMPASSWD} | chpasswd
    echo ${TMPASSWD} | passwd --stdin toor

    warning "[!] toor 用户密码为 ${TMPASSWD}，请注意保存！"
    sleep 3

    info "[-] 分配密钥"
    mkdir -p /home/toor/.ssh/
    touch /home/toor/.ssh/authorized_keys
    echo ${PUB_RSA_KEY} >>/home/toor/.ssh/authorized_keys
    echo ${PUB_Ed25519_KEY} >>/home/toor/.ssh/authorized_keys
    # 恢复目录权限
    chown toor:toor -R /home/toor
    chmod 0600 -R /home/toor/.ssh

    info "[-] 追加用户的SUDO权限"
    cp /etc/sudoers /etc/sudoers.bak
    # 一些服务器不支持 include 语法，需要判断注意
    # egrep -q "^(#)?includedir.*" /etc/sudoers && sed -ri "s|^(#)?includedir.*|includedir \/etc\/sudoers.d|g" /etc/sudoers || TMPSUDO=0
    # 2023.05.17 include 语法还不知道为什么一直会报错，暂时都追加到根文件中去
    TMPSUDO=0
    if [ ${TMPSUDO} -ne 0 ]; then
        # 不支持 include 的时候，直接追加
        SUDOPATH="/etc/sudoers"
    else
        # 支持语法
        mkdir -p /etc/sudoers.d/
        touch /etc/sudoers.d/toor
        SUDOPATH="/etc/sudoers.d/toor"
    fi
    cat >>${SUDOPATH} <<EOF
    #Create By Gan.GuangChuan. Tel: 13560089519. 允许toor用户免密使用sudo
    toor      ALL=(ALL)             NOPASSWD:ALL
EOF

    info "[-] 追加用户的SU权限"
    cp /etc/pam.d/su /etc/pam.d/.su.bak
    # cat >>/etc/pam.d/su <<EOF
    # #Create By Gan.GuangChuan. Tel: 13560089519. 允许toor用户使用su
    # auth        sufficient  pam_succeed_if.so use_uid user = toor
    new_lines="auth       [success=ignore default=1] pam_succeed_if.so user = toor\nauth       sufficient   pam_succeed_if.so use_uid user ingroup toor"
    sed -i '/pam_succeed_if.so/ a\'"$new_lines" /etc/pam.d/su


    info "[-] 修改一些SSHD设置(DNS和X11转发)"
    egrep -q "^\s*UseDNS\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*UseDNS\s+.+$/UseDNS no/" /etc/ssh/sshd_config
    egrep -q "^\s*X11Forwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11Forwarding\s+.+$/X11Forwarding no/" /etc/ssh/sshd_config

}

info "[-] 远程SSH登录前后提示警告Banner设置"
egrep -q "^\s*(banner|Banner)\s+\W+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*(banner|Banner)\s+\W+.*$/Banner \/etc\/issue/" /etc/ssh/sshd_config ||
    echo "Banner /etc/issue" >>/etc/ssh/sshd_config
sudo rm -f /etc/issue
sudo tee /etc/issue <<'EOF'
####################### [ 安全登陆 (Security Login) ] ########################
                    正在尝试授权，您的所有操作将会被审计和记录。


EOF
# SSH登录后提示Banner
# 艺术字B格: http://www.network-science.de/ascii/
sudo rm -f /etc/motd
sudo tee /etc/motd <<'EOF'

####################### [ 安全运维 (Security Operation) ] ####################
                          _______   _____     _____
                         |__   __| |  __ \   / ____|
                            | |    | |__) | | (___
                            | |    |  _  /   \___ \
                            | |    | | \ \   ____) |
                            |_|    |_|  \_\ |_____/

登录成功，我们信任您有足够的能力来承担每一条命令执行后的结果。权力越大责任越大，祝您好运。
EOF

info "[-] 记录安全事件日志，开启审计 (需要一点时间...)"
touch /var/log/.history/adm &>/dev/null
chmod 755 /var/log/.history/adm
# ------------------------------------------------------------------------------------
semanage fcontext -a -t security_t '/var/log/.history/adm'
if [ $? -ne 0 ]; then
    # ;; policycoreutils policycoreutils-python
    err "[!] 执行 semanage 命令失败, 请检查服务器是否安装 semanage !"
    read -r -p "按任意键以继续… " input
    case $input in
    *)
        sleep 3
        ;;
    esac    
fi
restorecon -v '/var/log/.history/adm' &>/dev/null
egrep -q "^\s*\*\.err;kern.debug;daemon.notice\s+.+$" /etc/rsyslog.conf && sed -ri "s/^\s*\*\.err;kern.debug;daemon.notice\s+.+$/*.err;kern.debug;daemon.notice  \/var\/log\/.history\/adm/" /etc/rsyslog.conf || echo "*.err;kern.debug;daemon.notice  /var/log/.history/adm" >>/etc/rsyslog.conf
# ------------------------------------------------------------------------------------
systemctl restart rsyslog
if [ $? -ne 0 ]; then
    err "[!] 启动 rsyslog 服务失败, 请检查服务器 rsyslog 配置是否有误（一般不存在不安装此命令）!"
fi
# ------------------------------------------------------------------------------------
which auditd 2 &>/dev/null
if [ $? -eq 2 ]; then
    err "[!] 没有安装 auditd 审计插件!"
    read -r -p "按任意键以继续… " input
    case $input in
    *)
        sleep 3
        ;;
    esac    
else
    systemctl start auditd
    if [ $? -ne 0 ]; then
        err "[!] 启动 rsyslog 审计插件失败!"
        read -r -p "按任意键以继续… " input
        case $input in
        *)
            sleep 3
            ;;
    esac
    else
        systemctl enable auditd
        info "[-] 审计日志: 密码修改、selinux策略、内核模块修改"
        auditctl -w /etc/passwd -p wa -k passwd_changes
        auditctl -w /etc/selinux/ -p wa -k selinux_changes
        auditctl -w /sbin/insmod -p x -k module_insertion
        #[登录、注销、会话]
        info "[-] 审计日志: 登录、注销、会话"
        auditctl -a always,exit -F arch=b64 -S execve -k logins
        auditctl -a exit,always -F arch=b64 -S login -S logout -S session -S execve -k logins
        auditctl -a exit,always -F arch=b32 -S login -S logout -S session -S execve -k logins
        #[记录执行了特权命令（即使用了setuid或setgid标志的命令）]
        #auditctl -a exit,always -F arch=b64 -S setuid -S setgid -k priv-cmds
        #auditctl -a exit,always -F arch=b32 -S setuid -S setgid -k priv-cmds
        #[记录所有命令]
        info "[-] 记录所有命令"
        auditctl -a exit,always -F arch=b64 -S execve -F key=exec
        auditctl -a exit,always -F arch=b32 -S execve -F key=exec
        info "[-] 使用 ausearch 来查看审计日志："
        info "[·] ausearch -m execve -i / ausearch -k exec"
    fi
fi
# ------------------------------------------------------------------------------------
info "[-] SELINUX 禁用"
sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
setenforce 0 2 &>/dev/null
# ------------------------------------------------------------------------------------
info "[-] 操作系统安全加固配置(符合等保要求-三级要求)"
warning "[-] 带 * 号配置请谨慎配置, 推荐有能力的实施自行配置"

read -r -p "是否配置系统用户及其终端核查配置 [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    userManager
    ;;
esac

read -r -p "是否配置用户口令复杂性策略设置 [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    passwdManager
    ;;
esac

read -r -p "是否设置或恢复重要目录和文件的权限、日志轮替时间 [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    fileManager
    ;;
esac

# read -r -p "*** 是否设置sshd[端口/远程登录/严格模式]配置? (不推荐) [Y/n] " input
# case $input in
#     [nN][oO]|[nN])
#         ;;
#     *)
#         sshManager
#         ;;
# esac

read -r -p "* 是否设置sshd[用户远程]配置? (登录失败/超时策略) [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    loginManager
    ;;
esac

read -r -p "* 是否优化系统内核参数 [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    Optimizationn
    ;;
esac

read -r -p "是否优化终端执行的历史命令 [Y/n] " input
case $input in
[nN][oO] | [nN]) ;;
*)
    historyManager
    ;;
esac

read -r -p "是否设定一个非Root用户? [y/N] " input
case $input in
    [nN][oO] | [nN]) ;;
    [yY]) createNoRoot;;
    *) ;;
esac

info "[-] End..."
rm -f base_line.sh*
