#!/bin/bash
#shc -rvf update-openssl-openssh.default-offline.sh -o sshd-all-in-one.x
#bash <(wget -qO- https://example.com/demo.sh) 

function err() {
    printf "[%s]: \033[41;97mERROR  : %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[41;97mERROR  : $@ \033[0m\n"
}
function info() {
    printf "[%s]: \033[40;38;5;82mINFO   : %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[40;38;5;82mINFO   : $@ \033[0m\n"
}
function warn() {
    printf "[%s]: \033[43;30mWARNING: %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[43;30mWARNING: $@ \033[0m\n"
}
clear
echo -e '\e[47;30m                                                                                                    \e[0m'
echo -e '\e[47;30m                                                                                  █                 \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                 ███                \e[0m'
echo -e '\e[47;30m                                                                                 ████               \e[0m'
echo -e '\e[47;30m                                                         █                       ████               \e[0m'
echo -e '\e[47;30m          ██                                             █                      ██████              \e[0m'
echo -e '\e[47;30m         ████                                           ███                    ████████             \e[0m'
echo -e '\e[47;30m       ████████                                      █████████               ███████████            \e[0m'
echo -e '\e[47;30m     ███████████████████████████████████████████████████████████           ████████████████         \e[0m'
echo -e '\e[47;30m       ████████              ████                      █████                    ██████              \e[0m'
echo -e '\e[47;30m        ███████             ██████                      ███  ███                 ████        █      \e[0m'
echo -e '\e[47;30m        ███████  ███████████████████████████     ████████████████   ██████████████████████████████  \e[0m'
echo -e '\e[47;30m        ███████  ███████              ████████        █████████████ ████████     ███      █████████ \e[0m'
echo -e '\e[47;30m        ███████  ███████              ███████    ████  ████████████ ███████      ████     ████████  \e[0m'
echo -e '\e[47;30m        ███████  ███████              ███████    ████  █████        ███████    ████████   ████████  \e[0m'
echo -e '\e[47;30m        ███████  ███████████████████  ███████    ████  █████  ████  ██████████████████████████████  \e[0m'
echo -e '\e[47;30m        ███████  ███████              ███████    ████  █████  ████  ████████ ████████████ ████████  \e[0m'
echo -e '\e[47;30m        ███████  ███████              ███████    ████  █████  ████  ███████     ██████    ████████  \e[0m'
echo -e '\e[47;30m        ██████   ████████████████████████████    ████  █████  ████  ███████      ████     ████████  \e[0m'
echo -e '\e[47;30m       ███████   ████       ██████    ████       ████  █████  ████  ██████████████████████████████  \e[0m'
echo -e '\e[47;30m       ██████               ██████              █████  █████  ███   ███████       ██       ███████  \e[0m'
echo -e '\e[47;30m      ██████     ███████    ██████    ███████   █████  █████  █     █████        ████        █████  \e[0m'
echo -e '\e[47;30m     ██████  █████████████ ███████  ████████████████   █████                   ████████             \e[0m'
echo -e '\e[47;30m    █████   ████████        ██████        █████████    █████               ████████████████         \e[0m'
echo -e '\e[47;30m   ████      ███            ██████            ███      █████                 ████████████           \e[0m'
echo -e '\e[47;30m  █              ██         ██████         ██          █████                   ████████             \e[0m'
echo -e '\e[47;30m                            ████                       ████                     ██████              \e[0m'
echo -e '\e[47;30m                            ██                         ██                       █████               \e[0m'
echo -e '\e[47;30m                                                                                 ████               \e[0m'
echo -e '\e[47;30m                                                                                 ████               \e[0m'
echo -e '\e[47;30m                                                                                 ███                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  ██                \e[0m'
echo -e '\e[47;30m                                                                                  █                 \e[0m'
echo -e '\e[47;30m                                                                                  █                 \e[0m'
echo -e '\e[47;30m                                                                                                    \e[0m'
echo -e '\e[47;30m                                                                                                    \e[0m'
sleep 2
#export LANG="en_US.UTF-8"
source /etc/profile > /dev/null 2>&1 
source /etc/rc.d/init.d/functions > /dev/null 2>&1
setenforce 0 > /dev/null 2>&1
sed -i 's/enforcing/disabled/' /etc/selinux/config > /dev/null 2>&1


################# 禁止 Ctrl + C 退出！！！
trap 'CC' INT
function CC () {
    echo -e "\033[41;37m \t\tCtrl+C is forbidden!!!\t\t \033[0m\n"

}

#脚本变量
DATE=`date "+%Y%m%d"`
PREFIX="/usr/local"
PERL_VERSION="perl-5.38.2"
OPENSSL_VERSION="openssl-3.2.1"
OPENSSH_VERSION="openssh-9.6p1"
DROPBEAR_VERSION="dropbear-2022.83"
##PERL_DOWNLOAD="https://www.cpan.org/src/5.0/perl-$PERL_VERSION.tar.gz"
##OPENSSL_DOWNLOAD="https://www.openssl.org/source/$OPENSSL_VERSION.tar.gz"
##OPENSSH_DOWNLOAD="https://mirrors.aliyun.com/pub/OpenBSD/OpenSSH/portable/$OPENSSH_VERSION.tar.gz"
##DROPBEAR_DOWNLOAD="https://matt.ucc.asn.au/dropbear/releases/$DROPBEAR_VERSION.tar.bz2"
DROPBEAR_PORT="6666"
OPENSSH_RPM_INSTALLED=$(rpm -qa | grep ^openssh | wc -l) > /dev/null 2>&1
SYSTEM_VERSION=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/') > /dev/null 2>&1

#检查用户
if [ $(id -u) != 0 ]; then
    err "必须使用Root用户运行脚本"
    exit
fi

#检查系统
if [ ! -e /etc/redhat-release ] || [ "$SYSTEM_VERSION" == "3" ] || [ "$SYSTEM_VERSION" == "4" ];then
    err "脚本仅适用于RHEL和CentOS操作系统5.x-8.x版本" 
    exit
fi

#使用说明
info "升级OpenSSH，建议先临时安装DropbearSSH，再开始升级OpenSSH"
info "旧版本OpenSSH备份在/tmp/openssh_bak_$DATE"
info "本脚本只负责升级，需自备开发环境以便安装编译用的依赖："
info "gcc bzip2 make perl-devel pam-devel zlib-devel"
info "操作过程严禁擅自中断 否则后果自负"

#安装Dropbear
function INSTALL_DROPBEAR() {
    echo -e "\033[33m正在安装DropBearSSH\033[0m"
    echo ""	

    #安装依赖包
    yum -y install gcc bzip2 make
    if [ $? -eq 0 ];then
        action "安装依赖包成功"   /bin/true
    else
        echo -e "安装依赖包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""	

    #解压源码包
    cd /tmp
    tar xjf ~/ssh/$DROPBEAR_VERSION.tar.bz2 -C /tmp/
    if [ -d /tmp/$DROPBEAR_VERSION ];then
        action "解压源码包成功"   /bin/true
    else
        echo -e "解压源码包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""	

    #安装Dropbear
    cd /tmp/$DROPBEAR_VERSION	

    ./configure --disable-zlib > /dev/null 2>&1
    if [ $? -eq 0 ];then
        echo "开始安装Dropbear"
        make -j4 > /dev/null 2>&1
        make install -j4 > /dev/null 2>&1
    else
        echo -e "编译安装失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi	

    #启动Dropbear
    mkdir /etc/dropbear > /dev/null 2>&1
    /usr/local/bin/dropbearkey -t rsa -s 2048 -f /etc/dropbear/dropbear_rsa_host_key > /dev/null 2>&1
    /usr/local/sbin/dropbear -p $DROPBEAR_PORT > /dev/null 2>&1
    ps aux | grep dropbear | grep -v grep > /dev/null 2>&1
    if [ $? -eq 0 ];then
        rm -rf /tmp/$DROPBEAR_VERSION*
        action "启动服务端成功" /bin/true
    else
        echo -e "启动服务端失败" "\033[31m Failure\033[0m"
        exit
    fi
        firewall-cmd --add-port=6666/tcp --permanent
    if [ $? -eq 0 ];then
        rm -rf /tmp/$DROPBEAR_VERSION*
        action "开启防火墙对应端口成功" /bin/true
        firewall-cmd --reload > /dev/null 2>&1
    elif [ $? -eq 1 ];then
        echo -e "防火墙服务没有启动" "\033[33m Ignore\033[0m"
    else
        echo -e "开启防火墙时遇到致命错误" "\033[31m Failure\033[0m"
        exit
    fi
    action "安装&启动Dropbear" /bin/true
}

#卸载Dropbear
function UNINSTALL_DROPBEAR() {
    echo -e "\033[33m正在卸载DropBearSSH\033[0m"
    echo ""
    ps aux | grep dropbear | grep -v grep | awk '{print $2}' | xargs kill -9 > /dev/null 2>&1
    rm -rf /etc/dropbear
    rm -f /var/run/dropbear.pid
    rm -f /usr/local/sbin/dropbear
    rm -f /usr/local/bin/dropbearkey
    rm -f /usr/local/bin/dropbearconvert
    rm -f /usr/local/share/man/man8/dropbear*
    rm -f /usr/local/share/man/man1/dropbear*
    ps aux | grep dropbear | grep -v grep > /dev/null 2>&1
    if [ $? -ne 0 ];then
        action "卸载Dropbear" /bin/true
    else
        echo -e "卸载服务端失败" "\033[31m Failure\033[0m"
        exit
    fi
    echo ""
    firewall-cmd --remove-port=6666/tcp --permanent > /dev/null 2>&1
    if [ $? -eq 0 ];then
        rm -rf /tmp/$DROPBEAR_VERSION*
        echo -e "关闭防火墙对应端口成功" "\033[32m Success\033[0m"
        firewall-cmd --reload > /dev/null 2>&1
    elif [ $? -eq 1 ];then
        echo -e "防火墙服务没有启动" "\033[33m Ignore\033[0m"
    else
        echo -e "操作防火墙时遇到致命错误" "\033[31m Failure\033[0m"
        exit
    fi
}


function INSTALL_PERL(){
    #升级Perl
    echo -e "\033[33m正在编译Perl\033[0m (5/7)"
    cd /tmp
    tar -xzvf ~/ssh/$PERL_VERSION.tar.gz -C /tmp/
    cd $PERL_VERSION
    ./Configure -des -Dprefix=/usr/local/perl-$PERL_VERSION
    make -j4 && make install -j4
    ./installman
    ./installperl
    action "编译Perl" /bin/true    
}




#升级OpenSSL
function INSTALL_OPENSSL() {
    echo -e "\033[33m正在升级OpenSSL\033[0m"
    echo ""

    #安装依赖包
    echo -e "\033[33m安装依赖包\033[0m (1/7)"
    yum -y install gcc make perl-devel pam-devel zlib-devel
    if [ $? -eq 0 ];then
        action "安装依赖包成功" /bin/true
    else
        echo -e "安装依赖包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""

    #解压源码包
    echo -e "\033[33m解压OPENSSH和OPENSSL依赖包\033[0m (2/7)"
    cd /tmp
    tar xzf ~/ssh/$OPENSSL_VERSION.tar.gz -C /tmp/
    tar xzf ~/ssh/$OPENSSH_VERSION.tar.gz -C /tmp/
    if [ -d /tmp/$OPENSSL_VERSION ] && [ -d /tmp/$OPENSSH_VERSION ];then
        action "解压源码包成功" /bin/true
    else
        echo -e "解压源码包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""

    #创建备份目录
    echo -e "\033[33m备份OPENSSH和OPENSSL\033[0m (3/7)"
    mkdir -p /tmp/openssh_bak_$DATE/etc/{init.d,pam.d,ssh}
    mkdir -p /tmp/openssh_bak_$DATE/usr/{bin,sbin,libexec}
    mkdir -p /tmp/openssh_bak_$DATE/usr/libexec/openssh
    mkdir -p /tmp/openssl_bal_$DATE/usr/bin

    #备份旧程序
    cp -af /etc/ssh/* /tmp/openssh_bak_$DATE/etc/ssh/ > /dev/null 2>&1
    cp -af /etc/init.d/sshd /tmp/openssh_bak_$DATE/etc/init.d/ > /dev/null 2>&1
    cp -af /etc/pam.d/sshd /tmp/openssh_bak_$DATE/etc/pam.d/ > /dev/null 2>&1
    cp -af /usr/bin/scp /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/sftp /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/ssh* /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/slogin /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/sbin/sshd* /tmp/openssh_bak_$DATE/usr/sbin/ > /dev/null 2>&1
    cp -af /usr/libexec/ssh* /tmp/openssh_bak_$DATE/usr/libexec/ > /dev/null 2>&1
    cp -af /usr/libexec/sftp* /tmp/openssh_bak_$DATE/usr/libexec/ > /dev/null 2>&1
    cp -af /usr/libexec/openssh/* /tmp/openssh_bak_$DATE/usr/libexec/openssh/ > /dev/null 2>&1
    cp -af /usr/bin/openssl* /tmp/openssl_bal_$DATE/usr/bin/ > /dev/null 2>&1
    action "备份旧版本OpenSSH和OpenSSL" /bin/true

    #卸载旧程序
    #echo -e "\033[33m正在卸载旧OpenSSH\033[0m (4/7)"
    #if [ "$OPENSSH_RPM_INSTALLED" == "0" ];then
    #    rm -f /etc/ssh/*
    #    rm -f /etc/init.d/sshd
    #    rm -f /etc/pam.d/sshd
    #    rm -f /usr/bin/scp
    #    rm -f /usr/bin/sftp
    #    rm -f /usr/bin/ssh
    #    rm -f /usr/bin/slogin
    #    rm -f /usr/bin/ssh-add
    #    rm -f /usr/bin/ssh-agent
    #    rm -f /usr/bin/ssh-keygen
    #    rm -f /usr/bin/ssh-copy-id
    #    rm -f /usr/bin/ssh-keyscan
    #    rm -f /usr/sbin/sshd
    #    rm -f /usr/sbin/sshd-keygen
    #    rm -f /usr/libexec/openssh/*
    #    rm -f /usr/libexec/sftp-server
    #    rm -f /usr/libexec/ssh-keysign
    #    rm -f /usr/libexec/ssh-sk-helper
    #    rm -f /usr/libexec/ssh-pkcs11-helper
    #else
    #    rpm -e --nodeps `rpm -qa | grep ^openssh` > /dev/null 2>&1
    #    rm -f /etc/ssh/*
    #fi
    #action "卸载旧版本OpenSSH和OpenSSL" /bin/true

    #安装OpenSSL
    echo -e "\033[33m正在安装OpenSSL\033[0m (6/7)"
    cd /tmp/$OPENSSL_VERSION/
    if [ $? -eq 0 ];then
        ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl/ssl
        make -j4
        make install -j4
        # 加入运行库
        echo "/usr/local/lib" >> /etc/ld.so.conf
        echo "/usr/local/lib64" >> /etc/ld.so.conf
        ldconfig
        source /etc/profile
        # 使用替换的办法取代openssl链接
        cp /usr/local/openssl/bin/openssl /usr/bin/openssl -af

        action "安装OpenSSL" /bin/true
    else
        echo -e "编译安装OpenSSL失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
}



function INSTALL_OPENSSH() {
    #安装依赖包
    echo -e "\033[33m安装依赖包\033[0m (1/7)"
    yum -y install gcc make perl-devel pam-devel zlib-devel
    if [ $? -eq 0 ];then
        action "安装依赖包成功" /bin/true
    else
        echo -e "安装依赖包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""

    #解压源码包
    echo -e "\033[33m解压OPENSSH和OPENSSL依赖包\033[0m (2/7)"
    cd /tmp
    tar xzf ~/ssh/$OPENSSL_VERSION.tar.gz -C /tmp/
    tar xzf ~/ssh/$OPENSSH_VERSION.tar.gz -C /tmp/
    if [ -d /tmp/$OPENSSL_VERSION ] && [ -d /tmp/$OPENSSH_VERSION ];then
        action "解压源码包成功" /bin/true
    else
        echo -e "解压源码包失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi
    echo ""
        
    #创建备份目录
    echo -e "\033[33m备份OPENSSH和OPENSSL\033[0m (3/7)"
    mkdir -p /tmp/openssh_bak_$DATE/etc/{init.d,pam.d,ssh}
    mkdir -p /tmp/openssh_bak_$DATE/usr/{bin,sbin,libexec}
    mkdir -p /tmp/openssh_bak_$DATE/usr/libexec/openssh
    mkdir -p /tmp/openssl_bal_$DATE/usr/bin

    #备份旧程序
    cp -af /etc/ssh/* /tmp/openssh_bak_$DATE/etc/ssh/ > /dev/null 2>&1
    cp -af /etc/init.d/sshd /tmp/openssh_bak_$DATE/etc/init.d/ > /dev/null 2>&1
    cp -af /etc/pam.d/sshd /tmp/openssh_bak_$DATE/etc/pam.d/ > /dev/null 2>&1
    cp -af /usr/bin/scp /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/sftp /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/ssh* /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/bin/slogin /tmp/openssh_bak_$DATE/usr/bin/ > /dev/null 2>&1
    cp -af /usr/sbin/sshd* /tmp/openssh_bak_$DATE/usr/sbin/ > /dev/null 2>&1
    cp -af /usr/libexec/ssh* /tmp/openssh_bak_$DATE/usr/libexec/ > /dev/null 2>&1
    cp -af /usr/libexec/sftp* /tmp/openssh_bak_$DATE/usr/libexec/ > /dev/null 2>&1
    cp -af /usr/libexec/openssh/* /tmp/openssh_bak_$DATE/usr/libexec/openssh/ > /dev/null 2>&1
    cp -af /usr/bin/openssl* /tmp/openssl_bal_$DATE/usr/bin/ > /dev/null 2>&1
    action "备份旧版本OpenSSH和OpenSSL" /bin/true

    #安装OpenSSH
    echo -e "\033[33m正在安装OpenSSH\033[0m (7/7)"
    cd /tmp/$OPENSSH_VERSION
    ./configure --prefix=/usr/local/openssh --sysconfdir=/usr/local/openssh/etc --with-zlib --with-md5-passwords --with-ssl-dir=/usr/local/lib64/ #--with-pam --with-selinux 
    if [ $? -eq 0 ];then
        make -j4
        make install -j4
        # 用我的配置！
        cp -af ~/ssh/sshd_config /usr/local/openssh/etc/sshd_config
        cp -af ~/ssh/pam.d.sshd /etc/pam.d/sshd
        # 防止你误会啦，改下位置好不好？
        rm -rf /etc/ssh
        ln -s /usr/local/etc/ssh /etc/ssh
        # 取代源文件
        cp /usr/local/sbin/sshd /usr/sbin/sshd -af
        cp /usr/local/bin/sftp /usr/bin/sftp -af
        cp /usr/local/bin/scp /usr/bin/scp -af
        cp /usr/local/bin/ssh /usr/bin/ssh -af

        #最后的处理
        echo -e "\033[41;37m 请按提示进行操作，默认为是（Y） \033[0m\n"
        read -r -p "是否允许Root从远程登录?(SSH) [Y/n] " input
        case $input in
            [nN][oO]|[nN])
                ;;
            *)
                sed -i 's/#PermitRootLogin no/PermitRootLogin yes/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                ;;
        esac
        read -r -p "是否允许Root使用密码登录? [Y/n] " input
        case $input in
            [nN][oO]|[nN])
                sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                sed -i 's/#PasswordAuthentication no/PasswordAuthentication no/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                ;;
            *)
                sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /usr/local/openssh/etc/sshd_config > /dev/null 2>&1
                ;;
        esac
        # 给我开机启动！
        cp -af /tmp/$OPENSSH_VERSION/contrib/redhat/sshd.init /etc/init.d/sshd
        chmod +x /etc/init.d/sshd
        chmod 600 /etc/ssh/*
        # 删除原有的sshd启动
        rm -f /usr/lib/systemd/system/sshd.service
        # 
        systemctl daemon-reload 
        # 用 init.d 自动重新生成 sshd 自启动
        /etc/init.d/sshd condrestart
        # chkconfig --add sshd
        # chkconfig sshd on
        action "安装OpenSSH" /bin/true
    else
        echo -e "编译安装OpenSSH失败" "\033[31m Failure\033[0m"
        echo ""
        exit
    fi

    #启动OpenSSH
    cp -af /etc/pam.d/sshd /tmp/openssh_bak_$DATE/etc/pam.d/ > /dev/null 2>&1
    action "恢复配置文件" /bin/true
    systemctl enable sshd --now
    systemctl restart sshd
    if [ $? -eq 0 ];then
        action "启动服务端" /bin/true
        openssl version
        ssh -V
        action "升级OpenSSL&OpenSSH" /bin/true
        info "请完成步骤：1. 测试SSH连接成功；2. 删除备用SSH服务；3. 重要!编辑sshd_config配置文件."
        info "sshd 配置文件在：/usr/local/etc/ssh/"
        err "完成测试前 严禁关闭此连接"
    else
        echo -e "启动服务端失败" "\033[31m Failure\033[0m"
        exit
    fi
    echo ""
    echo "按任意键继续"
    read -n 1

    #删除源码包
    echo -e "\033[33m开始清理临时文件\033[0m (7/7)"
    rm -rf /tmp/$OPENSSL_VERSION*
    rm -rf /tmp/$OPENSSH_VERSION*
    rm -rf /tmp/perl-$PERL_VERSION*
    action "删除临时文件" /bin/true

}

#脚本菜单
echo -e "\033[36m1: 安装DropBearSSH\033[0m"
echo ""
echo -e "\033[36m2: 卸载DropBearSSH\033[0m"
echo ""
echo -e "\033[36m3: 升级 Perl\033[0m"
echo ""
echo -e "\033[36m4: 升级 OpenSSL\033[0m"
echo ""
echo -e "\033[36m5: 升级 OpenSSH\033[0m"
echo ""
echo -e "\033[36m0: 退出脚本\033[0m"
echo ""
read -p  "请输入对应数字后按回车开始执行脚本: " SELECT
if [ "$SELECT" == "1" ];then
clear
INSTALL_DROPBEAR
fi
if [ "$SELECT" == "2" ];then
clear
UNINSTALL_DROPBEAR
fi
if [ "$SELECT" == "3" ];then
clear
INSTALL_PERL
fi
if [ "$SELECT" == "4" ];then
clear
INSTALL_OPENSSL
fi
if [ "$SELECT" == "5" ];then
clear
INSTALL_OPENSSH
fi
if [ "$SELECT" == "0" ];then
echo ""
exit
fi
