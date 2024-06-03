#!/bin/bash
###
### jar 自动启动脚本 ver. 1.0.2 (2024/05/13 18:00)
###
### Usage:
###   ./startup.sh -[h|d|b]
### 
###
### Options:
###   -d        debug       
###   -auto     使用容器内存，自动设置CPU和内存大小
###   -h        Show this message.
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
help() {
    awk -F'### ' '/^###/ { print $2 }' "$0"
}
if [[ "$1" == "-h" ]]; then
    help
    exit 1
fi
# if [[ $# == 0 ]] ; then
#     start
#     exit 1
# fi


source /etc/profile > /dev/null 2>&1
source /etc/rc.d/init.d/functions > /dev/null 2>&1

########################################################################
# 找出当前目录下最新的jar
application=$(ls -lt *.jar | head -n 1 | awk '{print $NF}')
## JAVA 通用启动程序
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
#JVM_ARGS="-Xmx8g -Xms8g"
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## JAR的依赖包在指定的文件夹
#LIBS="-Dloader.path=lib";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## Spring 启动端口
#PROFILE="$PROFILE --server.port=0";
#PROFILE="$PROFILE --server.port=-1";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## Spring 工程使用的配置文件
#PROFILE="$PROFILE --spring.profiles.active=prod";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## NACOS
NACOS_ADDR="127.0.0.1"
#SP_ARGS="$SP_ARGS --spring.cloud.nacos.username=";
#SP_ARGS="$SP_ARGS --spring.cloud.nacos.password=";
#SP_ARGS="$SP_ARGS --spring.cloud.nacos.discovery.server-addr=$NACOS_ADDR";
#SP_ARGS="$SP_ARGS --spring.cloud.nacos.config.server-addr=$NACOS_ADDR";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## 让logback打印的时候尝试使用彩色
SP_ARGS="$SP_ARGS --spring.output.ansi.enabled=DETECT";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## 设置线程的栈大小为768k。栈大小决定了线程可以调用的深度
## 设置永久代的初始大小为128MB。永久代用于存放类的元数据、常量池等信息
## 设置永久代的最大大小为512MB。当永久代的大小超过这个值时，JVM会触发Full GC来回收永久代的内存
#JVM_ARGS="$JVM_ARGS -Xss768k -XX:PermSize=128m -XX:MaxPermSize=512m"
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## 禁用显式的垃圾回收
## 在异常信息中显示代码详细信息
#JVM_ARGS="$JVM_ARGS -XX:+DisableExplicitGC -XX:+ShowCodeDetailsInExceptionMessages"
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## 启用并行垃圾回收器;
## 打印详细的垃圾回收信息;
## 打印对象年龄分布信息。用于查看对象在新生代和老年代之间的年龄分布情况;
## 在发生内存溢出错误时生成堆转储文件
#mkdir -p /TRS/JVM/${application}
#JVM_ARGS="$JVM_ARGS -XX:+UseParallelGC -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintTenuringDistribution -XX:+PrintHeapAtGC -XX:+PrintReferenceGC -XX:+PrintGCApplicationStoppedTime -XX:+HeapDumpOnOutOfMemoryError"
#JVM_ARGS="$JVM_ARGS -XX:HeapDumpPath=/TRS/JVM/${application}/dump-$(date '+%s').hprof -Xloggc:/TRS/JVM/${application}/gc-%t.log -XX:+UseGCLogFileRotation -XX:GCLogFileSize=100M -XX:NumberOfGCLogFiles=10"
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
## 开启远程调试参数
#REMOTE_DEBUG_FOR_JDK7ORLOWER='-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005'
#JVM_ARGS="$JVM_ARGS $REMOTE_DEBUG_FOR_JDK7ORLOWER";
#REMOTE_DEBUG_FOR_JDK9ORLATER='-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005'
#JVM_ARGS="$JVM_ARGS $REMOTE_DEBUG_FOR_JDK9ORLATER";
## ;;;;;;;;;;;;;;;;;;;;;;;;;;;
# 其他需要的参数
#JAVA_HOME=/TRS/APP/jdk-20.0.1/
#PATH=/TRS/APP/redis/bin:$JAVA_HOME/bin:$PATH
#CLASSPATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar
#
########################################################################
function err() {
    printf "[%s]: \033[41;97mERROR  : %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[41;97mERROR  : $@ \033[0m\n"
}
function info() {
    printf "[%s]: \033[40;38;5;82mINFO   : %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[40;38;5;82mINFO   : $@ \033[0m\n"
}
function warning() {
    printf "[%s]: \033[43;30mWARNING: %s \033[0m\n" "$(date +'%Y-%m-%dT%H:%M:%S')" "$@"
    #printf "[$(date +'%Y-%m-%dT%H:%M:%S')]: \033[43;30mWARNING: $@ \033[0m\n"
}
startup() {
    # log4j2 强制缓解
    JVM_ARGS="$JVM_ARGS -Dlog4j2.formatMsgNoLookups=true"
    # 
    comm="nohup java -server $JVM_ARGS $LIBS -jar $application $PROFILE $SP_ARGS &"
    info "JAVA_HOME：【$JAVA_HOME】 JAVA_OPTS：【$JAVA_OPTS】 JAVA：【$(which java)】"
    info "启动命令：【$comm】"
    nohup java -server $JVM_ARGS $LIBS -jar $application $PROFILE $SP_ARGS &
    tail -f -n 0 nohup.out
}
########################################################################

if [[ "$1" == "-d" ]]; then
    SP_ARGS="$SP_ARGS --logging.level.root=debug";
fi 
if [[ "$1" == "-b" ]]; then
    info "使用自动参数需JDK 8u191+、JDK 10及以上版本。"
    mkdir -p /TRS/JVM/${application}
    JVM_ARGS="-server -XX:+UseContainerSupport -XX:InitialRAMPercentage=70.0 -XX:MaxRAMPercentage=70.0 -XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:/TRS/JVM/${application}/gc-$(date '+%s').log -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/TRS/JVM/${application}/dump-$(date '+%s').hprof";
fi 
# 检查是否有程序正在运行
pid=$(pgrep -f -n "$application")
# 第一次关闭
if [ -n "$pid" ]; then
    warning '善良的结束进程…'
    # 发送退出信号给程序
    kill -15 "$pid"
else
    info "程序启动……"
    startup
fi
# 等待结束完毕
sleep 5
# 第二次关闭
pid=$(pgrep -f -n "$application")
if [ -n "$pid" ]; then
    warning '残忍的结束进程…'
    # 发送退出信号给程序
    kill -9 "$pid"
else
    info "程序启动……"
    startup
fi
sleep 2
info "程序启动……"
startup

