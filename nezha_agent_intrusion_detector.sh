#!/usr/bin/env bash
# Nezha agent intrusion and outbound-abuse detector for Linux hosts.
# This script is read-only: it collects host/network/process evidence, stores
# detailed logs, then prints a heuristic risk analysis to the terminal.

set -o pipefail

VERSION="1.0.0"
DEFAULT_LOG_ROOT="/var/log/nezha-agent-intrusion-detector"
LOG_ROOT="${LOG_ROOT:-$DEFAULT_LOG_ROOT}"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
HOSTNAME_SAFE="$(hostname 2>/dev/null | tr -cs 'A-Za-z0-9_.-' '_' | sed 's/_$//')"
REPORT_DIR="${REPORT_DIR:-$LOG_ROOT/${HOSTNAME_SAFE:-host}-$TIMESTAMP}"
RAW_DIR="$REPORT_DIR/raw"
REPORT_FILE="$REPORT_DIR/report.txt"
SUMMARY_FILE="$REPORT_DIR/summary.txt"
FINDINGS_FILE="$REPORT_DIR/findings.tsv"
SUSPICIOUS_SCORE=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0
COLLECTION_WARNINGS_FILE="$REPORT_DIR/collection_warnings.tsv"

mkdir -p "$RAW_DIR" 2>/dev/null || {
  REPORT_DIR="/tmp/nezha-agent-intrusion-detector/${HOSTNAME_SAFE:-host}-$TIMESTAMP"
  RAW_DIR="$REPORT_DIR/raw"
  REPORT_FILE="$REPORT_DIR/report.txt"
  SUMMARY_FILE="$REPORT_DIR/summary.txt"
  FINDINGS_FILE="$REPORT_DIR/findings.tsv"
  COLLECTION_WARNINGS_FILE="$REPORT_DIR/collection_warnings.tsv"
  mkdir -p "$RAW_DIR" || {
    echo "ERROR: cannot create log directory" >&2
    exit 1
  }
}
: >"$REPORT_FILE"
: >"$SUMMARY_FILE"
: >"$FINDINGS_FILE"
: >"$COLLECTION_WARNINGS_FILE"

log() {
  printf '[%s] %s\n' "$(date '+%F %T %z')" "$*" | tee -a "$REPORT_FILE"
}

section() {
  printf '\n===== %s =====\n' "$*" | tee -a "$REPORT_FILE"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

record_collection_warning() {
  local name="$1"
  local reason="$2"
  printf '%s\t%s\n' "$name" "$reason" >>"$COLLECTION_WARNINGS_FILE"
}

run_capture() {
  local name="$1"
  shift
  local outfile="$RAW_DIR/$name.txt"
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$outfile" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    record_collection_warning "$name" "command returned rc=$rc"
  fi
  if [ ! -s "$outfile" ]; then
    record_collection_warning "$name" "command produced no output"
  fi
  printf '\n--- %s (rc=%s) ---\n' "$name" "$rc" >>"$REPORT_FILE"
  sed -n '1,220p' "$outfile" >>"$REPORT_FILE"
  local lines
  lines=$(wc -l <"$outfile" 2>/dev/null || echo 0)
  if [ "${lines:-0}" -gt 220 ]; then
    printf '\n[truncated in report; full output: %s]\n' "$outfile" >>"$REPORT_FILE"
  fi
  return 0
}

add_finding() {
  local severity="$1"
  local points="$2"
  local category="$3"
  local message="$4"
  local evidence="$5"
  SUSPICIOUS_SCORE=$((SUSPICIOUS_SCORE + points))
  case "$severity" in
    CRITICAL) CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1)) ;;
    HIGH) HIGH_FINDINGS=$((HIGH_FINDINGS + 1)) ;;
    MEDIUM) MEDIUM_FINDINGS=$((MEDIUM_FINDINGS + 1)) ;;
    LOW) LOW_FINDINGS=$((LOW_FINDINGS + 1)) ;;
  esac
  printf '%s\t%s\t%s\t%s\n' "$severity" "$category" "$message" "$evidence" >>"$FINDINGS_FILE"
}

safe_grep_count() {
  local pattern="$1"
  shift
  local readable_files=()
  local file
  for file in "$@"; do
    if [ -r "$file" ]; then
      readable_files+=("$file")
    else
      record_collection_warning "analysis_input" "missing or unreadable file: $file"
    fi
  done
  if [ "${#readable_files[@]}" -eq 0 ]; then
    printf '0\n'
    return 0
  fi
  grep -Ehi -- "$pattern" "${readable_files[@]}" 2>/dev/null | grep -Ev '^\$' | wc -l | tr -d " " || true
}

collect_baseline() {
  section "基础信息 / Baseline"
  log "Nezha Agent Intrusion Detector v$VERSION"
  log "Report directory: $REPORT_DIR"
  log "Run as UID=$(id -u); root privileges provide more complete evidence."
  run_capture uname uname -a
  run_capture date date -R
  run_capture uptime uptime
  run_capture id id
  [ -r /etc/os-release ] && cp /etc/os-release "$RAW_DIR/os-release.txt" && cat /etc/os-release >>"$REPORT_FILE"
  run_capture mounts mount
  run_capture disk_usage df -hT
  run_capture top_processes ps auxww
}

collect_nezha_context() {
  section "哪吒 Agent 进程与服务 / Nezha agent context"
  if have_cmd systemctl; then
    run_capture nezha_service systemctl status nezha-agent --no-pager -l
    run_capture failed_units systemctl --failed --no-pager
  fi
  run_capture nezha_processes sh -c "ps auxww | grep -Ei '[n]ezha|[a]gent'"
  run_capture nezha_files sh -c "find /opt /etc /usr/local /var/lib -maxdepth 4 \( -iname '*nezha*' -o -iname '*agent*' \) -print 2>/dev/null | head -300"
}

collect_persistence() {
  section "持久化与定时任务 / Persistence"
  run_capture crontab_root sh -c "crontab -l 2>/dev/null || true"
  run_capture cron_files sh -c "find /etc/cron* /var/spool/cron /var/spool/cron/crontabs -type f -maxdepth 3 -print -exec sed -n '1,160p' {} \; 2>/dev/null"
  run_capture systemd_services sh -c "find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) -mtime -30 -print -exec sed -n '1,120p' {} \; 2>/dev/null"
  if [ "${FULL_SENSITIVE:-0}" = "1" ]; then
    run_capture shell_profiles sh -c "find /root /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o -name '.zshrc' -o -name 'authorized_keys' \) -print -exec sed -n '1,120p' {} \; 2>/dev/null"
  else
    run_capture shell_profiles sh -c "find /root /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o -name '.zshrc' \) -print -exec sed -n '1,120p' {} \; 2>/dev/null; find /root /home -maxdepth 3 -type f -name 'authorized_keys' -print -exec awk '{printf \"key_type=%s key_body=%s comment=%s\\n\", \\$1, \"redacted\", length(\\$3)?\"present\":\"absent\"}' {} \; 2>/dev/null"
  fi
  run_capture suid_recent sh -c "find / -xdev -perm -4000 -type f -printf '%TY-%Tm-%Td %TT %p\n' 2>/dev/null | sort"
}

collect_network() {
  section "网络连接与对外攻击迹象 / Network and outbound-abuse evidence"
  if have_cmd ss; then
    run_capture ss_all ss -tunap
    run_capture ss_summary ss -s
  elif have_cmd netstat; then
    run_capture netstat_all netstat -tunap
  else
    record_collection_warning "network_connections" "neither ss nor netstat found; connection evidence skipped"
  fi
  if have_cmd ip; then
    run_capture route ip route
    run_capture addr ip addr
  else
    record_collection_warning "ip" "command not found; route and address evidence skipped"
  fi
  if have_cmd iptables-save || have_cmd iptables; then
    run_capture iptables sh -c "iptables-save 2>/dev/null || iptables -S 2>/dev/null || true"
  else
    record_collection_warning "iptables" "command not found; iptables rules skipped"
  fi
  if have_cmd nft; then
    run_capture nftables sh -c "nft list ruleset 2>/dev/null || true"
  else
    record_collection_warning "nft" "command not found; nftables rules skipped"
  fi
  run_capture dns_config sh -c "cat /etc/resolv.conf 2>/dev/null; printf '\n--- hosts ---\n'; cat /etc/hosts 2>/dev/null"
  run_capture conntrack_count sh -c "wc -l /proc/net/nf_conntrack /proc/net/ip_conntrack 2>/dev/null || true"
}

collect_logs() {
  section "系统日志摘要 / Log evidence"
  run_capture auth_failures sh -c "grep -Eai 'failed password|invalid user|accepted password|accepted publickey|session opened|sudo|su:' /var/log/auth.log /var/log/secure 2>/dev/null | tail -500 || true"
  run_capture kernel_security sh -c "dmesg 2>/dev/null | grep -Eai 'segfault|out of memory|killed process|audit|denied|promiscuous|firewall|iptables|nft' | tail -300 || true"
  if have_cmd journalctl; then
    run_capture journal_recent sh -c "journalctl --since '72 hours ago' --no-pager -o short-iso 2>/dev/null | grep -Eai 'nezha|agent|failed password|invalid user|accepted publickey|sudo|curl|wget|bash -c|/tmp|kdevtmpfsi|kinsing|xmrig|masscan|zmap|nmap|sshpass' | tail -800 || true"
  fi
}

collect_filesystem_iocs() {
  section "文件系统 IOC / Filesystem indicators"
  run_capture tmp_suspicious sh -c "find /tmp /var/tmp /dev/shm -xdev -type f -mtime -14 -printf '%TY-%Tm-%Td %TT %m %u:%g %s %p\n' 2>/dev/null | sort | tail -500"
  run_capture recent_exec sh -c "find /tmp /var/tmp /dev/shm /run /opt /usr/local/bin -xdev -type f -perm /111 -mtime -14 -printf '%TY-%Tm-%Td %TT %m %u:%g %s %p\n' 2>/dev/null | sort | tail -500"
  run_capture known_malware_names sh -c "find / -xdev -type f \( -iname '*xmrig*' -o -iname '*kinsing*' -o -iname '*kdevtmpfsi*' -o -iname '*masscan*' -o -iname '*zmap*' -o -iname '*mirai*' -o -iname '*sshpass*' \) -printf '%TY-%Tm-%Td %TT %m %u:%g %s %p\n' 2>/dev/null | head -500"
}

analyze_results() {
  section "智能分析 / Heuristic analysis"
  local ps_file="$RAW_DIR/top_processes.txt"
  local net_file="$RAW_DIR/ss_all.txt"
  [ -f "$net_file" ] || net_file="$RAW_DIR/netstat_all.txt"
  [ -f "$net_file" ] || net_file="/dev/null"

  local malware_hits
  malware_hits=$(safe_grep_count 'xmrig|kinsing|kdevtmpfsi|kinswap|watchbog|mirai|gafgyt|tsunami|pnscan|masscan|zmap|sshpass|miner|stratum\+tcp|pool\.' "$ps_file" "$net_file" "$RAW_DIR/known_malware_names.txt" "$RAW_DIR/journal_recent.txt" "$RAW_DIR/tmp_suspicious.txt" "$RAW_DIR/recent_exec.txt")
  [ "${malware_hits:-0}" -gt 0 ] && add_finding CRITICAL 35 "IOC" "发现常见恶意程序/挖矿/扫描工具关键词" "匹配次数: $malware_hits"

  local tmp_exec_hits
  tmp_exec_hits=$(safe_grep_count '/tmp/|/var/tmp/|/dev/shm/' "$ps_file")
  [ "${tmp_exec_hits:-0}" -gt 0 ] && add_finding HIGH 25 "Process" "存在从临时目录运行的进程，常见于入侵后载荷" "进程匹配次数: $tmp_exec_hits"

  local outbound_many
  outbound_many=$(awk '/ESTAB|ESTABLISHED|SYN-SENT/ {print}' "$net_file" 2>/dev/null | wc -l | tr -d ' ')
  if [ "${outbound_many:-0}" -gt 200 ]; then
    add_finding HIGH 25 "Network" "当前连接数异常偏高，可能存在扫描、爆破、代理或 DDoS 行为" "连接数: $outbound_many"
  elif [ "${outbound_many:-0}" -gt 80 ]; then
    add_finding MEDIUM 12 "Network" "当前连接数偏高，需要结合业务确认" "连接数: $outbound_many"
  fi

  local scanner_hits
  scanner_hits=$(awk '/ESTAB|ESTABLISHED|SYN-SENT/ && /:22|:23|:2323|:3389|:445|:6379|:8080/ {print}' "$net_file" 2>/dev/null | wc -l | tr -d ' ')
  [ "${scanner_hits:-0}" -gt 150 ] && add_finding HIGH 20 "Network" "大量连接涉及常见管理/数据库/代理端口，疑似扫描或爆破" "端口匹配次数: $scanner_hits"

  local suspicious_persistence
  suspicious_persistence=$(safe_grep_count 'curl|wget|bash -c|base64|/tmp/|/dev/shm|nc |ncat|socat|python -c|perl -e|chmod \+x|xmrig|kinsing|masscan|zmap' "$RAW_DIR"/cron_files.txt "$RAW_DIR"/systemd_services.txt "$RAW_DIR"/shell_profiles.txt)
  [ "${suspicious_persistence:-0}" -gt 0 ] && add_finding HIGH 25 "Persistence" "定时任务、systemd 或 shell 配置中存在可疑下载/执行/反连痕迹" "匹配次数: $suspicious_persistence"

  local ssh_success
  ssh_success=$(safe_grep_count 'accepted password|accepted publickey' "$RAW_DIR/auth_failures.txt")
  local ssh_fail
  ssh_fail=$(safe_grep_count 'failed password|invalid user' "$RAW_DIR/auth_failures.txt")
  [ "${ssh_fail:-0}" -gt 100 ] && add_finding MEDIUM 10 "SSH" "近期 SSH 爆破失败次数较多" "失败次数: $ssh_fail"
  [ "${ssh_success:-0}" -gt 0 ] && add_finding LOW 3 "SSH" "发现 SSH 登录成功记录，请核对是否为本人/自动化运维" "成功次数: $ssh_success"

  local recent_exec_count
  recent_exec_count=$(grep -E '/tmp/|/var/tmp/|/dev/shm|/run/' "$RAW_DIR/recent_exec.txt" 2>/dev/null | grep -Ev '^\$' | wc -l | tr -d " " || true)
  [ "${recent_exec_count:-0}" -gt 0 ] && add_finding MEDIUM 12 "Filesystem" "临时或运行目录存在近期可执行文件" "文件数: $recent_exec_count"

  {
    echo "Nezha Agent Intrusion Detector v$VERSION"
    echo "Report directory: $REPORT_DIR"
    echo "Risk score: $SUSPICIOUS_SCORE"
    echo "Findings: CRITICAL=$CRITICAL_FINDINGS HIGH=$HIGH_FINDINGS MEDIUM=$MEDIUM_FINDINGS LOW=$LOW_FINDINGS"
    if [ -s "$COLLECTION_WARNINGS_FILE" ]; then
      echo "Collection warnings: $(wc -l <"$COLLECTION_WARNINGS_FILE" | tr -d ' ')"
    else
      echo "Collection warnings: 0"
    fi
    if [ "$SUSPICIOUS_SCORE" -ge 60 ] || [ "$CRITICAL_FINDINGS" -gt 0 ]; then
      echo "Conclusion: 高风险。建议立即隔离主机、保全日志和镜像、轮换 Nezha/SSH/API 密钥，并人工复核 raw 日志。"
    elif [ "$SUSPICIOUS_SCORE" -ge 30 ]; then
      echo "Conclusion: 中风险。发现多项可疑迹象，建议暂停非必要出站流量并逐项复核。"
    elif [ "$SUSPICIOUS_SCORE" -ge 10 ]; then
      echo "Conclusion: 低到中风险。存在少量异常或需确认项，请结合业务基线判断。"
    else
      echo "Conclusion: 未发现明显入侵或对外攻击迹象；仍建议保留日志并定期复查。"
    fi
    echo
    echo "Detailed findings:"
    if [ -s "$FINDINGS_FILE" ]; then
      awk -F '\t' '{printf "- [%s] %s: %s (%s)\n", $1, $2, $3, $4}' "$FINDINGS_FILE"
    else
      echo "- No heuristic findings."
    fi
    echo
    if [ -s "$COLLECTION_WARNINGS_FILE" ]; then
      echo "Collection warnings:"
      awk -F '\t' '{printf "- %s: %s\n", $1, $2}' "$COLLECTION_WARNINGS_FILE" | head -20
      echo
    fi
    echo "Suggested next steps:"
    echo "1. 若风险为中/高，先在云防火墙限制出站，只保留必要管理 IP。"
    if [ -f "$RAW_DIR/ss_all.txt" ]; then
      echo "2. 复核 $RAW_DIR/ss_all.txt、top_processes.txt、cron_files.txt、systemd_services.txt。"
    elif [ -f "$RAW_DIR/netstat_all.txt" ]; then
      echo "2. 复核 $RAW_DIR/netstat_all.txt、top_processes.txt、cron_files.txt、systemd_services.txt。"
    else
      echo "2. 复核 $RAW_DIR/top_processes.txt、cron_files.txt、systemd_services.txt；网络连接证据未采集成功时请补装 ss 或 netstat 后重跑。"
    fi
    echo "3. 对可疑 PID 执行只读取证：readlink -f /proc/PID/exe; ls -l /proc/PID/fd; cat /proc/PID/cmdline。"
    echo "4. 升级/重装可信 Nezha agent，轮换 dashboard 通信密钥和 SSH 凭据。"
  } | tee "$SUMMARY_FILE" | tee -a "$REPORT_FILE"
}

main() {
  collect_baseline
  collect_nezha_context
  collect_persistence
  collect_network
  collect_logs
  collect_filesystem_iocs
  analyze_results
  echo
  echo "完整日志: $REPORT_FILE"
  echo "原始证据目录: $RAW_DIR"
  echo "摘要: $SUMMARY_FILE"
}

main "$@"
