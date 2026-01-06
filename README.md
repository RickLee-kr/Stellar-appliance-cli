# Stellar Appliance CLI

Stellar Cyber Appliance를 위한 명령줄 인터페이스(CLI) 도구입니다. KVM 호스트의 네트워크 설정, NTP 설정, 방화벽 규칙 등을 관리할 수 있습니다.

## 목적

이 CLI 도구는 Stellar Cyber Appliance 환경에서 다음을 수행하기 위해 개발되었습니다:

- **네트워크 설정 관리**: IP 주소, Gateway, DNS 서버 설정
- **NTP 설정 관리**: 다양한 NTP 구현체 지원 (ntpsec, chrony, systemd-timesyncd)
- **방화벽 규칙 관리**: iptables를 사용한 Access Control List (ACL) 관리
- **시스템 정보 조회**: 호스트명, 서비스 상태, 라우팅 테이블 등
- **시스템 설정**: 타임존, 시간, 패치 관리 등

## 주요 기능

### 1. 네트워크 설정 관리

#### 인터페이스 정보 조회 및 설정
```bash
show interface              # 모든 네트워크 인터페이스 정보 표시
set interface <interface> ip <IP> <netmask> [gateway]  # IP 주소 설정
set interface <interface> gateway <gateway>            # Gateway 설정
set interface <interface> dns <dns1> [dns2 ...]        # DNS 서버 설정
unset interface <interface>                            # 인터페이스 설정 제거
```

#### DNS 서버 조회 및 설정
```bash
show dns                   # 현재 설정된 DNS 서버 표시
set dns <interface> <dns1> [dns2 ...]  # DNS 서버 설정
```

#### Gateway 조회
```bash
show gateway               # 기본 Gateway 정보 표시
```

### 2. NTP 설정 관리

다양한 NTP 구현체를 자동으로 감지하고 지원합니다:
- **ntpsec**: `/etc/ntpsec/ntp.conf`
- **chrony**: `/etc/chrony/chrony.conf`
- **systemd-timesyncd**: `/etc/systemd/timesyncd.conf`
- **legacy ntp**: `/etc/ntp.conf`

```bash
show ntp                   # 현재 NTP 설정 및 서버 정보 표시
set ntp <server>           # NTP 서버 추가
unset ntp <server>         # NTP 서버 제거
```

**특징:**
- 설치 스크립트가 설정한 NTP 구성을 자동으로 인식
- 활성 NTP 서비스를 자동 감지
- NTP 서비스 자동 재시작

### 3. Access Control List (ACL) 관리

iptables를 사용한 방화벽 규칙 관리:

```bash
show acl                   # 현재 iptables INPUT 체인 규칙 표시
set acl allow <IP/network> <port> [port2 ...] | all [description]  # 허용 규칙 추가
set acl deny <IP/network> <port> [port2 ...] | all [description]   # 거부 규칙 추가
unset acl <IP/network> <port> [port2 ...] | all                    # 규칙 제거
```

**예시:**
```bash
# 단일 IP의 특정 포트 허용
set acl allow 192.168.1.100 22 "Admin SSH access"

# 네트워크의 여러 포트 허용
set acl allow 192.168.1.0/24 80 443 "Web servers"

# 네트워크의 모든 포트 허용
set acl allow 10.0.0.0/8 all "Internal network"

# 규칙 제거
unset acl 192.168.1.100 22
```

**특징:**
- IP 주소 또는 CIDR 네트워크 지원 (예: `192.168.1.0/24`)
- 단일 포트, 여러 포트, 또는 모든 포트 지원
- 각 규칙에 설명(description) 추가 가능
- `show acl` 명령으로 설명과 함께 규칙 확인 가능

### 4. 시스템 정보 조회

```bash
show version               # 시스템 정보 표시
show hostname              # 호스트명 표시
show service               # 서비스 상태 표시
show timezone              # 타임존 정보 표시
show time                  # 시스템 시간 표시
show route                 # 라우팅 테이블 표시
```

### 5. 시스템 설정

```bash
set timezone <timezone>    # 타임존 설정
set time <YYYY-MM-DD HH:MM:SS>  # 시스템 시간 설정
set hostname <hostname>    # 호스트명 설정
set password               # 관리자 비밀번호 변경
```

### 6. 서비스 관리

```bash
start <service>            # 서비스 시작
restart <service>          # 서비스 재시작
shutdown <service>         # 서비스 종료
```

### 7. 기타 기능

```bash
show autostart             # VM 자동 시작 설정 조회
set autostart <vm> <on|off>  # VM 자동 시작 설정
show patch_history         # 패치 적용 이력 조회
set patches <patch_file>   # 패치 적용
monitor                    # VM 리소스 및 시스템 상태 모니터링
```

## 설치 방법

### 요구사항

- Python 3.10 이상
- Linux 환경 (Ubuntu 16.04 이상 권장)
- sudo 권한

### 설치

1. 저장소 클론:
```bash
git clone https://github.com/RickLee-kr/Stellar-appliance-cli.git
cd Stellar-appliance-cli
```

2. 가상 환경 생성 및 활성화 (권장):
```bash
python3 -m venv venv
source venv/bin/activate
```

3. 패키지 설치:
```bash
pip install -e .
```

## 사용 방법

CLI를 실행합니다:
```bash
aella_cli
```

또는 Python 모듈로 직접 실행:
```bash
python -m dp_cli.aella_cli_aio_appliance
```

### 명령어 구조

CLI는 다음과 같은 명령어 구조를 사용합니다:

```
<command> <subcommand> [parameters]
```

주요 명령어:
- `show <item>`: 정보 조회
- `set <item> <parameters>`: 설정 변경
- `unset <item> <parameters>`: 설정 제거
- `start <service>`: 서비스 시작
- `restart <service>`: 서비스 재시작
- `shutdown <service>`: 서비스 종료

### 도움말

```bash
help                    # 전체 명령어 목록
help <command>          # 특정 명령어 도움말
show <item> ?           # 특정 항목의 사용법
set <item> ?            # 설정 명령어 사용법
```

## 지원되는 설치 스크립트

이 CLI는 다음 설치 스크립트와 호환됩니다:

- Ubuntu 16.04 base DP installer
- Ubuntu 24.04 base DP Installer
- AIO-Sensor installer
- xdr-sensor-installer
- xdr-6000-sensor-installer

설치 스크립트가 설정한 네트워크 구성, NTP 설정 등을 자동으로 인식하고 관리할 수 있습니다.

## 네트워크 설정 파일 구조

CLI는 다음 파일들을 관리합니다:

- `/etc/network/interfaces`: 메인 네트워크 인터페이스 설정
- `/etc/network/interfaces.d/*.cfg`: 인터페이스별 설정 파일

## NTP 설정 파일

CLI는 다음 NTP 설정 파일을 지원합니다:

- `/etc/ntpsec/ntp.conf`: ntpsec 설정
- `/etc/chrony/chrony.conf`: chrony 설정
- `/etc/systemd/timesyncd.conf`: systemd-timesyncd 설정
- `/etc/ntp.conf`: legacy ntp 설정

## ACL (iptables) 규칙

ACL 규칙은 iptables의 INPUT 체인에 추가됩니다. 규칙을 영구적으로 저장하려면 다음 명령어를 사용하세요:

```bash
sudo iptables-save > /etc/iptables/rules.v4
```

또는 Ubuntu의 경우:
```bash
sudo netfilter-persistent save
```

## 주의사항

- 네트워크 설정 변경 후에는 인터페이스를 재시작해야 적용됩니다:
  ```bash
  set interface <interface> restart
  ```

- NTP 설정 변경 시 해당 NTP 서비스가 자동으로 재시작됩니다.

- ACL 규칙은 즉시 적용되지만, 시스템 재부팅 후에도 유지하려면 iptables 규칙을 저장해야 합니다.

- 일부 명령어는 `sudo` 권한이 필요할 수 있습니다.

## 라이선스

Copyright (c) 2026, Stellar Cyber Inc.

## 기여

이슈 리포트나 기능 제안은 GitHub Issues를 통해 제출해주세요.

## 관련 프로젝트

- [OpenXDR KVM Installer](https://github.com/RickLee-kr/OpenXDR-KVM-Installer): KVM 호스트 설치 스크립트

