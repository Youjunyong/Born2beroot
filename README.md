# Born2beroot

## Project Overview

### #Signature.txt (sha1sum)

[##_Image|kage@c2tEfA/btrhFsFDdqj/YFKMNcpf9NkjvY3LvDECyK/img.png|alignCenter|data-origin-width="1610" data-origin-height="160" data-ke-mobilestyle="widthOrigin"|||_##]

(리눅스에서는 sha1sum , 맥(유닉스)에서는 shasum이다.)

소프트웨어 패키지 혹은 CD / DVD 파일을 공유할때, `shasum` 파일을 함께 배포되는 경우가 많다. shasum 파일은 원본 파일과 정확히 동일한 파일인지 확인할때 체크되는 파일이다. 체크섬(checksum)정보가 포함되어있다. (160bit)

-   체크섬(checksum) : 중복 검사의 한 형태로, 공간이나 시간속에서 송신된 자료의 무결성을 보호하는 단순한 방법이다.
-   **즉, Born2beroot 프로젝트를 제출할때의 시점의 가상머신과, 동료평가를 받을때의 가상머신이 정확히 동일한 파일인지 확인하는 방법으로 shasum이 사용되며, 이를 signature.txt에 담아 제출하게된다.**

### #가상머신(Vritual machine)은 무엇이며 왜 필요할까?

[##_Image|kage@cZnSX4/btrhDFepzaO/xKR3bgyKiIUHLj0kI4sf1k/img.png|alignCenter|data-origin-width="1312" data-origin-height="824" width="725" height="455" data-ke-mobilestyle="widthOrigin"|||_##]

우리가 사용하는 맥북은 호스트이다. 내부에는 맥 운영체제가 있다. 만약 과제처럼 CentOS 혹은 Debian이라는 운영체제가 필요한 경우가 생긴다면 방법은 두가지이다.

1.  새로운 기기를 구매하여 필요한 OS를 설치하는 방법
    -   가상 머신보다 효율성, 성능이 높을것이다.
2.  가상머신을 활용하여 현재 있는 맥북에 가상화된 운영체제를 설치하는 방법
    -   새로운 하드웨어를 구매하는것보다 경제적으로 효율적이다. (물리적 리소스 절약)
    -   VM을 사용하면 개발 환경을 완전히 새로 **프로비저닝** 하는것보다 간단하다.즉, 가상 머신은 물리적 컴퓨터와 동일한 기능을 제공하는 소프트웨어 컴퓨터이다. 원래 사용하던 OS와는 별도로 새로운 컴퓨터 시스템처럼 작동하게 된다. 그리고 생성된 가상환경은 sandbox화 되므로, 호스트 컴퓨터를 변조할 수 없다.

-   **하이퍼바이저(hypervisor)** : 가상 머신을 생성하고 구동하는 소프트웨어를 말한다. 하이퍼 바이저가 CPU, 메모리 등의 리소스를 처리하여 게스트(가상 머신)에 할당하여 VM 리소스를 관리해준다. 이러한 과정을 통해서 여러개의 게스트 OS들을 다룰 수 있게 해준다.
-   **프로비저닝(provisioning)** : 사용자의 요구에 맞게 시스템 자원을 할당, 배치, 배포해 두었다가 필요 시 시스템을 즉시 사용가능한 상태로 만드는것을 말한다.

### #Debian vs CentOS

데비안과 센토스 모두 리눅스 배포판이다. 리눅스 배포판은 **리눅스 커널 + 자유소프트웨어**로 구성된 유닉스 계열의 운영체제를 말한다.

-   리눅스 커널 (linux kernel) : 커널의 뜻은 껍질 속 알맹이다. 즉, 운영체제 내부에 위치하며 컴퓨터 하드웨어와 프로세스를 잇는 핵심 인터페이스를 말한다. 주요 기능으로는 4가지가 있는데, **(1) 메모리관리 , (2) 프로세스 관리 (3) 장치 드라이버 관리 (4) 시스템 호출 및 보안** 이다.
-   따라서 데비안과 센토스는 리눅스 커널이라는 공통점을 가지고있다. 그렇기 때문에 차이점은 자유 소프트웨어 부분인데, 패키지 포맷, 패키지 관리 툴 등이 차이점에 해당된다.

```
$ cat /etc/os-release # os-release
```

### Debian

-   데비안은 완전한 자유 운영체제이며, 커뮤니티에 의해서 개발되고 디버깅된다.
-   개인용으로 만들어졌다.
-   우분투 리눅스의 기반
-   2년마다 릴리즈 되기 때문에, 안정화 및 디버깅 작업에 시간이 충분하다.
-   [https://www.debian.org/index.ko.html](https://www.debian.org/index.ko.html)
-   패키지 포맷 : DEB 패키지 (deb라는 확장자를 가지며, 컴파일이 완료된 바이너리 파일 + 파일 정보를 의미한다.)
-   패키지 관리 툴 : apt, dpkg, aptitude

### CentOS

-   기업용(데스크탑/서버)이다.
-   RHEL(Red Hat Enterprise Linux)를 똑같이 카피하여 배포된다.
-   따라서 RHEL 보다 이슈 해결이 느리다. 안정화 작업, 업그레이드가 느리다
-   [https://www.centos.org/](https://www.centos.org/)
-   패키지 포맷 : RPM
-   패키지 관리 툴 : YUM/DNF

### #Package Managing Tool (Apt vs Aptitude)

소프트웨어(패키지)의 설치, 제거, 업데이트를 관리해주는 툴을 말한다. 데비안에서는 사용되는 툴은 Apt와 Aptitude, dpkg가 있다.

#### Apt (Advanced Packaging Tool)

```
$ sudo apt-get install <package name>
```

-   온라인 저장소에서 패키지를 다운받아 설치하며 자동으로 의존성처리를 해준다. 설치, 제거, 업데이트는 Apt단독으로 처리한다.
-   디스크 내부에 저장된 deb파일을 이용하여 패키지를 설치하거나 체크하는 기능이 없기 때문에 **실질적으로 dpkg와 함께 사용한다.** 또한 특정 파일이 어떤 패키지에 포함되는지 확인 할때도 dpkg가 필요하다.

#### Aptitude

```
$ sudo aptitude install <pakage name>
```

-   패키지 작업 과정이 Apt보다 더 자동화 되어있다. (더 상위 수준의 툴이다.)
-   대화형 인터페이스, 비 대화형(command line interface)을 모두 제공한다.
-   대부분의 apt-get 구문이 동일하게 유지되어 Aptitude로 마이그레이션 하기 쉽게 만들어졌다. (많은 명령어에서 apt-get만 aptitude로 바꾸면 된다는 의미)
-   현재는 아직 자료들이 apt-get을 사용한 정보들이 많아 apt가 더 많이 사용되고 있다고 한다.

### #AppArmor

-   리눅스 커널의 보안모듈이다.
-   시스템 관리자가 프로그램 프로필 별로 프로그램의 역량을 제한하도록 해준다.
-   프로필들은 네트워크 엑세스, raw 소켓 엑세스, 파일의 crud 등을 허용할 수 있다.
-   Enforce mode : 허용되지 않은 파일에 접근을 거부한다.
-   Complain mode : 어플리케이션이 허용되지 않은 행동을 하면 로그를 남긴다.

```
$ aa-enabled # 현재 활성화 여부 확인
$ sudo aa-status # enforced/ complain 모드 확인
$ pa auxZ | grep -v '^unconfined' # 접근 제한된 실행파일 확인
```

**%동료평가를 받을때 AppAromor는 실행중이어야 한다.%**

### #유저의 권한과 그룹 , Sudo , Su

리눅스 계열의 운영체제에서는 특정 단계의 명령을 실행하거나, 파일에 접근하려면 root 권한이 필요하다. 이때 root 계정이 아닌 일반 유저로 로그인 되어있다면 `su` 혹은 `sudo` 명령어를 사용할 수 있다.

#### Su (Switch user) vs Sudo

현재 로그인 되어있는 계정을 로그아웃하지 않고 다른 계정으로 전환하는 명령어이다. 즉, Su는 계정을 변화한것이다. 따라서 바꿀 계정의 Password를 요구한다.

Sudo는 해당 명령어에 대해서만 root 권한으로 실행하는것이다. 따라서 현재 로그인된 사용자의 Password를 요구한다.

### #Sudoer 설정 (/etc/sudoers.tmp)

```
$ sudo visudo # sudoers 파일 엑세스
```

````
```
# User privilege specification
root    ALL=(ALL:ALL) ALL
user01  ALL=(ALL:ALL) ALL
# 위와같이 수정해놓으면 user01도 sudo 명령어를 쓸 수 있다.

Defaults    authfail_message="Authentication attempt failed."
# 권한획득 실패시 메시지
Defaults    badpass_message="Wrong password!"
# 비밀번호 틀렸을시 메시지
Defaults    log_input
Defaults    log_output
# Sudo와 함께 쓰인 input, output을 로그에 기록한다.
Defaults    requiretty # tty를 필수로 요구한다. 즉, 반드시 콘솔(터미널)에서 sudo를 사용해야한다. (shell script에서는 sudo 사용 불가)
Defaults    iolog_dir="/var/log/sudo/"
# input, ouput 로그 저장할 경로. 
# (미리 mkdir로 경로를 만들어놔야한다.)

````

### #Sudo, User, Group 설정

```
$ dpkg -l sudo # sudo 설치 확인
$ id <user> # user의 그룹 확인

$ sudo deluser <user> <group> # 그룹에서 유저 삭제
$ sudo userdel -r <user> # 유저 계정 삭제
$ getent group sudo #sudo 그룹에 속해있는지 확인
$ groupadd <new group> # new group 추가하기
$ usermod -aG <group> <user> # user를 group에 포함시키기.
# G: 명령어에 명시한 그룹들에만 사용자를 포함시킨다. 즉, 명시하지 않으면 원래 있던 그룹에서 빠지기 때문에 a :append옵션을 추가

$ usermod -g <group> <user> # user의 primary group을 설정
```

### #UFW (Uncomplicated FireWall)

UFW는 데비안 계열 리눅스 환경에서 작동하는 이름대로 "복잡하지 않은" 방화벽 관리 프로그램이다. 간단히 메뉴얼을 봤는데 **서비스명(ex: SSH), IP 주소, 포트 번호, Ping 요청** 등을 허용/거부 할 수 있는 기능을 제공한다.

본 과제에서는 기본 SSH 포트인 22번 포트를 닫고, 4242번 포트를 개방하는데 사용되었다.

```
$ sudo apt install ufw # 설치
$ sudo ufw status verbose # 작동 상태 확인
$ sudo ufw enable # 부팅시 ufw 활성화
$ sudo ufw allow 4242 # 4242 Port 개방
$ sudo ufw default deny # 기본 정책을 차단
$ sudo ufw status numbered # 정책들에 번호를 붙여 나열하여 확인
$ sudo ufw delete <규칙번호> # 정책번호로 삭제
```

### #SSH (Seucure Shell)

호스트 컴퓨터에 접속하기 위해 사용되는 인터넷 프로토콜이다. 기본 포트는 22번이다. 이름대로 Shell로 원격 접속을 하는것이기 때문에 접속 후에도 CLI(Command line interface)에서 작업을 하게 된다.

Key를 이용하여 보안을 구성하는데, 기본적으로 SSH key는 public key, private key 두가지로 이루어진다. 비공개 키는 로컬 머신(게스트)에 위치해야하며, 공개키는 리모트 머신(호스트)에 위치해야한다. SSH 접속을 시도하면 로컬 머신의 비공개키와 리모트 머신의 비공개키를 비교하여 일치하는지 확인하게된다.

```
$ apt search openssh-sever # ssh가 설치되어있는지 검색
$ systemctl status ssh # ssh status 확인
$ apt install openssh-server # 설치
$ apt sudo ufw allow 4242 # 4242Port를 개방
$ sudo systemctl restart ssh # ssh 재시작
```

#### Guest SSH 설정파일 : sshd\_config

```
$ sudo nano /etc/ssh/sshd_config 
# ssh설정 파일, Port 4242로 바꿔준다.
```

-   `PermitRootLogin = no` 로 파일을 수정하여 Root 계정으로 ssh통신을 못하도록 할 수 있다. (보안상의 이유)
-   **게스트(Virtualbox의 가상머신은) ip의 기본값은 `10.0.2.15`이다.**
-   **호스트(iMac) ip는 $ipconfig 로 확인할 수 있다.**
-   Virual box에서 데비안 - 설정 - 네트워크 어댑터로 가서 포트포워딩을 설정해주고 밑의 명령어를 통해 SSH연결을 할 수 있다. -> 참고 글 : [https://mrgamza.tistory.com/506](https://mrgamza.tistory.com/506)

#### iMac (host)에서

```
imac$ ifconfig # host ip vboxnet0 확인 (보통 가장 밑에 뜬다.)
imac$ ssh USER@<hostIP> -p 4242 
# USER로 guest에 접속시도. 포트 4242
```

[##_Image|kage@bjR8x4/btrhFxGVOgo/xrFXN4aB2AAMFoBF4phdRK/img.png|alignCenter|data-origin-width="1588" data-origin-height="218" data-ke-mobilestyle="widthOrigin"|||_##]

만약 위의 경고문구와 함께 접속이 안된다면 맥(host)에서

/Users/<디렉토리>/.ssh/known\_hosts 파일에서 ssh-rsa 이후를 삭제해주고 재시도하면 된다. ssh가 연결될때 호스트키 검증에 실패한건데 이미 생성된 key가 있기 때문에 게스트의 키와 맞지 않는다. 따라서 known\_hosts파일에서 ssh-rsa 로 시작하는 부분 이후를 삭제해주면 재생성하면서 연결에 성공할 수 있다.

### #Hostname & Partitions (LVM)

[##_Image|kage@YQXlM/btrhB1aVLkm/0F5gdvPNLMU1hMYXeSZFj0/img.png|alignCenter|data-origin-width="1588" data-origin-height="880" data-ke-mobilestyle="widthOrigin"|||_##][##_Image|kage@l9xf4/btrhFxtquQK/gSPkTno5AK6CK6ZFbBckUK/img.png|alignCenter|data-origin-width="1148" data-origin-height="1066" data-ke-mobilestyle="widthOrigin"|||_##]

```
$ lsblk # 블록디스크 구성 목록
```

-   LVM : Logical Volume Manager
-   Logical Volume을 효율적이고 유연하게 관리하기 위한 커널의 한 부분이자 프로그램
-   기존(옛날) : 파일시스템을 블록 장치에 직접 접근해서 쓰는 방식
-   LVM: 파일 시스템이 LVM이 만들어 놓은 가상의 블록 장치에 읽고 쓰는 방식.

### LVM과 파티션(옛날 방식) 비교

즉, 옛날 방식은 물리 디스크를 파티션이라는 단위로 나누고, 이를 OS에 마운트 해서 사용했다. 그리고 마운트를 하기 위해 특정 디렉토리와 파티션을 일치시켜주어야 했다. 그리고 마운트된 파티션의 용량이 일정 수준 이상으로 채워졌다면 다음 작업이 필요하다.

-   추가 디스크 장착
-   추가 디스크 파티션 생성 및 포맷
-   새로운 마운트 포인트 (/home2)를 생성하고 추가한 파티션과 마운트(일치화)
-   기존 home 데이터를 home2로 이동
-   기존 home 파티션을 언마운트
-   home2를 home으로 마운트

하지만 LVM을 통해 파티션 대신 볼륨으로 저장 단위를 지정하는 방식을 사용하면서 위의 과정들에 대해 유연하게 대응할 수 있게 되었다. LVM을 사용하다 용량이 일정 수준 이상으로 채워진다면 다음 작업이 필요하다.

-   추가 디스크 장착
-   추가 디스크에 파티션을 만들어 PV(물리 볼륨) 생성
-   PV를 VG(볼륨 그룹)에 추가해준다.
-   /home이 사용하는 논리 볼륨인 lv\_home의 볼륨 사이즈를 증가시킨다.

**즉, LVM을 통해 기존의 데이터를 새로운 디스크로 이동하거나 복사하는 과정이 필요 없고, 서비스가 구동중인 상태에서도 유연하게 볼륨을 확장시킬수 있다.**

#### System hostname 대한 명령어

```
$ hostnamectl # hostname check
$ sudo hostnamectl set-hostname <새 호스트 이름>


$ nano /etc/hosts 
$ nano /etc/hostname # 두 파일에서의 hostname이 일치해야 충돌이 없다.
```

### #Password Policy

비밀번호 정책은 비밀번호를 생성하는 규칙이다. 일반적인 웹사이트 회원 가입시, "대문자, 숫자, 소문자를 1개씩 포함한 8자리 이상의 비밀번호로 설정하세요" 라는것들이 그 사이트의 password policy이다. 정책이 너무 간단하면 보안에 취약할 것이고, 정책이 너무 복잡하면 오히려 사용자로부터 비밀번호를 메모하게 만들어 유출위험을 발생시키거나, 혹은 너무 복잡한 비밀번호를 분실하게 되는 역효과가 발생할 것이다.

데비안에서는 2가지 파일에서 비밀번호 정책을 수정할 수 있다.

#### login.defs

```
$ sudo nano /etc/login.defs

### 아래와 같이 수정 
PASS_MAX_DAYS 30 # 30일 후 만료
PASS_MIN_DAYS 2  # 최소 사용기간 2일
PASS_WARN_AGE 7  # 7일전에 경고 보내기
PASS_MIN_LEN 10  # 최소 10글자 이상
```

#### libpam-pwquality : 패스워드 유효성 제한 패키지

```
$ sudo apt install libpam-pwquality # 패키지 설치
$ sudo nano /etc/pam.d/common-password # 이 파일에서 비밀번호 정책 수정

### common-passwrod 파일 수정
retry = 3 # 암호 재입력은 최대 3회까지
minlen = 10 # 최소 길이 10
difok = 7 # 기존 패스워드와 달라야 하는 문자 수 7
ucredit = -1 # 대문자 한개 이상 포함
lcredit = -1 # 소문자 한개 이상 포함
dcredit = -1 # digit 한개 이상 포함
reject_username # username이 그대로 혹은 reversed 된 문자는 패스워드로 사용 불가
enforce_for_root # root 계정도 위의 정책들 적용
```

```
$ passwd -e <유저네임> # 다음 로그인시 비밀번호를 변경하도록 하게 됨
```

### #Cron (시간 기반 잡 스케줄러)

유닉스 계열 OS의 시간 기반 잡 스케줄러이다. 고정된 시간, 날짜, 간격으로 주기적으로 실행하기 위해 cron이 사용된다.

시간단위를 설정하는 방법은 다음과 같다. cron작업은 crontab 이라는 파일에서 설정한다. 이 파일로 가서 시간설정에 관한 부분은 다음과 같다.

```
* * * * * command
```

애스터마스크가 5개 있는데, 가장 왼쪽부터 분, 시간, 날짜(1

~31), 월(1~

12), 요일(0~6)이다. 필요한 항목에

`-`(그 사이의 모든 값)

`,`(지정 값)

`/` (특정 주기로 나누기)

등의 문자를 사용하여 주기를 정할 수 있다.

프로젝트에서는 10분마다 한번씩 monitoring.sh를 실행해야한다. 따라서 모든 터미널로 메시지를 보내는 `wall`명령과 함께 다음 처럼 작성해주면 된다.

```
*/10 * * * * bash Mypath/monitoring.sh | wall
```

또, 30초 단위로도 설정해야하는데 sleep을 사용하면 된다.

```
*/1 * * * * bash Mypath/monitoring.sh | wall # 이 명령이 매 1분마다 실행되니까
*/1 * * * * sleep 30; bash Mypath/monitoring.sh | wall # 이 명령은 매 1분때 30초를 기다리고 실행되므로....
```

결국 위와같이 작성하면 30초마다 한번 실행되게 된다.

```
$ systemctl status cron.service # status check


$ sudo service cron start # start
$ /etc/init.d/cron start # 멈추기
$ sudo systemctl disable cron # 재부팅 후에 멈추기

$ /etc/init.d/cron stop # stop
$ sudo service cron stop # stop

$ sudo crontab -e # edit
$ sudo crontab -l # list
```

### Monitoring.sh

[##_Image|kage@cwnOEE/btrhEFFeOEs/RbkPIkwhrXqFfnH0Nrfbn0/img.png|alignCenter|data-origin-width="1550" data-origin-height="576" data-ke-mobilestyle="widthOrigin"|||_##]

위 예시처럼 컴퓨터의 여러 정보들을 매 지정된 시간마다 출력해주어야한다.

```
#!/bin/bash

echo -ne "#Architecture: "; uname -a

echo -ne "#CPU physical : "; grep -c ^processor /proc/cpuinfo

echo -ne "#vCPU : "; cat /proc/cpuinfo | grep processor | wc -l

echo -ne "#Memory Usage: "; free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'

echo -ne "#Disk Usage: "; df -h | awk '$NF=="/"{printf "%d/%dGB (%s)\n", $3,$2,$5}'

echo -ne "#CPU load: "; top -bn1 | grep load | awk '{printf "%.2f%%\n", $(NF-2)}'

echo -ne "#Last boot: "; who | awk '{print $3}' | tr '\n' ' ' && who | awk '{print $4}'

echo -ne "#LVM use: "; if cat /etc/fstab | grep -q "/dev/mapper/"; then echo "yes"; else echo "no"; fi

echo -ne "#Connexions TCP : "; cat /proc/net/tcp | wc -l | awk '{print $1-1}' | tr '\n' ' ' && echo "ESTABLISHED"

echo -ne "#User log : "; w | wc -l | awk '{print$1-2}'

echo -ne "#Network : "; echo -n "IP " && ip route list | grep link | awk '{print $9}' | tr '\n' ' ' && echo -n "(" && ip link show | grep link/ether | awk '{print $2}' | tr '\n' ')' && printf "\n"

echo -ne "#Sudo : "; cat /var/log/sudo.log | wc -l | tr '\n' ' ' && echo "cmd"
printf "\n"
```

```
# bash의 if문
if [조건절]
then
    실행절
fi
```

awk : 파일의 특정 필드(col), 레코드(row) 출력

```
$ awk '{printf $1}' awkfile # 1번 Field
$ awk 'NR>=2' awkfile # 2,3,4.... Record
```

grep : 특정 문자열이 들어간것 찾아서 출력

-   ^ : 문자열 라인의 처음

tr : 문자 변환 / 삭제

\* - d : 삭제

wc : 라인 세기

printf : 줄바꿈을 안해준다.

echo : 기본적으로 줄바꿈을 해준다. (-n 후행 개행 출력 안하기 , -e : 백 슬래시 이스케이프 해석 활성화)

### MAC (Media Access Control) 주소

-   랜카드 또는 네트워크 장비들이 하나식 가지고 있는 유일하며 고정된 48bit 주소이다.
-   맥 어드레스, 혹은 하드웨어 어드레스, (물리적 주소) 라고도 부른다.
-   표시 방식은 3가지가 있다.
    -   00-56-94-6F-8F-94
    -   00:56:94:6F:8F:94
    -   00.56.94.6F.8F.94
    -   앞의 3부분은 생산자, 뒤의 3부분은 일련번호(Host Identifier)를 나타낸다.