#!/bin/bash
# EC2 인스턴스 초기 설정 스크립트
# Ubuntu 22.04/24.04 LTS 기준
# 사용법: ssh ec2-user@<IP> 'bash -s' < setup-ec2.sh

set -e

echo "=== Docker 설치 ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# docker 그룹에 현재 사용자 추가
usermod -aG docker "${SUDO_USER:-ubuntu}"

systemctl enable docker
systemctl start docker

echo "=== mini-protection 배포 ==="
REPO_URL="${REPO_URL:-https://github.com/YOUR_USERNAME/mini-protection.git}"
DEPLOY_DIR="/opt/mini-protection"

if [ -d "$DEPLOY_DIR" ]; then
  cd "$DEPLOY_DIR" && git pull
else
  git clone "$REPO_URL" "$DEPLOY_DIR"
fi

cd "$DEPLOY_DIR"

# 운영 환경 시크릿 설정
if [ -z "$JS_TOKEN_SECRET" ]; then
  echo "[WARNING] JS_TOKEN_SECRET not set — generating random secret"
  JS_TOKEN_SECRET=$(openssl rand -hex 32)
fi

# .env 파일 생성 (docker compose가 자동으로 읽음)
cat > .env <<EOF
JS_TOKEN_SECRET=${JS_TOKEN_SECRET}
CAPTCHA_SITE_KEY=${CAPTCHA_SITE_KEY:-}
EOF

docker compose up -d --build

echo "=== 배포 완료 ==="
docker compose ps
