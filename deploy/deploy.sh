#!/bin/bash
# 로컬에서 실행: EC2로 최신 코드 배포
# 사용법: ./deploy.sh <EC2_PUBLIC_IP> [--pem <pem-file>]
#
# 사전 조건:
#   - EC2에 setup-ec2.sh 이미 실행 완료
#   - AWS 보안그룹: 인바운드 80(TCP), 22(TCP) 오픈

set -e

EC2_IP="${1:?사용법: $0 <EC2_PUBLIC_IP> [--pem <pem-file>]}"
PEM_FILE=""

shift
while [[ $# -gt 0 ]]; do
  case $1 in
    --pem) PEM_FILE="-i $2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SSH="ssh $PEM_FILE -o StrictHostKeyChecking=no ubuntu@$EC2_IP"

echo "=== $EC2_IP 에 배포 시작 ==="

$SSH "cd /opt/mini-protection && git pull && docker compose up -d --build"

echo "=== 헬스체크 ==="
sleep 10
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$EC2_IP/__mini-protection/health")
if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ 배포 성공: http://$EC2_IP"
else
  echo "✗ 헬스체크 실패 (HTTP $HTTP_CODE)"
  $SSH "cd /opt/mini-protection && docker compose logs --tail=50 rust-engine"
  exit 1
fi
