# EC2 배포 가이드

## 1. EC2 인스턴스 생성

AWS 콘솔 또는 CLI:

```bash
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \   # Ubuntu 22.04 LTS (리전마다 다름)
  --instance-type t3.small \
  --key-name <your-key-pair> \
  --security-group-ids <sg-id> \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=waf-engine}]'
```

**권장 사양**: t3.small (2 vCPU, 2GB RAM) 이상

## 2. 보안그룹 설정

| 포트 | 프로토콜 | 소스 | 용도 |
|------|----------|------|------|
| 22 | TCP | 내 IP | SSH |
| 80 | TCP | 0.0.0.0/0 | WAF HTTP |

```bash
# 보안그룹 인바운드 규칙 추가
aws ec2 authorize-security-group-ingress \
  --group-id <sg-id> \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id <sg-id> \
  --protocol tcp --port 22 --cidr <my-ip>/32
```

## 3. 초기 설정

```bash
# EC2에 접속
ssh -i <pem-file> ubuntu@<EC2_PUBLIC_IP>

# GitHub에 코드가 있는 경우
export REPO_URL=https://github.com/YOUR_USERNAME/waf.git
export JS_TOKEN_SECRET=$(openssl rand -hex 32)   # 반드시 변경
export CAPTCHA_SITE_KEY=<your-recaptcha-site-key> # 선택사항

bash -s < deploy/setup-ec2.sh
```

## 4. 배포 (이후 업데이트)

```bash
# 로컬에서
./deploy/deploy.sh <EC2_PUBLIC_IP> --pem <pem-file>
```

## 5. 동작 확인

```bash
# 헬스체크
curl http://<EC2_PUBLIC_IP>/__waf/health

# 봇 UA 차단 확인
curl -H "User-Agent: python-requests/2.31.0" http://<EC2_PUBLIC_IP>/

# 브라우저에서 http://<EC2_PUBLIC_IP>/ 접속 → JS Challenge 확인
```

## 6. 로그 확인

```bash
ssh -i <pem-file> ubuntu@<EC2_PUBLIC_IP>

# WAF 엔진 로그
docker compose -f /opt/waf/docker-compose.yml logs -f rust-engine

# Kafka 이벤트
docker compose -f /opt/waf/docker-compose.yml exec kafka \
  kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic waf-events --from-beginning
```
