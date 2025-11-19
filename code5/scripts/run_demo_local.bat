@echo off
setlocal
cd /d %~dp0

REM 1) 서버가 떠있다고 가정하고, 로그인 후 샘플 호출 수행
set BASE=http://localhost:8081

echo Login...
curl -s -X POST %BASE%/login -H "Content-Type: application/json" -c cookies.txt -d "{\"id\":\"user@company.com\",\"password\":\"user_password\"}" >nul

echo Case: BLOCK (account)
curl -s -X POST %BASE%/chat -b cookies.txt -F "model=demo-local" -F "user_prompt_text=계좌번호 123-456-789012로 이체해주세요" | jq .

echo Case: MASK (name)
curl -s -X POST %BASE%/chat -b cookies.txt -F "model=demo-local" -F "user_prompt_text=홍길동 고객 가입 절차 알려줘" | jq .

echo Case: ALLOW (fee general)
curl -s -X POST %BASE%/chat -b cookies.txt -F "model=demo-local" -F "user_prompt_text=수수료는 어떻게 결정되나요?" | jq .

echo Done.


