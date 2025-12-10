-- ===================================================================
-- 금융 상담 챗봇 데이터베이스 초기화 SQL
-- ===================================================================
-- 사용법: sqlite3 instance/database.db < database_init.sql
-- 또는 Flask CLI: flask --app app.py init-db

-- ===================================================================
-- 1. 사용자 테이블 초기 데이터
-- ===================================================================

-- 기본 관리자 계정
INSERT OR IGNORE INTO user (id, password, role) 
VALUES ('admin@company.com', 'admin_password', 'admin');

-- 기본 사용자 계정
INSERT OR IGNORE INTO user (id, password, role) 
VALUES ('user@company.com', 'user_password', 'user');

-- ===================================================================
-- 2. 탐지 규칙 테이블 초기 데이터 (patterns.json 기반)
-- ===================================================================

-- 계좌번호 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('계좌번호', '\d{4}[-\s]?\d{4}[-\s]?\d{4,6}|\d{12,14}', 'block', 1);

-- 고객번호 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('고객번호', '고객번호[:\\s]?\d{6,12}|\d{6,12}(?=\s*고객)', 'block', 1);

-- 고객명 (Mask)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('고객명', '[가-힣]{2,4}(?=\s*(님|고객|분|씨))|[가-힣]{2,4}(?=\s*계좌)|성명[:\\s]*[가-힣]{2,4}', 'mask', 1);

-- 생년월일 (Mask) - 차단 사유에 나타나지 않고 마스킹만 적용
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('생년월일', '\d{4}[-.\s]?\d{2}[-.\s]?\d{2}|\d{6}(?=\s*생년)|생년월일[:\\s]*\d{4}[-.\s]?\d{2}[-.\s]?\d{2}', 'mask', 1);

-- 전화번호 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('전화번호', '010[-\s]?\d{4}[-\s]?\d{4}|0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}', 'block', 1);

-- 주소 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('주소', '([서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주]\s*[시도군구]|\d{5}[-\s]?\d{6})', 'block', 1);

-- 금리 확정 표현 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('금리 확정 표현', '금리는\s*\d+[.\d]*%입니다|금리\s*\d+[.\d]*%|이자율\s*\d+[.\d]*%', 'block', 1);

-- 수수료 확정 표현 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('수수료 확정 표현', '수수료는\s*\d+[,\d]*원입니다|수수료\s*\d+[,\d]*원|보험료는\s*\d+[,\d]*원입니다', 'block', 1);

-- 계좌 이체 요청 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('계좌 이체 요청', '계좌\s*이체|송금\s*요청|이체\s*가능', 'block', 1);

-- 대출 신청 (Block)
INSERT OR IGNORE INTO rule (name, regex, action, is_active) 
VALUES ('대출 신청', '대출\s*신청|대출\s*가입|대출\s*가능', 'block', 1);

-- ===================================================================
-- 3. 통계 쿼리 (참고용)
-- ===================================================================

-- 총 사용자 수
-- SELECT COUNT(*) as total_users FROM user;

-- 총 규칙 수
-- SELECT COUNT(*) as total_rules FROM rule WHERE is_active = 1;

-- 활성 규칙 목록
-- SELECT id, name, action, is_active FROM rule WHERE is_active = 1 ORDER BY name;

-- 차단 규칙 목록
-- SELECT id, name, regex, action FROM rule WHERE action = 'block' AND is_active = 1;

-- 마스킹 규칙 목록
-- SELECT id, name, regex, action FROM rule WHERE action = 'mask' AND is_active = 1;

-- ===================================================================
-- 4. 로그 테이블 예시 쿼리 (참고용)
-- ===================================================================

-- 최근 로그 10개
-- SELECT id, timestamp, user_id, action, 
--        json_extract(detections_in, '$[0].name') as first_detection
-- FROM log 
-- ORDER BY timestamp DESC 
-- LIMIT 10;

-- 차단된 요청 수
-- SELECT COUNT(*) as blocked_count FROM log WHERE action = 'block';

-- 마스킹된 요청 수
-- SELECT COUNT(*) as masked_count FROM log WHERE action = 'mask';

-- 탐지된 PII 종류별 통계
-- SELECT 
--   json_extract(value, '$.name') as pii_type,
--   COUNT(*) as count
-- FROM (
--   SELECT json_each.value 
--   FROM log, json_each(detections_in) 
--   WHERE detections_in IS NOT NULL
-- )
-- GROUP BY pii_type
-- ORDER BY count DESC;

