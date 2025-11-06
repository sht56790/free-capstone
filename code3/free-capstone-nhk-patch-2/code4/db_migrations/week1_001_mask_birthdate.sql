-- 생년월일 룰을 Block -> Mask로 변경
UPDATE rule
SET action = 'mask'
WHERE name = '생년월일';

-- 검증용
SELECT id, name, action FROM rule WHERE name = '생년월일';

