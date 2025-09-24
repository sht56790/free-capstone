import os
import json
import re
import google.generativeai as genai
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

# Gemini API 키 설정 (환경 변수에서 가져오기)
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

# Gemini 모델 설정
model = genai.GenerativeModel('gemini-2.5-pro')

# Flask 앱 초기화
app = Flask(__name__)

# 민감 정보 패턴 파일 불러오기
def load_sensitive_patterns(file_path='patterns.json'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('sensitive_patterns', [])
    except FileNotFoundError:
        print(f"Error: {file_path} not found. Using empty patterns list.")
        return []

SENSITIVE_PATTERNS = load_sensitive_patterns()

# === [수정된 부분] ===
# LLM에게 지시를 내리는 시스템 프롬프트 정의
SYSTEM_PROMPT = "너는 프록시 서버의 인공지능이야. 사용자가 요청한 질문에만 간결하고 직접적으로 답변해. 사적인 대화나 보안 관련 조언, 인사말은 절대 하지 마."
# ======================

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_prompt = data.get('prompt')

    if not user_prompt:
        return jsonify({"error": "No prompt provided"}), 400

    # 1. 민감 정보 탐지 및 처리
    processed_prompt = user_prompt
    is_blocked = False

    for pattern_info in SENSITIVE_PATTERNS:
        regex_pattern = re.compile(pattern_info['regex'])
        action = pattern_info['action']

        if re.search(regex_pattern, user_prompt):
            if action == 'mask':
                processed_prompt = re.sub(regex_pattern, "[MASKED_DATA]", processed_prompt)
            elif action == 'block':
                is_blocked = True
                break

    if is_blocked:
        return jsonify({"response": "민감 정보가 포함되어 요청을 처리할 수 없습니다."}), 200

    # === [수정된 부분] ===
    # 2. 시스템 프롬프트와 사용자 입력을 결합
    final_prompt = f"{SYSTEM_PROMPT}\n\n사용자: {processed_prompt}"

    # 3. Gemini API에 결합된 프롬프트 전달 및 응답 생성
    try:
        response = model.generate_content(final_prompt)
        response_text = response.text
        return jsonify({"response": response_text})
    # ======================

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)