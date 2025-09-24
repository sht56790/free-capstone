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

        # 패턴이 있는지 확인
        if re.search(regex_pattern, user_prompt):
            if action == 'mask':
                # 마스킹 액션
                processed_prompt = re.sub(regex_pattern, "[MASKED_DATA]", processed_prompt)
            elif action == 'block':
                # 차단 액션
                is_blocked = True
                break # 차단할 경우 더 이상 검사하지 않음

    # 2. 만약 차단해야 할 경우, LLM 호출을 건너뛰고 바로 반환
    if is_blocked:
        return jsonify({"response": "민감 정보가 포함되어 요청을 처리할 수 없습니다."}), 200

    # 3. Gemini API에 처리된 프롬프트 전달 및 응답 생성
    try:
        response = model.generate_content(processed_prompt)
        response_text = response.text
        return jsonify({"response": response_text})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)