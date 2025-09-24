import os
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

@app.route('/chat', methods=['POST'])
def chat():
    # 사용자 요청에서 프롬프트 추출
    data = request.get_json()
    user_prompt = data.get('prompt')

    if not user_prompt:
        return jsonify({"error": "No prompt provided"}), 400

    # Gemini API에 프롬프트 전달 및 응답 생성
    try:
        response = model.generate_content(user_prompt)
        response_text = response.text
        return jsonify({"response": response_text})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)