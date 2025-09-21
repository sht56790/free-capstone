import os
import google.generativeai as genai
from flask import Flask, request, jsonify
from dotenv import load_dotenv 

load_dotenv()

# Flask 앱 초기화
app = Flask(__name__)

# Gemini API 키 설정 (환경 변수에서 가져오기)
# 'set GOOGLE_API_KEY=...' 명령어를 통해 설정한 API 키를 불러옵니다.
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

# Generative AI 모델 초기화
# 'gemini-pro' 모델을 사용합니다.
model = genai.GenerativeModel('gemini-2.5-pro')

@app.route('/chat', methods=['POST'])
def chat():
    # 1. 사용자 요청에서 프롬프트 추출
    data = request.get_json()
    user_prompt = data.get('prompt')

    # 프롬프트가 없는 경우 오류 반환
    if not user_prompt:
        return jsonify({"error": "No prompt provided"}), 400

    # 2. Gemini API에 프롬프트 전달 및 응답 생성
    try:
        response = model.generate_content(user_prompt)
        
        # 3. Gemini 응답에서 텍스트 추출
        # 응답이 여러 부분으로 나뉘어 있을 수 있으므로 join()을 사용합니다.
        # 응답이 없을 경우를 대비한 처리도 추가합니다.
        chat_response = ''.join(part.text for part in response.parts) if response and response.parts else "No response from Gemini."

        # 4. Gemini 응답을 JSON 형태로 반환
        return jsonify({"response": chat_response}), 200

    except Exception as e:
        # API 통신 중 오류 발생 시
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Flask 서버 실행
    app.run(debug=True)