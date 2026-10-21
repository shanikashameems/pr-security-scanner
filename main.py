import os
import requests
from fastapi import FastAPI, Request, HTTPException
import google.generativeai as genai

app = FastAPI(title="Autonomous PR Security Scanner")

# Load environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.5-flash")

@app.get("/")
def health_check():
    return {"status": "active", "service": "Render PR Security Scanner Engine"}

@app.post("/webhook")
async def handle_webhook(request: Request):
    payload = await request.json()
    action = payload.get("action")
    
    # Process when a PR is newly opened or pushed to
    if action in ["opened", "synchronize"]:
        pull_request = payload.get("pull_request", {})
        diff_url = pull_request.get("diff_url")
        comments_url = pull_request.get("comments_url")
        
        if not diff_url or not comments_url:
            raise HTTPException(status_code=400, detail="Invalid PR payload received.")
            
        # 1. Fetch Code Diff from GitHub
        diff_res = requests.get(diff_url)
        if diff_res.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch git diff.")
        
        diff_text = diff_res.text[:8000] # Cap text payload size
        
        # 2. Analyze Diff with Gemini 2.5 Flash
        prompt = (
            "You are an expert static analysis & security auditor. Analyze the following Git diff "
            "for security vulnerabilities, hardcoded API keys/passwords, SQL injection risks, or bugs.\n\n"
            "Format your output clearly in Markdown:\n"
            "1. **Risk Severity Rating** (Low / Medium / High / Critical)\n"
            "2. **Vulnerability Summary**\n"
            "3. **Suggested Fixes (with code snippets)**\n\n"
            f"Git Diff:\n{diff_text}"
        )
        
        gemini_response = model.generate_content(prompt)
        review_body = gemini_response.text
        
        # 3. Post Findings as PR Comment
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        comment_res = requests.post(comments_url, json={"body": review_body}, headers=headers)
        return {"status": "success", "github_response_code": comment_res.status_code}
        
    return {"status": "ignored", "action": action}
