import uvicorn
from fastapi import FastAPI, Query

app = FastAPI(title="API Discovery Test Server")

@app.get("/")
def read_root():
    return {"message": "Test Server is running on port 8099"}

@app.get("/api/v1/users/{user_id}")
def get_user_details(user_id: int):
    return {"user_id": user_id, "status": "active"}

@app.post("/api/v1/auth/login")
def login():
    return {"token": "sample_token_123"}

@app.get("/api/v1/search")
def search(q: str = Query(None, min_length=3)):
    return {"results": f"Found items for {q}"}

@app.put("/api/v1/settings/update")
def update_settings():
    return {"status": "settings updated"}

@app.delete("/api/v1/admin/delete-cache")
def clear_cache():
    return {"status": "cache cleared"}

if __name__ == "__main__":
    # This runs the server specifically on port 8099
    uvicorn.run(app, host="127.0.0.1", port=8099)