from fastapi import FastAPI, Request
import uvicorn

app = FastAPI(title="Protected Backend Application Service")


@app.get("/api/products")
async def get_products():
    return {
        "status": "success",
        "data": [
            {"id": 1, "name": "Security Key", "price": 49.99},
            {"id": 2, "name": "Encrypted Drive", "price": 129.99}
        ]
    }


@app.post("/api/login")
async def login(request: Request):
    data = await request.json()
    return {"status": "authenticated", "user": data.get("username", "guest")}


@app.get("/api/user/profile")
async def profile(name: str = "guest"):
    return {"status": "ok", "profile": {"name": name, "role": "user"}}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
