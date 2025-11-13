import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document

# Security setup
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI app
app = FastAPI(title="CCTV Commerce API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


class TokenData(BaseModel):
    user_id: str
    role: str


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role", "customer")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])  # serialize
        return {"user": user, "role": role}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


async def require_admin(user_ctx=Depends(get_current_user)):
    if user_ctx.get("role") != "admin" and user_ctx["user"].get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user_ctx


# Pydantic models for requests
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CameraCreate(BaseModel):
    name: str
    location: Optional[str] = None
    stream_url: Optional[str] = None


class AlertCreate(BaseModel):
    user_id: Optional[str] = None
    camera_id: Optional[str] = None
    title: str
    message: str
    level: str = "info"


class ServiceCreate(BaseModel):
    service_type: str
    preferred_date: Optional[datetime] = None
    address: str
    notes: Optional[str] = None


class ServiceUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None


class SubscriptionUpdate(BaseModel):
    plan: str


class PaymentCreate(BaseModel):
    amount: float
    description: Optional[str] = None
    order_id: Optional[str] = None


class DeviceToken(BaseModel):
    token: str
    platform: str


# Store/Product models
class ProductIn(BaseModel):
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    price: float
    images: List[str] = []
    stock: int = 0
    featured: bool = False
    specs: Optional[dict] = {}


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    price: Optional[float] = None
    images: Optional[List[str]] = None
    stock: Optional[int] = None
    featured: Optional[bool] = None
    specs: Optional[dict] = None


class OrderItemIn(BaseModel):
    product_id: str
    qty: int


class OrderCreate(BaseModel):
    items: List[OrderItemIn]
    address: Optional[str] = None


class OrderUpdate(BaseModel):
    status: Optional[str] = None
    address: Optional[str] = None


@app.get("/")
def read_root():
    return {"message": "CCTV Commerce API Running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", None)
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# Auth endpoints
@app.post("/auth/register")
def register(req: RegisterRequest):
    if db["user"].find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": req.name,
        "email": req.email,
        "password_hash": hash_password(req.password),
        "role": "customer",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(result.inserted_id), "role": user_doc["role"]})
    user_doc["_id"] = str(result.inserted_id)
    del user_doc["password_hash"]
    return {"token": token, "user": user_doc}


@app.post("/auth/login")
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "customer")})
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    return {"token": token, "user": user}


@app.get("/me")
def me(ctx=Depends(get_current_user)):
    return ctx["user"]


# Product catalog
@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, featured: Optional[bool] = None):
    query: dict = {}
    if q:
        query["name"] = {"$regex": q, "$options": "i"}
    if category:
        query["category"] = category
    if featured is not None:
        query["featured"] = featured
    items = list(db["product"].find(query).sort("featured", -1))
    for i in items:
        i["_id"] = str(i["_id"])
    return items


@app.get("/products/{product_id}")
def get_product(product_id: str):
    try:
        item = db["product"].find_one({"_id": ObjectId(product_id)})
    except Exception:
        item = None
    if not item:
        raise HTTPException(status_code=404, detail="Product not found")
    item["_id"] = str(item["_id"])
    return item


@app.post("/admin/products")
def create_product(body: ProductIn, admin=Depends(require_admin)):
    doc = body.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res_id = create_document("product", doc)
    doc["_id"] = res_id
    return doc


@app.patch("/admin/products/{product_id}")
def update_product(product_id: str, body: ProductUpdate, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": update})
    item = db["product"].find_one({"_id": ObjectId(product_id)})
    if not item:
        raise HTTPException(status_code=404, detail="Product not found")
    item["_id"] = str(item["_id"])
    return item


@app.delete("/admin/products/{product_id}")
def delete_product(product_id: str, admin=Depends(require_admin)):
    db["product"].delete_one({"_id": ObjectId(product_id)})
    return {"status": "deleted"}


# Orders
@app.post("/orders")
def create_order(body: OrderCreate, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    if not body.items:
        raise HTTPException(status_code=400, detail="No items")

    product_ids = [ObjectId(i.product_id) for i in body.items]
    products = {str(p["_id"]): p for p in db["product"].find({"_id": {"$in": product_ids}})}

    order_items: List[dict] = []
    subtotal = 0.0
    for item in body.items:
        prod = products.get(item.product_id)
        if not prod:
            raise HTTPException(status_code=400, detail=f"Product not found: {item.product_id}")
        if prod.get("stock", 0) < item.qty:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for {prod['name']}")
        line_total = float(prod.get("price", 0)) * int(item.qty)
        subtotal += line_total
        order_items.append({
            "product_id": item.product_id,
            "name": prod.get("name"),
            "price": float(prod.get("price", 0)),
            "qty": int(item.qty),
            "total": line_total,
        })

    tax = round(subtotal * 0.07, 2)
    total = round(subtotal + tax, 2)

    order_doc = {
        "user_id": uid,
        "items": order_items,
        "subtotal": round(subtotal, 2),
        "tax": tax,
        "total": total,
        "status": "placed",
        "address": body.address,
        "created_at": datetime.now(timezone.utc),
    }
    order_id = create_document("order", order_doc)

    # Reduce stock
    for item in body.items:
        db["product"].update_one({"_id": ObjectId(item.product_id)}, {"$inc": {"stock": -int(item.qty)}})

    return {"_id": order_id, **order_doc}


@app.get("/orders")
def my_orders(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    orders = list(db["order"].find({"user_id": uid}).sort("created_at", -1))
    for o in orders:
        o["_id"] = str(o["_id"])
    return orders


@app.get("/admin/orders")
def admin_orders(admin=Depends(require_admin)):
    orders = list(db["order"].find().sort("created_at", -1))
    for o in orders:
        o["_id"] = str(o["_id"])
    return orders


@app.patch("/admin/orders/{order_id}")
def update_order(order_id: str, body: OrderUpdate, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update:
        return {"status": "noop"}
    db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": update})
    item = db["order"].find_one({"_id": ObjectId(order_id)})
    if not item:
        raise HTTPException(status_code=404, detail="Order not found")
    item["_id"] = str(item["_id"])
    return item


# Existing CCTV-related endpoints (cameras, recordings, alerts, services, subscription, payments, device tokens)
# Camera endpoints
@app.get("/cameras")
def list_my_cameras(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    cams = list(db["camera"].find({"user_id": uid}))
    for c in cams:
        c["_id"] = str(c["_id"])
    return cams


@app.post("/cameras")
def add_camera(body: CameraCreate, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    doc = {"user_id": uid, **body.model_dump(), "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
    inserted = db["camera"].insert_one(doc)
    doc["_id"] = str(inserted.inserted_id)
    return doc


@app.get("/admin/cameras")
def admin_cameras(admin=Depends(require_admin)):
    cams = list(db["camera"].find())
    for c in cams:
        c["_id"] = str(c["_id"])
    return cams


# Recordings
@app.get("/recordings")
def my_recordings(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    recs = list(db["recording"].find({"user_id": uid}).sort("started_at", -1))
    for r in recs:
        r["_id"] = str(r["_id"])
    return recs


# Alerts
@app.get("/alerts")
def my_alerts(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    alerts = list(db["alert"].find({"$or": [{"user_id": uid}, {"user_id": None}]}).sort("created_at", -1))
    for a in alerts:
        a["_id"] = str(a["_id"])
    return alerts


@app.post("/admin/alerts")
def create_alert(body: AlertCreate, admin=Depends(require_admin)):
    doc = body.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    inserted = db["alert"].insert_one(doc)
    doc["_id"] = str(inserted.inserted_id)
    return doc


@app.post("/alerts/{alert_id}/read")
def mark_alert_read(alert_id: str, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    db["alert"].update_one({"_id": ObjectId(alert_id), "$or": [{"user_id": uid}, {"user_id": None}]}, {"$set": {"read": True}})
    return {"status": "ok"}


# Services
@app.post("/services")
def create_service(body: ServiceCreate, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    doc = {"user_id": uid, **body.model_dump(), "status": "pending", "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
    res_id = create_document("servicerequest", doc)
    doc["_id"] = res_id
    return doc


@app.get("/services")
def my_services(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    items = list(db["servicerequest"].find({"user_id": uid}).sort("created_at", -1))
    for i in items:
        i["_id"] = str(i["_id"])
    return items


@app.get("/admin/services")
def admin_services(admin=Depends(require_admin)):
    items = list(db["servicerequest"].find().sort("created_at", -1))
    for i in items:
        i["_id"] = str(i["_id"])
    return items


@app.patch("/admin/services/{service_id}")
def update_service(service_id: str, body: ServiceUpdate, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["servicerequest"].update_one({"_id": ObjectId(service_id)}, {"$set": update})
    item = db["servicerequest"].find_one({"_id": ObjectId(service_id)})
    if not item:
        raise HTTPException(status_code=404, detail="Service not found")
    item["_id"] = str(item["_id"])
    return item


# Subscription & Payments (mocked)
@app.get("/subscription")
def my_subscription(ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    sub = db["subscription"].find_one({"user_id": uid})
    if not sub:
        sub = {"user_id": uid, "plan": "basic", "status": "active"}
        db["subscription"].insert_one(sub)
        sub = db["subscription"].find_one({"user_id": uid})
    sub["_id"] = str(sub["_id"]) if "_id" in sub else None
    return sub


@app.post("/subscription")
def update_subscription(body: SubscriptionUpdate, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    db["subscription"].update_one({"user_id": uid}, {"$set": {"plan": body.plan, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    return {"status": "ok"}


@app.post("/payments/checkout")
def checkout(body: PaymentCreate, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    pay_doc = {
        "user_id": uid,
        "amount": body.amount,
        "currency": "USD",
        "description": body.description,
        "paid": True,
        "provider": "mock",
        "created_at": datetime.now(timezone.utc),
    }
    pid = create_document("payment", pay_doc)

    # If paying for an order, mark it paid
    if body.order_id:
        try:
            db["order"].update_one({"_id": ObjectId(body.order_id)}, {"$set": {"status": "paid", "payment_id": pid}})
        except Exception:
            pass

    # extend subscription as well (optional demo behavior)
    period_end = datetime.now(timezone.utc) + timedelta(days=30)
    db["subscription"].update_one({"user_id": uid}, {"$set": {"status": "active", "current_period_end": period_end}}, upsert=True)
    return {"payment_id": pid, "status": "paid"}


# Device tokens (mock push)
@app.post("/devices/register")
def register_device(body: DeviceToken, ctx=Depends(get_current_user)):
    uid = ctx["user"]["_id"]
    doc = {"user_id": uid, "token": body.token, "platform": body.platform, "created_at": datetime.now(timezone.utc)}
    create_document("device", doc)
    return {"status": "registered"}


@app.post("/admin/alerts/push")
def admin_push_alert(body: AlertCreate, admin=Depends(require_admin)):
    # In a real system, integrate with FCM/APNs. Here we just record the alert.
    doc = body.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    create_document("alert", doc)
    return {"status": "queued"}


# Admin extras
@app.get("/admin/users")
def admin_users(admin=Depends(require_admin)):
    users = list(db["user"].find({}, {"password_hash": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
    return users


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
