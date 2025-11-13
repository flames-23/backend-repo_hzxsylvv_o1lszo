"""
Database Schemas for the CCTV Commerce App

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name (e.g., User -> "user").
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

# Core user model
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    role: str = Field("customer", description="Role: customer | admin | technician")
    is_active: bool = Field(True, description="Whether user is active")

# Product sold by the CCTV company
class Product(BaseModel):
    name: str = Field(..., description="Product name")
    description: Optional[str] = Field(None, description="Long description")
    category: Optional[str] = Field(None, description="camera | accessory | system | dvr | nvr | cable | service")
    price: float = Field(..., ge=0, description="Unit price in USD")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    stock: int = Field(0, ge=0, description="Units in stock")
    featured: bool = Field(False, description="Featured on homepage")
    specs: Optional[dict] = Field(default_factory=dict, description="Key-value specs")

# Order and items
class OrderItem(BaseModel):
    product_id: str = Field(..., description="Product _id as string")
    name: str
    price: float
    qty: int
    total: float

class Order(BaseModel):
    user_id: str = Field(..., description="Buyer user _id")
    items: List[OrderItem]
    subtotal: float
    tax: float
    total: float
    status: str = Field("placed", description="placed | paid | processing | shipped | completed | cancelled")
    address: Optional[str] = None
    payment_id: Optional[str] = None
    created_at: Optional[datetime] = None

# Camera registered to a customer account (optional for existing app users)
class Camera(BaseModel):
    user_id: str = Field(..., description="Owner user _id as string")
    name: str = Field(..., description="Camera friendly name")
    location: Optional[str] = Field(None, description="Where the camera is installed")
    stream_url: Optional[str] = Field(None, description="Live stream URL (HLS/RTSP via gateway)")
    status: str = Field("online", description="online | offline | maintenance")

# Recorded video metadata
class Recording(BaseModel):
    user_id: str = Field(..., description="Owner user _id as string")
    camera_id: str = Field(..., description="Camera _id as string")
    started_at: datetime = Field(..., description="Recording start time (UTC)")
    ended_at: datetime = Field(..., description="Recording end time (UTC)")
    playback_url: str = Field(..., description="Playback URL (HLS/MP4)")

# Motion or system alert
class Alert(BaseModel):
    user_id: Optional[str] = Field(None, description="Target user _id (None for broadcast)")
    camera_id: Optional[str] = Field(None, description="Camera _id if applicable")
    title: str = Field(..., description="Short title of the alert")
    message: str = Field(..., description="Alert message body")
    level: str = Field("info", description="info | warning | critical")
    read: bool = Field(False, description="Has the user read this alert")
    created_at: Optional[datetime] = None

# Service booking (installation/maintenance)
class ServiceRequest(BaseModel):
    user_id: str = Field(..., description="Requester user _id")
    service_type: str = Field(..., description="installation | maintenance | upgrade | inspection")
    preferred_date: Optional[datetime] = Field(None, description="Preferred date/time")
    address: str = Field(..., description="Service address")
    notes: Optional[str] = None
    status: str = Field("pending", description="pending | scheduled | in_progress | completed | cancelled")
    assigned_to: Optional[str] = Field(None, description="Technician user _id")

# Subscription for cloud recording/alerts (for existing app users)
class Subscription(BaseModel):
    user_id: str = Field(..., description="Subscriber user _id")
    plan: str = Field(..., description="basic | standard | pro")
    status: str = Field("active", description="active | past_due | canceled")
    current_period_end: Optional[datetime] = None

# Payment record (mocked gateway)
class Payment(BaseModel):
    user_id: str = Field(..., description="Payer user _id")
    amount: float = Field(..., ge=0, description="Amount in USD")
    currency: str = Field("USD", description="Currency code")
    description: Optional[str] = None
    paid: bool = Field(False, description="Payment success flag")
    provider: str = Field("mock", description="Payment provider id")
    created_at: Optional[datetime] = None
