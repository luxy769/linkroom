from pydantic import BaseModel, EmailStr, constr
from typing import List, Optional
from datetime import datetime

class TagBase(BaseModel):
    name: str

class TagCreate(TagBase):
    pass

class Tag(TagBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class NoteBase(BaseModel):
    title: str
    content: str

class NoteCreate(NoteBase):
    tags: Optional[List[str]] = []

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    tags: Optional[List[str]] = None

class Note(NoteBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    user_id: int
    tags: List[Tag]

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=50)

class UserCreate(UserBase):
    password: constr(min_length=8)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[constr(min_length=3, max_length=50)] = None
    password: Optional[constr(min_length=8)] = None

class User(UserBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    notes: List[Note] = []

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None 