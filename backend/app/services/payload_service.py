from __future__ import annotations

import base64
import hashlib
import urllib.parse
import uuid
from html import escape as html_escape
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.payload import Payload
from app.models.user import User
from app.schemas.payload import PayloadCreate, PayloadUpdate


class PayloadService:
    def __init__(self, db: Session):
        self.db = db

    def list_payloads(
        self,
        offset: int = 0,
        limit: int = 20,
        category: Optional[str] = None,
        search: Optional[str] = None,
        user: Optional[User] = None,
    ) -> tuple[List[Payload], int]:
        query = self.db.query(Payload)
        if category:
            query = query.filter(Payload.category == category)
        if search:
            query = query.filter(
                Payload.name.ilike(f"%{search}%") | Payload.description.ilike(f"%{search}%")
            )
        total = query.count()
        payloads = query.order_by(Payload.created_at.desc()).offset(offset).limit(limit).all()
        return payloads, total

    def get_payload(self, payload_id: uuid.UUID) -> Payload:
        payload = self.db.query(Payload).filter(Payload.id == payload_id).first()
        if not payload:
            raise NotFoundError(f"Payload {payload_id} not found")
        return payload

    def create_payload(self, data: PayloadCreate, user: User) -> Payload:
        payload = Payload(
            user_id=user.id,
            name=data.name,
            category=data.category,
            subcategory=data.subcategory,
            file_path=data.file_path,
            content_hash=data.content_hash,
            payload_count=data.payload_count,
            tags=data.tags,
            description=data.description,
            source=data.source,
            is_builtin=data.is_builtin,
        )
        self.db.add(payload)
        self.db.commit()
        self.db.refresh(payload)
        return payload

    def update_payload(self, payload_id: uuid.UUID, data: PayloadUpdate, user: User) -> Payload:
        payload = self.get_payload(payload_id)
        if payload.is_builtin and user.role != "admin":
            from app.core.exceptions import ForbiddenError
            raise ForbiddenError("Cannot modify built-in payloads")
        update_data = data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(payload, key, value)
        self.db.commit()
        self.db.refresh(payload)
        return payload

    def delete_payload(self, payload_id: uuid.UUID, user: User) -> None:
        payload = self.get_payload(payload_id)
        if payload.is_builtin and user.role != "admin":
            from app.core.exceptions import ForbiddenError
            raise ForbiddenError("Cannot delete built-in payloads")
        self.db.delete(payload)
        self.db.commit()

    def get_category_tree(self) -> Dict[str, List[str]]:
        payloads = self.db.query(Payload.category, Payload.subcategory).distinct().all()
        tree: Dict[str, List[str]] = {}
        for category, subcategory in payloads:
            if category not in tree:
                tree[category] = []
            if subcategory and subcategory not in tree[category]:
                tree[category].append(subcategory)
        return tree

    def mutate_payloads(self, payloads: List[str], mutations: List[str]) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {}
        for payload in payloads:
            mutated = []
            if "case" in mutations:
                mutated.extend([payload.upper(), payload.lower(), payload.swapcase()])
            if "url_encode" in mutations:
                mutated.append(urllib.parse.quote(payload))
                mutated.append(urllib.parse.quote(payload, safe=""))
            if "html_encode" in mutations:
                mutated.append(html_escape(payload))
            if "double_encode" in mutations:
                mutated.append(urllib.parse.quote(urllib.parse.quote(payload)))
            if "base64" in mutations:
                mutated.append(base64.b64encode(payload.encode()).decode())
            if "hex" in mutations:
                mutated.append(payload.encode().hex())
            if "null_byte" in mutations:
                mutated.extend([f"{payload}%00", f"{payload}\x00"])
            results[payload] = mutated
        return results

    def encode_payload(self, payload: str, encoding: str) -> str:
        encoders = {
            "url": lambda p: urllib.parse.quote(p),
            "html": lambda p: html_escape(p),
            "base64": lambda p: base64.b64encode(p.encode()).decode(),
            "hex": lambda p: p.encode().hex(),
            "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
            "double_url": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        }
        encoder = encoders.get(encoding)
        if not encoder:
            raise ValueError(f"Unknown encoding: {encoding}")
        return encoder(payload)
