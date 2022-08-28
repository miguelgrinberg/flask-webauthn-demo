import time
import uuid
from sqlalchemy import Column, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from .app import db, login


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = Column(Text, primary_key=True, default=lambda: uuid.uuid4().hex)
    username = Column(Text)
    password_hash = Column(Text)

    keys = relationship('Key', back_populates='user')


class Key(db.Model):
    __tablename__ = 'keys'
    id = Column(Text, primary_key=True, default=lambda: uuid.uuid4().hex)
    user_id = Column(Text, ForeignKey('users.id'))
    name = Column(Text)
    credential_id = Column(Text, index=True)
    public_key = Column(Text)
    sign_count = Column(Integer, default=1)
    last_used = Column(Integer, default=time.time)

    user = relationship('User', back_populates='keys')


@login.user_loader
def load_user(id):
    return db.session.get(User, id)
