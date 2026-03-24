from bson.objectid import ObjectId
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.hash import argon2
from pydantic import BaseModel, Field, field_serializer
from pydantic_core import core_schema
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

import jwt
import os
import uvicorn


load_dotenv()


MONGODB_USERNAME = os.getenv("MONGODB_USERNAME")
MONGODB_PASSWORD = os.getenv("MONGODB_PASSWORD")
MONGODB_URL = f"mongodb+srv://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@cluster0.pcppfcw.mongodb.net/?appName=Cluster0"

client = MongoClient(MONGODB_URL)
db = client["commons"]
users_collection = db["users"]
posts_collection = db["posts"]


TOKEN_SECRET_KEY = os.getenv("TOKEN_SECRET_KEY")
TOKEN_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

security = HTTPBearer()

app = FastAPI()


class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source, _handler):
        python_schema = core_schema.union_schema([
            core_schema.is_instance_schema(ObjectId),
            core_schema.str_schema(),
        ])
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.no_info_after_validator_function(cls._validate, python_schema),
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _validate(cls, value):
        if isinstance(value, ObjectId):
            return value
        if isinstance(value, str) and ObjectId.is_valid(value):
            return ObjectId(value)
        raise ValueError("Invalid ObjectId")

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=20)
    password: str = Field(..., min_length=8, max_length=20)

class LoginRequest(BaseModel):
    username: str
    password: str

class PublishPostRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=10)
    content: str = Field(..., min_length=1, max_length=1000)
    repost_source_post_id: PyObjectId | None = None

class Post(BaseModel):
    id: PyObjectId = Field(..., alias="_id")
    title: str | None = None
    content: str
    repost_source_post_id: PyObjectId | None = None
    author_id: PyObjectId
    published_at: datetime
    liked_by: list[PyObjectId]
    model_config = {"populate_by_name": True}

class DisplayPost(Post):
    author_username: str
    num_display_likes: int

class RepostChain(BaseModel):
    posts: list[DisplayPost]

class FeedResponse(BaseModel):
    posts: list[RepostChain]


def create_token(user_id: ObjectId) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, TOKEN_SECRET_KEY, algorithm=TOKEN_ALGORITHM)

def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> ObjectId:
    try:
        token = jwt.decode(credentials.credentials, TOKEN_SECRET_KEY, algorithms=[TOKEN_ALGORITHM])
        user_id = ObjectId(token["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")

    user = users_collection.find_one({"_id": user_id})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found.")
    return user_id

def get_repost_tree_ids(post_id: ObjectId) -> list[ObjectId]:
    """Returns the list of post IDs in the repost tree of which the given post is a node (i.e., identifies the root post and all its descendants)."""

    # first find the root post
    result = posts_collection.aggregate([
        {"$match": {"_id": post_id}},
        {"$graphLookup": {
            "from": "posts",
            "startWith": "$repost_source_post_id",
            "connectFromField": "repost_source_post_id",
            "connectToField": "_id",
            "as": "ancestors",
        }},
    ]).next()

    # the ancestor with no repost_source_post_id is the root post
    root_id = post_id
    for ancestor in result["ancestors"]:
        if ancestor["repost_source_post_id"] is None:
            root_id = ancestor["_id"]
            break

    # then gather all the descendants of the root post
    result = posts_collection.aggregate([
        {"$match": {"_id": root_id}},
        {"$graphLookup": {
            "from": "posts",
            "startWith": "$_id",
            "connectFromField": "_id",
            "connectToField": "repost_source_post_id",
            "as": "descendants",
        }},
    ]).next()

    all_ids = [root_id] + [descendant["_id"] for descendant in result["descendants"]]
    return all_ids

def get_repost_chain(leaf_post: DisplayPost) -> RepostChain:
    """Returns the ordered repost chain ending at the given post (root -> ... -> leaf)."""

    result = posts_collection.aggregate([
        {"$match": {"_id": leaf_post.id}},
        {"$graphLookup": {
            "from": "posts",
            "startWith": "$repost_source_post_id",
            "connectFromField": "repost_source_post_id",
            "connectToField": "_id",
            "as": "ancestors",
        }},
    ]).next()

    ancestors = result["ancestors"]
    author_ids = list({a["author_id"] for a in ancestors})
    authors = {u["_id"]: u["username"] for u in users_collection.find({"_id": {"$in": author_ids}})}

    for ancestor in ancestors:
        ancestor["author_username"] = authors.get(ancestor["author_id"], "[deleted]")
        ancestor["num_display_likes"] = leaf_post.num_display_likes

    chain = [DisplayPost.model_validate(a) for a in ancestors] + [leaf_post]
    chain.sort(key=lambda p: p.published_at)

    return RepostChain(posts=chain)


@app.post("/users/register", status_code=201)
def register(request: RegisterRequest) -> dict:
    password_hash = argon2.hash(request.password)
    user = {
        "username": request.username,
        "password_hash": password_hash,
        "following": [],
    }

    try:
        users_collection.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail={"message": "Account already exists."})
    return {"message": "Account created."}

@app.post("/users/login", status_code=200)
def login(request: LoginRequest) -> dict:
    user = users_collection.find_one({"username": request.username})
    if user is None:
        raise HTTPException(status_code=401, detail={"message": "Invalid username or password."})

    actual_hash = user["password_hash"]
    if argon2.verify(request.password, actual_hash):
        token = create_token(user["_id"])
        return {"message": "Login valid.", "token": token}
    raise HTTPException(status_code=401, detail={"message": "Invalid username or password."})

@app.post("/users/{user_to_follow_id}/follow", status_code=200)
def follow_user(
    user_to_follow_id: PyObjectId,
    user_id: ObjectId = Depends(get_current_user_id),
) -> dict:
    if user_to_follow_id == user_id:
        raise HTTPException(status_code=400, detail={"message": "You cannot follow yourself."})

    result = users_collection.update_one(
        {"_id": user_id, "following": {"$ne": user_to_follow_id}},
        {"$addToSet": {"following": user_to_follow_id}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail={"message": "User not found or already followed."})
    return {"message": "User followed."}

@app.post("/users/{user_to_unfollow_id}/unfollow", status_code=200)
def unfollow_user(
    user_to_unfollow_id: PyObjectId,
    user_id: ObjectId = Depends(get_current_user_id),
) -> dict:
    result = users_collection.update_one(
        {"_id": user_id, "following": user_to_unfollow_id},
        {"$pull": {"following": user_to_unfollow_id}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail={"message": "User not found or not followed."})
    return {"message": "User unfollowed."}

@app.post("/posts/publish", status_code=201)
def publish_post(
    request: PublishPostRequest,
    user_id: ObjectId = Depends(get_current_user_id),
) -> dict:
    post = {
        "title": request.title,
        "content": request.content,
        "author_id": user_id,
        "repost_source_post_id": request.repost_source_post_id,
        "published_at": datetime.now(timezone.utc),
        "liked_by": [],
    }
    posts_collection.insert_one(post)
    return {"message": "Post published."}

@app.post("/posts/{post_id}/like", status_code=200)
def like_post(
    post_id: PyObjectId,
    user_id: ObjectId = Depends(get_current_user_id),
) -> dict:
    result = posts_collection.update_one(
        {"_id": post_id, "liked_by": {"$ne": user_id}},
        {"$addToSet": {"liked_by": user_id}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail={"message": "Post not found or already liked."})
    return {"message": "Post liked."}

@app.post("/posts/{post_id}/unlike", status_code=200)
def unlike_post(
    post_id: PyObjectId,
    user_id: ObjectId = Depends(get_current_user_id),
) -> dict:
    result = posts_collection.update_one(
        {"_id": post_id, "liked_by": user_id},
        {"$pull": {"liked_by": user_id}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail={"message": "Post not found or not liked."})
    return {"message": "Post unliked."}

@app.get("/feed/private", status_code=200)
def get_private_feed(user_id: ObjectId = Depends(get_current_user_id)) -> FeedResponse:
    user = users_collection.find_one({"_id": user_id})
    if user is None:
        raise HTTPException(status_code=404, detail={"message": "User not found."})

    pipeline = [
        {"$match": {
            "author_id": {"$in": user["following"]},
            "published_at": {"$gte": datetime.now(timezone.utc) - timedelta(weeks=2)},
        }},
        {"$sort": {"published_at": -1}},
        {"$lookup": {
            "from": "users",
            "localField": "author_id",
            "foreignField": "_id",
            "as": "author",
        }},
        {"$unwind": "$author"},
        {"$addFields": {"author_username": "$author.username"}},
        {"$project": {"author": False}},
    ]
    posts = list(posts_collection.aggregate(pipeline))

    for post in posts:
        tree_ids = get_repost_tree_ids(post["_id"])
        tree_likes = posts_collection.aggregate([
            {"$match": {"_id": {"$in": tree_ids}}},
            {"$group": {
                "_id": None,
                "total_likes": {"$sum": {"$size": "$liked_by"}},
            }},
        ]).next()
        post["num_display_likes"] = tree_likes["total_likes"]

    repost_chains = [get_repost_chain(DisplayPost.model_validate(post)) for post in posts]

    return FeedResponse(posts=repost_chains)


if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)
