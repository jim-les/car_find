from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt as pyjwt
import joblib
import sqlite3  
import pandas as pd

# Load the model from the file
model = joblib.load('trained_model.pkl')

app = FastAPI()

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
# Create SQLite database connection
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create users table if not exists
cursor.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, hashed_password TEXT)''')
conn.commit()

# JWT Token creation
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Models
class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Security
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Signup
@app.post("/signup", response_model=User)
async def signup(user: User):
    cursor.execute("SELECT * FROM users WHERE username=?", (user.username,))
    existing_user = cursor.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = user.password  # In real-world app, hash the password
    cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (user.username, hashed_password))
    conn.commit()
    return user

# Login
@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT * FROM users WHERE username=?", (form_data.username,))
    user = cursor.fetchone()
    if not user or form_data.password != user[2]:  # 2 is the index of hashed_password in the table
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": create_access_token({"sub": user[1]}), "token_type": "bearer"}


def banner():
    # Include a banner for the app CarFind
    print('''
    _______  _______  _______  _______  _______  _______  _______  _______  _______
    |       ||       ||       ||       ||       ||       ||       ||       ||       |
    |   _   ||   _   ||  _____||  _____||  _____||   _   ||  _____||  _____||_     _|
    |  | |  ||  | |  || |_____ | |_____ | |_____ |  | |  || |_____ | |_____   |   |
    |  |_|  ||  |_|  ||_____  ||_____  ||_____  ||  |_|  ||_____  ||_____  |  |   |
    |       ||       | _____| | _____| | _____| ||       | _____| | _____| |  |   |
    |_______||_______||_______||_______||_______||_______||_______||_______|  |___|
    ''')

class CarFind(BaseModel):
    make: str
    model: str
    year: int
    country_of_origin: str
    transmission: str
    engine_type: str
    engine_size: float
    mileage: float
    condition: str
    previous_owners: int
    additional_features: str

@app.get("/")
def read_root():
    banner()
    return {"message": "Welcome to CarFind API"}



@app.post("/predict")
def predict_resale_value(car: CarFind):
    data = pd.DataFrame({
        'Make': [car.make],
        'Model': [car.model],
        'Year': [car.year],
        'Country of Origin': [car.country_of_origin],
        'Transmission': [car.transmission],
        'Engine Type': [car.engine_type],
        'Engine Size (L)': [car.engine_size],
        'Mileage (km)': [car.mileage],
        'Condition': [car.condition],
        'Previous Owners': [car.previous_owners],
        'Additional Features': [car.additional_features]
    })
    
    prediction = model.predict(data)
    return {"predicted_resale_value": f"{prediction[0]:,.2f} Ksh"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
