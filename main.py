from fastapi import FastAPI, Depends, HTTPException, status,Request, Form, File, UploadFile,Query
import mysql.connector
from dotenv import load_dotenv
from mysql.connector import Error 
import os
import io
import qrcode
from starlette.datastructures import UploadFile as StarletteUploadFile

from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import date, datetime, timedelta
from typing import Optional, List
from jose import jwt, JWTError
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from supabase import create_client, Client
import uuid
import json
import ast

# Load environment variables
load_dotenv()
host = os.getenv("DB_HOST")
user = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
db = os.getenv("DB_DATABASE")
SECRET_KEY = os.getenv("SECRET_KEY", "Transport_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
BUCKET_NAME = "uploads"  # Supabase bucket name
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Database connection
def get_db():
    conn = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_DATABASE")
)
    cursor = conn.cursor(dictionary=True,buffered=True)
    try:
        yield conn, cursor
    finally:
        cursor.close()
        conn.close()


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# JWT OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # username = payload.get("sub")
        role_id = payload.get("role_id")
        user_id = payload.get("user_id")
        vehicle_id = payload.get("vehicle_id") 


        if  role_id is None or user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token data")

        conn, cursor = db
        cursor.execute("SELECT * FROM users WHERE id=%s AND status=%s", (user_id, 1))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return {"id": user["id"],  "role_id": user["role_id"],"vehicle_id":vehicle_id}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# FastAPI app
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class LoginModel(BaseModel):
    username: str
    password: str

class DeleteGroupModel(BaseModel):
    id: int

class StatusUpdate(BaseModel):
    status: int  # 0 = deleted, 1 = active


class VehicleAssignRequest(BaseModel):
    attendee_id: int
    vehicle_id: int
    # assignment_date: str = None
    # notes: str = None


class SupervisorModel(BaseModel):
    name: str
    # username: str
    password: str
    email: str
    group_name: List[int] 

class deleteVehicle(BaseModel):
    id:int


class AssignDriverRequest(BaseModel):
    driver_id: int
    bus_id: int


class DeleteSupervisorModel(BaseModel):
    id:int

# class UpdateSupervisor(BaseModel):
#     id: int
#     name: str
#     # username:Optional[str]
#     password:str
#     email: str
#     vehicle_no: Optional[int]

class UpdateSupervisor(BaseModel):
    id: int
    emp_id:Optional[str]
    name: str
    email: str
    password: Optional[str] = None
    group_ids: List[int] = []


class AttendeeUpdate(BaseModel):
    name: Optional[str]
    password: Optional[str] 
    email: Optional[str]
    contact_number: Optional[int]

# class UpdateDriver(BaseModel):
#     id:Optional[int] 
#     name:Optional[str]
#     username:Optional[str]
#     email:Optional[str]

@app.get("/")
def index(db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("SELECT * FROM roles")
    return cursor.fetchall()

# Admin creation
@app.get("/admin_login_credentials")
def admin_login(db=Depends(get_db)):
    conn, cursor = db
    cursor.execute('SELECT * FROM users WHERE username=%s AND status=%s', ("admin", 1))
    exists = cursor.fetchone()
    if exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Admin already exists!")
    pwd = hash_password("admin@123")
    cursor.execute(
        "INSERT INTO users(role_id, name, username, password, email) VALUES (%s, %s, %s, %s, %s)",
        (1, "admin", "admin", pwd, "admin@gmail.com")
    )
    conn.commit()
    return {"message": "Inserted Successfully!"}

# Login
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    username = form_data.username
    password = form_data.password
    conn, cursor = db
    user=None
    
    cursor.execute("SELECT * FROM users WHERE email=%s AND status=%s", (username, 1))
    user = cursor.fetchone()

   
    if not user:
        cursor.execute("SELECT * FROM users WHERE emp_id=%s AND status=%s", (username, 1))
        user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=401,detail="Invalid Crendentials!")   

    if user["role_id"] == 1:
       
        if username != user["email"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admins must log in with email")
   


    assigned_vehicle=None
    if user["role_id"]==3:
        cursor.execute("select vehicle_id from driver_master where user_id=%s",(user["id"],))
        row=cursor.fetchone()
        if row:
            assigned_vehicle=row['vehicle_id']
    
    if user and verify_password(password, user['password']):
        token_data = {
            "role_id": user["role_id"],
            "user_id": user["id"],
            "vehicle_id":assigned_vehicle,
        }

        access_token = create_access_token(token_data)
  
        # Return token + role + user info
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role_id": user["role_id"],
            "user_id": user["id"],
            "email": user["email"],
             "vehicle_id":assigned_vehicle,
        }

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Login Details")


    
async def handle_file_upload(file: Optional[UploadFile], folder: str = "") -> Optional[str]:
   
    if file and file.filename:
       
        filename = f"{uuid.uuid4()}.{file.filename.split('.')[-1]}"
        path = f"{folder}/{filename}" if folder else filename

        data = await file.read()
        supabase.storage.from_(BUCKET_NAME).upload(path, data, {"content-type": file.content_type})
        public_url = supabase.storage.from_(BUCKET_NAME).get_public_url(path)
        return public_url
    return None


async def generate_and_upload_qr(vehicle_id: str) -> Optional[str]:
    """Generate QR code for a vehicle and upload it to Supabase in 'qrcodes' folder."""
    
    # Generate QR code image in memory
    qr = qrcode.make(vehicle_id)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

   
    qr_file = StarletteUploadFile(
        filename=f"{vehicle_id}.png",
        file=buffer
    )

   
    qrcode_url = await handle_file_upload(qr_file, "qrcodes")

    return qrcode_url

@app.post("/store_vehicles")
async def store_vehicle(
    request: Request, 
    vehicle_no: str = Form(...),
    bus_number: str = Form(...),
    rc_number: Optional[str] = Form(None),
    rc_document: Optional[UploadFile] = File(None),
    insurance_number: Optional[str] = Form(None),
    insurance_document: Optional[UploadFile] = File(None),
    insurance_expiry: Optional[str] = Form(None),
    tax: Optional[str] = Form(None),
    permit: Optional[str] = Form(None),
    permit_document: Optional[UploadFile] = File(None),
    permit_expiry: Optional[str] = Form(None),
    emission_certificate_no: Optional[str] = Form(None),
    emission_certificate_doc: Optional[UploadFile] = File(None),
    emission_expiry: Optional[str] = Form(None),
    fitness_certificate_no: Optional[str] = Form(None),
    fitness_certificate_doc: Optional[UploadFile] = File(None),
    fitness_expiry: Optional[str] = Form(None),
    gps: Optional[str] = Form(None),
    loan_status: Optional[str] = Form(None),
    loan_provider: Optional[str] = Form(None),
    loan_amount: Optional[str] = Form(None),
    loan_start_date: Optional[str] = Form(None),
    loan_end_date: Optional[str] = Form(None),

    loan_emi_amount: Optional[str] = Form(None),
    cameras: Optional[str] = Form(None),
    diesel_per_km: Optional[str] = Form(None),
    dlf_filling: Optional[str] = Form(None),
    service_date: Optional[str] = Form(None),
    wheel_alignment_date: Optional[str] = Form(None),
    battery_sts: Optional[str] = Form(None),
    tyre_count: Optional[int] = Form(None),
    front_left_tyre_status: Optional[str] = Form(None),
    front_right_tyre_status: Optional[str] = Form(None),
    rear_left_tyre_status: Optional[str] = Form(None),
    rear_right_tyre_status: Optional[str] = Form(None),
    
    others: Optional[str] = Form(None),
    vehicle_image: Optional[UploadFile] = File(None),
    service_status:Optional[str]=Form(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db
    form_data = await request.form()  # ⬅️ Capture all form fields

   
    cursor.execute("SELECT vehicle_id FROM vehicle_master ORDER BY id DESC LIMIT 1")
    last = cursor.fetchone()
    


    if last and last.get("vehicle_id"):  # access by column name
       last_num = int(last["vehicle_id"].replace("VEH", ""))
       new_num = last_num + 1
    else:
       new_num = 1

    vehicle_id = f"VEH{new_num:03}"
    qrcode_url = await generate_and_upload_qr(vehicle_id)
    

  


    # # Handle all file uploads
    # image_url = await handle_file_upload(vehicle_image)
    # rc_doc_url = await handle_file_upload(rc_document)
    # insurance_doc_url = await handle_file_upload(insurance_document)
    # emission_doc_url = await handle_file_upload(emission_certificate_doc)
    # fitness_doc_url = await handle_file_upload(fitness_certificate_doc)
    image_url = await handle_file_upload(vehicle_image, "vehicle_image")
    rc_doc_url = await handle_file_upload(rc_document, "vehicle_documents")
    insurance_doc_url = await handle_file_upload(insurance_document, "vehicle_documents")
    emission_doc_url = await handle_file_upload(emission_certificate_doc, "vehicle_documents")
    fitness_doc_url = await handle_file_upload(fitness_certificate_doc, "vehicle_documents")
    permit_doc_url = await handle_file_upload(permit_document, "vehicle_documents")


    

  
    def clean_value(value):
        return value if value and value != "" else None

    cameras = clean_value(cameras)  
    tyre_count_val = int(form_data.get("tyre_count") or 0)
    additional_tyres_list = []
    if tyre_count_val > 4:
     for i in range(tyre_count_val - 4):
        stepney_val = clean_value(form_data.get(f"stepney_{i+1}_status"))  # Use form_data
        if stepney_val:
            additional_tyres_list.append(stepney_val)
    additional_tyres_json = json.dumps(additional_tyres_list) if additional_tyres_list else None


    # ✅ Convert to JSON string for DB (varchar or JSON type)
    additional_tyres_json = json.dumps(additional_tyres_list) if additional_tyres_list else None

  
    cursor.execute("""
    INSERT INTO vehicle_master (
        vehicle_id,vehicle_no,qrcode_url, bus_number, rc_number, rc_document, insurance_number, insurance_document, insurance_expiry,
        tax, permit_no, permit_doc, permit_expiry, emission_certificate_no, emission_certificate_doc, emission_expiry,
        fitness_certificate_no, fitness_certificate_doc, fitness_expiry, gps, loan_status, loan_provider,loan_start_date,loan_end_date, loan_amount,
        loan_emi_amount, tyre_count, front_left_tyre_status, front_right_tyre_status, rear_left_tyre_status, rear_right_tyre_status,
       additional_tyres, cameras, diesel_per_km, dlf_filling, service_date,wheel_alignment_date, battery_sts, others, vehicle_image, service_status, vehicle_status
    ) VALUES (%s,%s,%s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
""", (
    vehicle_id,vehicle_no, qrcode_url,bus_number, rc_number, rc_doc_url, insurance_number, insurance_doc_url, insurance_expiry,
    tax, permit, permit_doc_url, permit_expiry, emission_certificate_no, emission_doc_url, emission_expiry,
    fitness_certificate_no, fitness_doc_url, fitness_expiry, gps, loan_status, loan_provider,loan_start_date,loan_end_date, loan_amount,
    loan_emi_amount, tyre_count_val, front_left_tyre_status, front_right_tyre_status, rear_left_tyre_status, rear_right_tyre_status,
    additional_tyres_json,cameras, diesel_per_km, dlf_filling, service_date, wheel_alignment_date,battery_sts, others, image_url, service_status, 'active'
))

    conn.commit()
    return {"message": "Vehicle inserted successfully!"}

# # Vehicle list
# @app.get('/vehicle_list')
# def vehicle_list(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
#     conn, cursor = db
#     cursor.execute('SELECT * FROM vehicle_master WHERE status=%s ', (1,))
#     return cursor.fetchall()

@app.get("/vehicle_list")
def get_vehicle_list(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    cursor.execute("""
        SELECT 
            vm.*,
            dm.name AS driver_name,
            gm.group_name,
            sm.name AS supervisor_name
        FROM vehicle_master vm
        LEFT JOIN driver_master dm ON dm.vehicle_id = vm.id
        LEFT JOIN group_master gm ON gm.id = vm.group_id
        LEFT JOIN supervisor_master sm ON sm.group_id = gm.id
        where vm.status=1
    """)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]
@app.get("/get_buses_for_edit/{group_id}")
def get_buses_for_edit(group_id: int, db=Depends(get_db),current_user: dict = Depends(get_current_user)):
    conn, cursor = db

    # Find buses already assigned to this group
    cursor.execute("SELECT buses FROM group_master WHERE id=%s AND status=1", (group_id,))
    group = cursor.fetchone()
    assigned_buses = []
    if group and group.get("buses"):
        try:
            import ast
            assigned_buses = ast.literal_eval(group["buses"])
        except Exception:
            assigned_buses = []

    # Fetch all active & idle buses plus assigned ones
    format_strings = ",".join(["%s"] * len(assigned_buses)) if assigned_buses else ""
    if assigned_buses:
        query = f"""
            SELECT id, vehicle_no
            FROM vehicle_master
            WHERE status=1 AND (vehicle_status='Active'  OR id IN ({format_strings}))
        """
        cursor.execute(query, assigned_buses)
    else:
        cursor.execute(
            "SELECT id, vehicle_no FROM vehicle_master WHERE status=1 AND vehicle_status='Active'"
        )

    buses = cursor.fetchall()

    return {
        "assigned_bus_ids": assigned_buses,
        "buses": buses,
    }



# Delete vehicle
@app.post('/delete_vehicle')
def delete_vehicle(data:deleteVehicle,current_user:dict=Depends(get_current_user),db=Depends(get_db)):
    conn,cursor=db
    id=data.id
    cursor.execute("update vehicle_master set status=%s where id=%s",(0,id))
    conn.commit()
    return {"message":"Vehicle Deleted Successfully!"}

@app.post('/update_vehicle')
async def update_vehicle(
    request: Request, 
    id: int = Form(...),
    
    vehicle_no: str = Form(...),
    bus_number: Optional[str] = Form(None),
    rc_number: Optional[str] = Form(None),
    rc_document: Optional[UploadFile] = File(None),
    insurance_number: Optional[str] = Form(None),
    insurance_document: Optional[UploadFile] = File(None),
    insurance_expiry: Optional[str] = Form(None),
    tax: Optional[str] = Form(None),
    permit_no: Optional[str] = Form(None),
    permit_doc: Optional[UploadFile] = File(None),
    permit_expiry: Optional[str] = Form(None),
    emission_certificate_no: Optional[str] = Form(None),
    emission_certificate_doc: Optional[UploadFile] = File(None),
    emission_expiry: Optional[str] = Form(None),
    fitness_certificate_no: Optional[str] = Form(None),
    fitness_certificate_doc: Optional[UploadFile] = File(None),
    fitness_expiry: Optional[str] = Form(None),
    gps: Optional[str] = Form(None),
    loan_status: Optional[str] = Form(None),
    loan_provider: Optional[str] = Form(None),
    loan_amount: Optional[str] = Form(None),
    loan_emi_amount: Optional[str] = Form(None),
    loan_start_date:Optional[str]=Form(None),
    loan_end_date:Optional[str]=Form(None),
    cameras: Optional[str] = Form(None),
    diesel_per_km: Optional[str] = Form(None),
    dlf_filling: Optional[str] = Form(None),
    service_date: Optional[str] = Form(None),
    battery_sts: Optional[str] = Form(None),
    tyre_count: Optional[str] = Form(None),
    front_left_tyre_status: Optional[str] = Form(None),
    front_right_tyre_status: Optional[str] = Form(None),
    rear_left_tyre_status: Optional[str] = Form(None),
    rear_right_tyre_status: Optional[str] = Form(None),
    service_status: Optional[str] = Form(None),
    wheel_alignment_date: Optional[str] = Form(None),
    others: Optional[str] = Form(None),
    vehicle_image: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user),
  
    db=Depends(get_db)
):
    conn, cursor = db
    form_data = await request.form()

    def clean(value):
        if not value or str(value).strip().lower() in ["", "null", "none"]:
            return None
        return value

    # Handle uploaded files
    image_url = await handle_file_upload(vehicle_image, "vehicle_image")
    rc_doc_url = await handle_file_upload(rc_document, "vehicle_documents")
    insurance_doc_url = await handle_file_upload(insurance_document, "vehicle_documents")
    emission_doc_url = await handle_file_upload(emission_certificate_doc, "vehicle_documents")
    fitness_doc_url = await handle_file_upload(fitness_certificate_doc, "vehicle_documents")
    permit_doc_url = await handle_file_upload(permit_doc, "vehicle_documents")

    update_fields = []
    update_values = []
    # Clear loan fields if loan_status is Cleared
    if loan_status and loan_status.lower() == 'cleared':
        loan_provider = ''
        loan_amount = ''
        loan_emi_amount = ''
    if loan_status and loan_status.lower() =="not applicable":
        loan_provider=" "
        loan_amount=''
        loan_emi_amount=''
        loan_start_date=''
        loan_end_date=''

    tyre_count_val = int(form_data.get("tyre_count") or 0)

    additional_tyres_list = []
    if tyre_count_val > 4:
     for i in range(tyre_count_val - 4):
        stepney_val = clean(form_data.get(f"stepney_{i+1}_status"))
        if stepney_val:
            additional_tyres_list.append(stepney_val)

    additional_tyres_json = json.dumps(additional_tyres_list) if additional_tyres_list else None
    fields_to_update = [
        ("vehicle_no", vehicle_no),
        ("bus_number", bus_number),
        ("rc_number", rc_number),
        ("insurance_number", insurance_number),
        ("insurance_expiry", insurance_expiry),
        ("tax", tax),
        ("permit_no", permit_no),
        ("permit_expiry", permit_expiry),
        ("emission_certificate_no", emission_certificate_no),
        ("emission_expiry", emission_expiry),
        ("fitness_certificate_no", fitness_certificate_no),
        ("fitness_expiry", fitness_expiry),
        ("gps", gps),
        ("loan_status", loan_status),
        ("loan_provider", loan_provider),
        ("loan_amount", loan_amount),
        ("loan_emi_amount", loan_emi_amount),
        ("loan_start_date",loan_start_date),
        ("loan_end_date",loan_end_date),
        ("cameras", cameras),
        ("diesel_per_km", diesel_per_km),
        ("dlf_filling", dlf_filling),
        ("service_date", service_date),
        ("battery_sts", battery_sts),
        ("tyre_count", tyre_count),
        ("front_left_tyre_status", front_left_tyre_status),
        ("front_right_tyre_status", front_right_tyre_status),
        ("rear_left_tyre_status", rear_left_tyre_status),
        ("rear_right_tyre_status", rear_right_tyre_status),
        ("additional_tyres", additional_tyres_json),  
        ("service_status", service_status),
        ("wheel_alignment_date", wheel_alignment_date),
        ("others", others),
    ]

    # Include uploaded files if present
    if image_url:
        fields_to_update.append(("vehicle_image", image_url))
    if rc_doc_url:
        fields_to_update.append(("rc_document", rc_doc_url))
    if insurance_doc_url:
        fields_to_update.append(("insurance_document", insurance_doc_url))
    if permit_doc_url:
        fields_to_update.append(("permit_doc", permit_doc_url))
    if emission_doc_url:
        fields_to_update.append(("emission_certificate_doc", emission_doc_url))
    if fitness_doc_url:
        fields_to_update.append(("fitness_certificate_doc", fitness_doc_url))

    for field, value in fields_to_update:
    # Only skip None values, allow empty strings
      if value is not None:
        update_fields.append(f"{field}=%s")
        update_values.append(value)


    update_values.append(id)  # WHERE id=%s

    if update_fields:
        query = f"UPDATE vehicle_master SET {', '.join(update_fields)} WHERE id=%s"
        cursor.execute(query, update_values)
        conn.commit()
        return {"success": True, "message": "Vehicle updated successfully!"}
    else:
        return {"success": False, "message": "No valid fields to update"}

@app.get('/get_buses')
def buses_list(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("""
        SELECT id, vehicle_no 
        FROM vehicle_master 
        WHERE vehicle_status = %s 
         
          AND status = %s
    """, ('Active',  1))
    rows = cursor.fetchall()
    return rows


# @app.get("/get_buses_for_edit/{supervisor_id}")
# def get_buses_for_edit(supervisor_id: int, db=Depends(get_db)):
#     conn, cursor = db

   
#     cursor.execute(
#         "SELECT buses FROM group_master WHERE user_id=%s",
#         (supervisor_id,)
#     )
#     assigned_vehicle = cursor.fetchone()
#     assigned_id = assigned_vehicle['vehicle_id'] if assigned_vehicle else None

#     if assigned_id:
#         cursor.execute(
#             """
#             SELECT id, vehicle_no
#             FROM vehicle_master
#             WHERE status=1 and vehicle_status=%s and service_status=%s OR id=%s
#             """,
#             ("Active","Idle",assigned_id)
#         )
#     else:
#         cursor.execute(
#             "SELECT id, vehicle_no FROM vehicle_master WHERE status=1"
#         )

#     vehicles = cursor.fetchall()
#     return vehicles

@app.post("/update_group")
def update_group(
    id: int = Form(...),
    group_name: str = Form(...),
    buses: str = Form(...), 
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
  
):
    conn, cursor = db
    try:
    
        cursor.execute("SELECT buses FROM group_master WHERE id = %s", (id,))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

      
        old_buses = json.loads(group["buses"] or "[]")
        new_buses = json.loads(buses or "[]")

     
        removed_buses = [b for b in old_buses if b not in new_buses]
        added_buses = [b for b in new_buses if b not in old_buses]

      
        if removed_buses:
            cursor.execute(
                f"""
                UPDATE vehicle_master 
                SET vehicle_status='active', group_id=NULL 
                WHERE id IN ({','.join(map(str, removed_buses))})
                """
            )

        if added_buses:
            cursor.execute(
                f"""
                UPDATE vehicle_master 
                SET  group_id=%s ,vehicle_status=%s
                WHERE id IN ({','.join(map(str, added_buses))})
                """,
                (id,"Inactive"),
            )

       
        cursor.execute(
            "UPDATE group_master SET group_name=%s, buses=%s WHERE id=%s",
            (group_name, json.dumps(new_buses), id),
        )

        
        conn.commit()
        return {"status": "success", "message": "Group updated successfully"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

class SupervisorCreate(BaseModel):
    name: str
    password: str
    emp_id: Optional[str] = None
    email: Optional[str] = None
    group_ids: Optional[List[int]] = None

@app.post('/add_supervisor')
def add_supervisor(
    data: SupervisorCreate,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    conn, cursor = db
    try:
        group_ids_list = data.group_ids or []
        hashed_pwd = hash_password(data.password)
        # cursor.execute("SELECT id FROM users WHERE name=%s", (data.name,))
        # if cursor.fetchone():
        #     raise HTTPException(status_code=400, detail="Username already exists")

        # Insert into users
        cursor.execute(
            "INSERT INTO users (role_id, emp_id, name, password, email) VALUES (%s, %s, %s, %s, %s)",
            (2, data.emp_id, data.name, hashed_pwd, data.email)
        )
        user_id = cursor.lastrowid

        # Insert into supervisor_master (one per group)
        if group_ids_list:
            for group_id in group_ids_list:
                cursor.execute(
                    "INSERT INTO supervisor_master (user_id, name, group_id) VALUES (%s, %s, %s)",
                    (user_id, data.name, group_id)
                )
                cursor.execute(
                    "UPDATE group_master SET group_status=%s WHERE id=%s",
                    (0, group_id)
                )
        else:
            # If no group selected, still insert base supervisor
            cursor.execute(
                "INSERT INTO supervisor_master (user_id, name) VALUES (%s, %s)",
                (user_id, data.name)
            )

        conn.commit()
        return {"message": "Supervisor added successfully!"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/supervisor_list')
def supervisor_list(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db

    try:
        # ✅ Fetch unique supervisors (DISTINCT avoids duplicates)
        cursor.execute("""
            SELECT DISTINCT 
                u.id AS user_id,
                u.emp_id,
                u.name,
                u.username,
                u.email
            FROM users u
            INNER JOIN supervisor_master s ON u.id = s.user_id
            WHERE u.role_id = %s AND s.status = %s
        """, (2, 1))
        supervisors = cursor.fetchall()

        result = []

        for sup in supervisors:
            # ✅ Fetch all groups linked to this supervisor
            cursor.execute("""
                SELECT g.id AS group_id, g.group_name
                FROM supervisor_master sm
                INNER JOIN group_master g ON sm.group_id = g.id
                WHERE sm.user_id = %s AND sm.status = 1
            """, (sup['user_id'],))
            
            group_data = cursor.fetchall()
            groups = [g['group_name'] for g in group_data]
            group_ids = [g['group_id'] for g in group_data]

            result.append({
                "id": sup['user_id'],  
                "emp_id": sup['emp_id'],     
                "name": sup['name'],
                "username": sup['username'],
                "email": sup['email'],
                "group_ids": group_ids,
                "groups": groups
            })

        # print("✅ FINAL RESULT:", result)
        return result

    except Exception as e:
        # print("❌ Error in /supervisor_list:", str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/delete_supervisor")
def delete_supervisor(data: dict, current_user: dict = Depends(get_current_user),db=Depends(get_db)):
    conn, cursor = db
    try:
        user_id = data.get("user_id")
        group_id = data.get("group_id")

        if not user_id or not group_id:
            raise HTTPException(status_code=400, detail="user_id and group_id required")

        # Step 1: Unlink supervisor from the given group
        cursor.execute(
            "UPDATE supervisor_master SET group_id = 0 WHERE user_id = %s AND group_id = %s",
            (user_id, group_id),
        )
        unlink_count = cursor.rowcount

        if unlink_count == 0:
            raise HTTPException(status_code=404, detail="Supervisor-group link not found")

        # Step 2: Mark that group as available
        cursor.execute(
            "UPDATE group_master SET group_status = 1 WHERE id = %s",
            (group_id,),
        )

        conn.commit()
        # print(f"✅ Supervisor {user_id} unlinked from group {group_id}")

        # ✅ Fetch updated supervisor data
        cursor.execute("""
            SELECT u.id AS id, u.name, u.email
            FROM users u
            WHERE u.id = %s
        """, (user_id,))
        supervisor = cursor.fetchone()

        if not supervisor:
            raise HTTPException(status_code=404, detail="Supervisor not found")

        # ✅ Fetch remaining group assignments
        cursor.execute("""
            SELECT g.id, g.group_name
            FROM supervisor_master s
            JOIN group_master g ON g.id = s.group_id
            WHERE s.user_id = %s AND s.group_id != 0
        """, (user_id,))
        groups = cursor.fetchall()

        updated_groups = [g["group_name"] for g in groups]
        updated_group_ids = [g["id"] for g in groups]

       
        return {
            "status": "success",
            "message": f"Supervisor unlinked from group successfully.",
            "supervisor": {
                "id": supervisor["id"],
                "name": supervisor["name"],
                "email": supervisor["email"],
                "group_ids": updated_group_ids,
                "groups": updated_groups,
            },
        }

    except Exception as e:
        conn.rollback()
        # print("❌ Error in /delete_supervisor:", str(e))
        raise HTTPException(status_code=500, detail=str(e))


# Update Supervisor
# @app.post("/update_supervisor")
# def update_supervisor(data: UpdateSupervisor, db=Depends(get_db)):
#     conn, cursor = db
#     try:
      
#         # 0. Check if user exists
#         cursor.execute("SELECT * FROM users WHERE id=%s", (data.id,))
#         user_row = cursor.fetchone()
#         if not user_row:
#             raise HTTPException(status_code=400, detail="User does not exist. Cannot assign supervisor role.")

#         # 1. Check if supervisor row exists
#         cursor.execute("SELECT * FROM supervisor_master WHERE user_id=%s", (data.id,))
#         supervisor_row = cursor.fetchone()
#         old_vehicle_no = supervisor_row.get('vehicle_id') if supervisor_row else None

#         # 2. Update or Insert supervisor_master
#         if supervisor_row:
#             cursor.execute(
#                 "UPDATE supervisor_master SET vehicle_id=%s, status=%s WHERE user_id=%s",
#                 (data.vehicle_no, 1, data.id)
#             )
#         else:
#             cursor.execute(
#                 "INSERT INTO supervisor_master (user_id, vehicle_id, status) VALUES (%s, %s, %s)",
#                 (data.id, data.vehicle_no, 1)
#             )

#         # 3. Update users table
#         cursor.execute(
#             """
#             UPDATE users
#             SET name=%s, username=%s, email=%s
#             WHERE id=%s
#             """,
#             (data.name, data.username, data.email, data.id)
#         )

#         # 4. Update vehicle_master status
#         if old_vehicle_no and old_vehicle_no != data.vehicle_no:
#             cursor.execute(
#                 "UPDATE vehicle_master SET vehicle_status=%s WHERE id=%s",
#                 ('Active', old_vehicle_no)
#             )
#             if data.vehicle_no:
#                 cursor.execute(
#                     "UPDATE vehicle_master SET vehicle_status=%s WHERE id=%s",
#                     ('Inactive', data.vehicle_no)
#                 )
#         elif data.vehicle_no:
#             cursor.execute(
#                 "UPDATE vehicle_master SET vehicle_status=%s WHERE id=%s",
#                 ('Inactive', data.vehicle_no)
#             )

#         conn.commit()
#         return {"message": "Supervisor updated successfully"}

#     except mysql.connector.Error as e:
#         conn.rollback()
#         raise HTTPException(status_code=400, detail=str(e))
#     except Exception as e:
#         conn.rollback()
#         raise HTTPException(status_code=500, detail="Unexpected error: " + str(e))
@app.post("/update_supervisor")
def update_supervisor(data: UpdateSupervisor,current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
       

        
        cursor.execute(
            "UPDATE users SET name=%s,emp_id=%s, email=%s WHERE id=%s",
            (data.name, data.emp_id,data.email, data.id)
        )
        cursor.execute(
            "UPDATE supervisor_master SET name=%s WHERE user_id=%s",
            (data.name, data.id)
        )

        
        if data.password:
            
            hashed_pwd = hash_password(data.password)
            cursor.execute(
                "UPDATE users SET password=%s WHERE id=%s",
                (hashed_pwd, data.id)
            )

       
        cursor.execute(
        "SELECT group_id FROM supervisor_master WHERE user_id=%s",
        (data.id,))
        rows = cursor.fetchall() or []

        old_groups = [row['group_id'] for row in rows]
       


        
        removed_groups = set(old_groups) - set(data.group_ids)
        added_groups = set(data.group_ids) - set(old_groups)
        

        # 3️⃣ Update group assignments
        for gid in removed_groups:
            cursor.execute(
        """
        UPDATE supervisor_master
        SET  group_id=NULL
        WHERE user_id=%s AND group_id=%s
        """,
        (data.id, gid)
    )
                
            cursor.execute(
                "UPDATE group_master SET group_status=1 WHERE id=%s",
                (gid,)
            )

        for gid in added_groups:
            cursor.execute(
                "INSERT INTO supervisor_master(name,user_id, group_id) VALUES(%s,%s,%s)",
                (data.name,data.id, gid)
            )
            cursor.execute(
                "UPDATE group_master SET group_status=0 WHERE id=%s",
                (gid,)
            )

       
        conn.commit()
       
        return {"status": "success", "message": "Supervisor updated successfully!"}

    except Exception as e:
        conn.rollback()
        # DEBUG: log full exception type and message
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"GENERAL ERROR: {str(e)}")

@app.get("/get_groups_for_edit/{supervisor_id}")
def get_groups_for_edit(supervisor_id: int,current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
        dict_cursor = conn.cursor(dictionary=True)

        # Step 1: Get assigned groups for this supervisor
        dict_cursor.execute(
            "SELECT group_id FROM supervisor_master WHERE user_id=%s and status=1",
            (supervisor_id,)
        )
        rows = dict_cursor.fetchall()
        assigned_groups = [row['group_id'] for row in rows]  # safe

        # Step 2: Get all groups from group_master
        dict_cursor.execute("SELECT id, group_name, group_status FROM group_master")
        all_groups = dict_cursor.fetchall()  # list of dicts

        # Step 3: Include active groups (group_status=1) or already assigned
        filtered_groups = [
            g for g in all_groups if g['group_status'] == 1 or g['id'] in assigned_groups
        ]

        return {
            "status": "success",
            "data": filtered_groups,
            "assigned_group_ids": assigned_groups
        }

    except Exception as e:
        
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/add_driver")
async def add_driver(
    name: str = Form(...),             
    password: str = Form(...),          
    emp_id: Optional[str] = Form(None), 
    email: Optional[str] = Form(None),
    contact_number: Optional[str] = Form(None),
    bus_id: Optional[int] = Form(None),  # optional integer
    id_proof_no: Optional[str] = Form(None),
    driving_license_no: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
    id_proof: Optional[UploadFile] = File(None),
    driving_license: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db
    hashed_pwd = hash_password(password)
    bus_id = int(bus_id) if bus_id else None

    
    
    
    # Create user
    cursor.execute(
        "INSERT INTO users(role_id, emp_id, name, password, email) VALUES (%s,%s, %s, %s, %s)",
        (3, emp_id,name,hashed_pwd, email)
    )
    user_id = cursor.lastrowid

    # Upload files
    image_url = await handle_file_upload(image, "driver_images")
    id_proof_url = await handle_file_upload(id_proof, "driver_id")
    driving_license_url = await handle_file_upload(driving_license, "driver_license")

   
    cursor.execute("""
        INSERT INTO driver_master(
           emp_id, user_id,name, contact_number, image, vehicle_id,
            id_proof, id_proof_no, driving_license,license_no
        ) VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
       emp_id, user_id, name, contact_number, image_url, bus_id,
        id_proof_url, id_proof_no, driving_license_url, driving_license_no
    ))

    # Update vehicle status
    cursor.execute("UPDATE vehicle_master SET driver_status=0 WHERE id=%s", (bus_id,))

    conn.commit()
    return {"message": "Driver added successfully!"}

# @app.get("/check_driver_name")
# def check_driver_name(name: str, db=Depends(get_db)):
#     conn, cursor = db
#     cursor.execute("SELECT id FROM users WHERE name=%s", (name,))
#     return {"exists": cursor.fetchone() is not None}

# @app.get("/check_driver_email")
# def check_driver_email(email: str, db=Depends(get_db)):
#     conn, cursor = db
#     cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
#     return {"exists": cursor.fetchone() is not None}

# @app.post("/update_driver")
# async def update_driver(
#     user_id: int = Form(...),
#     name: str = Form(...),
#     username: str = Form(...),
#     email: str = Form(...),
#     contact_number: Optional[str] = Form(None),
#     db=Depends(get_db)
  
   
# ):
#     conn, cursor = db
#     cursor.execute("update users set name=%s,username=%s,email=%s where id=%s",(name,username,email,user_id))
#     cursor.execute("UPDATE driver_master SET contact_number=%s WHERE user_id=%s", (contact_number, user_id))

#     conn.commit()
#     return {"message": "Driver updated successfully!"}

# @app.get("/drivers")
# def get_drivers(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
#     conn, cursor = db
#     try:
#         cursor.execute("""
#             SELECT 
#                 v.vehicle_no,
#                 u.id as user_id,
#                 u.emp_id as emp_id,
#                 d.driving_license,
#                 d.license_no as driving_license_no,
#                 d.id_proof,
                
#                 d.id_proof_no, 
#                 u.name,
#                 u.username,
#                 u.email,
#                 d.contact_number,
#                 d.vehicle_id,
#                 d.image as driver_image
#             FROM users u
#             INNER JOIN driver_master d ON u.id = d.user_id
#             LEFT JOIN vehicle_master v on v.id=d.vehicle_id
#             WHERE u.role_id = 3 AND d.status=1
#         """)
#         drivers = cursor.fetchall()
      
#         return drivers
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error fetching drivers: {str(e)}")
    


@app.get("/drivers")
def get_drivers(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
        cursor.execute("""
            SELECT 
                u.id AS user_id,
                u.emp_id,
                u.name,
                u.username,
                u.email,
                d.contact_number,
                d.driving_license,
                d.license_no AS driving_license_no,
                d.id_proof,
                d.id_proof_no,
                d.vehicle_id,
                v.vehicle_no,
                v.bus_number,
                d.image AS driver_image,

                -- Trip details
                COUNT(t.id) AS trip_count,
                MAX(t.start_time) AS last_clock_in,
                MAX(t.end_time) AS last_clock_out,

                -- Ticket details (latest ticket only)
                tk.issue_type,
                tk.description

            FROM users u
            INNER JOIN driver_master d ON u.id = d.user_id
            LEFT JOIN vehicle_master v ON v.id = d.vehicle_id
            LEFT JOIN trips t ON t.driver_id = u.id
            LEFT JOIN tickets tk ON tk.driver_id = u.id 
                AND tk.created_at = (
                    SELECT MAX(t2.created_at)
                    FROM tickets t2
                    WHERE t2.driver_id = u.id
                )

            WHERE u.role_id = 3 AND d.status = 1
            GROUP BY 
                u.id, u.emp_id, u.name, u.username, u.email, d.contact_number, 
                d.driving_license, d.license_no, d.id_proof, d.id_proof_no, 
                d.vehicle_id, v.vehicle_no, d.image, tk.issue_type, tk.description
         
        """)
        
        drivers = cursor.fetchall()
        return drivers

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching drivers: {str(e)}")



@app.post("/drivers/{driver_id}")
def deactivate_driver(driver_id: int, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db

    # 1. Get the vehicle assigned to this driver
    cursor.execute("SELECT vehicle_id FROM driver_master WHERE user_id=%s", (driver_id,))
    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Driver not found")
    vehicle_id = result["vehicle_id"]

    # 2. Update driver_master status to 0 (deactivated)
    cursor.execute("UPDATE driver_master SET status=0 WHERE user_id=%s", (driver_id,))

    # 3. Update vehicle_master driver_status to 1 (available)
    if vehicle_id:
        cursor.execute("UPDATE vehicle_master SET driver_status=1 WHERE id=%s", (vehicle_id,))

    conn.commit()
    return {"message": "Driver deactivated successfully"}


@app.get('/get_supervisors')
def get_supervisors(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("""
        SELECT 
            u.id AS user_id,
            u.name,
            u.username,
            u.email,
            s.vehicle_id
        FROM users u
        INNER JOIN supervisor_master s ON u.id = s.user_id
        WHERE s.status = %s AND u.role_id = %s
    """, (1, 2))
    rows = cursor.fetchall()
    return rows

@app.post("/add_attendee")
async def add_attendee(
    name: str = Form(...),
    password: str = Form(...),
    emp_id: Optional[str] = Form(None),

    email: Optional[str] = Form(None),

    contact_number: Optional[str] = Form(None),
    id_proof_no: Optional[str] = Form(None),
    id_proof: Optional[UploadFile] = File(None),
    attendee_image: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db

    try:
        # Check for existing name/email
        cursor.execute("SELECT id FROM users WHERE name=%s", (name,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists")

        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email already exists")

        hashed_pwd = hash_password(password)

        # Insert into users table
        cursor.execute(
            "INSERT INTO users (role_id, emp_id, name, password, email) VALUES (%s,%s,%s,%s,%s)",
            (4, emp_id, name, hashed_pwd, email)
        )
        user_id = cursor.lastrowid

        # Handle attendee_image upload
        attendee_img_url = None
        if attendee_image and attendee_image.filename:
            attendee_img_url = await handle_file_upload(attendee_image, "attendee_image")

        # Handle id_proof upload
        id_proof_url = None
        if id_proof and id_proof.filename:
            id_proof_url = await handle_file_upload(id_proof, "id_proof")

        # Insert into attendee_master
        cursor.execute("""
            INSERT INTO attendee_master (user_id, id_proof, id_proof_no, contact_number, attendee_img)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, id_proof_url, id_proof_no, contact_number, attendee_img_url))

        conn.commit()

        return {
            "message": "Attendee added successfully!",
            "user_id": user_id,
            "status": "success"
        }

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error adding attendee: {str(e)}")


@app.get("/check_name_exists")
def check_name_exists(name: str, db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("SELECT id FROM users WHERE name=%s", (name,))
    if cursor.fetchone():
        return {"exists": True}
    return {"exists": False}


@app.get("/check_email_exists")
def check_email_exists(email: str, db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        return {"exists": True}
    return {"exists": False}

@app.get("/attendees")
def attendees(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    try:
        cursor.execute("""
            SELECT 
                u.id AS user_id,
                u.emp_id,
                a.id_proof,
                a.id_proof_no,
                u.name,
                u.username,
                u.email,
                a.contact_number,
                a.attendee_img,
                a.status,
                v.vehicle_no
            FROM users u
            INNER JOIN attendee_master a ON u.id = a.user_id
            inner join vehicle_master v on v.id=a.vehicle_id
            WHERE u.role_id = 4 AND a.status = 1
        """)
        attendees = cursor.fetchall()
        print(attendees)

        # Ensure empty fields are None
        for a in attendees:
            if not a.get("attendee_img"):
                a["attendee_img"] = None
            if not a.get("id_proof"):
                a["id_proof"] = None

        return {"status": "success", "data": attendees}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching attendees: {str(e)}")


@app.post('/delete_attendee/{attendee_id}')
def delete_attendee(attendee_id: int, current_user: dict = Depends(get_current_user),db=Depends(get_db)):
    conn, cursor = db
    try:
        
        cursor.execute("Update attendee_master set status=%s WHERE user_id = %s", (0,attendee_id))
        conn.commit()

       
      
        return {"status": "success", "message": "Attendee deleted successfully"}

    except Exception as e:
        conn.rollback() 
       
        raise HTTPException(status_code=500, detail="Error deleting attendee")


@app.post('/update_attendee/{user_id}')
async def update_attendee(
   
    user_id: int,
    emp_id:Optional[str]=Form(None),
    name: str = Form(...),
    password: str | None = Form(None), 
    email: str = Form(...),
    contact_number: str = Form(...),
    attendee_img: UploadFile | None = None,
    id_proof: UploadFile | None = None,
    id_proof_no:Optional[str]=Form(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db
    try:
        if password:
           hashed_pwd = hash_password(password)
        # Update users table
           cursor.execute("""
            UPDATE users
            SET emp_id=%s,name = %s, password = %s, email = %s
            WHERE id = %s
        """, ( emp_id,name,hashed_pwd, email, user_id))
        else:
           cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s WHERE id=%s",
            (name, emp_id, email, user_id)
        )
     
        cursor.execute("""
            UPDATE attendee_master
            SET contact_number = %s,id_proof_no=%s
            WHERE user_id = %s
        """, (contact_number,id_proof_no, user_id))

        # Upload files to Supabase
        if attendee_img:
            attendee_url = await handle_file_upload(attendee_img, folder="attendee_image")
            cursor.execute("""
                UPDATE attendee_master SET attendee_img = %s WHERE user_id = %s
            """, (attendee_url, user_id))

        if id_proof:
            idproof_url = await handle_file_upload(id_proof, folder="id_proof")
            cursor.execute("""
                UPDATE attendee_master SET id_proof = %s WHERE user_id = %s
            """, (idproof_url, user_id))

        conn.commit()
        return {"status": "success", "message": "Attendee updated successfully!"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating attendee: {e}")


@app.post("/store_group")
def store_group(
    group_name: str = Form(...),
    buses: str = Form(...),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db
    cursor.execute("SELECT id FROM group_master WHERE group_name=%s", (group_name,))
    if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Group already exists")
    
    if not group_name.strip():
        raise HTTPException(status_code=400, detail="Group name is required")

    try:
        buses_list = json.loads(buses)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid buses format")

    if not buses_list:
        raise HTTPException(status_code=400, detail="Select at least one bus")

    try:
        # ✅ Insert into group_master
        cursor.execute(
            "INSERT INTO group_master (group_name, buses) VALUES (%s, %s)",
            (group_name, json.dumps(buses_list))
        )
        group_id = cursor.lastrowid  # ✅ Get the newly created group ID

        # ✅ Update vehicle_master: set group_id and status
        for vehicle_id in buses_list:

            cursor.execute(
                "UPDATE vehicle_master SET vehicle_status=%s, group_id=%s WHERE id=%s",
                ("Inactive", group_id, vehicle_id)
            )
            # after execute(...)
            print("Updated vehicle id:", vehicle_id, "rowcount:", cursor.rowcount)
            print("buses_list:", buses_list, "group_id:", group_id)


            

        conn.commit()
        return {"status": "success", "message": "Group added successfully!"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error saving group: {str(e)}")


@app.get("/check_group_exists")
def check_group_exists(group_name: str, db=Depends(get_db)):
    conn, cursor = db
    cursor.execute("SELECT id FROM group_master WHERE group_name=%s", (group_name,))
    if cursor.fetchone():
        return {"exists": True}
    return {"exists": False}

@app.get("/group_list")
def group_list(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
       
        cursor.execute("SELECT * FROM group_master  where status=%s  ",(1,))
        groups = cursor.fetchall()

        for g in groups:
            buses_info = []
            buses_field = g.get("buses")
            
            if buses_field:
                try:
                   
                    bus_ids = ast.literal_eval(buses_field)
                    
                    if bus_ids:
                        # Fetch vehicle_no for each bus id
                        format_strings = ",".join(["%s"] * len(bus_ids))
                        cursor.execute(
                            f"SELECT id, vehicle_no FROM vehicle_master WHERE id IN ({format_strings}) AND status=%s",
                            tuple(bus_ids) + (1,)  # Only active vehicles
                        )
                        buses_info = cursor.fetchall()
                
                except (ValueError, SyntaxError):
                    buses_info = []

            # Replace 'buses' with actual vehicle info
            g["buses"] = buses_info

        return {"status": "success", "data": groups}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching groups: {str(e)}")
@app.get("/get_groups")
def get_groups(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
        # Fetch only active groups (status=1)
        cursor.execute("SELECT id, group_name FROM group_master WHERE group_status=%s and status=%s ORDER BY id DESC", (1,1))
        groups = cursor.fetchall()

        return {"status": "success", "data": groups}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching groups: {str(e)}")

@app.post("/delete_group")
def delete_group(data: DeleteGroupModel, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
        
        cursor.execute("SELECT buses FROM group_master WHERE id=%s AND status=%s", (data.id, 1))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found or already deleted")

        buses_field = group.get("buses")
        if buses_field:
            try:
                bus_ids = ast.literal_eval(buses_field)
            except (ValueError, SyntaxError):
                bus_ids = []
        else:
            bus_ids = []

        # Update vehicle_master for these buses to 'Active'
        if bus_ids:
            format_strings = ",".join(["%s"] * len(bus_ids))
            query = f"UPDATE vehicle_master SET vehicle_status=%s WHERE id IN ({format_strings})"
            params = ["active"] + bus_ids  # First param for vehicle_status, rest for IN clause
            cursor.execute(query, params)

        # Mark the group as inactive
        cursor.execute("UPDATE group_master SET status=%s WHERE id=%s", (0, data.id))
        cursor.execute("UPDATE supervisor_master SET group_id=NULL WHERE group_id=%s", (data.id,))


        conn.commit()
        return {"status": "success", "message": "Group deleted successfully!"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting group: {str(e)}")

@app.get('/get_group_buses')
def get_group_buses(group_id: int,current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    try:
        # 1️⃣ Get group data
        cursor.execute("SELECT id, group_name, buses FROM group_master WHERE id = %s", (group_id,))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # 2️⃣ Parse stored bus IDs
        try:
            group_buses = json.loads(group["buses"]) if group["buses"] else []
        except json.JSONDecodeError:
            group_buses = []

        # 3️⃣ Fetch all buses that meet conditions (excluding preselected)
        cursor.execute("""
            SELECT id, vehicle_no 
            FROM vehicle_master 
            WHERE vehicle_status = 'active' 
              AND service_status = 'Idle' 
              AND status = 1
        """)
        filtered_buses = cursor.fetchall()

        # 4️⃣ Fetch preselected buses (ignore conditions)
        preselected_buses = []
        if group_buses:
            cursor.execute(
                f"SELECT id, vehicle_no FROM vehicle_master WHERE id IN ({','.join(map(str, group_buses))})"
            )
            preselected_buses = cursor.fetchall()

        # 5️⃣ Merge: preselected + filtered (exclude duplicates)
        preselected_ids = {b['id'] for b in preselected_buses}
        remaining_buses = [b for b in filtered_buses if b['id'] not in preselected_ids]

        all_buses = preselected_buses + remaining_buses

        # 6️⃣ Format for react-select
        all_bus_options = [{"value": b["id"], "label": b["vehicle_no"]} for b in all_buses]
        selected_buses_options = [{"value": b["id"], "label": b["vehicle_no"]} for b in preselected_buses]

        return {
            "group_id": group["id"],
            "group_name": group["group_name"],
            "all_buses": all_bus_options,
            "selected_buses": selected_buses_options,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
   
@app.post("/update_group")
def update_group(
    id: int = Form(...),
    group_name: str = Form(...),
    buses: str = Form(...),  # JSON string: "[4,5]"
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    conn, cursor = db
    try:
        # 1️⃣ Fetch existing group
        cursor.execute("SELECT buses FROM group_master WHERE id = %s", (id,))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # 2️⃣ Parse old and new bus lists
        old_buses = json.loads(group["buses"] or "[]")
        new_buses = json.loads(buses or "[]")

        # 3️⃣ Determine which buses were added/removed
        removed_buses = [b for b in old_buses if b not in new_buses]
        added_buses = [b for b in new_buses if b not in old_buses]

        # 4️⃣ Update vehicle statuses & group_id accordingly
        if removed_buses:
            cursor.execute(
                f"""
                UPDATE vehicle_master 
                SET vehicle_status='active', group_id=NULL 
                WHERE id IN ({','.join(map(str, removed_buses))})
                """
            )

        if added_buses:
            cursor.execute(
                f"""
                UPDATE vehicle_master 
                SET  group_id=%s 
                WHERE id IN ({','.join(map(str, added_buses))})
                """,
                (id,),
            )

        # 5️⃣ Update group_master with new group_name and buses
        cursor.execute(
            "UPDATE group_master SET group_name=%s, buses=%s WHERE id=%s",
            (group_name, json.dumps(new_buses), id),
        )

        # 6️⃣ Commit all changes
        conn.commit()
        return {"status": "success", "message": "Group updated successfully"}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/available_buses")
def available_buses(db=Depends(get_db),current_user: dict = Depends(get_current_user)):
    conn, cursor = db
   
    cursor.execute("""
            SELECT id, vehicle_no 
            FROM vehicle_master
            WHERE service_status='Idle'
              AND status=1
              AND driver_status=1
        """)
    buses = cursor.fetchall()
    return buses
    
@app.get('/available_buses_for_driver')
def available_buses_for_edit(user_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user),):
    try:
        conn, cursor = db
       
       
        cursor.execute("""
            SELECT vehicle_id
            FROM driver_master
            WHERE user_id = %s
            LIMIT 1
        """, (user_id,))
        driver_vehicle = cursor.fetchone()
        assigned_vehicle_id = driver_vehicle["vehicle_id"] if driver_vehicle else None

        # 2️⃣ Get available buses (Idle + current assigned)
        if assigned_vehicle_id:
            cursor.execute("""
                SELECT id, vehicle_no 
                FROM vehicle_master
                WHERE 
                    (
                        service_status='Idle' 
                        AND status=1 
                        AND driver_status=1
                    )
                    OR id = %s
            """, (assigned_vehicle_id,))
        else:
            cursor.execute("""
                SELECT id, vehicle_no 
                FROM vehicle_master
                WHERE service_status='Idle' 
                  AND status=1 
                  AND driver_status=1
            """)

        buses = cursor.fetchall()
        


        return {
            "buses": [{"id": bus["id"], "vehicle_no": bus["vehicle_no"]} for bus in buses],
            "assigned_vehicle_id": assigned_vehicle_id
        }
    except Exception as e:
        print("Error fetching buses:", e)
        return {"error": str(e)}

@app.post("/update_driver")
async def update_driver(
    user_id: int = Form(...),
    name: str = Form(...),
    emp_id: Optional[str] = Form(None),
    email: str = Form(...),
    contact_number: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    bus_id: Optional[int] = Form(None), 
    id_proof_no: Optional[str] = Form(None),
    driving_license_no: Optional[str] = Form(None),
    driver_image: Optional[UploadFile] = File(None),
    id_proof: Optional[UploadFile] = File(None),
    driving_license: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db

    # Handle password update
    if password:
        hashed_pwd = hash_password(password)
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s, password=%s WHERE id=%s",
            (name, emp_id, email, hashed_pwd, user_id)
        )
    else:
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s WHERE id=%s",
            (name, emp_id, email, user_id)
        )

    # Update driver_master table
    cursor.execute(
        "UPDATE driver_master SET name=%s, contact_number=%s, id_proof_no=%s, license_no=%s WHERE user_id=%s",
        (name, contact_number, id_proof_no, driving_license_no, user_id)
    )

    # Handle vehicle assignment
    if bus_id is not None:
        cursor.execute("SELECT vehicle_id FROM driver_master WHERE user_id=%s", (user_id,))
        old_vehicle_id = cursor.fetchone().get("vehicle_id")

        if old_vehicle_id != bus_id:
            # Free old vehicle
            if old_vehicle_id:
                cursor.execute(
                    "UPDATE vehicle_master SET driver_status=1 WHERE id=%s",
                    (old_vehicle_id,)
                )

                cursor.execute(
                    "UPDATE driver_master SET vehicle_id=0 WHERE user_id=%s",
                    (user_id,)
                )
            # Assign new vehicle
            cursor.execute(
                "UPDATE vehicle_master SET driver_status=0 WHERE id=%s",
                (bus_id,)
            )
            # Update driver_master
            cursor.execute(
                "UPDATE driver_master SET vehicle_id=%s WHERE user_id=%s",
                (bus_id, user_id)
            )

    # Handle file uploads to Supabase
    driver_image_url = await handle_file_upload(driver_image, "drivers")
    id_proof_url = await handle_file_upload(id_proof, "drivers")
    driving_license_url = await handle_file_upload(driving_license, "drivers")

    if driver_image_url:
        cursor.execute(
            "UPDATE driver_master SET image=%s WHERE user_id=%s",
            (driver_image_url, user_id)
        )
    if id_proof_url:
        cursor.execute(
            "UPDATE driver_master SET id_proof=%s WHERE user_id=%s",
            (id_proof_url, user_id)
        )
    if driving_license_url:
        cursor.execute(
            "UPDATE driver_master SET driving_license=%s WHERE user_id=%s",
            (driving_license_url, user_id)
        )

    conn.commit()
    return {"message": "Driver updated successfully"}

@app.get("/user-details/{user_id}")
def get_user_details(user_id: int, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    
    cursor.execute("""
        SELECT u.id, u.role_id, u.name, u.email, u.emp_id
        FROM users u 
        WHERE u.id = %s
    """, (user_id,))
    
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/submit_ticket")
async def submit_ticket(
    issue_type: str = Form(...),
    otherIssue: Optional[str] = Form(None),
    priority: str = Form(...),
    description: str = Form(...),
    vehicle_id: Optional[int] = Form(None),
    driver_id: Optional[int] = Form(None),
    photos: Optional[List[UploadFile]] = None,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
):
    conn,cursor=db
    print(current_user)
    driver_id=current_user["id"]
    vehicle_id=current_user['vehicle_id']
    if issue_type == "Other" and otherIssue:
        issue_type = otherIssue
   
    try:
        photo_urls = []
        if photos:
            for photo in photos:
       
                public_url = await handle_file_upload(photo, "trip_photos")
                if public_url:
                    photo_urls.append(public_url)

        photos_json = json.dumps(photo_urls) if photo_urls else None

        cursor.execute("""
            INSERT INTO tickets (issue_type, priority, description, vehicle_id, driver_id, photos)
            VALUES (%s, %s, %s, %s,%s, %s)
        """, (issue_type, priority, description, vehicle_id, driver_id, photos_json))
        conn.commit()

        return {"message": "Ticket submitted successfully!", "photos": photo_urls}

    except Exception as e:
        conn.rollback()
      
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/user-details")
def get_user_details(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    
    cursor.execute("""
        SELECT u.id, u.role_id, u.name, u.email, u.emp_id
        FROM users u 
        WHERE u.id = %s
    """, (current_user["id"],))
    
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/validate_driver_vehicle")
def validate_driver_vehicle(
    data: dict,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    conn, cursor = db
    
    vehicle_id = data.get('vehicle_id')
    driver_id = data.get('driver_id')
    
    if not vehicle_id or not driver_id:
        raise HTTPException(status_code=400, detail="Vehicle ID and Driver ID are required")
    
    try:
        # Check if driver exists and get their assigned vehicle
        cursor.execute("""
            SELECT dm.vehicle_id, vm.vehicle_id as vehicle_code, vm.vehicle_no
            FROM driver_master dm
            LEFT JOIN vehicle_master vm ON dm.vehicle_id = vm.id
            WHERE dm.user_id = %s AND dm.status = 1
        """, (driver_id,))
        
        driver_data = cursor.fetchone()
        
        if not driver_data:
            return {"valid": False, "message": "Driver not found or inactive"}
        
        # Get the vehicle ID from vehicle_master that matches the QR code
        cursor.execute("""
            SELECT id, vehicle_id, vehicle_no 
            FROM vehicle_master 
            WHERE vehicle_id = %s AND status = 1
        """, (vehicle_id,))
        
        vehicle_data = cursor.fetchone()
        
        if not vehicle_data:
            return {"valid": False, "message": "Vehicle not found"}
        
        # Check if the scanned vehicle matches the driver's assigned vehicle
        if driver_data['vehicle_id'] == vehicle_data['id']:
            return {
                "valid": True, 
                "message": "Vehicle assignment validated",
                "vehicle_no": vehicle_data['vehicle_no']
            }
        else:
            return {
                "valid": False, 
                "message": f"This vehicle is not assigned to you.",
                "assigned_vehicle": driver_data.get('vehicle_code')
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

@app.post("/trip_action")
def trip_action(data: dict, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    action = data.get("action")  # Either "clock_in" or "clock_out"
    trip_id = data.get("tripId")

    if not action or not trip_id:
        raise HTTPException(status_code=400, detail="Missing required fields: action or tripId")

    try:
        if action == "clock_in":
            # ✅ CLOCK-IN → Insert a new trip
            cursor.execute("""
                INSERT INTO trips (
                    trip_id, vehicle_id, vehicle_no, driver_id, driver_name,
                    start_km, start_time, start_photo, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'ongoing')
            """, (
                trip_id,
                data.get("vehicleId"),
                data.get("vehicleNo"),
                data.get("driverId"),
                data.get("driverName"),
                data.get("startKm"),
                data.get("startTime"),
                data.get("startPhoto")
            ))
            conn.commit()
            return {"message": "Clock-In successful, trip started"}

        elif action == "clock_out":
            # ✅ CLOCK-OUT → Update existing trip
            cursor.execute("SELECT * FROM trips WHERE trip_id = %s", (trip_id,))
            trip = cursor.fetchone()
            if not trip:
                raise HTTPException(status_code=404, detail="Trip not found")

            cursor.execute("""
                UPDATE trips
                SET end_km = %s,
                    total_km = %s,
                    end_time = %s,
                    end_photo = %s,
                    status = 'completed'
                WHERE trip_id = %s
            """, (
                data.get("endKm"),
                data.get("totalKm"),
                data.get("endTime"),
                data.get("endPhoto"),
                trip_id
            ))
            conn.commit()
            return {"message": "Clock-Out successful, trip completed"}

        else:
            raise HTTPException(status_code=400, detail="Invalid action type")

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error processing trip: {str(e)}")

@app.post("/upload_trip_photo")
async def upload_trip_photo(
    photo: UploadFile = File(...),
    tripId: str = Form(...),
    photoType: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        # Upload trip photo to Supabase
        photo_url = await handle_file_upload(photo, "trip_photos")
        return {"photoUrl": photo_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading photo: {str(e)}")


@app.get("/driver_active_trip")
def driver_active_trip(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    print(current_user)
    driver_id = current_user["id"]

    cursor.execute("""
        SELECT * FROM trips 
        WHERE driver_id = %s AND status = 'ongoing'
        ORDER BY start_time DESC LIMIT 1
    """, (driver_id,))
    trip = cursor.fetchone()
    print(trip)

    if trip:
        return {"activeTrip":{"tripId": trip["trip_id"],
            "vehicleId": trip["vehicle_id"],
            "vehicleNo": trip["vehicle_no"],
            "startKm": trip["start_km"],
            "startTime": trip["start_time"],
            "driverId": trip["driver_id"],
            "driverName": trip["driver_name"],
            "status": trip["status"],
            "endKm": trip.get("end_km"),
            "totalKm": trip.get("total_km"),
            "endTime": trip.get("end_time")
        }}
    return {"activeTrip": None}


# @app.get("/vehicle_info")
# def get_vehicle_info(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
#     conn, cursor = db

#     # Get driver ID from session
#     driver_id = current_user.get("id")  # assuming current_user has driver's id
#     if not driver_id:
#         raise HTTPException(status_code=404, detail="No driver ID found in session")

#     # Get the vehicle assigned to this driver
#     cursor.execute("""
#         SELECT 
#             vm.*,
#             dm.name AS driver_name,
#             gm.group_name,
#             sm.name AS supervisor_name
#         FROM driver_master dm
#         JOIN vehicle_master vm ON vm.id = dm.vehicle_id
#         LEFT JOIN group_master gm ON gm.id = vm.group_id
#         LEFT JOIN supervisor_master sm ON sm.group_id = gm.id
#         WHERE dm.id = %s AND vm.status=1
#     """, (driver_id,))

#     row = cursor.fetchone()
#     if not row:
#         raise HTTPException(status_code=404, detail="Vehicle not found for this driver")

#     return dict(row)


@app.get("/driver/ticket-history")
def get_driver_ticket_history(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    driver_id = current_user["id"]

    # Step 1: Get driver details
    cursor.execute("SELECT user_id, vehicle_id FROM driver_master WHERE user_id = %s and status=1", (driver_id,))
    driver = cursor.fetchone()
    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found in driver_master")

    vehicle_id = driver["vehicle_id"]

    # Step 2: Get vehicle details
    cursor.execute("SELECT vehicle_no, bus_number FROM vehicle_master WHERE id = %s", (vehicle_id,))
    vehicle = cursor.fetchone()
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found in vehicle_master")

    # Step 3: Get driver’s tickets
    cursor.execute("""
        SELECT id, issue_type, priority, description, photos, created_at,flag
        FROM tickets 
        WHERE driver_id = %s and status=%s
        ORDER BY created_at DESC
    """, (driver_id,1))
    tickets = cursor.fetchall()

    ticket_list = []
    for t in tickets:
        # Parse photo JSON
        photo_url = None
        if t["photos"]:
            try:
                photo_list = json.loads(t["photos"])
                if isinstance(photo_list, list) and len(photo_list) > 0:
                    photo_url = photo_list[0]
            except Exception:
                photo_url = None

        created_at = t["created_at"]
        date_part = created_at.strftime("%Y-%m-%d") if created_at else None
        time_part = created_at.strftime("%H:%M:%S") if created_at else None

        ticket_list.append({
            "ticket_id": t["id"],
            "issue_type": t["issue_type"],
            "priority": t["priority"],
            "description": t["description"],
            "photo": photo_url,
            "date": date_part,
            "time": time_part,
            "vehicle_no": vehicle["vehicle_no"],
            "bus_number": vehicle["bus_number"],
            "flag":t["flag"]
        })

    return {"driver_id": driver_id, "vehicle_no": vehicle["vehicle_no"], "bus_number": vehicle["bus_number"], "tickets": ticket_list}



@app.get("/admin/ticket-history")
def get_tickets_history(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db
    
    # Step 1: Get vehicle details (assuming 1 vehicle only)
    cursor.execute("SELECT vehicle_no, bus_number FROM vehicle_master WHERE status=%s", (1,))
    vehicle = cursor.fetchone()
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found in vehicle_master")

    # Step 2: Get driver's tickets with emp_id and driver_name
    cursor.execute("""
        SELECT 
            u.emp_id,
            u.name AS driver_name,
            t.id,
            t.issue_type,
            t.priority,
            t.description,
            t.photos,
            t.created_at,
            t.flag
        FROM tickets t
        INNER JOIN users u ON u.id = t.driver_id
        WHERE t.status = %s AND u.role_id = 3
        ORDER BY t.created_at DESC
    """, (1,))
    tickets = cursor.fetchall()

    ticket_list = []
    for t in tickets:
        # Parse photo JSON
        photo_url = None
        if t["photos"]:
            try:
                photo_list = json.loads(t["photos"])
                if isinstance(photo_list, list) and len(photo_list) > 0:
                    photo_url = photo_list[0]
            except Exception:
                photo_url = None

        created_at = t["created_at"]
        date_part = created_at.strftime("%Y-%m-%d") if created_at else None
        time_part = created_at.strftime("%H:%M:%S") if created_at else None

        ticket_list.append({
            "ticket_id": t["id"],
            "issue_type": t["issue_type"],
            "priority": t["priority"],
            "description": t["description"],
            "photo": photo_url,
            "date": date_part,
            "time": time_part,
            "emp_id": t["emp_id"],
            "driver_name": t["driver_name"],
            "vehicle_no": vehicle["vehicle_no"],
            "bus_number": vehicle["bus_number"],
            "flag": t["flag"]
        })

    return {
        "vehicle_no": vehicle["vehicle_no"],
        "bus_number": vehicle["bus_number"],
        "tickets": ticket_list
    }

@app.get("/supervisor/vehicles")
def get_avail_vehicles(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    try:
        conn,cursor = db
        
        query = """
            SELECT id, vehicle_no
            FROM vehicle_master
            WHERE driver_status = 1 AND status = 1
        """
        cursor.execute(query)
        vehicles = cursor.fetchall()
        cursor.close()

        if not vehicles:
            return {"message": "No available vehicles found", "data": []}

        return {"data": vehicles}

    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"MySQL Error: {err}")

@app.get("/supervisor/drivers")
def get_avail_drivers(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    try:
        conn, cursor = db
      
        query = """
            SELECT id,user_id, emp_id,name AS name
            FROM driver_master
            WHERE vehicle_id IS NULL AND status = 1
        """
        cursor.execute(query)
        drivers = cursor.fetchall()
       
        

        if not drivers:
            return {"message": "No available drivers found", "data": []}

        return {"data": drivers}

    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"MySQL Error: {err}")


@app.get("/driver/schedule")
def get_driver_schedule(current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    conn, cursor = db

    # Use dictionary cursor
    cursor = conn.cursor(dictionary=True)

    driver_id = current_user["id"]

    
    cursor.execute("""
        SELECT v.id AS vehicle_id, v.vehicle_no, d.supervisor_flag,v.bus_number
        FROM driver_master d
        JOIN vehicle_master v ON d.vehicle_id = v.id
        WHERE d.user_id = %s AND d.status = 1
    """, (driver_id,))

    assigned_vehicles = cursor.fetchall()
    
    if not assigned_vehicles:
        raise HTTPException(status_code=404, detail="No assigned vehicles found")

    return {"driver_id": driver_id, "assigned_vehicles": assigned_vehicles}




@app.get("/driver/clock-report")
def get_driver_clock_report(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db),
    from_date: str = Query(None, description="Start date YYYY-MM-DD"),
    to_date: str = Query(None, description="End date YYYY-MM-DD")
):
    conn, cursor = db
    
    try:
        # Determine date filter
        if from_date and to_date:
            start = datetime.strptime(from_date, "%Y-%m-%d").date()
            end = datetime.strptime(to_date, "%Y-%m-%d").date()
            
            # Fetch trips with date filter
            cursor.execute("""
                SELECT 
                   t.trip_id, 
                    t.driver_name, 
                    t.vehicle_no, 
                   t. start_time, 
                   t. end_time, 
                   t. status,
                   t. start_photo,
                   t. end_photo,
                   u.emp_id,
                   u.name as driver_name

                FROM trips t inner join users u on u.id=t.driver_id
                WHERE DATE(t.start_time) BETWEEN %s AND %s and u.role_id=3
                ORDER BY t.start_time DESC
            """, (start, end))
        else:
            # Show all data when no dates are provided
            cursor.execute("""
            select
               t.trip_id, 
                    t.driver_name, 
                    t.vehicle_no, 
                   t. start_time, 
                   t. end_time, 
                   t. status,
                   t. start_photo,
                   t. end_photo,
                   u.emp_id,
                   u.name as driver_name

                FROM trips t inner join users u on u.id=t.driver_id where u.role_id=3
                ORDER BY t.start_time DESC
            """)
        
        trips = cursor.fetchall()
        
        if not trips:
            raise HTTPException(status_code=404, detail="No trip records found")
        
        # Format report
        report = []
        for t in trips:
            start_time = t["start_time"]
            end_time = t["end_time"]

            report.append({
                "trip_id": t["trip_id"],
                "driver_name": t["driver_name"],
                "vehicle_no": t["vehicle_no"],
                "clock_in_date": start_time.strftime("%Y-%m-%d") if start_time else None,
                "clock_in_time": start_time.strftime("%H:%M:%S") if start_time else None,
                "clock_out_date": end_time.strftime("%Y-%m-%d") if end_time else None,
                "clock_out_time": end_time.strftime("%H:%M:%S") if end_time else None,
                "status": t["status"],
                "emp_id":t["emp_id"],
               
                "start_photo": t["start_photo"],
                "end_photo": t["end_photo"]
            })

        return {"clock_report": report}
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")


@app.post("/assign_driver")
def assign_driver(data: AssignDriverRequest, current_user: dict = Depends(get_current_user), db=Depends(get_db)):
    try:
        conn,cursor=db
        print(data)


        update_driver_query = """
            UPDATE driver_master
            SET vehicle_id = %s, supervisor_flag = 1
            WHERE user_id = %s
        """
        cursor.execute(update_driver_query, (data.bus_id, data.driver_id))
        
       
        update_vehicle_query = """
            UPDATE vehicle_master
            SET driver_status = 0
            WHERE id = %s
        """
        cursor.execute(update_vehicle_query, (data.bus_id,))
        conn.commit()

        

        return {"message": "Driver assigned successfully", "flag": 1}

    except mysql.connector.Error as err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"MySQL Error: {err}")



# @app.put("/ticket-update/{ticket_id}")
# def update_ticket_flag(
#     ticket_id: int,
#     current_user: dict = Depends(get_current_user),
#     db = Depends(get_db)
# ):
#     conn, cursor = db

#     cursor.execute("SELECT ticket_id, flag FROM ticket_master WHERE ticket_id = %s", (ticket_id,))
#     ticket = cursor.fetchone()
#     if not ticket:
#         raise HTTPException(status_code=404, detail="Ticket not found")

#     cursor.execute("UPDATE ticket_master SET flag = 2 WHERE ticket_id = %s", (ticket_id,))
#     conn.commit()

#     return {"status": True, "message": "Ticket flag updated successfully", "ticket_id": ticket_id, "flag": 2}


# ✅ Update ticket flag API
@app.put("/admin/ticket-update/{ticket_id}")
def update_ticket_flag(ticket_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    try:
       
        cursor.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")

      
        if ticket["flag"] == 1:
            cursor.execute("UPDATE tickets SET flag = %s WHERE id = %s", (2, ticket_id))
            conn.commit()
            return {"message": "Ticket marked as resolved", "ticket_id": ticket_id, "new_flag": 2}
        else:
            return {"message": "Ticket already resolved", "ticket_id": ticket_id, "flag": ticket["flag"]}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/vehicle-show")
def get_active_vehicles(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    try:
        cursor.execute("""
            SELECT id, vehicle_no 
            FROM vehicle_master 
            WHERE attendee_status = %s AND status = %s
        """, (1, 1))
        vehicles = cursor.fetchall()

        return {"vehicles": vehicles}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching vehicles: {str(e)}")


@app.get("/admin/assign-bus-data")
def get_assign_bus_data(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    try:
        # Fetch all active BO users (role_id=4, status=1)
        cursor.execute("SELECT id, name FROM users WHERE role_id = %s AND status = %s", (4, 1))
        bo_users = cursor.fetchall()

        # Fetch attendees not yet assigned to a vehicle
        cursor.execute("""
            SELECT user_id
            FROM attendee_master 
            WHERE vehicle_id IS NULL
        """)
        attendees = cursor.fetchall()

        return {
            "bo_users": bo_users,
            "unassigned_attendees": attendees
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching assign bus data: {str(e)}")



@app.post("/admin/assign-vehicle")
def assign_vehicle_to_attendee(
    request: VehicleAssignRequest,
    db=Depends(get_db), 
    current_user: dict = Depends(get_current_user)
):
    conn, cursor = db
    try:
        cursor.execute(
            "SELECT user_id FROM attendee_master WHERE user_id = %s", 
            (request.attendee_id,)
        )
        attendee = cursor.fetchone()
        if not attendee:
            raise HTTPException(status_code=404, detail="Attendee not found")

        user_id = attendee["user_id"]
        cursor.execute(
            "UPDATE attendee_master SET vehicle_id = %s,supervisor_flag=%s WHERE user_id = %s", 
            (request.vehicle_id,1, user_id)
        )

        cursor.execute(
            "UPDATE vehicle_master SET attendee_status = %s WHERE id = %s", 
            (0, request.vehicle_id)
        )

        conn.commit()
        return {
            "message": "Vehicle assigned successfully",
            "attendee_id": request.attendee_id,
            "vehicle_id": request.vehicle_id,
            "updated_user_id": user_id
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error assigning vehicle: {str(e)}")

@app.put("/tickets/update-flag")
def update_ticket_flag(
    ticket_id: str = Query(..., description="ID of the ticket to update"),
    flag_update: StatusUpdate = ...,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):

    conn, cursor = db
    
    # Check ticket exists
    cursor.execute("SELECT * FROM tickets WHERE id=%s", (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # Update flag
    cursor.execute("UPDATE tickets SET flag=%s WHERE id=%s", (flag_update.status, ticket_id))
    conn.commit()
    
    return {
        "message": f"Ticket flag updated to {flag_update.status}",
        "ticket_id": ticket_id
    }



@app.get("/supervisor/driver-list")
def get_driver_list(current_user: dict = Depends(get_current_user),
    db=Depends(get_db)):
    conn,cursor=db
  
    try:
        query = """
        SELECT 
            u.id AS user_id,
            u.emp_id,
            u.name,
            u.username,
            u.email,
            d.contact_number,
            d.driving_license,
            d.license_no AS driving_license_no,
            d.id_proof,
            d.id_proof_no,
            d.vehicle_id,
            v.vehicle_no,
            v.bus_number,
            d.image AS driver_image,
            COUNT(t.id) AS trip_count,
            MAX(t.start_time) AS last_clock_in,
            MAX(t.end_time) AS last_clock_out,
            tk.issue_type,
            tk.description
        FROM users u
        INNER JOIN driver_master d ON u.id = d.user_id
        LEFT JOIN vehicle_master v ON v.id = d.vehicle_id
        LEFT JOIN trips t ON t.driver_id = u.id
        LEFT JOIN tickets tk ON tk.driver_id = u.id 
            AND tk.created_at = (
                SELECT MAX(t2.created_at)
                FROM tickets t2
                WHERE t2.driver_id = u.id
            )
        WHERE u.role_id = 3 AND d.status = 1
        GROUP BY 
            u.id, u.emp_id, u.name, u.username, u.email, d.contact_number, 
            d.driving_license, d.license_no, d.id_proof, d.id_proof_no, 
            d.vehicle_id, v.vehicle_no, d.image, tk.issue_type, tk.description
        """
        cursor.execute(query)
        drivers = cursor.fetchall()
        return {"status": "success", "data": drivers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.put("/supervisor/update-driver-status")
def update_driver_status(user_id: int, data: dict, current_user: dict = Depends(get_current_user),
    db=Depends(get_db)):
    conn,cursor=db
   
    cursor.execute("UPDATE driver_master SET status = %s,supervisor_flag=%s WHERE user_id = %s",
    (0, 2,user_id)
)

    conn.commit()
    return {"message": "Driver status updated successfully"}
@app.put("/attendees/delete/{user_id}")
def soft_delete_attendee(user_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    conn, cursor = db
    cursor.execute("""
        UPDATE attendee_master
        SET status = 0,
            supervisor_flag = 2
        WHERE user_id = %s
    """, (user_id,))
    conn.commit()
    return {"message": "Attendee status updated successfully"}