from fastapi import FastAPI
import psycopg2
from psycopg2._psycopg import cursor
from pydantic import BaseModel
import hashlib
import bcrypt
import jwt


class Item(BaseModel):
    username: str
    password: str


# salt = b'$2b$12$qoT5U4j1hclfbNIhBnt/Ju'

app = FastAPI()

conn = psycopg2.connect(database="postgres",
                        host="localhost",
                        user="postgres",
                        password="1234",
                        port="5432")


@app.get("/username/{username}/password/{password}")
def insert_data_user(username: str, password: str):
    cursor = conn.cursor()
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    hashed_password.decode()
    try:
        cursor.execute('''INSERT into form_login (username,hashed_password) VALUES (%s,%s);''',
                       [username, hashed_password.decode()])
    except Exception as e:
        conn.rollback()
        raise e
    else:
        conn.commit()

    return {"username": username, "hashed": hashed_password}


@app.get("/login/username/{username}/password/{password}")
def login(username: str, password: str):
    cursor = conn.cursor()
    cursor.execute('''SELECT user_id, hashed_password FROM form_login where username = %s;''', [username])
    # cursor.execute('''SELECT hashed_password FROM form_login;''')
    data = cursor.fetchone()
    # c = str(b)
    # w = c.encode("utf-8")
    # w.decode()
    # salt = password.encode("utf-8")
    # salt = bcrypt.gensalt(rounds=12)
    # salt.decode()

    if bcrypt.checkpw(password.encode(), data[1].encode()):
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }

        secret = "Ravipass"

        payload = {
            "user_id": data[1]
        }

        encoded_jwt = jwt.encode(payload, secret, algorithm="HS256", headers=header)

        return {"toke": encoded_jwt}
    else:
        return {"Password is incorrect"}


@app.get("/veryfi_token/{token}")
def jwt_verify(token: str):
    secret = "Ravipass"

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    decode_token = jwt.decode(token, secret, algorithms=['HS256'], headers=header)
    if decode_token == token:
        return decode_token
    else:
        return decode_token


@app.get("/users/me")
def check_me(user_id:str):
    cursor = conn.cursor()


    
    cursor.execute('''SELECT username, hashed_password FROM form_login where hashed_password = %s;''',  [user_id])
    data = cursor.fetchone()
    return data
# @app.get("/Update")
# def Update(hashed_password: str):
#     cursor = conn.cursor()
#     cursor.execute("""UPDATE form_login SET hashed_password = %s WHERE user_id = 1;""", [hashed_password])
#     conn.commit()
#     cursor.close()



@app.get("/delete")
def delete(username: str, lastname: str, Phone: str, ):
    cursor = conn.cursor()
    cursor.execute("""DELETE FROM form_login WHERE username = %s AND lastname = %s AND Phone = %s ;""",
                   [username, lastname, Phone])
    conn.commit()
    cursor.close()


if __name__ == '__main__':
    import uvicorn

    uvicorn.run('main:app', host='localhost', port=5010, reload=True, workers=1)
