from dotenv import load_dotenv
import os, mysql.connector

load_dotenv()

config = {
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT')),
    'database': os.getenv('DB_NAME')
}

users_create = """
create table Users (
    id serial primary key,
    email varchar(255) not null unique,
    password varchar(255) not null,
    name varchar(255) not null,
    age int not null
)
"""

games_create = """
create table Games (
    id serial primary key,
    name varchar(255) not null
)
"""

scores_create = """
create table Scores (
    id serial primary key,
    user_id bigint unsigned not null,
    game_id bigint unsigned not null,
    score int not null,
    created_at timestamp default current_timestamp,
    foreign key (user_id) references Users(id),
    foreign key (game_id) references Games(id)
)
"""

def get_db_connection():
    return mysql.connector.connect(**config)

def main():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # cursor.execute(users_create)
    # cursor.execute(games_create)
    cursor.execute(scores_create)
    conn.commit()

    cursor.close()
    conn.close()

if __name__ == '__main__':
    main()
