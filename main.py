from LoginHasher import Login_Hasher

def main():
    database = "users.db"
    db = Login_Hasher(database)
    if db.conn is not None:
        while True:
            print("\n1. Register a new user")
            print("2. Log in")
            print("3. Exit")

            choice = input("Choose an option: ")

            if choice == '1':
                login = input("Enter login: ")
                password1 = input("Enter password: ")
                password2 = input("Confirm password: ")
                if password1 == password2:
                    db.add_user(login, password1)
                    print("Register successful!")
                else:
                    print("Passwords do not match.")
            elif choice == '2':
                login = input("Enter login: ")
                password = input("Enter password: ")
                login_result = db.verify_login(login, password)
                if (login_result):
                    print("Login successful!")
                else:
                    print("Wrong login or password!")
            elif choice == '3':
                db.close_connection()
                break
            else:
                print("Invalid option. Please choose again.")

if __name__ == '__main__':
    main()
