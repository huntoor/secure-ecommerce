# Flask E-commerce Application

This is a simple e-commerce platform built with Flask. It features user registration and authentication, product management, and admin privileges for managing products and users.

## Features

- User registration and login.
- Product addition and listing.
- Admin dashboard for promoting users to admin and listing all users.
- Admin-only access to adding products.
- Session management for user logins.

## Prerequisites

Before you run this application, you will need the following installed:

- Python 3.8 or higher
- Flask
- SQLite3

## Installation

Follow these steps to set up the project locally:

1. Clone the repository:
   ```bash
   git clone [url-to-your-repo]
   cd [repository-name]
    ```
2. Install the required packages:
    ```bash
    pip install flask sqlite3
    ```
3. Set up the environment variable for Flask:
    ```bash
    export FLASK_APP=app.py
    export FLASK_ENV=development  # For development purposes
    ```

## Running the Application

To run the application, use the following command from the root directory of the project:

```bash
    flask run
```
This will start the application on http://localhost:5000/. You can access the application via any web browser.

## Usage
- Register: Navigate to /register to create a new user account.
- Login: Go to /login to log into the application.
- Add Product: (Admins only) Add a new product from the admin dashboard or by navigating to /add_product.
- List Products: Accessible at /products, which lists all available products.
- Admin Dashboard: (Admins only) Accessible at /admin_page, where admins can promote users to admin and view all registered users.

## Admin Login
To log into the application as an administrator, you need to manually set a user as an admin in the database or use an existing admin account.

## Logging Out
To log out of the application, navigate to /logout.

## License
The project is licensed under the [MIT License](./LICENSE).

