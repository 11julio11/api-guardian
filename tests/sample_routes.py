# Sample vulnerable route handler for DiffScanner testing

import os

# 1. Hardcoded secret vulnerability
jwt_secret = "super_secret_jwt_key_999888777666"

def get_order_endpoint(req, res):
    # 2. BOLA / IDOR vulnerability: direct lookup without tenant/ownership check
    order_id = req.params.id
    order = Order.findById(req.params.id)
    return order

def create_user_endpoint(request):
    # 3. Mass Assignment vulnerability: raw body into create
    new_user = User.create(request.data)
    return new_user

def search_products(query_param):
    # 4. Raw SQL concatenation
    db.execute(f"SELECT * FROM products WHERE name = '{query_param}'")

def error_handler(err, req, res):
    # 5. Sensitive error stack disclosure
    return res.status(500).json({"error": err.message, "stack": err.stack})
