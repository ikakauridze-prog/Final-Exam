import json
from flask import Flask, render_template, request, redirect, session, flash
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required, apology

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///shop.db")


with open("products.json", "r") as f:
    PRODUCTS = json.load(f)


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/")
def index():
    return render_template("index.html", products=PRODUCTS)


@app.route("/products")
def products_page():
    category = request.args.get("category", None)

    if category:
        filtered = [p for p in PRODUCTS if p["category"] == category]
    else:
        filtered = PRODUCTS

    categories = sorted(list({p["category"] for p in PRODUCTS}))

    return render_template("products.html", products=filtered, categories=categories, selected_category=category)



@app.route("/product/<int:id>")
def product(id):
    product = next((p for p in PRODUCTS if p["id"] == id), None)
    if not product:
        return apology("Product not found")
    return render_template("product.html", product=product)


@app.route("/buy/<int:id>", methods=["GET", "POST"])
@login_required
def buy(id):
    product = next((p for p in PRODUCTS if p["id"] == id), None)
    if not product:
        return apology("Product not found")

    if request.method == "POST":
        user_id = session["user_id"]
        quantity = int(request.form.get("quantity"))

        db.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
                   user_id, product["id"], quantity)
        flash(f"{product['title']} added to cart!")
        return redirect("/cart")

    return render_template("buy.html", product=product)


@app.route("/add_to_cart", methods=["POST"])
@login_required
def add_to_cart():
    product_id = int(request.form.get("product_id"))
    quantity = int(request.form.get("quantity"))
    user_id = session["user_id"]

    db.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
               user_id, product_id, quantity)
    flash("Product added to cart!")
    return redirect("/cart")


@app.route("/remove_from_cart", methods=["POST"])
@login_required
def remove_from_cart():
    user_id = session["user_id"]
    product_ids = request.form.getlist("product_ids")

    for pid in product_ids:
        db.execute("DELETE FROM cart WHERE user_id = ? AND product_id = ?", user_id, pid)

    flash(f"{len(product_ids)} item(s) removed from cart!")
    return redirect("/cart")


@app.route("/cart")
@login_required
def cart():
    user_id = session["user_id"]
    rows = db.execute("SELECT * FROM cart WHERE user_id = ?", user_id)

    items = []
    total = 0
    for r in rows:
        p = next((prod for prod in PRODUCTS if prod["id"] == r["product_id"]), None)
        if p:
            p_copy = p.copy()
            p_copy["quantity"] = r["quantity"]
            p_copy["total"] = p_copy["price"] * r["quantity"]
            items.append(p_copy)
            total += p_copy["total"]

    return render_template("cart.html", items=items, total=round(total, 2))

@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    user_id = session["user_id"]
    rows = db.execute("SELECT * FROM cart WHERE user_id = ?", user_id)

    if not rows:
        flash("Your cart is empty!")
        return redirect("/cart")

    items = []
    total = 0
    for r in rows:
        p = next((prod for prod in PRODUCTS if prod["id"] == r["product_id"]), None)
        if p:
            p_copy = p.copy()
            p_copy["quantity"] = r["quantity"]
            p_copy["total"] = p_copy["price"] * r["quantity"]
            items.append(p_copy)
            total += p_copy["total"]

    db.execute(
        "INSERT INTO orders (user_id, products, total) VALUES (?, ?, ?)",
        user_id, json.dumps(items), total
    )

    db.execute("DELETE FROM cart WHERE user_id = ?", user_id)

    flash("✅ You successfully purchased the items!")

    return redirect("/orders")




@app.route("/orders")
@login_required
def orders():
    user_id = session["user_id"]
    rows = db.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY created DESC", user_id)

    for order in rows:
        order["products_list"] = json.loads(order["products"])

    return render_template("orders.html", orders=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username or password")

        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        flash(f"Welcome, {session['username']}!")
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not username or not password:
            return apology("missing fields")
        if password != confirm:
            return apology("passwords do not match")

        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(existing_user) > 0:
            flash("User is already registered!")
            return redirect("/register")

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, generate_password_hash(password))
        flash("Registered successfully! You may log in.")
        return redirect("/login")

    return render_template("register.html")


if __name__ == "__main__":
    app.run(debug=True)
