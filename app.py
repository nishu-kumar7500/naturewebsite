from flask import Flask, render_template, url_for, abort
import json
import os

app = Flask(__name__, static_folder="static", template_folder="templates")

def load_destinations():
    data_path = os.path.join(os.path.dirname(__file__), "data", "destinations.json")
    with open(data_path, "r", encoding="utf-8") as f:
        return json.load(f)

DESTINATIONS = load_destinations()

@app.route("/")
def index():
    featured = [d for d in DESTINATIONS if d.get("featured")]
    return render_template("index.html", featured=featured)

@app.route("/explore")
def explore():
    return render_template("explore.html", destinations=DESTINATIONS)

@app.route("/destination/<slug>")
def destination(slug):
    match = next((d for d in DESTINATIONS if d["slug"] == slug), None)
    if not match:
        abort(404)
    return render_template("destination.html", d=match)

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", title="Not found", content="<div class='container py-5'><h2>Page not found</h2></div>"), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


@app.route("/")
def index():
    return render_template("index.html", title="Home")

@app.route("/explore")
def explore():
    return render_template("explore.html", title="Explore")

@app.route("/destinations")
def destinations():
    return render_template("destinations.html", title="Destinations")

@app.route("/experiences")
def experiences():
    return render_template("experiences.html", title="Experiences")

@app.route("/community")
def community():
    return render_template("community.html", title="Community")

@app.route("/about")
def about():
    return render_template("about.html", title="About Us")

@app.route("/careers")
def careers():
    return render_template("careers.html", title="Careers")

@app.route("/contact")
def contact():
    return render_template("contact.html", title="Contact")

@app.route("/help-center")
def help_center():
    return render_template("help-center.html", title="Help Center")

@app.route("/travel-guides")
def travel_guides():
    return render_template("travel-guides.html", title="Travel Guides")

@app.route("/sustainability")
def sustainability():
    return render_template("sustainability.html", title="Sustainability")