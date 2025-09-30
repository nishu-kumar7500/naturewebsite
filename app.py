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
