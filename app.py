import os
import uuid
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from log_parser import parse_logs
from threat_analyst import analyze_logs
import traceback

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max

ALLOWED_EXTENSIONS = {"evtx", "json", "csv", "txt", "log", "xml"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    filepath = None
    try:
        # Handle file upload
        if "file" in request.files and request.files["file"].filename:
            file = request.files["file"]
            if not allowed_file(file.filename):
                return jsonify({"error": f"File type not supported. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
            file.save(filepath)

            parsed = parse_logs(filepath=filepath, filename=filename)

        # Handle raw text paste
        elif request.form.get("raw_logs"):
            raw = request.form.get("raw_logs").strip()
            if not raw:
                return jsonify({"error": "No log content provided."}), 400
            parsed = parse_logs(raw_content=raw, filename="pasted_logs.txt")

        else:
            return jsonify({"error": "Please upload a file or paste log content."}), 400

        if parsed["event_count"] == 0:
            return jsonify({"error": "No parseable log entries found. Check the file format."}), 400

        # Run AI analysis
        analysis = analyze_logs(parsed)

        return jsonify({
            "parse_info": {
                "format": parsed["format"],
                "event_count": parsed["event_count"],
                "summary": parsed["summary"]
            },
            "analysis": analysis
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

    finally:
        # Clean up uploaded file
        if filepath and os.path.exists(filepath):
            os.remove(filepath)

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)