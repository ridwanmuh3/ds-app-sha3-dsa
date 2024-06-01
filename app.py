import os
from flask import Flask, redirect, render_template, request, send_from_directory
from function import generate_dsa_keys, save_keys_to_file, load_privatekey_from_file, load_publickey_from_file, sign_pdf_and_embed, verify_signature_from_pdf

app = Flask(__name__,static_url_path='/static')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app.config["UPLOAD"] = os.path.abspath("upload")
app.config["UTILITY"] = os.path.abspath("utility")

@app.route("/")
def main_page():
   return render_template("index.html")

@app.route("/sign", methods=["GET", "POST"])
def sign_page():
   global uploaded_file
   
   if request.method == "POST":
      try:
         uploaded_file = request.files["input-doc-file"]
         upload_path = os.path.join(app.config["UPLOAD"], uploaded_file.filename) # type: ignore
         uploaded_file.save(upload_path)
      except Exception as e:
         print(f"Error saving uploaded file: {e}")

      try:
         key = request.files["private-key"]
         key_path = os.path.join(app.config["UTILITY"], key.filename) # type: ignore
         key.save(key_path)
      except Exception as e:
         print(f"Error saving key file: {e}")
            
      private_key =  load_privatekey_from_file(os.path.join(app.config["UTILITY"], key.filename))
      sign_pdf_and_embed(private_key, upload_path, os.path.join(app.config["UPLOAD"], f"signed-{uploaded_file.filename}"))
      
      output_path = os.path.join(app.config["UPLOAD"], f"signed-{uploaded_file.filename}")
      
      return render_template("sign.html", result="Berhasil melakukan Tanda Tangan Digital pada File Anda")
   
   return render_template("sign.html")

@app.route("/validasi", methods=["GET", "POST"])
def validasi_page():
   if request.method == "POST":
      try:
         uploaded_file = request.files["input-doc-file"]
         upload_path = os.path.join(app.config["UPLOAD"], uploaded_file.filename) # type: ignore
         uploaded_file.save(upload_path)
      except Exception as e:
         print(f"Error saving uploaded file: {e}")

      try:
         key = request.files["public-key"]
         key_path = os.path.join(app.config["UTILITY"], key.filename) # type: ignore
         key.save(key_path)
      except Exception as e:
         print(f"Error saving key file: {e}")
    
      public_key =  load_publickey_from_file(os.path.join(app.config["UTILITY"], key.filename))
      print(public_key)
      
      result = "Document dan tanda tangan valid" if verify_signature_from_pdf(public_key, upload_path) else "Document dan tanda tangan tidak valid"
     
      return render_template("validasi.html", result=result)
   
   return render_template("validasi.html")

@app.route("/keys")
def generate_keys():
   private_key, public_key = generate_dsa_keys()
   
   private_key_file = os.path.join(app.config["UTILITY"], "private_key.pem")
   public_key_file = os.path.join(app.config["UTILITY"], "public_key.pem")
   
   save_keys_to_file(private_key, public_key, private_key_file, public_key_file)
   
   return redirect("/")
   

@app.route('/download')
def downloadFile():
    global uploaded_file 
    return send_from_directory(app.config["UPLOAD"], f"signed-{uploaded_file.filename}", as_attachment=True)
