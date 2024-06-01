from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
import base64
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
import io



# Fungsi untuk membuat kunci DSA
def generate_dsa_keys():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Fungsi untuk menyimpan kunci ke file
def save_keys_to_file(private_key, public_key, private_key_file, public_key_file):
    with open(private_key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )

    with open(public_key_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
        )

# Fungsi untuk memuat kunci dari file
def load_publickey_from_file(public_key_file):
    with open(public_key_file, "rb") as f:
        try:
            public_key = load_pem_public_key(f.read())
        except:
            return False

    return public_key

def load_privatekey_from_file(private_key_file):
    with open(private_key_file, "rb") as f:
        try:
            private_key = load_pem_private_key(f.read(), password=None)
        except:
            return False

    return private_key

# Fungsi untuk membuat tanda tangan digital dan menyisipkannya ke dokumen PDF
def sign_pdf_and_embed(private_key, document_path, output_path):

    def format_signature_to_32bit_blocks(signature):
        # Konversi signature ke bentuk biner
        # Pecah menjadi blok-blok 32 bit
        block_size = 32
        blocks = [
            signature[i : i + block_size] for i in range(0, len(signature), block_size)
        ]
        return blocks

    # Read the existing PDF
    reader = PdfReader(document_path)
    writer = PdfWriter()

    # Create a hash of the PDF content
    hasher = hashes.Hash(hashes.SHA3_256())
    for page in reader.pages[1:]:
        hasher.update(page.extract_text().encode("utf-8"))
    document_hash = hasher.finalize()

    # Create the signature
    signature = private_key.sign(document_hash, Prehashed(hashes.SHA3_256()))
    ascii_signature = base64.b64encode(signature).decode("ascii")
    signature_blocks = format_signature_to_32bit_blocks(ascii_signature)

    # Create a new PDF with the signature
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=reader.page_layout)

    # Wrap the signature text
    textobject = can.beginText(20, 60)
    textobject.setFont("Helvetica", 8)
    textobject.textLines("<== BEGIN DIGITAL SIGNATURE ==>\n\n")
    for block in signature_blocks:
        textobject.textLine(block)
        can.drawText(textobject)

    textobject.textLines("\n\n<== END DIGITAL SIGNATURE ==>\n")
    can.drawText(textobject)
    can.save()

    packet.seek(0)

    new_pdf = PdfReader(packet)

    # Merge the new PDF with the existing PDF
    for i in range(len(reader.pages)):
        if (
            i == 0
        ):  # Jika ini halaman terakhir, tambahkan tanda tangan digital
            last_page = reader.pages[i]
            last_page.merge_page(
                new_pdf.pages[0]
            )  # Merge konten halaman dengan tanda tangan
            writer.add_page(last_page)
        else:
            writer.add_page(reader.pages[i])

    # Add metadata from the original PDF
    writer.add_metadata(reader.metadata)

    # Add metadata for the digital signature
    writer.add_metadata({"/Signature": ascii_signature})

    # Write the modified PDF to a new file
    with open(output_path, "wb") as f:
        writer.write(f)

    return signature

# Fungsi untuk memverifikasi tanda tangan digital dari dokumen PDF
def verify_signature_from_pdf(public_key, document_path):
    reader = PdfReader(document_path)
    metadata = reader.metadata
    signature = metadata.get("/Signature", None)
    if not signature:
        return False

    signature = base64.b64decode(signature)

    # Create a hash of the PDF content
    hasher = hashes.Hash(hashes.SHA3_256())
    for page in reader.pages[1:]:  # Exclude the last page with the visible signature
        hasher.update(page.extract_text().encode("utf-8"))
    document_hash = hasher.finalize()

    try:
        public_key.verify(signature, document_hash, Prehashed(hashes.SHA3_256()))
        return True
    except Exception as e:
        print(e)
        return False

