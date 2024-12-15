from flask import Flask, request, jsonify, send_file
from flask_cors import CORS, cross_origin
import easyocr
import yara
import fitz  # PyMuPDF
import cv2
import pyzxing
from PIL import Image, ImageFilter
import io
import numpy as np
import re
import os
from presidio_analyzer import AnalyzerEngine

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "supports_credentials": True}})

# Initialize EasyOCR Reader
reader = easyocr.Reader(['en','hi'])

desired_recognizers = ["EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_TIME", "PERSON", "CREDIT_CARD", "PASSPORT"]
# Compile YARA rules when the app starts
rules = yara.compile(filepath='scan_rules.yara')
analyzer = AnalyzerEngine()

is_image_only=False

def scan_text_with_yara(text):
    matches = rules.match(data=text)
    matched_rules = [match.rule for match in matches]
    return matched_rules

def detect_pii(text):
    """Detect PII in the provided text using Presidio and custom regex patterns."""
    # Detect PII with Presidio
    results = analyzer.analyze(text=text, language='en',entities=desired_recognizers)
    pii_results = []

    for result in results:
        # Check if 'text' attribute is present
        if hasattr(result, 'text'):
            value = result.text
        else:
            # Fallback to result.start and result.end to extract the text substring
            value = text[result.start:result.end]

        pii_results.append({
            'entity_type': result.entity_type,
            'start': result.start,
            'end': result.end,
            'value': value
        })

    # Custom regex patterns
    patterns = {
        'AADHAAR_NUMBER': r'\b\d{4}\s\d{4}\s\d{4}\b',
        'PAN_NUMBER': r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        'BLOOD_GROUP': r'\b(?:A|B|AB|O)[+-]\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'CREDIT_CARD': r'\b(?:\d[ -]*?){13,16}\b'
    }

    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            if not any(r['entity_type'] == label for r in pii_results):
                pii_results.append({
                    'entity_type': label,
                    'start': match.start(),
                    'end': match.end(),
                    'value': match.group()
                })

    return pii_results

def list_detected_pii(text, results):
    """List detected PII types and their values."""
    pii_list = {}
    for result in results:
        entity_text = result['value']
        pii_list[entity_text] = result['entity_type']  # Use actual text as the key
    return pii_list

def scan_pdf_for_images_and_qrcodes(pdf_doc):
    """Scan PDF for images, QR codes, and signatures."""
    images = []
    qrcodes = []
    signatures = []

    reader = pyzxing.BarCodeReader()

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        image_list = page.get_images(full=True)

        for img in image_list:
            xref = img[0]
            base_image = pdf_doc.extract_image(xref)
            image_bytes = base_image["image"]
            image = Image.open(io.BytesIO(image_bytes))

            # Convert PIL image to OpenCV format
            open_cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

            # Detect QR codes using pyzxing
            decoded_objects = reader.decode_array(open_cv_image)
            if decoded_objects:
                qrcodes.extend([obj['parsed'] for obj in decoded_objects if 'parsed' in obj])

            # Heuristic to detect signatures (based on size, shape, etc.)
            if is_likely_signature(image):
                signatures.append(image)

    return images, qrcodes, signatures

def is_likely_signature(image):
    """
    Improved heuristic function to determine if the image is a signature.
    This approach analyzes the image for features commonly found in human signatures.
    """

    # Convert the image to grayscale
    gray_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)

    # Apply binary threshold to get a black-and-white image
    _, binary_image = cv2.threshold(gray_image, 150, 255, cv2.THRESH_BINARY_INV)

    # Find contours in the binary image
    contours, _ = cv2.findContours(binary_image, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    # Initialize variables for heuristics
    total_contour_area = 0
    total_contour_perimeter = 0
    contour_count = 0
    likely_signature = False

    # Loop through the contours to compute heuristic metrics
    for contour in contours:
        # Compute contour area and perimeter
        contour_area = cv2.contourArea(contour)
        contour_perimeter = cv2.arcLength(contour, True)

        # Filter out very small or very large contours (noise or background)
        if contour_area > 50 and contour_area < 2000:
            total_contour_area += contour_area
            total_contour_perimeter += contour_perimeter
            contour_count += 1

    if contour_count > 0:
        # Compute average contour area and perimeter
        avg_area = total_contour_area / contour_count
        avg_perimeter = total_contour_perimeter / contour_count

        # Heuristic rule: Signatures often have many small, continuous strokes
        # Check if the area/perimeter ratio and contour count fall within a signature-like range
        if avg_area > 100 and avg_perimeter > 50 and contour_count > 5:
            likely_signature = True

    return likely_signature

def extract_pdf_pages_as_images(pdf_path):
    pdf_doc = fitz.open(pdf_path)
    images = []

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        pix = page.get_pixmap()
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        images.append(img)

    return images

def detect_pii_with_easyocr(image, edited_pii_data):
    reader = easyocr.Reader(['en'])
    
    # Convert PIL image to NumPy array
    image_np = np.array(image)

    result = reader.readtext(image_np)  # Pass the NumPy array to EasyOCR

    pii_coordinates = []
    for (bbox, text, _) in result:
        for pii_key in edited_pii_data.keys():
            if pii_key.lower() in text.lower():
                # bbox gives the coordinates of the detected text
                pii_coordinates.append((bbox, text, edited_pii_data[pii_key]))
    return pii_coordinates

def redact_pdf_with_coordinates(pdf_path, pii_coordinates, image_masking_options):
    pdf_doc = fitz.open(pdf_path)
    white_color = (1.0, 1.0, 1.0)
    black_color = (0.0, 0.0, 0.0)
    fontsize = 18

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        
        # Redact the text and mask or remove images
        for bbox, original_text, new_value in pii_coordinates:
            rect = fitz.Rect(bbox[0], bbox[2])  # bbox[0] and bbox[2] represent top-left and bottom-right corners

            # Create redaction annotation and fill with white color
            page.add_redact_annot(rect, fill=white_color)
            page.apply_redactions()

            # Now insert the new value on top of the redaction
            if new_value:
                text_position = (rect.x0, rect.y1 - fontsize)
                print(f"Inserting new value '{new_value}' at position {text_position}")
                page.insert_text(text_position, new_value, fontsize=fontsize, color=black_color)

    masked_file_name = 'masked_' + os.path.basename(pdf_path)
    masked_file_path = os.path.join('masked', masked_file_name)
    pdf_doc.save(masked_file_path)
    pdf_doc.close()
    return masked_file_path


def is_image_only_pdf(pdf_doc):
    """
    Check if a PDF is an image-based PDF (scanned PDF).
    If all pages contain only images and no text, it's likely an image-based PDF.
    """
    image_only = True

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        text = page.get_text()  # Extract text from the page
        
        if text.strip():
            # If any page has text, it's not an image-only PDF
            image_only = False
            break

    return image_only


def apply_masking(image, option):
    """Apply masking options (blur or remove) to the image."""
    if option == "blur":
        return image.filter(ImageFilter.GaussianBlur(10))
    elif option == "remove":
        return None
    return image


def extract_text_from_pdf(file_path):
    """Extract text from PDF using EasyOCR."""
    pdf_text = ""
    pdf_doc = fitz.open(file_path)

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        # Extract image for OCR
        pix = page.get_pixmap()
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        text = reader.readtext(np.array(img))
        page_text = " ".join([item[1] for item in text])
        pdf_text += page_text

    return pdf_text

@app.route('/scan_and_upload', methods=['POST'])
@cross_origin()
def scan_and_upload():
    global is_image_only
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    if file and file.filename.endswith('.pdf'):
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)

        # Load PDF to determine if it is image-only or text-based
        pdf_doc = fitz.open(file_path)
        is_image_only = is_image_only_pdf(pdf_doc)
        
        text = ""
        print(is_image_only)
        if is_image_only:
            # Extract text from images in the PDF using EasyOCR
            text = extract_text_from_pdf(file_path)
            print(text)
        else:
            # Extract text from the PDF using fitz for text-based PDFs
            for page_num in range(len(pdf_doc)):
                page = pdf_doc.load_page(page_num)
                text += page.get_text()
            
            # Scan PDF for images, QR codes, and signatures
        images, qrcodes, signatures = scan_pdf_for_images_and_qrcodes(pdf_doc)

        # Step 2: Scan the text with YARA
        matched_rules = scan_text_with_yara(text)
        if matched_rules:
            return jsonify({
                'malicious': True, 
                'matched_rules': matched_rules
            })

        # Step 3: If no malicious content, proceed with PII detection
        pii_results = detect_pii(text)
        pii_list = list_detected_pii(text, pii_results)

        return jsonify({
            "malicious": False, 
            "pii_list": pii_list, 
            "images_detected": len(images), 
            "qrcodes_detected": len(qrcodes),
            "signatures_detected": len(signatures),
            "file_path": file_path
        })
    else:
        return jsonify({"error": "Unsupported file format"})

@app.route('/mask', methods=['POST'])
def mask_file():
    global is_image_only
    data = request.json
    file_path = data['file_path']
    edited_pii_data = data['edited_pii_data']
    image_masking_options = data.get('image_masking_options', {})
    
    # Ensure the 'masked' directory exists
    masked_dir = 'masked'
    if not os.path.exists(masked_dir):
        os.makedirs(masked_dir)

    if not os.path.isfile(file_path):
        return jsonify({"error": "File not found"})
    print(is_image_only)
    
    if is_image_only:
        # Handle image-only PDFs
        # Extract images from PDF pages
        print("img only masking")
        images = extract_pdf_pages_as_images(file_path)

        # Detect PII using EasyOCR
        pii_coordinates = []
        for img in images:
            detected_pii = detect_pii_with_easyocr(img, edited_pii_data)
            pii_coordinates.extend(detected_pii)
        # Apply redaction/masking based on the coordinates detected by EasyOCR
        masked_file_path = redact_pdf_with_coordinates(file_path, pii_coordinates,image_masking_options)
    else:
        # Handle text-based PDFs
        print("text based pdf masking")
        pdf_doc = fitz.open(file_path)

        # Define colors in normalized range [0, 1]
        white_color = (1.0, 1.0, 1.0)
        black_color = (0.0, 0.0, 0.0)
        fontsize = 12

        for page_num in range(len(pdf_doc)):
            page = pdf_doc.load_page(page_num)

            for entity_text, new_value in edited_pii_data.items():
                # Search for the text
                print(entity_text)
                print(new_value)
                areas = page.search_for(entity_text)
                for area in areas:
                    # Directly redact the original text (erases it permanently)
                    page.add_redact_annot(area, fill=(1, 1, 1))

                    # Apply the redaction to remove the text
                    page.apply_redactions()

                    # Insert new text over the redacted area
                    text_height = fontsize - 15  # Assuming that font size is used directly for height
                    text_rect = fitz.Rect(
                        area.x0,
                        area.y0 + (area.height - text_height) / 2,  # Center vertically
                        area.x1,
                        area.y1 + (area.height + text_height) / 2
                    )

                    # Insert the new value
                    page.insert_text(text_rect.tl, new_value, fontsize=fontsize, color=black_color)

            # Mask images, QR codes, and signatures
            image_list = page.get_images(full=True)
            for img in image_list:
                xref = img[0]
                mask_option = image_masking_options.get("images", "none")

                if mask_option == "remove":
                    # Remove the image entirely from the page
                    rects = page.get_image_rects(xref)
                    if rects:
                        for rect in rects:
                            page.add_redact_annot(rect, fill=(1, 1, 1))  # Mark area for redaction (which will delete content)
                        page.apply_redactions()  # Apply the redaction to remove the image
                else:
                    base_image = pdf_doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image = Image.open(io.BytesIO(image_bytes))
                    masked_image = apply_masking(image, mask_option)

                    if masked_image:
                        # Convert masked image back to bytes
                        img_byte_arr = io.BytesIO()
                        masked_image.save(img_byte_arr, format='PNG')
                        img_byte_arr = img_byte_arr.getvalue()

                        # Replace the original image in the PDF with the masked image
                        rect = page.get_image_rects(xref)[0]  # Assuming single rectangle per image
                        page.insert_image(rect, stream=img_byte_arr)

        masked_file_name = 'masked_' + os.path.basename(file_path)
        masked_file_path = os.path.join('masked', masked_file_name)
        pdf_doc.save(masked_file_path)
        pdf_doc.close()

    response = {
        "file_path": masked_file_path
    }
    return jsonify(response), 200

@app.route('/download/<path:filename>', methods=['GET'])
@cross_origin()
def download_file(filename):
    file_path=filename
    print(file_path)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('masked'):
        os.makedirs('masked')
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)