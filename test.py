from html2docx import html2docx

# Define the path to your HTML file
html_file_path = './templates/Document Preparation.html'

# Read the HTML content from the file
with open(html_file_path, 'r', encoding='utf-8') as file:
    html_content = file.read()

# Convert the HTML to DOCX
html2docx(html_content, "document_preparation.docx")

print("Conversion complete. The document 'document_preparation.docx' has been created.")
