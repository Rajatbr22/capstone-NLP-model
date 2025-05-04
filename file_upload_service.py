from flask import Blueprint, request, jsonify, current_app
import os
from werkzeug.utils import secure_filename
import uuid
import json
import base64

file_upload = Blueprint('file_upload', __name__)

# Configure upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'json', 'md', 'png', 'jpg', 'jpeg', 'gif'}

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@file_upload.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads from the frontend"""
    try:
        # Check if file part exists in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
            
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Check if file type is allowed
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
            
        # Secure the filename and generate a unique ID
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        unique_filename = f"{file_id}.{file_extension}"
        
        # Save the file
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        # Get file metadata
        file_size = os.path.getsize(file_path)
        file_type = file_extension
        
        # Generate a URL for accessing the file
        # This is a simplified example - in production you'd need proper URL generation
        base_url = request.host_url.rstrip('/')
        file_url = f"{base_url}/api/files/{file_id}"
        
        # Read file content for analysis
        file_content = ""
        if file_extension in ['txt', 'csv', 'json', 'md']:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        
        # Prepare response
        response = {
            'success': True,
            'file': {
                'id': file_id,
                'name': filename,
                'path': file_url,
                'size': file_size,
                'type': file_type,
                'uploadDate': str(uuid.time.timestamp())
            },
            'message': 'File uploaded successfully'
        }
        
        # If the file is analyzable, trigger analysis
        if file_extension in ['txt', 'csv', 'json', 'md']:
            # Add analysis info to the response
            response['analyzable'] = True
            
            # You could use the NLP service here
            # For example:
            # analysis_url = f"{base_url}/api/analyze"
            # analysis_data = {'text': file_content, 'file_id': file_id}
            # Trigger analysis asynchronously
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': 'Error uploading file', 'details': str(e)}), 500

@file_upload.route('/api/files', methods=['GET'])
def get_files():
    """Return a list of uploaded files"""
    try:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                file_id = filename.split('.')[0]
                file_extension = filename.split('.')[-1] if '.' in filename else ''
                
                # Generate a URL for accessing the file
                base_url = request.host_url.rstrip('/')
                file_url = f"{base_url}/api/files/{file_id}"
                
                # Try to determine original filename
                original_name = filename
                
                files.append({
                    'id': file_id,
                    'name': original_name,
                    'path': file_url,
                    'size': file_size,
                    'type': file_extension,
                    'uploadDate': str(os.path.getctime(file_path))
                })
        
        return jsonify({'files': files})
        
    except Exception as e:
        return jsonify({'error': 'Error retrieving files', 'details': str(e)}), 500

@file_upload.route('/api/files/<file_id>', methods=['GET'])
def get_file(file_id):
    """Return details for a specific file"""
    try:
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(file_id):
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file_size = os.path.getsize(file_path)
                file_extension = filename.split('.')[-1] if '.' in filename else ''
                
                # For supported text files, include content
                file_content = None
                if file_extension in ['txt', 'csv', 'json', 'md']:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_content = f.read()
                
                # For binary files like images, include base64 data
                binary_content = None
                if file_extension in ['png', 'jpg', 'jpeg', 'gif']:
                    with open(file_path, 'rb') as f:
                        binary_data = f.read()
                        binary_content = base64.b64encode(binary_data).decode('utf-8')
                
                response = {
                    'id': file_id,
                    'name': filename,
                    'path': file_path,
                    'size': file_size,
                    'type': file_extension,
                    'uploadDate': str(os.path.getctime(file_path))
                }
                
                if file_content:
                    response['content'] = file_content
                
                if binary_content:
                    response['base64Data'] = binary_content
                    response['dataUrl'] = f"data:image/{file_extension};base64,{binary_content}"
                
                return jsonify(response)
        
        return jsonify({'error': 'File not found'}), 404
        
    except Exception as e:
        return jsonify({'error': 'Error retrieving file', 'details': str(e)}), 500

@file_upload.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a specific file"""
    try:
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(file_id):
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                os.remove(file_path)
                return jsonify({'success': True, 'message': 'File deleted successfully'})
        
        return jsonify({'error': 'File not found'}), 404
        
    except Exception as e:
        return jsonify({'error': 'Error deleting file', 'details': str(e)}), 500

# Register blueprint with main app
def init_app(app):
    app.register_blueprint(file_upload)
