from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import numpy as np
from transformers import pipeline
import os
import base64
import re
import requests
from urllib.parse import urlparse
from file_upload_service import init_app
import magic
import chardet
import PyPDF2
import docx
import pandas as pd
from PIL import Image
import pytesseract
from io import BytesIO
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize file upload service
init_app(app)

@app.route('/')
def index():
    return jsonify({
        'status': 'ok',
        'message': 'File Analysis API is running',
        'endpoints': {
            '/api/analyze': 'POST - Analyze text content',
            '/api/analyze-file': 'POST - Analyze file content',
            '/api/health': 'GET - Health check'
        }
    })

# Download necessary NLTK data
required_nltk_data = [
    'punkt',
    'stopwords',
    'wordnet',
    'averaged_perceptron_tagger',
    'maxent_ne_chunker',
    'words',
    'punkt_tab'
]

print("Downloading NLTK data...")
for resource in required_nltk_data:
    try:
        nltk.download(resource, quiet=True)
        print(f"Downloaded {resource}")
    except Exception as e:
        print(f"Error downloading {resource}: {e}")

# Initialize lemmatizer and stop words
try:
    lemmatizer = WordNetLemmatizer()
    stop_words = set(stopwords.words('english'))
except Exception as e:
    print(f"Error initializing NLTK components: {e}")
    lemmatizer = None
    stop_words = set()

# Initialize NLP pipelines
try:
    print("Loading sentiment analysis pipeline...")
    sentiment_analyzer = pipeline("sentiment-analysis")
    print("Loading NER pipeline...")
    ner_pipeline = pipeline("ner")
    print("Loading text classification pipeline...")
    text_classifier = pipeline("text-classification")
    print("NLP pipelines loaded successfully")
except Exception as e:
    print(f"Error loading NLP pipelines: {e}")
    # Fallback to simple analysis if transformers fail
    sentiment_analyzer = None
    ner_pipeline = None
    text_classifier = None

# Text preprocessing function
def preprocess_text(text):
    if not text:
        return []
        
    try:
        # Tokenize the text
        tokens = word_tokenize(text.lower())
        
        # Remove stop words and lemmatize if components are available
        if lemmatizer and stop_words:
            preprocessed_tokens = [
                lemmatizer.lemmatize(token) 
                for token in tokens 
                if token.isalnum() and token not in stop_words
            ]
        else:
            # Fallback to simple tokenization
            preprocessed_tokens = [
                token for token in tokens 
                if token.isalnum()
            ]
        
        return preprocessed_tokens
    except Exception as e:
        print(f"Error in text preprocessing: {e}")
        # Return simple word split as fallback
        return [word.lower() for word in text.split() if word.isalnum()]

# Entity recognition function - using NLTK fallback if transformers fail
def extract_entities(text):
    if ner_pipeline:
        try:
            # Using transformers pipeline
            ner_results = ner_pipeline(text[:10000])  # Limit text size for performance
            entities = []
            for result in ner_results:
                if result['entity'].startswith('B-'):
                    entities.append(result['word'])
            return entities
        except Exception as e:
            print(f"Transformers NER failed: {e}")
    
    # Fallback to NLTK NER
    try:
        tokens = word_tokenize(text)
        pos_tags = nltk.pos_tag(tokens)
        chunks = nltk.ne_chunk(pos_tags)
        
        entities = []
        for chunk in chunks:
            if hasattr(chunk, 'label'):
                entities.append(' '.join(c[0] for c in chunk))
        return entities
    except Exception as e:
        print(f"NLTK NER failed: {e}")
        return []

# Simple language detection
def detect_language(text):
    # A very simple language detection
    # In a real app, use a library like langdetect or fasttext
    english_stopwords = set(stopwords.words('english'))
    tokens = word_tokenize(text.lower())
    
    # Count tokens that are in English stopwords
    english_count = sum(1 for token in tokens if token in english_stopwords)
    
    if english_count / max(len(tokens), 1) > 0.05:
        return "english"
    else:
        return "unknown"

# Check for sensitive content
def check_sensitive_content(text):
    # Patterns for detecting sensitive information
    patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[ -]?){3}\d{4}\b',
        'password': r'\b(?:password|pwd|passwd)\s*[:=]\s*\S+\b',
        'api_key': r'\b(?:api[_-]?key|token|secret|access[_-]?key)\s*[:=]\s*\S+\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'mac_address': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        'file_path': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        'jwt_token': r'\b(?:eyJ[a-zA-Z0-9_-]*\.){2}[a-zA-Z0-9_-]*\b',
        'private_key': r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
        'aws_key': r'\bAKIA[0-9A-Z]{16}\b',
        'azure_key': r'\b[a-zA-Z0-9+/]{32,}={0,2}\b',
        'google_key': r'\bAIza[0-9A-Za-z-_]{35}\b',
        'database_connection': r'\b(?:jdbc|mysql|postgresql|mongodb)://[^"\s]+\b',
        'encryption_key': r'\b(?:AES|DES|RSA|SHA|MD5)[0-9A-Fa-f]+\b'
    }
    
    sensitive_info = {}
    for pattern_name, pattern in patterns.items():
        matches = re.finditer(pattern, text, re.IGNORECASE)
        matches_list = [{'value': match.group(), 'line': text[:match.start()].count('\n') + 1} for match in matches]
        if matches_list:
            sensitive_info[pattern_name] = matches_list
            
    # Check for specific sensitive keywords with context
    sensitive_keywords = {
        'confidential': ['confidential', 'private', 'secret', 'classified', 'restricted', 'internal', 'proprietary'],
        'financial': ['bank', 'account', 'credit', 'debit', 'payment', 'transaction', 'salary', 'tax', 'invoice'],
        'personal': ['name', 'address', 'dob', 'birth', 'ssn', 'social security', 'passport', 'driver license'],
        'security': ['password', 'login', 'credential', 'authentication', 'authorization', 'encryption', 'certificate'],
        'health': ['medical', 'health', 'patient', 'diagnosis', 'treatment', 'prescription', 'insurance'],
        'legal': ['contract', 'agreement', 'nda', 'non-disclosure', 'lawsuit', 'court', 'attorney']
    }
    
    for category, keywords in sensitive_keywords.items():
        for keyword in keywords:
            if re.search(r'\b' + keyword + r'\b', text, re.IGNORECASE):
                if category not in sensitive_info:
                    sensitive_info[category] = []
                sensitive_info[category].append({'value': keyword, 'line': text.find(keyword) // 100 + 1})
    
    return sensitive_info

# Check for potentially malicious content
def check_malicious_content(text):
    malicious_info = {
        'malware_indicators': [],
        'suspicious_patterns': [],
        'code_injection': [],
        'network_indicators': [],
        'obfuscation_techniques': [],
        'exploit_patterns': []
    }
    
    # Malware-related keywords with context
    malware_keywords = {
        'malware': ['malware', 'virus', 'trojan', 'worm', 'ransomware', 'spyware', 'rootkit', 'backdoor'],
        'exploit': ['exploit', 'vulnerability', 'backdoor', 'rootkit', 'payload', 'shellcode', 'buffer overflow'],
        'attack': ['attack', 'breach', 'hack', 'crack', 'compromise', 'inject', 'bypass', 'escalate'],
        'network': ['ddos', 'botnet', 'proxy', 'tunnel', 'port scan', 'sniff', 'spoof', 'mitm']
    }
    
    for category, keywords in malware_keywords.items():
        for keyword in keywords:
            if re.search(r'\b' + keyword + r'\b', text, re.IGNORECASE):
                malicious_info['malware_indicators'].append({
                    'type': category,
                    'value': keyword,
                    'line': text.find(keyword) // 100 + 1
                })
    
    # Suspicious patterns
    suspicious_patterns = [
        (r'<script.*?>.*?<\/script>', 'JavaScript injection'),
        (r'exec\s*\(.*?\)', 'Command execution'),
        (r'system\s*\(.*?\)', 'System calls'),
        (r'SELECT.*?FROM.*?WHERE', 'SQL injection'),
        (r'DROP\s+TABLE', 'SQL DROP statement'),
        (r'--.*?$', 'SQL comment'),
        (r'/\*.*?\*/', 'Multi-line comment'),
        (r'eval\s*\(.*?\)', 'Code evaluation'),
        (r'base64_decode\s*\(.*?\)', 'Base64 decoding'),
        (r'file_get_contents\s*\(.*?\)', 'File reading'),
        (r'shell_exec\s*\(.*?\)', 'Shell execution'),
        (r'preg_replace\s*\(.*?/e', 'Code injection'),
        (r'assert\s*\(.*?\)', 'Code assertion'),
        (r'create_function\s*\(.*?\)', 'Dynamic function creation'),
        (r'include\s*\(.*?\)', 'File inclusion'),
        (r'require\s*\(.*?\)', 'File requirement'),
        (r'passthru\s*\(.*?\)', 'Command passthrough'),
        (r'proc_open\s*\(.*?\)', 'Process opening'),
        (r'popen\s*\(.*?\)', 'Process opening'),
        (r'curl_exec\s*\(.*?\)', 'CURL execution'),
        (r'fsockopen\s*\(.*?\)', 'Socket opening')
    ]
    
    for pattern, description in suspicious_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            malicious_info['suspicious_patterns'].append({
                'type': description,
                'value': match.group(),
                'line': text[:match.start()].count('\n') + 1
            })
    
    # Network-related indicators
    network_patterns = [
        (r'\b(?:https?://)?(?:[\w-]+\.)+[\w-]+(?::\d+)?\b', 'URL'),
        (r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', 'IP address with port'),
        (r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b', 'MAC address'),
        (r'\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+[^\s]+\s+HTTP/\d\.\d', 'HTTP request'),
        (r'\b(?:ftp|sftp|scp|ssh)://[^\s]+\b', 'File transfer protocol'),
        (r'\b(?:telnet|rlogin|rsh)://[^\s]+\b', 'Remote access protocol')
    ]
    
    for pattern, description in network_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            malicious_info['network_indicators'].append({
                'type': description,
                'value': match.group(),
                'line': text[:match.start()].count('\n') + 1
            })
    
    # Obfuscation techniques
    obfuscation_patterns = [
        (r'\\x[0-9a-fA-F]{2}', 'Hex encoding'),
        (r'%[0-9a-fA-F]{2}', 'URL encoding'),
        (r'&#x[0-9a-fA-F]+;', 'HTML entity encoding'),
        (r'[A-Za-z0-9+/]{4,}={0,2}', 'Base64 encoding'),
        (r'\\u[0-9a-fA-F]{4}', 'Unicode encoding'),
        (r'\\[0-7]{1,3}', 'Octal encoding'),
        (r'\\[abfnrtv]', 'Escape sequence'),
        (r'\\[\\\'"]', 'Escape character')
    ]
    
    for pattern, description in obfuscation_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            malicious_info['obfuscation_techniques'].append({
                'type': description,
                'value': match.group(),
                'line': text[:match.start()].count('\n') + 1
            })
    
    # Exploit patterns
    exploit_patterns = [
        (r'overflow\s*\(.*?\)', 'Buffer overflow'),
        (r'strcpy\s*\(.*?\)', 'Unsafe string copy'),
        (r'strcat\s*\(.*?\)', 'Unsafe string concatenation'),
        (r'sprintf\s*\(.*?\)', 'Unsafe string formatting'),
        (r'gets\s*\(.*?\)', 'Unsafe input reading'),
        (r'scanf\s*\(.*?\)', 'Unsafe input scanning'),
        (r'fgets\s*\(.*?\)', 'Unsafe file reading'),
        (r'fscanf\s*\(.*?\)', 'Unsafe file scanning')
    ]
    
    for pattern, description in exploit_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            malicious_info['exploit_patterns'].append({
                'type': description,
                'value': match.group(),
                'line': text[:match.start()].count('\n') + 1
            })
    
    return malicious_info

# Determine reading level with enhanced metrics
def determine_reading_level(text):
    if not text:
        return "unknown"
        
    try:
        # Tokenize text
        tokens = word_tokenize(text)
        sentences = nltk.sent_tokenize(text)
        
        # Calculate average word length
        avg_word_length = sum(len(word) for word in tokens) / len(tokens) if tokens else 0
        
        # Calculate average sentence length
        avg_sentence_length = sum(len(word_tokenize(sent)) for sent in sentences) / len(sentences) if sentences else 0
        
        # Determine reading level based on metrics
        if avg_word_length > 6 and avg_sentence_length > 20:
            return "Advanced"
        elif avg_word_length > 5 and avg_sentence_length > 15:
            return "Intermediate"
        else:
            return "Basic"
    except Exception as e:
        print(f"Error determining reading level: {e}")
        return "unknown"

def calculate_english_percentage(text):
    """Calculate the percentage of English words in the text"""
    words = text.split()
    english_words = sum(1 for word in words if word.lower() in stop_words)
    return (english_words / len(words)) * 100 if words else 0

def determine_content_category(text):
    """Determine the category of content in the text"""
    if not text:
        return ["Unknown"]
        
    try:
        categories = []
        
        # Check for code-like content
        code_patterns = [
            r'function\s+\w+\s*\(',
            r'class\s+\w+',
            r'def\s+\w+\s*\(',
            r'import\s+\w+',
            r'#include\s+<.*>',
            r'public\s+class',
            r'private\s+\w+',
            r'protected\s+\w+',
            r'<html>',
            r'<script>',
            r'<?php',
            r'SELECT\s+.*\s+FROM',
            r'CREATE\s+TABLE'
        ]
        
        for pattern in code_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                categories.append("Code")
                break
        
        # Check for structured data
        if re.search(r'\{.*\}', text) or re.search(r'\[.*\]', text):
            categories.append("Structured Data")
        
        # Check for natural language content
        if len(word_tokenize(text)) > 50 and not categories:
            categories.append("Natural Language")
        
        # Check for specific document types
        if re.search(r'<html>.*</html>', text, re.DOTALL):
            categories.append("HTML")
        elif re.search(r'<\?xml.*\?>', text):
            categories.append("XML")
        elif re.search(r'@\w+', text):
            categories.append("Social Media")
        
        # If no specific category found, mark as unknown
        if not categories:
            categories.append("Unknown")
            
        return categories
    except Exception as e:
        print(f"Error determining content category: {e}")
        return ["Unknown"]

def extract_text_from_file(file_path, file_type=None):
    """Extract text content from various file types"""
    try:
        # Detect file type if not provided
        if not file_type:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

        # Handle different file types
        if file_type.startswith('text/'):
            # Detect encoding for text files
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                detected = chardet.detect(raw_data)
                encoding = detected['encoding'] or 'utf-8'
            
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                return f.read()

        elif file_type == 'application/pdf':
            text = []
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                for page in pdf.pages:
                    text.append(page.extract_text())
            return '\n'.join(text)

        elif file_type in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                          'application/msword']:
            doc = docx.Document(file_path)
            return '\n'.join([paragraph.text for paragraph in doc.paragraphs])

        elif file_type in ['application/vnd.ms-excel', 
                          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            df = pd.read_excel(file_path)
            return df.to_string()

        elif file_type.startswith('image/'):
            # Extract text from images using OCR
            with Image.open(file_path) as img:
                return pytesseract.image_to_string(img)

        else:
            # For binary files, return metadata
            file_size = os.path.getsize(file_path)
            return f"Binary file: {os.path.basename(file_path)} ({file_size} bytes)"

    except Exception as e:
        print(f"Error extracting text from file: {e}")
        return f"Error processing file: {str(e)}"

def calculate_file_statistics(text, file_path):
    """Calculate detailed file statistics"""
    stats = {
        'fileInfo': {
            'name': os.path.basename(file_path),
            'size': os.path.getsize(file_path),
            'type': magic.Magic(mime=True).from_file(file_path),
            'lastModified': os.path.getmtime(file_path)
        },
        'contentStats': {
            'charCount': len(text),
            'wordCount': len(text.split()),
            'lineCount': len(text.splitlines()),
            'paragraphCount': len(re.split(r'\n\s*\n', text)),
            'sentenceCount': len(nltk.sent_tokenize(text)),
            'uniqueWordCount': len(set(word.lower() for word in text.split() if word.isalnum())),
            'averageWordLength': sum(len(word) for word in text.split() if word.isalnum()) / max(len(text.split()), 1),
            'averageSentenceLength': len(text.split()) / max(len(nltk.sent_tokenize(text)), 1),
            'averageParagraphLength': len(text.split()) / max(len(re.split(r'\n\s*\n', text)), 1)
        },
        'languageStats': {
            'detectedLanguage': detect_language(text),
            'englishWordPercentage': calculate_english_percentage(text),
            'specialCharacters': len(re.findall(r'[^a-zA-Z0-9\s]', text)),
            'numbers': len(re.findall(r'\d', text))
        }
    }
    return stats

def extract_keywords(text):
    """Extract keywords from text using frequency analysis"""
    try:
        # Tokenize and preprocess text
        tokens = preprocess_text(text)
        
        # Count word frequencies
        word_freq = {}
        for token in tokens:
            if token in word_freq:
                word_freq[token] += 1
            else:
                word_freq[token] = 1
        
        # Sort by frequency
        sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
        
        # Return top 10 keywords with their frequencies
        return [{'word': word, 'frequency': freq} for word, freq in sorted_words[:10]]
    except Exception as e:
        print(f"Error extracting keywords: {e}")
        return []

def calculate_confidence_score(text):
    """Calculate a confidence score for the analysis"""
    try:
        score = 0.0
        
        # Check text length
        if len(text) > 100:
            score += 0.2
        
        # Check for structured content
        if re.search(r'\{.*\}', text) or re.search(r'\[.*\]', text):
            score += 0.2
        
        # Check for natural language patterns
        if len(nltk.sent_tokenize(text)) > 5:
            score += 0.2
        
        # Check for code-like patterns
        code_patterns = [
            r'function\s+\w+\s*\(',
            r'class\s+\w+',
            r'def\s+\w+\s*\(',
            r'import\s+\w+',
            r'#include\s+<.*>'
        ]
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in code_patterns):
            score += 0.2
        
        # Check for HTML/XML patterns
        if re.search(r'<[^>]+>', text):
            score += 0.2
        
        # Normalize score to be between 0 and 1
        return min(score, 1.0)
    except Exception as e:
        print(f"Error calculating confidence score: {e}")
        return 0.0

def calculate_anomaly_score(text):
    """Calculate an anomaly score based on suspicious patterns"""
    try:
        score = 0.0
        weights = {
            'sensitive_content': 0.3,
            'malware_indicators': 0.2,
            'suspicious_patterns': 0.2,
            'network_indicators': 0.1,
            'obfuscation_techniques': 0.1,
            'exploit_patterns': 0.1
        }
        
        # Check for sensitive content
        sensitive_content = check_sensitive_content(text)
        if sensitive_content:
            score += weights['sensitive_content']
        
        # Check for malicious content
        malicious_content = check_malicious_content(text)
        
        if malicious_content['malware_indicators']:
            score += weights['malware_indicators']
        
        if malicious_content['suspicious_patterns']:
            score += weights['suspicious_patterns']
        
        if malicious_content['network_indicators']:
            score += weights['network_indicators']
        
        if malicious_content['obfuscation_techniques']:
            score += weights['obfuscation_techniques']
        
        if malicious_content['exploit_patterns']:
            score += weights['exploit_patterns']
        
        # Normalize score to be between 0 and 1
        return min(score, 1.0)
    except Exception as e:
        print(f"Error calculating anomaly score: {e}")
        return 0.0

@app.route('/api/analyze', methods=['POST'])
def analyze_text():
    if not request.json:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Handle both direct text and file uploads
        if 'file' in request.files:
            file = request.files['file']
            file_path = os.path.join('uploads', secure_filename(file.filename))
            file.save(file_path)
            text = extract_text_from_file(file_path)
            file_stats = calculate_file_statistics(text, file_path)
        else:
            text = request.json.get('text', '')
            file_path = request.json.get('file_path', '')
            file_stats = calculate_file_statistics(text, file_path) if file_path else None

        if not text:
            return jsonify({'error': 'No text content to analyze'}), 400

        # Perform analysis with error handling for each component
        analysis_result = {}
        
        try:
            analysis_result['contentCategory'] = determine_content_category(text)
        except Exception as e:
            print(f"Error in content category analysis: {e}")
            analysis_result['contentCategory'] = ["Unknown"]
        
        try:
            analysis_result['keywords'] = extract_keywords(text)
        except Exception as e:
            print(f"Error in keyword extraction: {e}")
            analysis_result['keywords'] = []
        
        try:
            analysis_result['language'] = detect_language(text)
        except Exception as e:
            print(f"Error in language detection: {e}")
            analysis_result['language'] = "unknown"
        
        try:
            analysis_result['readingLevel'] = determine_reading_level(text)
        except Exception as e:
            print(f"Error in reading level analysis: {e}")
            analysis_result['readingLevel'] = "unknown"
        
        try:
            analysis_result['sensitiveContent'] = check_sensitive_content(text)
        except Exception as e:
            print(f"Error in sensitive content analysis: {e}")
            analysis_result['sensitiveContent'] = {}
        
        try:
            analysis_result['maliciousContent'] = check_malicious_content(text)
        except Exception as e:
            print(f"Error in malicious content analysis: {e}")
            analysis_result['maliciousContent'] = {}
        
        try:
            analysis_result['detectedEntities'] = extract_entities(text)
        except Exception as e:
            print(f"Error in entity extraction: {e}")
            analysis_result['detectedEntities'] = []
        
        try:
            analysis_result['confidenceScore'] = calculate_confidence_score(text)
        except Exception as e:
            print(f"Error in confidence score calculation: {e}")
            analysis_result['confidenceScore'] = 0.0
        
        try:
            analysis_result['anomalyScore'] = calculate_anomaly_score(text)
        except Exception as e:
            print(f"Error in anomaly score calculation: {e}")
            analysis_result['anomalyScore'] = 0.0
        
        # Add statistics
        analysis_result['statistics'] = file_stats if file_stats else {
            'contentStats': {
                'charCount': len(text),
                'wordCount': len(text.split()),
                'sentenceCount': len(nltk.sent_tokenize(text))
            }
        }

        return jsonify(analysis_result)

    except Exception as e:
        print(f"Error in analyze_text endpoint: {e}")
        import traceback
        traceback.print_exc()  # Print full traceback
        return jsonify({
            'error': 'An error occurred during analysis',
            'details': str(e)
        }), 500

@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    """Endpoint to analyze a file uploaded from Supabase"""
    if not request.json:
        return jsonify({'error': 'No file data provided'}), 400
    
    try:
        file_data = request.json
        print(f"Received file for analysis: {file_data.get('name', 'unknown')} ({file_data.get('type', 'unknown type')})")
        
        # Extract file content - this could be text or base64 encoded binary
        content = file_data.get('content', '')
        file_type = file_data.get('type', 'unknown')
        public_url = file_data.get('publicUrl', '')
        
        # Process different file types
        text_to_analyze = ''
        
        # If we have content directly
        if content:
            if isinstance(content, str):
                text_to_analyze = content
            else:
                text_to_analyze = f"Binary content of type {file_type}"
        
        # If we have a public URL but no content
        elif public_url:
            print(f"Attempting to fetch content from URL: {public_url}")
            try:
                # Check if URL is valid
                parsed_url = urlparse(public_url)
                if parsed_url.scheme and parsed_url.netloc:
                    response = requests.get(public_url, timeout=10)
                    if response.ok:
                        content_type = response.headers.get('content-type', '')
                        
                        if 'text' in content_type or 'json' in content_type:
                            text_to_analyze = response.text
                        elif 'image' in content_type:
                            text_to_analyze = f"Image file: {file_data.get('name', 'unknown')}"
                        else:
                            text_to_analyze = f"Binary file of type: {content_type}"
                    else:
                        text_to_analyze = f"Could not access file at URL (Status: {response.status_code})"
                else:
                    text_to_analyze = "Invalid URL provided"
            except Exception as e:
                print(f"Error fetching file from URL: {e}")
                text_to_analyze = f"Error accessing file: {str(e)}"
        
        # If we have nothing to work with
        else:
            text_to_analyze = f"File metadata only - Name: {file_data.get('name', 'unknown')}, Type: {file_type}, Size: {file_data.get('size', 'unknown')}"
        
        # Now analyze the text using our existing function
        print(f"Analyzing extracted content (length: {len(text_to_analyze)})")
        request.json = {'text': text_to_analyze}
        return analyze_text()
        
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")
        return jsonify({
            'error': 'Error analyzing file',
            'details': str(e),
            'contentCategory': ['unknown'],
            'keywords': [],
            'language': 'unknown',
            'readingLevel': 'unknown',
            'sensitiveContent': False,
            'maliciousContent': False,
            'detectedEntities': [],
            'confidenceScore': 0,
            'anomalyScore': 0
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    nlp_status = "ok" if sentiment_analyzer else "limited"
    return jsonify({
        'status': 'ok', 
        'message': 'NLP service is running',
        'nlp_pipelines': nlp_status,
        'version': '1.0.1'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = True  # Enable debug mode
    host = '0.0.0.0'  # Listen on all available network interfaces
    
    print(f"Starting NLP analysis server on {host}:{port}")
    print(f"Debug mode: {debug_mode}")
    
    app.run(host=host, port=port, debug=debug_mode)
