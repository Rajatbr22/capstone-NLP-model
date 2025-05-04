import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json
import requests
import os
from datetime import datetime

class FileAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Security Analyzer")
        self.root.geometry("1000x800")
        
        # Configure style
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("TLabel", padding=6)
        style.configure("Risk.High.TLabel", foreground="red")
        style.configure("Risk.Medium.TLabel", foreground="orange")
        style.configure("Risk.Low.TLabel", foreground="green")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # File selection
        ttk.Label(main_frame, text="Select a file to analyze:").grid(row=0, column=0, sticky=tk.W)
        self.file_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.file_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=0, column=2)
        
        # Analyze button
        ttk.Button(main_frame, text="Analyze File", command=self.analyze_file).grid(row=1, column=1, pady=10)
        
        # Results area
        ttk.Label(main_frame, text="Analysis Results:").grid(row=2, column=0, sticky=tk.W)
        
        # Create notebook for tabbed results
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Summary tab
        self.summary_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_tab, text="Summary")
        
        # Risk score
        self.risk_frame = ttk.LabelFrame(self.summary_tab, text="Risk Assessment", padding="5")
        self.risk_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.risk_score = ttk.Label(self.risk_frame, text="Risk Score: N/A", font=("Arial", 14))
        self.risk_score.grid(row=0, column=0, padx=5, pady=5)
        
        self.risk_level = ttk.Label(self.risk_frame, text="Risk Level: N/A", font=("Arial", 14))
        self.risk_level.grid(row=1, column=0, padx=5, pady=5)
        
        # Statistics frame
        self.stats_frame = ttk.LabelFrame(self.summary_tab, text="File Statistics", padding="5")
        self.stats_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(self.stats_frame, height=5, width=50)
        self.stats_text.grid(row=0, column=0, padx=5, pady=5)
        
        # Tags frame
        self.tags_frame = ttk.LabelFrame(self.summary_tab, text="Detected Tags", padding="5")
        self.tags_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.tags_text = scrolledtext.ScrolledText(self.tags_frame, height=5, width=50)
        self.tags_text.grid(row=0, column=0, padx=5, pady=5)
        
        # Details tab
        self.details_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.details_tab, text="Details")
        
        self.details_text = scrolledtext.ScrolledText(self.details_tab, height=20, width=80)
        self.details_text.grid(row=0, column=0, padx=5, pady=5)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        self.summary_tab.columnconfigure(0, weight=1)
        self.details_tab.columnconfigure(0, weight=1)
        self.details_tab.rowconfigure(0, weight=1)
        
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("Word files", "*.doc;*.docx"),
                ("Excel files", "*.xls;*.xlsx"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_path.set(filename)
            self.clear_results()
    
    def clear_results(self):
        """Clear all previous analysis results"""
        self.risk_score.config(text="Risk Score: N/A")
        self.risk_level.config(text="Risk Level: N/A")
        self.stats_text.delete(1.0, tk.END)
        self.tags_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
    
    def analyze_file(self):
        file_path = self.file_path.get()
        if not file_path:
            self.show_error("Please select a file first")
            return
            
        try:
            # Clear previous results
            self.clear_results()
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Prepare request data
            data = {
                'text': content,
                'name': os.path.basename(file_path),
                'type': os.path.splitext(file_path)[1][1:],
                'size': os.path.getsize(file_path)
            }
            
            # Send request to local API
            response = requests.post('http://localhost:5000/api/analyze', json=data)
            
            if response.status_code == 200:
                results = response.json()
                self.display_results(results)
            else:
                self.show_error(f"Error analyzing file: {response.text}")
                
        except Exception as e:
            self.show_error(f"Error: {str(e)}")
    
    def display_results(self, results):
        # Calculate risk score and level
        risk_score = results.get('anomalyScore', 0) * 100
        risk_level = "High" if risk_score > 70 else "Medium" if risk_score > 30 else "Low"
        
        # Update risk assessment with color coding
        self.risk_score.config(
            text=f"Risk Score: {risk_score:.1f}%",
            style=f"Risk.{risk_level}.TLabel"
        )
        self.risk_level.config(
            text=f"Risk Level: {risk_level}",
            style=f"Risk.{risk_level}.TLabel"
        )
        
        # Update statistics
        stats = results.get('statistics', {})
        stats_text = []
        
        # File Information
        if 'fileInfo' in stats:
            file_info = stats['fileInfo']
            stats_text.append("File Information:")
            stats_text.append(f"Name: {file_info.get('name', 'N/A')}")
            stats_text.append(f"Size: {file_info.get('size', 0) / 1024:.2f} KB")
            stats_text.append(f"Type: {file_info.get('type', 'N/A')}")
            stats_text.append(f"Last Modified: {datetime.fromtimestamp(file_info.get('lastModified', 0)).strftime('%Y-%m-%d %H:%M:%S')}")
            stats_text.append("")
        
        # Content Statistics
        if 'contentStats' in stats:
            content_stats = stats['contentStats']
            stats_text.append("Content Statistics:")
            stats_text.append(f"Characters: {content_stats.get('charCount', 0):,}")
            stats_text.append(f"Words: {content_stats.get('wordCount', 0):,}")
            stats_text.append(f"Lines: {content_stats.get('lineCount', 0):,}")
            stats_text.append(f"Paragraphs: {content_stats.get('paragraphCount', 0):,}")
            stats_text.append(f"Sentences: {content_stats.get('sentenceCount', 0):,}")
            stats_text.append(f"Unique Words: {content_stats.get('uniqueWordCount', 0):,}")
            stats_text.append(f"Average Word Length: {content_stats.get('averageWordLength', 0):.1f}")
            stats_text.append(f"Average Sentence Length: {content_stats.get('averageSentenceLength', 0):.1f}")
            stats_text.append(f"Average Paragraph Length: {content_stats.get('averageParagraphLength', 0):.1f}")
            stats_text.append("")
        
        # Language Statistics
        if 'languageStats' in stats:
            lang_stats = stats['languageStats']
            stats_text.append("Language Statistics:")
            stats_text.append(f"Detected Language: {lang_stats.get('detectedLanguage', 'Unknown')}")
            stats_text.append(f"English Word Percentage: {lang_stats.get('englishWordPercentage', 0):.1f}%")
            stats_text.append(f"Special Characters: {lang_stats.get('specialCharacters', 0):,}")
            stats_text.append(f"Numbers: {lang_stats.get('numbers', 0):,}")
        
        self.stats_text.insert(tk.END, "\n".join(stats_text))
        
        # Update tags
        tags = []
        if results.get('contentCategory'):
            tags.extend(results['contentCategory'])
        if results.get('sensitiveContent'):
            tags.append("Sensitive Content")
        if results.get('maliciousContent'):
            tags.append("Malicious Content")
        if results.get('detectedEntities'):
            tags.append("Contains Entities")
            
        self.tags_text.insert(tk.END, "\n".join(tags))
        
        # Update details
        details = []
        details.append(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        details.append(f"File Type: {results.get('contentCategory', ['Unknown'])[0]}")
        details.append(f"Language: {results.get('language', 'Unknown')}")
        details.append(f"Reading Level: {results.get('readingLevel', 'Unknown')}")
        details.append(f"Confidence Score: {results.get('confidenceScore', 0) * 100:.1f}%")
        
        # Keywords with frequency
        details.append("\nKeywords:")
        for keyword in results.get('keywords', []):
            details.append(f"- {keyword['word']} (frequency: {keyword['frequency']})")
        
        # Sensitive content
        sensitive_content = results.get('sensitiveContent', {})
        if sensitive_content:
            details.append("\nSensitive Content Detected:")
            for category, items in sensitive_content.items():
                if items:
                    details.append(f"- {category}:")
                    for item in items:
                        details.append(f"  * Line {item['line']}: {item['value']}")
        
        # Malicious content
        malicious_content = results.get('maliciousContent', {})
        if malicious_content:
            details.append("\nMalicious Content Detected:")
            
            if malicious_content.get('malware_indicators'):
                details.append("- Malware Indicators:")
                for item in malicious_content['malware_indicators']:
                    details.append(f"  * Line {item['line']}: {item['value']} ({item['type']})")
            
            if malicious_content.get('suspicious_patterns'):
                details.append("- Suspicious Patterns:")
                for item in malicious_content['suspicious_patterns']:
                    details.append(f"  * Line {item['line']}: {item['value']} ({item['type']})")
            
            if malicious_content.get('network_indicators'):
                details.append("- Network Indicators:")
                for item in malicious_content['network_indicators']:
                    details.append(f"  * Line {item['line']}: {item['value']} ({item['type']})")
            
            if malicious_content.get('obfuscation_techniques'):
                details.append("- Obfuscation Techniques:")
                for item in malicious_content['obfuscation_techniques']:
                    details.append(f"  * Line {item['line']}: {item['value']} ({item['type']})")
            
            if malicious_content.get('exploit_patterns'):
                details.append("- Exploit Patterns:")
                for item in malicious_content['exploit_patterns']:
                    details.append(f"  * Line {item['line']}: {item['value']} ({item['type']})")
        
        # Entities
        details.append("\nDetected Entities:")
        for entity in results.get('detectedEntities', []):
            details.append(f"- {entity}")
        
        # Risk assessment
        details.append("\nRisk Assessment:")
        details.append(f"- Score: {risk_score:.1f}%")
        details.append(f"- Level: {risk_level}")
        
        # File Insights
        details.append("\nFile Insights:")
        details.append(f"- Content Type: {results.get('contentCategory', ['Unknown'])[0]}")
        details.append(f"- Language: {results.get('language', 'Unknown')}")
        details.append(f"- Reading Level: {results.get('readingLevel', 'Unknown')}")
        details.append(f"- Confidence Score: {results.get('confidenceScore', 0) * 100:.1f}%")
        
        # Summary
        details.append("\nSummary:")
        if sensitive_content or malicious_content:
            details.append("⚠️ Security Concerns Detected:")
            if sensitive_content:
                details.append("  - Contains sensitive information")
            if malicious_content:
                details.append("  - Contains potentially malicious content")
        else:
            details.append("✅ No significant security concerns detected")
        
        self.details_text.insert(tk.END, "\n".join(details))
    
    def show_error(self, message):
        messagebox.showerror("Error", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileAnalyzerUI(root)
    root.mainloop() 