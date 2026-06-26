import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


class ReportGenerator:
    """
    Generates scan reports in HTML, PDF, and JSON formats.
    """
    def __init__(self, template_dir: str = None):
        """
        Initialize the ReportGenerator and set up the Jinja2 environment.
        
        Args:
            template_dir: Path to the directory containing Jinja2 templates.
                          Defaults to 'sentinelrecon/reports/templates'.
        """
        if not template_dir:
            # Default to the templates folder relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(base_dir, "templates")
            
        if not os.path.exists(template_dir):
            os.makedirs(template_dir, exist_ok=True)
            
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_html(self, scan_data: dict) -> str:
        """
        Render the Jinja2 HTML template with scan data.
        
        Args:
            scan_data: Dictionary containing target, scan_type, started_at, etc.
            
        Returns:
            Rendered HTML string.
        """
        try:
            template = self.env.get_template("report.html.j2")
        except Exception as e:
            raise FileNotFoundError(f"Template report.html.j2 not found in templates directory. {str(e)}")
            
        return template.render(**scan_data)

    def generate_pdf(self, scan_data: dict) -> bytes:
        """
        Generate a PDF from HTML using WeasyPrint.
        
        Args:
            scan_data: Dictionary containing scan results.
            
        Returns:
            PDF content as bytes.
        """
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("WeasyPrint is not installed. PDF generation requires WeasyPrint. "
                              "Please install it using: pip install weasyprint")
            
        html_str = self.generate_html(scan_data)
        return weasyprint.HTML(string=html_str).write_pdf()

    def generate_json(self, scan_data: dict) -> str:
        """
        Dump scan data to formatted JSON.
        
        Args:
            scan_data: Dictionary containing scan results.
            
        Returns:
            JSON formatted string with indent=2.
        """
        # Convert non-serializable objects (like datetime) to string
        return json.dumps(scan_data, indent=2, default=str)

    def save(self, content, format: str, output_dir: str) -> str:
        """
        Save report content to a file and return the file path.
        
        Args:
            content: The string (HTML/JSON) or bytes (PDF) to save.
            format: The extension of the file ('html', 'pdf', 'json').
            output_dir: The directory where the file should be saved.
            
        Returns:
            Absolute path to the saved file.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.{format.lower()}"
        filepath = os.path.join(output_dir, filename)
        
        if format.lower() == "pdf":
            mode = "wb"
            encoding = None
        else:
            mode = "w"
            encoding = "utf-8"
            
        with open(filepath, mode, encoding=encoding) as f:
            f.write(content)
            
        return os.path.abspath(filepath)
