import json
import os
import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from dataclasses import dataclass, asdict
import json
from enum import Enum
import sys
import traceback

# Configure root logger with more detailed format
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to capture all logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # Log to console
        logging.FileHandler('data_validation.log', mode='w')  # Overwrite log file each run
    ]
)

# Configure specific loggers if needed
logging.getLogger('PIL').setLevel(logging.WARNING)  # Reduce PIL logging
logging.getLogger('matplotlib').setLevel(logging.WARNING)  # Reduce matplotlib logging

# Set up our logger
logger = logging.getLogger(__name__)

class Severity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"

@dataclass
class ValidationResult:
    rule_name: str
    description: str
    passed: bool
    failed_count: int = 0
    error_details: List[Dict] = None
    severity: Severity = Severity.ERROR

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "description": self.description,
            "passed": self.passed,
            "failed_count": self.failed_count,
            "severity": self.severity.value,
            "error_details": self.error_details
        }

class DataValidator:
    def __init__(self, config_path: str):
        """Initialize the data validator with a configuration file."""
        logger.info(f"Initializing DataValidator with config: {config_path}")
        self.config = self._load_config(config_path)
        self.data = None
        self.results = []
        self.report = {
            'summary': {
                'total_rules': 0,
                'passed': 0,
                'failed': 0,
                'execution_time': None,
                'timestamp': None
            },
            'details': []
        }
        # Ensure required directories exist
        self._ensure_directories()
        
    def _ensure_directories(self) -> None:
        """Ensure all required directories exist and are writable."""
        try:
            # Ensure reports directory exists
            reports_dir = self.config.get('reporting', {}).get('outputPath', 'reports')
            reports_path = Path(reports_dir)
            
            # Create directory if it doesn't exist
            if not reports_path.exists():
                logger.info(f"Creating reports directory: {reports_path.absolute()}")
                reports_path.mkdir(parents=True, exist_ok=True)
                
            # Verify directory is writable
            test_file = reports_path / '.write_test'
            try:
                test_file.touch()
                test_file.unlink()
                logger.debug(f"Successfully verified write access to {reports_path.absolute()}")
            except Exception as e:
                logger.error(f"Cannot write to reports directory {reports_path.absolute()}: {e}")
                raise PermissionError(f"Cannot write to reports directory: {e}")
                
            logger.info(f"Using reports directory: {reports_path.absolute()}")
            
        except Exception as e:
            logger.error(f"Error setting up directories: {e}")
            raise
        
    def _load_config(self, config_path: str) -> Dict:
        """Load validation configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Handle case where config is nested under 'clean' key
            if 'clean' in config and isinstance(config['clean'], dict):
                logger.debug("Found 'clean' section in config, using it as main config")
                return config['clean']
                
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            raise
    
    def _load_data(self) -> None:
        """
        Load data from the configured data source.
        
        Raises:
            FileNotFoundError: If the data file does not exist
            ValueError: If the data source type is unsupported
        """
        source = self.config.get('dataSource', {})
        data_path = source.get('path', '')
        
        if not data_path:
            error_msg = "No data source path specified in configuration"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        # Convert to absolute path if it's not already
        data_path = Path(data_path).absolute()
        
        if not data_path.exists():
            error_msg = f"Data file not found: {data_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
            
        if source.get('type') == 'csv':
            try:
                logger.info(f"Loading data from: {data_path}")
                self.df = pd.read_csv(
                    str(data_path),
                    header=0 if source.get('hasHeader', True) else None
                )
                logger.info(f"Successfully loaded {len(self.df)} rows from {data_path}")
            except Exception as e:
                error_msg = f"Error loading data from {data_path}: {str(e)}"
                logger.error(error_msg)
                raise RuntimeError(error_msg) from e
        else:
            error_msg = f"Unsupported data source type: {source.get('type')}"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
    def _run_validations(self) -> None:
        """
        Run all validations specified in the configuration.
        
        This method processes each validation rule in the configuration and runs
        the appropriate validation method based on the rule type.
        """
        if not hasattr(self, 'df'):
            error_msg = "No data loaded. Call _load_data() first."
            logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        validation_rules = self.config.get('validationRules', [])
        if not validation_rules:
            logger.warning("No validation rules found in configuration")
            return
            
        logger.info(f"Running {len(validation_rules)} validation rules")
        
        for rule in validation_rules:
            rule_name = rule.get('ruleName', 'unnamed_rule')
            rule_type = rule.get('ruleType', '').lower()
            column_name = rule.get('columnName', '')
            
            logger.debug(f"Processing rule '{rule_name}' of type '{rule_type}' on column '{column_name}'")
            
            try:
                # Skip if the column doesn't exist in the dataframe
                if column_name and column_name not in self.df.columns:
                    error_msg = f"Column '{column_name}' not found in data"
                    logger.error(f"Validation rule '{rule_name}': {error_msg}")
                    self.results.append(ValidationResult(
                        rule_name=rule_name,
                        description=rule.get('description', ''),
                        passed=False,
                        error_message=error_msg,
                        severity=Severity.ERROR,
                        column_name=column_name,
                        failed_count=0,
                        error_samples=[]
                    ))
                    continue
                
                # Route to the appropriate validation method based on rule type
                if rule_type == 'regex':
                    result = self._validate_regex(rule)
                elif rule_type == 'not_null':
                    result = self._validate_not_null(rule)
                elif rule_type == 'unique':
                    result = self._validate_unique(rule)
                elif rule_type == 'date_format':
                    result = self._validate_date_format(rule)
                else:
                    error_msg = f"Unsupported rule type: {rule_type}"
                    logger.warning(f"Validation rule '{rule_name}': {error_msg}")
                    result = ValidationResult(
                        rule_name=rule_name,
                        description=rule.get('description', ''),
                        passed=False,
                        error_message=error_msg,
                        severity=Severity.ERROR,
                        column_name=column_name,
                        failed_count=0,
                        error_samples=[]
                    )
                
                self.results.append(result)
                status = "PASSED" if result.passed else "FAILED"
                logger.info(f"Validation '{rule_name}' {status}")
                
            except Exception as e:
                error_msg = f"Error executing validation rule '{rule_name}': {str(e)}"
                logger.error(error_msg, exc_info=True)
                self.results.append(ValidationResult(
                    rule_name=rule_name,
                    description=rule.get('description', ''),
                    passed=False,
                    error_message=error_msg,
                    severity=Severity.ERROR,
                    column_name=column_name,
                    failed_count=0,
                    error_samples=[]
                ))
                
        logger.info(f"Completed {len(validation_rules)} validation rules")
    
    def _validate_regex(self, rule: Dict) -> ValidationResult:
        """Validate column values against a regex pattern."""
        column = rule['columnName']
        pattern = rule['pattern']
        result = ValidationResult(
            rule_name=rule['ruleName'],
            description=rule['description'],
            passed=True,
            severity=Severity(rule.get('severity', 'ERROR')),
            error_details=[]
        )
        
        try:
            mask = ~self.df[column].astype(str).str.match(pattern, na=False)
            failed_rows = self.df[mask]
            
            if not failed_rows.empty:
                result.passed = False
                result.failed_count = len(failed_rows)
                result.error_details = [
                    {"row_index": int(idx), "value": str(val), "message": f"Value does not match pattern: {pattern}"}
                    for idx, val in failed_rows[column].items()
                ]
                
        except Exception as e:
            result.passed = False
            result.error_details = [{"error": str(e)}]
            logger.error(f"Error in regex validation for {column}: {e}")
            
        return result
    
    def _validate_not_null(self, rule: Dict) -> ValidationResult:
        """Validate that column values are not null."""
        column = rule['columnName']
        result = ValidationResult(
            rule_name=rule['ruleName'],
            description=rule['description'],
            passed=True,
            severity=Severity(rule.get('severity', 'ERROR')),
            error_details=[]
        )
        
        try:
            mask = self.df[column].isna()
            failed_rows = self.df[mask]
            
            if not failed_rows.empty:
                result.passed = False
                result.failed_count = len(failed_rows)
                result.error_details = [
                    {"row_index": int(idx), "message": "Value is null or missing"}
                    for idx in failed_rows.index
                ]
                
        except Exception as e:
            result.passed = False
            result.error_details = [{"error": str(e)}]
            logger.error(f"Error in not-null validation for {column}: {e}")
            
        return result
    
    def _validate_unique(self, rule: Dict) -> ValidationResult:
        """Validate that column values are unique."""
        column = rule['columnName']
        result = ValidationResult(
            rule_name=rule['ruleName'],
            description=rule['description'],
            passed=True,
            severity=Severity(rule.get('severity', 'ERROR')),
            error_details=[]
        )
        
        try:
            duplicates = self.df[self.df.duplicated(subset=[column], keep=False)]
            
            if not duplicates.empty:
                result.passed = False
                result.failed_count = len(duplicates)
                result.error_details = [
                    {
                        "row_index": int(idx),
                        "value": str(row[column]),
                        "message": f"Duplicate value found in column '{column}'"
                    }
                    for idx, row in duplicates.iterrows()
                ]
                
        except Exception as e:
            result.passed = False
            result.error_details = [{"error": str(e)}]
            logger.error(f"Error in unique validation for {column}: {e}")
            
        return result
    
    def _validate_date_format(self, rule: Dict) -> ValidationResult:
        """Validate that date values match the specified format."""
        column = rule['columnName']
        date_format = rule['format']
        result = ValidationResult(
            rule_name=rule['ruleName'],
            description=rule['description'],
            passed=True,
            severity=Severity(rule.get('severity', 'ERROR')),
            error_details=[]
        )
        
        try:
            # First filter out null values as they're handled by not_null rule
            non_null_mask = self.df[column].notna()
            invalid_dates = []
            
            for idx, value in self.df[non_null_mask][column].items():
                try:
                    datetime.strptime(str(value), date_format)
                except ValueError:
                    invalid_dates.append(idx)
            
            if invalid_dates:
                result.passed = False
                result.failed_count = len(invalid_dates)
                result.error_details = [
                    {
                        "row_index": int(idx),
                        "value": str(self.df.at[idx, column]),
                        "message": f"Date does not match format: {date_format}"
                    }
                    for idx in invalid_dates
                ]
                
        except Exception as e:
            result.passed = False
            result.error_details = [{"error": str(e)}]
            logger.error(f"Error in date format validation for {column}: {e}")
            
        return result
    
    def _save_report(self) -> None:
        """Save validation report to file."""
        try:
            # Get the output path from config or use default
            output_path = self.config.get('reporting', {}).get('outputPath', 'reports')
            report_dir = Path(output_path)
            
            # Log the absolute path for debugging
            abs_path = report_dir.absolute()
            logger.info(f"Attempting to save reports to: {abs_path}")
            
            # Ensure the directory exists
            try:
                report_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Directory exists or was created: {abs_path}")
            except Exception as dir_error:
                logger.error(f"Failed to create directory {abs_path}: {dir_error}")
                raise
            
            # Check if directory is writable
            if not os.access(str(report_dir), os.W_OK):
                error_msg = f"Directory is not writable: {abs_path}"
                logger.error(error_msg)
                raise PermissionError(error_msg)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"validation_report_{timestamp}"
            
            # Save JSON report if requested
            if 'json' in self.config.get('reporting', {}).get('formats', []):
                try:
                    json_path = report_dir / f"{base_filename}.json"
                    with open(json_path, 'w') as f:
                        json.dump(self.report, f, indent=2)
                    logger.info(f"JSON report successfully saved to: {json_path.absolute()}")
                except Exception as json_error:
                    logger.error(f"Failed to save JSON report: {json_error}")
                    raise
            
            # Save HTML report if requested
            if 'html' in self.config.get('reporting', {}).get('formats', []):
                try:
                    html_path = report_dir / f"{base_filename}.html"
                    self._generate_html_report(html_path)
                    logger.info(f"HTML report successfully saved to: {html_path.absolute()}")
                except Exception as html_error:
                    logger.error(f"Failed to generate/save HTML report: {html_error}")
                    raise
                    
        except Exception as e:
            logger.error(f"Critical error in _save_report: {str(e)}", exc_info=True)
            raise
    
    def _generate_html_report(self, output_path: str) -> None:
        """
        Generate an HTML report of the validation results.
        
        Args:
            output_path: Path where the HTML report should be saved.
            
        Raises:
            Exception: If there's an error generating the HTML report.
        """
        try:
            logger.info(f"Starting HTML report generation for {len(self.results)} validation results")
            
            # Calculate summary statistics
            passed_count = sum(1 for r in self.results if r.passed)
            failed_count = len(self.results) - passed_count
            total_rules = len(self.results)
            
            logger.debug(f"Report stats - Passed: {passed_count}, Failed: {failed_count}, Total: {total_rules}")
            
            # Get execution time and timestamp from report summary
            execution_time = self.report.get('summary', {}).get('execution_time', 'N/A')
            timestamp = self.report.get('summary', {}).get('timestamp', 'N/A')
            
            logger.debug(f"Report metadata - Execution Time: {execution_time}, Timestamp: {timestamp}")
            
            # Determine status for the summary cards
            overall_status = 'passed' if failed_count == 0 else 'failed'
            
            # Start building the HTML content with proper escaping
            try:
                html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Data Quality Validation Report</title>
                    <style>
                        body {{ 
                            font-family: Arial, sans-serif; 
                            margin: 20px; 
                            line-height: 1.6;
                            color: #333;
                        }}
                        .summary {{ 
                            margin-bottom: 30px; 
                            padding: 15px;
                            background-color: #f8f9fa;
                            border-radius: 5px;
                        }}
                        .summary h2 {{
                            margin-top: 0;
                            color: #2c3e50;
                        }}
                        .summary-cards {{
                            display: flex;
                            flex-wrap: wrap;
                            gap: 15px;
                            margin: 15px 0;
                        }}
                        .summary-card {{ 
                            flex: 1;
                            min-width: 150px;
                            padding: 15px; 
                            border-radius: 5px; 
                            color: white; 
                            font-weight: bold;
                            text-align: center;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }}
                        .summary-card.passed {{ 
                            background-color: #4CAF50;
                        }}
                        .summary-card.failed {{ 
                            background-color: #f44336;
                        }}
                        .summary-card.neutral {{
                            background-color: #2196F3;
                        }}
                        .summary-card .count {{
                            font-size: 24px;
                            margin: 5px 0;
                            font-weight: bold;
                        }}
                        .rule {{ 
                            border: 1px solid #e0e0e0; 
                            margin: 10px 0; 
                            padding: 15px; 
                            border-radius: 5px;
                            background-color: #fff;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                        }}
                        .rule.passed {{ 
                            border-left: 5px solid #4CAF50;
                        }}
                        .rule.failed {{ 
                            border-left: 5px solid #f44336;
                        }}
                        .rule h3 {{
                            margin-top: 0;
                            color: #2c3e50;
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                        }}
                        .rule .status {{
                            display: inline-block;
                            padding: 3px 8px;
                            border-radius: 3px;
                            font-size: 0.8em;
                            font-weight: bold;
                            text-transform: uppercase;
                            color: white;
                        }}
                        .rule .status.passed {{ background-color: #4CAF50; }}
                        .rule .status.failed {{ background-color: #f44336; }}
                        .error-details {{ 
                            margin-top: 10px; 
                            padding: 10px; 
                            background-color: #f8f9fa; 
                            border-radius: 5px;
                            font-family: 'Courier New', Courier, monospace;
                            font-size: 0.9em;
                            max-height: 200px;
                            overflow-y: auto;
                            border: 1px solid #e0e0e0;
                        }}
                        table {{ 
                            width: 100%; 
                            border-collapse: collapse; 
                            margin: 10px 0;
                            font-size: 0.9em;
                        }}
                        th, td {{ 
                            border: 1px solid #ddd; 
                            padding: 8px 12px; 
                            text-align: left; 
                            vertical-align: top;
                        }}
                        th {{ 
                            background-color: #f2f2f2;
                            font-weight: bold;
                        }}
                        tr:nth-child(even) {{
                            background-color: #f9f9f9;
                        }}
                        pre {{ 
                            margin: 0; 
                            white-space: pre-wrap;
                            font-family: inherit;
                        }}
                        .no-issues {{
                            color: #666;
                            font-style: italic;
                            padding: 10px;
                            text-align: center;
                        }}
                        footer {{
                            margin-top: 30px;
                            padding-top: 15px;
                            border-top: 1px solid #eee;
                            color: #777;
                            font-size: 0.9em;
                            text-align: center;
                        }}
                    </style>
                </head>
                <body>
                    <h1>Data Quality Validation Report</h1>
                    <div class="summary">
                        <h2>Summary</h2>
                        <div class="summary-cards">
                            <div class="summary-card {'passed' if passed_count > 0 or failed_count == 0 else 'failed'}">
                                <div>Overall Status</div>
                                <div class="count">{'PASSED' if failed_count == 0 else 'FAILED'}</div>
                            </div>
                            <div class="summary-card passed">
                                <div>Passed Rules</div>
                                <div class="count">{passed_count}</div>
                            </div>
                            <div class="summary-card {'failed' if failed_count > 0 else 'passed'}">
                                <div>Failed Rules</div>
                                <div class="count">{failed_count}</div>
                            </div>
                            <div class="summary-card neutral">
                                <div>Total Rules</div>
                                <div class="count">{total_rules}</div>
                            </div>
                        </div>
                        <div>
                            <p><strong>Execution Time:</strong> {execution_time}</p>
                            <p><strong>Timestamp:</strong> {timestamp}</p>
                        </div>
                    </div>
                    <h2>Validation Results</h2>
                """
                
                logger.debug("HTML template generated successfully")
                
            except Exception as template_error:
                logger.error(f"Error generating HTML template: {template_error}")
                raise
            
            for result in self.results:
                status_class = "passed" if result.passed else "failed"
                status_text = "PASSED" if result.passed else "FAILED"
                
                html_content += f"""
                <div class="rule {status_class}">
                    <h3>{result.rule_name} <span style="color: {'#4CAF50' if result.passed else '#f44336'}">({status_text})</span></h3>
                    <p><strong>Description:</strong> {result.description}</p>
                    <p><strong>Severity:</strong> {result.severity.value}</p>
                    <p><strong>Failed Rows:</strong> {result.failed_count if not result.passed else 0}</p>
                """
                
                if not result.passed and result.error_details:
                    html_content += "<div class='error-details'><strong>Error Details:</strong>"
                    
                    # If there are many errors, show a table
                    if len(result.error_details) > 3:
                        html_content += """
                        <table>
                            <tr>
                                <th>Row</th>
                                <th>Value</th>
                                <th>Message</th>
                            </tr>
                        """
                        for error in result.error_details[:50]:  # Limit to first 50 errors
                            html_content += f"""
                            <tr>
                                <td>{error.get('row_index', 'N/A')}</td>
                                <td>{error.get('value', 'N/A')}</td>
                                <td>{error.get('message', 'N/A')}</td>
                            </tr>
                            """
                        html_content += "</table>"
                        if len(result.error_details) > 50:
                            html_content += f"<p>... and {len(result.error_details) - 50} more errors</p>"
                    else:
                        for error in result.error_details:
                            html_content += f"<pre>{json.dumps(error, indent=2)}</pre>"
                    
                    html_content += "</div>"
                
                html_content += "</div>"
            
            html_content += """
                <footer style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                    <p>Generated by OpenDQ Validation Tool</p>
                </footer>
            </body>
            </html>
            """
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def _send_email_notification(self, success: bool) -> None:
        """Send email notification with validation results."""
        if not self.config.get('notifications', {}).get('email', {}).get('enabled', False):
            return
            
        try:
            email_config = self.config['notifications']['email']
            
            # Only send email if configured to do so for this result
            if (success and not email_config.get('onSuccess', False)) or \
               (not success and not email_config.get('onFailure', False)):
                return
                
            msg = MIMEMultipart()
            msg['From'] = email_config.get('from', 'noreply@opendq.com')
            msg['To'] = ", ".join(email_config['recipients'])
            
            if success:
                msg['Subject'] = "✅ Data Validation Succeeded"
                body = "All data validation rules passed successfully.\n\n"
            else:
                msg['Subject'] = "❌ Data Validation Failed"
                body = "Some data validation rules failed. Please check the report for details.\n\n"
            
            # Add summary to email body
            body += f"Validation Summary:\n"
            body += f"- Total Rules: {len(self.results)}\n"
            body += f"- Passed: {sum(1 for r in self.results if r.passed)}\n"
            body += f"- Failed: {sum(1 for r in self.results if not r.passed)}\n\n"
            
            # Add failed rules to email body
            failed_rules = [r for r in self.results if not r.passed]
            if failed_rules:
                body += "Failed Rules:\n"
                for rule in failed_rules:
                    body += f"- {rule.rule_name}: {rule.description} (Failed: {rule.failed_count} rows)\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # For demo purposes, just log the email content
            # In production, you would use smtplib to send the email
            logger.info(f"Email notification prepared. To: {msg['To']}")
            logger.info(f"Subject: {msg['Subject']}")
            logger.info(f"Body:\n{body}")
            
            # Uncomment and configure this in production:
            """
            with smtplib.SMTP('smtp.example.com', 587) as server:
                server.starttls()
                server.login('username', 'password')
                server.send_message(msg)
            """
                
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    def validate(self) -> Dict:
        """
        Run all validations and return results.
        
        Returns:
            Dict: A dictionary containing the validation results and summary
            
        Raises:
            Exception: If any critical error occurs during validation
        """
        start_time = datetime.now()
        
        try:
            # Load data
            if not self.config or not self.config.get('dataSource') or not self.config['dataSource'].get('path'):
                raise ValueError("No data source path specified in configuration")
                
            self._load_data()
            
            # Run validations
            self._run_validations()
            
            # Generate reports
            self._save_report()
            
            # Send notifications if configured
            if self.config.get('notifications', {}).get('email', {}).get('enabled', False):
                self._send_email_notification(success=True)
            
            # Prepare results
            self.report['summary']['timestamp'] = datetime.now().isoformat()
            self.report['summary']['execution_time'] = str(datetime.now() - start_time)
            
            return {
                'status': 'SUCCESS',
                'summary': self.report['summary'],
                'details': [r.to_dict() for r in self.results]
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Validation failed: {error_msg}", exc_info=True)
            return {
                'status': 'ERROR',
                'summary': {
                    'total_rules': 0,
                    'passed': 0,
                    'failed': 0,
                    'execution_time': str(datetime.now() - start_time),
                    'timestamp': datetime.now().isoformat()
                },
                'details': [],
                'error': error_msg
            }

def main():
    """Main function to run the validator from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run data quality validations')
    parser.add_argument('--config', type=str, default='../config/rules/customer_validation_rules.json',
                        help='Path to validation rules JSON file')
    
    args = parser.parse_args()
    
    try:
        validator = DataValidator(args.config)
        result = validator.validate()
        
        # Print summary to console
        print("\n=== Validation Summary ===")
        print(f"Status: {result['status']}")
        print(f"Total Rules: {result['summary']['total_rules']}")
        print(f"Passed: {result['summary']['passed']}")
        print(f"Failed: {result['summary']['failed']}")
        print(f"Execution Time: {result['summary']['execution_time']}")
        
        if result['status'] != 'SUCCESS':
            print("\nFailed Rules:")
            for rule in result['details']:
                if not rule['passed']:
                    print(f"- {rule['rule_name']}: {rule['description']} (Failed: {rule['failed_count']} rows)")
        
        return 0 if result['status'] == 'SUCCESS' else 1
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(main())
