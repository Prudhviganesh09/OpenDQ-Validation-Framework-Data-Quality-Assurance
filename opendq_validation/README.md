# OpenDQ Data Validation Project

This project implements a data quality validation framework similar to Great Expectations, built using Python and Pandas. It provides a flexible way to define and execute data quality rules against your datasets.

## Features

- **Multiple Validation Rule Types**:
  - Regex pattern matching
  - Not-null checks
  - Uniqueness validation
  - Date format validation
- **Comprehensive Reporting**:
  - HTML and JSON report generation
  - Detailed error reporting with row-level details
- **Email Notifications**: Configure email alerts for validation results
- **Flexible Configuration**: Define validation rules in a simple JSON format

## Project Structure

```
opendq_validation/
├── config/
│   └── rules/                    # Validation rule definitions
│       └── customer_validation_rules.json
├── data/                         # Sample data files
│   └── sample_customers.csv
├── reports/                      # Generated validation reports
├── scripts/
│   ├── data_validator.py         # Main validation script
│   └── requirements.txt          # Python dependencies
└── README.md                     # This file
```

## Getting Started

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd opendq_validation
   ```

2. Install the required Python packages:
   ```bash
   pip install -r scripts/requirements.txt
   ```

## Usage

### Running Validations

To run the data validation with the default configuration:

```bash
python scripts/data_validator.py
```

To specify a custom configuration file:

```bash
python scripts/data_validator.py --config path/to/your/rules.json
```

### Configuration

The validation rules are defined in JSON format. See `config/rules/customer_validation_rules.json` for an example.

#### Example Rule Definition

```json
{
  "jobName": "customer_data_validation",
  "description": "Data quality validation for customer records",
  "dataSource": {
    "type": "csv",
    "path": "../../data/sample_customers.csv",
    "hasHeader": true
  },
  "validationRules": [
    {
      "ruleName": "email_format_validation",
      "description": "Email must be in valid format",
      "ruleType": "regex",
      "columnName": "email",
      "pattern": "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
      "severity": "ERROR"
    }
  ],
  "notifications": {
    "email": {
      "enabled": true,
      "recipients": ["your-email@example.com"],
      "onSuccess": true,
      "onFailure": true
    }
  },
  "reporting": {
    "formats": ["html", "json"],
    "outputPath": "../../reports/"
  }
}
```

### Rule Types

1. **Regex Validation**: Validates text against a regular expression pattern
2. **Not-Null Validation**: Ensures a column has no null values
3. **Unique Validation**: Ensures all values in a column are unique
4. **Date Format Validation**: Validates dates against a specified format

## Viewing Reports

After running the validation, reports will be generated in the `reports/` directory:

- `validation_report_<timestamp>.html`: Interactive HTML report
- `validation_report_<timestamp>.json`: Raw JSON data

## Email Notifications

To enable email notifications, update the email configuration in your rules file:

```json
"notifications": {
  "email": {
    "enabled": true,
    "from": "noreply@yourdomain.com",
    "recipients": ["user@example.com"],
    "onSuccess": true,
    "onFailure": true
  }
}
```

> **Note**: You'll need to configure your SMTP server settings in the `_send_email_notification` method of `data_validator.py`.

## Extending the Framework

You can add new validation rule types by extending the `DataValidator` class and implementing new validation methods following the existing pattern.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by Great Expectations
- Built with Python and Pandas
