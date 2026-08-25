import argparse
import logging
import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from .config import Config
from .container import ServiceContainer
from .security.validators import InputValidator

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging for SentinelRecon.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger("SentinelRecon")
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    return logger

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='SentinelRecon v2.0 - AWS Cloud Enumeration & Security Analysis',
        epilog='Examples: \n' +
        '  AWS:   python -m sentinelrecon.v2.main --account 123456789012 --scan s3,ec2\n' +
        '  Azure: python -m sentinelrecon.v2.main --cloud azure --subscription sub-id\n' +
        '  GCP:   python -m sentinelrecon.v2.main --cloud gcp --project project-id\n' +
        '  All:   python -m sentinelrecon.v2.main --cloud all --account 123... --subscription sub-id --project proj-id',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        '--account',
        type=str,
        required=False,
        help='AWS account ID (12 digits, required for AWS scans)'
    )

    parser.add_argument(
        '--cloud',
        type=str,
        choices=['aws', 'azure', 'gcp', 'all'],
        default='aws',
        help='Cloud provider to scan (default: aws)'
    )

    parser.add_argument(
        '--subscription',
        type=str,
        required=False,
        help='Azure subscription ID (required for Azure scans)'
    )

    parser.add_argument(
        '--project',
        type=str,
        required=False,
        help='GCP project ID (required for GCP scans)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--region',
        type=str,
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    
    parser.add_argument(
        '--scan',
        type=str,
        default='all',
        help='Scan types: s3, ec2, iam, or all (default: all)'
    )
    
    parser.add_argument(
        '--output-format',
        type=str,
        choices=['json', 'html', 'all'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--scan-name',
        type=str,
        default=None,
        help='Custom scan name (auto-generated if not provided)'
    )
    
    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    return parser.parse_args()

def validate_arguments(args: argparse.Namespace) -> bool:
    """Validate parsed arguments for security.
    
    Args:
        args: Parsed arguments
        
    Returns:
        bool: True if valid
    """
    validator = InputValidator(logging.getLogger("SentinelRecon"))
    
    # Validate based on cloud provider
    if args.cloud in ['aws', 'all']:
        if not args.account:
            print("❌ --account is required for AWS scans")
            return False
        
        valid, error = validator.validate_aws_account_id(args.account)
        if not valid:
            print(f"❌ Account ID validation failed: {error}")
            return False
        
        valid, error = validator.validate_aws_region(args.region)
        if not valid:
            print(f"❌ Region validation failed: {error}")
            return False
    
    if args.cloud in ['azure', 'all']:
        if not args.subscription:
            print("❌ --subscription is required for Azure scans")
            return False
    
    if args.cloud in ['gcp', 'all']:
        if not args.project:
            print("❌ --project is required for GCP scans")
            return False
    
    # Validate scan name if provided
    if args.scan_name:
        valid, error = validator.validate_scan_name(args.scan_name)
        if not valid:
            print(f"❌ Scan name validation failed: {error}")
            return False
    
    return True

def generate_scan_name(account_id: str, scan_type: str) -> str:
    """Generate scan name if not provided.
    
    Args:
        account_id: AWS account ID
        scan_type: Type of scan (s3, ec2, iam, all)
        
    Returns:
        str: Generated scan name
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"aws_{account_id}_{scan_type}_{timestamp}"

def main() -> int:
    """Main entry point for SentinelRecon.
    
    Returns:
        int: Exit code (0 = success, 1 = error)
    """
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging
        logger = setup_logging(args.log_level)
        logger.info("SentinelRecon v2.0 - AWS Cloud Enumeration Starting")
        
        # Validate arguments
        if not validate_arguments(args):
            return 1
        
        # Validate config
        Config.validate()
        
        # Create dependency injection container
        container = ServiceContainer.create()
        
        # Generate scan name
        scan_name = args.scan_name or generate_scan_name(args.account, args.scan)
        
        # Initialize report directory
        report_manager = container.get_report_manager()
        report_dir = report_manager.initialize_report_directory(scan_name)
        logger.info(f"Report directory: {report_dir}")
        
        # Log scan parameters
        logger.info(f"Account ID: {args.account}")
        logger.info(f"Region: {args.region}")
        logger.info(f"Scan type: {args.scan}")
        logger.info(f"Output format: {args.output_format}")
        
        # Import orchestrator (will implement in PROMPT 4-2)
        from .orchestrator import Orchestrator
        
        # Create orchestrator
        orchestrator = Orchestrator(container, logger)
        
        # Execute scan (will implement in PROMPT 4-2)
        results = orchestrator.execute_scan(
            account_id=args.account if args.cloud in ['aws', 'all'] else None,
            region=args.region if args.cloud in ['aws', 'all'] else None,
            scan_types=args.scan.split(',') if args.scan != 'all' else ['all'],
            report_manager=report_manager,
            cloud_provider=args.cloud,
            azure_subscription_id=args.subscription,
            gcp_project_id=args.project
        )
        
        logger.info("✅ Scan completed successfully")
        logger.info(f"Results saved to: {report_dir}")
        
        return 0
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"\nFatal error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
