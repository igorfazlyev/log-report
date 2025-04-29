import argparse
import os
import re
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Tuple, DefaultDict, Optional

# Type aliases
LogStats = Dict[str, Dict[str, int]]
HandlerStats = Dict[str, Dict[str, int]]
ReportData = Dict[str, Dict[str, int]]


class LogAnalyzer:
    """Base class for log analysis functionality."""

    LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    #LOG_PATTERN = re.compile(
    #    r'^.*django\.request\s+:\s+(?P<level>\w+)\s+.*"(?P<method>\w+)\s+(?P<handler>[^ ]+)'
    #)
    #LOG_PATTERN = re.compile(
    #    r'^.*django\.request\s+:\s+(?P<level>\w+)\s+.*"(?P<method>\w+)\s+(?P<handler>[^"\s]+)'
    #)
    LOG_PATTERN = re.compile(
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+(?P<level>\w+)\s+django\.request:\s+(?P<method>\w+)\s+(?P<handler>[^\s]+)'
    )

    @classmethod
    def parse_log_line(cls, line: str) -> Optional[Tuple[str, str]]:
        """Parse a single log line and extract handler and log level if it's a request log.
        
        Args:
            line: A line from the log file
            
        Returns:
            Tuple of (handler, log_level) if it's a request log, None otherwise
        """
        match = cls.LOG_PATTERN.match(line)
        if match:
            return match.group("handler"), match.group("level")
        return None

    @classmethod
    def process_log_file(cls, file_path: str) -> LogStats:
        """Process a single log file and return statistics.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Dictionary with handler statistics
        """
        stats: DefaultDict[str, DefaultDict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                for line in file:
                    result = cls.parse_log_line(line)
                    if result:
                        handler, level = result
                        stats[handler][level] += 1
        except UnicodeDecodeError:
            # Try with different encoding if utf-8 fails
            with open(file_path, "r", encoding="latin-1") as file:
                for line in file:
                    result = cls.parse_log_line(line)
                    if result:
                        handler, level = result
                        stats[handler][level] += 1

        return {handler: dict(levels) for handler, levels in stats.items()}

    @classmethod
    def merge_stats(cls, stats_list: List[LogStats]) -> ReportData:

        merged: DefaultDict[str, DefaultDict[str, int]] = defaultdict(lambda: defaultdict(int))  # Fixed: Added missing parenthesis
        
        for stats in stats_list:
            for handler, levels in stats.items():
                for level, count in levels.items():
                    merged[handler][level] += count
        
        return {handler: dict(levels) for handler, levels in merged.items()}


class HandlersReport:
    """Class for generating handlers report."""

    @classmethod
    def generate(cls, data: ReportData) -> str:
        """Generate handlers report.
        
        Args:
            data: Processed log data
            
        Returns:
            Formatted report as string
        """
        # Sort handlers alphabetically
        sorted_handlers = sorted(data.keys())
        
        # Prepare header
        header = f"{'HANDLER':<25}" + "".join(
            f"{level:<10}" for level in LogAnalyzer.LOG_LEVELS
        )
        
        # Prepare rows
        rows = []
        total_counts: DefaultDict[str, int] = defaultdict(int)
        
        for handler in sorted_handlers:
            levels = data[handler]
            row = f"{handler:<25}"
            for level in LogAnalyzer.LOG_LEVELS:
                count = levels.get(level, 0)
                row += f"{count:<10}"
                total_counts[level] += count
            rows.append(row)
        
        # Prepare footer with totals
        footer = f"{'':<25}" + "".join(
            f"{total_counts.get(level, 0):<10}" for level in LogAnalyzer.LOG_LEVELS
        )
        
        # Calculate total requests
        total_requests = sum(total_counts.values())
        
        # Combine all parts
        report = [f"Total requests: {total_requests}\n", header]
        report.extend(rows)
        report.append(footer)
        
        return "\n".join(report)


class ReportFactory:
    """Factory class for creating reports."""
    
    REPORT_TYPES = {
        "handlers": HandlersReport,
    }
    
    @classmethod
    def create_report(cls, report_type: str, data: ReportData) -> str:
        """Create a report of specified type.
        
        Args:
            report_type: Type of report to create
            data: Processed log data
            
        Returns:
            Formatted report as string
            
        Raises:
            ValueError: If report type is unknown
        """
        if report_type not in cls.REPORT_TYPES:
            raise ValueError(f"Unknown report type: {report_type}")
        
        return cls.REPORT_TYPES[report_type].generate(data)


class LogAnalyzerApp:
    """Main application class."""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create CLI argument parser."""
        parser = argparse.ArgumentParser(
            description="Analyze Django application logs and generate reports."
        )
        parser.add_argument(
            "log_files",
            nargs="+",
            help="Paths to log files to analyze"
        )
        parser.add_argument(
            "--report",
            required=True,
            choices=ReportFactory.REPORT_TYPES.keys(),
            help="Type of report to generate"
        )
        return parser
    
    def _validate_files(self, file_paths: List[str]) -> None:
        """Validate that log files exist.
        
        Args:
            file_paths: List of file paths to validate
            
        Raises:
            FileNotFoundError: If any file doesn't exist
        """
        for file_path in file_paths:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
    
    def run(self) -> None:
        """Run the application."""
        args = self.parser.parse_args()
        
        try:
            self._validate_files(args.log_files)
            
            # Process files in parallel
            with ProcessPoolExecutor() as executor:
                stats_list = list(executor.map(
                    LogAnalyzer.process_log_file, 
                    args.log_files
                ))
            
            # Merge statistics from all files
            merged_stats = LogAnalyzer.merge_stats(stats_list)
            
            # Generate and print report
            report = ReportFactory.create_report(args.report, merged_stats)
            print(report)
            
        except Exception as e:
            print(f"Error: {e}")
            self.parser.print_help()
            exit(1)


if __name__ == "__main__":
    app = LogAnalyzerApp()
    app.run()