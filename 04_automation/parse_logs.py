#!/usr/bin/env python3
"""
Log Parser for Security Analysis

This script parses various log formats and extracts security-relevant information.
It supports Windows Event Logs, Syslog, Web server logs, and custom formats.

Author: [Your Name]
Version: 1.0.0
Date: 2023-04-15
"""

import argparse
import csv
import datetime
import json
import os
import re
import sys
from typing import Dict, List, Any, Optional, Union

import pandas as pd
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)


class LogParser:
    """Base class for log parsing functionality."""

    def __init__(self, log_format: str, input_file: str, output_file: str):
        """
        Initialize the LogParser with format and file information.

        Args:
            log_format: The format of logs to parse (windows, syslog, apache, iis, custom)
            input_file: Path to the input log file
            output_file: Path to the output file for results
        """
        self.log_format = log_format.lower()
        self.input_file = input_file
        self.output_file = output_file
        self.parsed_logs = []
        self.supported_formats = {
            "windows": self._parse_windows_event,
            "syslog": self._parse_syslog,
            "apache": self._parse_apache,
            "iis": self._parse_iis,
            "custom": self._parse_custom
        }

        # Validate input file exists
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Validate log format is supported
        if log_format.lower() not in self.supported_formats:
            raise ValueError(
                f"Unsupported log format: {log_format}. " 
                f"Supported formats: {', '.join(self.supported_formats.keys())}"
            )

    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse the log file based on the specified format.

        Returns:
            List of dictionaries containing parsed log entries
        """
        print(f"{Fore.BLUE}[*] Parsing {self.log_format} format logs from {self.input_file}")

        try:
            # Call the appropriate parsing method based on log format
            parse_method = self.supported_formats[self.log_format]
            self.parsed_logs = parse_method()
            
            print(f"{Fore.GREEN}[+] Successfully parsed {len(self.parsed_logs)} log entries")
            return self.parsed_logs
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing logs: {str(e)}")
            raise

    def save_results(self, output_format: str = "json") -> None:
        """
        Save parsed results to the specified output file.

        Args:
            output_format: Format to save results (json, csv)
        """
        if not self.parsed_logs:
            print(f"{Fore.YELLOW}[!] No parsed logs to save")
            return

        try:
            if output_format.lower() == "json":
                with open(self.output_file, 'w') as f:
                    json.dump(self.parsed_logs, f, indent=2, default=str)
            
            elif output_format.lower() == "csv":
                # Flatten nested dictionaries for CSV output
                flattened_logs = []
                for log in self.parsed_logs:
                    flat_log = {}
                    for key, value in log.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                flat_log[f"{key}_{sub_key}"] = sub_value
                        else:
                            flat_log[key] = value
                    flattened_logs.append(flat_log)
                
                # Write to CSV
                if flattened_logs:
                    df = pd.DataFrame(flattened_logs)
                    df.to_csv(self.output_file, index=False)
            
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
            
            print(f"{Fore.GREEN}[+] Results saved to {self.output_file}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}")
            raise

    def analyze(self) -> Dict[str, Any]:
        """
        Perform basic analysis on the parsed logs.

        Returns:
            Dictionary containing analysis results
        """
        if not self.parsed_logs:
            print(f"{Fore.YELLOW}[!] No parsed logs to analyze")
            return {}

        analysis = {
            "total_entries": len(self.parsed_logs),
            "time_range": {
                "start": None,
                "end": None
            },
            "event_counts": {},
            "source_counts": {},
            "severity_counts": {}
        }

        # Extract timestamps for time range analysis
        timestamps = []
        for log in self.parsed_logs:
            if "timestamp" in log:
                try:
                    if isinstance(log["timestamp"], str):
                        timestamps.append(pd.to_datetime(log["timestamp"]))
                    else:
                        timestamps.append(log["timestamp"])
                except:
                    pass

        if timestamps:
            analysis["time_range"]["start"] = min(timestamps)
            analysis["time_range"]["end"] = max(timestamps)

        # Count events by type/ID
        for log in self.parsed_logs:
            # Count event types/IDs
            event_id = log.get("event_id") or log.get("EventID") or log.get("id") or "unknown"
            analysis["event_counts"][str(event_id)] = analysis["event_counts"].get(str(event_id), 0) + 1
            
            # Count sources
            source = log.get("source") or log.get("Source") or log.get("host") or log.get("hostname") or "unknown"
            analysis["source_counts"][str(source)] = analysis["source_counts"].get(str(source), 0) + 1
            
            # Count severity levels
            severity = log.get("severity") or log.get("level") or "unknown"
            analysis["severity_counts"][str(severity)] = analysis["severity_counts"].get(str(severity), 0) + 1

        return analysis

    def _parse_windows_event(self) -> List[Dict[str, Any]]:
        """
        Parse Windows Event Log format.

        Returns:
            List of dictionaries containing parsed Windows event logs
        """
        parsed_logs = []
        
        # Check if input is XML or EVTX converted to text
        with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1000)  # Read first 1000 chars to determine format
            
        if content.strip().startswith("<?xml") or "<Event xmlns=" in content:
            # XML format
            import xml.etree.ElementTree as ET
            try:
                tree = ET.parse(self.input_file)
                root = tree.getroot()
                
                for event in root.findall(".//Event"):
                    log_entry = {}
                    
                    # Extract System metadata
                    system = event.find("System")
                    if system is not None:
                        for child in system:
                            log_entry[child.tag] = child.text
                            
                            # Handle attributes
                            if child.attrib:
                                log_entry[f"{child.tag}_attributes"] = child.attrib
                    
                    # Extract EventData
                    event_data = event.find("EventData")
                    if event_data is not None:
                        data = {}
                        for data_item in event_data.findall("Data"):
                            name = data_item.attrib.get("Name", "")
                            if name:
                                data[name] = data_item.text
                            elif data_item.text:
                                # Handle unnamed data items
                                data[f"Data_{len(data)}"] = data_item.text
                        
                        log_entry["EventData"] = data
                    
                    parsed_logs.append(log_entry)
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error parsing XML Windows Event Log: {str(e)}")
                raise
        
        else:
            # Assume text-based export format
            with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                current_event = {}
                for line in f:
                    line = line.strip()
                    
                    # Check for new event start
                    if line.startswith("Log Name:") or (not line and current_event):
                        if current_event:  # Save previous event if exists
                            parsed_logs.append(current_event)
                            current_event = {}
                        
                        if not line:  # Skip empty lines between events
                            continue
                    
                    # Parse key-value pairs
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        current_event[key.strip()] = value.strip()
                
                # Add the last event if exists
                if current_event:
                    parsed_logs.append(current_event)
        
        return parsed_logs

    def _parse_syslog(self) -> List[Dict[str, Any]]:
        """
        Parse Syslog format logs.

        Returns:
            List of dictionaries containing parsed syslog entries
        """
        parsed_logs = []
        
        # Regex pattern for standard syslog format
        # <priority>timestamp hostname process[pid]: message
        syslog_pattern = r"(?:<(\d+)>)?([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)"
        
        # Alternative pattern for RFC5424 format
        rfc5424_pattern = r"<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\S*) (.*)"
        
        with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Try standard syslog format first
                match = re.match(syslog_pattern, line)
                if match:
                    priority, timestamp, hostname, process, pid, message = match.groups()
                    
                    log_entry = {
                        "timestamp": timestamp,
                        "hostname": hostname,
                        "process": process,
                        "pid": pid,
                        "message": message
                    }
                    
                    if priority:
                        # Calculate facility and severity from priority
                        priority = int(priority)
                        log_entry["facility"] = priority >> 3
                        log_entry["severity"] = priority & 0x7
                    
                    parsed_logs.append(log_entry)
                    continue
                
                # Try RFC5424 format
                match = re.match(rfc5424_pattern, line)
                if match:
                    pri, timestamp, hostname, app_name, proc_id, msg_id, structured_data, message = match.groups()
                    
                    log_entry = {
                        "timestamp": timestamp,
                        "hostname": hostname,
                        "app_name": app_name,
                        "proc_id": proc_id,
                        "msg_id": msg_id,
                        "structured_data": structured_data,
                        "message": message
                    }
                    
                    if pri:
                        # Calculate facility and severity from priority
                        pri = int(pri)
                        log_entry["facility"] = pri >> 3
                        log_entry["severity"] = pri & 0x7
                    
                    parsed_logs.append(log_entry)
                    continue
                
                # If no match, add as raw message
                parsed_logs.append({"raw_message": line})
        
        return parsed_logs

    def _parse_apache(self) -> List[Dict[str, Any]]:
        """
        Parse Apache web server logs.

        Returns:
            List of dictionaries containing parsed Apache log entries
        """
        parsed_logs = []
        
        # Common Log Format pattern
        clf_pattern = r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" (\d+) (\d+|-)'
        
        # Combined Log Format pattern (extends CLF with referrer and user agent)
        combined_pattern = r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        
        with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Try Combined Log Format first
                match = re.match(combined_pattern, line)
                if match:
                    client_ip, identity, user_id, timestamp, request, status, size, referrer, user_agent = match.groups()
                    
                    # Parse the request into method, path, and protocol
                    request_parts = request.split()
                    method = path = protocol = ""
                    if len(request_parts) >= 1:
                        method = request_parts[0]
                    if len(request_parts) >= 2:
                        path = request_parts[1]
                    if len(request_parts) >= 3:
                        protocol = request_parts[2]
                    
                    log_entry = {
                        "client_ip": client_ip,
                        "identity": identity if identity != "-" else None,
                        "user_id": user_id if user_id != "-" else None,
                        "timestamp": timestamp,
                        "request": {
                            "method": method,
                            "path": path,
                            "protocol": protocol,
                            "raw": request
                        },
                        "status": int(status),
                        "size": int(size) if size != "-" else 0,
                        "referrer": referrer if referrer != "-" else None,
                        "user_agent": user_agent if user_agent != "-" else None
                    }
                    
                    parsed_logs.append(log_entry)
                    continue
                
                # Try Common Log Format
                match = re.match(clf_pattern, line)
                if match:
                    client_ip, identity, user_id, timestamp, request, status, size = match.groups()
                    
                    # Parse the request into method, path, and protocol
                    request_parts = request.split()
                    method = path = protocol = ""
                    if len(request_parts) >= 1:
                        method = request_parts[0]
                    if len(request_parts) >= 2:
                        path = request_parts[1]
                    if len(request_parts) >= 3:
                        protocol = request_parts[2]
                    
                    log_entry = {
                        "client_ip": client_ip,
                        "identity": identity if identity != "-" else None,
                        "user_id": user_id if user_id != "-" else None,
                        "timestamp": timestamp,
                        "request": {
                            "method": method,
                            "path": path,
                            "protocol": protocol,
                            "raw": request
                        },
                        "status": int(status),
                        "size": int(size) if size != "-" else 0
                    }
                    
                    parsed_logs.append(log_entry)
                    continue
                
                # If no match, add as raw message
                parsed_logs.append({"raw_message": line})
        
        return parsed_logs

    def _parse_iis(self) -> List[Dict[str, Any]]:
        """
        Parse IIS web server logs.

        Returns:
            List of dictionaries containing parsed IIS log entries
        """
        parsed_logs = []
        field_names = []
        
        with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Skip comments, but look for field definitions
                if line.startswith('#'):
                    if "Fields:" in line:
                        # Extract field names from the directive
                        field_names = line.split("Fields: ")[1].split(" ")
                    continue
                
                # Parse data lines
                if field_names:
                    # Split by space, but respect quotes
                    values = re.findall(r'"([^"]*)"|([^ "]+)', line)
                    values = [v[0] if v[0] else v[1] for v in values]
                    
                    if len(values) == len(field_names):
                        log_entry = {}
                        for i, field in enumerate(field_names):
                            value = values[i]
                            # Convert to appropriate types
                            if field in ["sc-status", "sc-substatus", "sc-win32-status", "time-taken"]:
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            elif field in ["cs-uri-query", "cs(User-Agent)", "cs(Referer)"] and value == "-":
                                value = None
                            
                            log_entry[field] = value
                        
                        parsed_logs.append(log_entry)
                    else:
                        # If field count doesn't match, add as raw message
                        parsed_logs.append({"raw_message": line})
                else:
                    # No field names defined yet, add as raw message
                    parsed_logs.append({"raw_message": line})
        
        return parsed_logs

    def _parse_custom(self) -> List[Dict[str, Any]]:
        """
        Parse custom format logs based on file extension.

        Returns:
            List of dictionaries containing parsed log entries
        """
        parsed_logs = []
        file_ext = os.path.splitext(self.input_file)[1].lower()
        
        if file_ext == ".json":
            # Parse JSON logs
            with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    # Try parsing as JSON array
                    data = json.load(f)
                    if isinstance(data, list):
                        parsed_logs = data
                    else:
                        # Single JSON object
                        parsed_logs = [data]
                except json.JSONDecodeError:
                    # Try parsing line by line (JSON Lines format)
                    f.seek(0)  # Reset file pointer
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            parsed_logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            parsed_logs.append({"raw_message": line})
        
        elif file_ext == ".csv":
            # Parse CSV logs
            try:
                df = pd.read_csv(self.input_file)
                parsed_logs = df.to_dict(orient="records")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error parsing CSV, trying with different dialect: {str(e)}")
                # Try with different CSV dialect
                with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                    try:
                        dialect = csv.Sniffer().sniff(f.read(1024))
                        f.seek(0)
                        reader = csv.DictReader(f, dialect=dialect)
                        for row in reader:
                            parsed_logs.append(dict(row))
                    except Exception as e2:
                        print(f"{Fore.RED}[!] Error parsing CSV with sniffer: {str(e2)}")
                        raise
        
        elif file_ext == ".xml":
            # Parse XML logs
            import xml.etree.ElementTree as ET
            try:
                tree = ET.parse(self.input_file)
                root = tree.getroot()
                
                # Find all elements that look like log entries
                log_elements = root.findall(".//*[@timestamp]")
                if not log_elements:
                    log_elements = root.findall(".//*[@time]")
                if not log_elements:
                    log_elements = root.findall(".//*[@date]")
                if not log_elements:
                    # If no obvious log entries, use direct children of root
                    log_elements = list(root)
                
                for element in log_elements:
                    log_entry = {}
                    # Add attributes
                    for key, value in element.attrib.items():
                        log_entry[key] = value
                    
                    # Add child elements
                    for child in element:
                        if child.text and child.text.strip():
                            log_entry[child.tag] = child.text.strip()
                        # Add child's attributes if any
                        if child.attrib:
                            log_entry[f"{child.tag}_attributes"] = child.attrib
                    
                    parsed_logs.append(log_entry)
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error parsing XML: {str(e)}")
                raise
        
        else:
            # Try to guess format based on content
            with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000)  # Read first 1000 chars to determine format
                f.seek(0)  # Reset file pointer
                
                if content.strip().startswith("{") or content.strip().startswith("["):
                    # Looks like JSON
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            parsed_logs = data
                        else:
                            parsed_logs = [data]
                    except json.JSONDecodeError:
                        # Try parsing line by line
                        f.seek(0)  # Reset file pointer
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                parsed_logs.append(json.loads(line))
                            except json.JSONDecodeError:
                                parsed_logs.append({"raw_message": line})
                
                elif "," in content and content.count("\n") > 0:
                    # Might be CSV
                    try:
                        df = pd.read_csv(self.input_file)
                        parsed_logs = df.to_dict(orient="records")
                    except:
                        # Fall back to line-by-line parsing
                        f.seek(0)  # Reset file pointer
                        for line in f:
                            parsed_logs.append({"raw_message": line.strip()})
                
                else:
                    # Default to line-by-line parsing
                    for line in f:
                        parsed_logs.append({"raw_message": line.strip()})
        
        return parsed_logs


def extract_security_events(parsed_logs: List[Dict[str, Any]], log_format: str) -> List[Dict[str, Any]]:
    """
    Extract security-relevant events from parsed logs.

    Args:
        parsed_logs: List of parsed log entries
        log_format: The format of the logs

    Returns:
        List of security-relevant events
    """
    security_events = []
    
    # Define security-relevant patterns based on log format
    security_patterns = {
        "windows": {
            "event_ids": [4624, 4625, 4634, 4648, 4672, 4688, 4720, 4722, 4724, 4728, 4732, 4756, 4776, 5140, 7045],
            "keywords": ["logon", "failed", "failure", "account", "password", "privilege", "admin", "firewall"]
        },
        "syslog": {
            "keywords": ["fail", "error", "denied", "unauthorized", "authentication", "permission", "sudo", "root", "admin"]
        },
        "apache": {
            "status_codes": [401, 403, 404, 500],
            "methods": ["PUT", "DELETE", "CONNECT"],
            "path_patterns": ["\.php", "wp-admin", "admin", "login", "shell", "cmd", "exec"]
        },
        "iis": {
            "status_codes": [401, 403, 404, 500],
            "methods": ["PUT", "DELETE", "CONNECT"],
            "path_patterns": ["\.asp", "\.aspx", "admin", "login", "shell", "cmd", "exec"]
        }
    }
    
    for log in parsed_logs:
        is_security_event = False
        
        if log_format == "windows":
            # Check Event ID
            event_id = None
            if "EventID" in log:
                event_id = log["EventID"]
            elif "Event_ID" in log:
                event_id = log["Event_ID"]
            elif "Id" in log:
                event_id = log["Id"]
            
            if event_id:
                try:
                    event_id = int(event_id)
                    if event_id in security_patterns["windows"]["event_ids"]:
                        is_security_event = True
                except (ValueError, TypeError):
                    pass
            
            # Check for security keywords in message
            if not is_security_event:
                message = ""
                if "Message" in log:
                    message = log["Message"]
                elif "Description" in log:
                    message = log["Description"]
                
                if message:
                    for keyword in security_patterns["windows"]["keywords"]:
                        if keyword.lower() in message.lower():
                            is_security_event = True
                            break
        
        elif log_format == "syslog":
            # Check for security keywords in message
            message = ""
            if "message" in log:
                message = log["message"]
            elif "raw_message" in log:
                message = log["raw_message"]
            
            if message:
                for keyword in security_patterns["syslog"]["keywords"]:
                    if keyword.lower() in message.lower():
                        is_security_event = True
                        break
        
        elif log_format in ["apache", "iis"]:
            # Check status code
            status = None
            if "status" in log:
                status = log["status"]
            elif "sc-status" in log:
                status = log["sc-status"]
            
            if status:
                try:
                    status = int(status)
                    if status in security_patterns[log_format]["status_codes"]:
                        is_security_event = True
                except (ValueError, TypeError):
                    pass
            
            # Check HTTP method
            method = None
            if "request" in log and isinstance(log["request"], dict) and "method" in log["request"]:
                method = log["request"]["method"]
            elif "cs-method" in log:
                method = log["cs-method"]
            
            if method and method in security_patterns[log_format]["methods"]:
                is_security_event = True
            
            # Check request path
            path = None
            if "request" in log and isinstance(log["request"], dict) and "path" in log["request"]:
                path = log["request"]["path"]
            elif "cs-uri-stem" in log:
                path = log["cs-uri-stem"]
            
            if path:
                for pattern in security_patterns[log_format]["path_patterns"]:
                    if re.search(pattern, path, re.IGNORECASE):
                        is_security_event = True
                        break
        
        # For custom format, check common security indicators
        else:
            # Convert log to string for keyword searching
            log_str = str(log).lower()
            for keyword in ["fail", "error", "denied", "unauthorized", "authentication", "permission", "admin"]:
                if keyword in log_str:
                    is_security_event = True
                    break
        
        if is_security_event:
            security_events.append(log)
    
    return security_events


def main():
    """
    Main function to parse and analyze log files.
    """
    parser = argparse.ArgumentParser(description="Parse and analyze security logs")
    parser.add_argument("--input", "-i", required=True, help="Input log file path")
    parser.add_argument("--format", "-f", required=True, 
                        choices=["windows", "syslog", "apache", "iis", "custom"],
                        help="Log format to parse")
    parser.add_argument("--output", "-o", default="parsed_logs.json", 
                        help="Output file path (default: parsed_logs.json)")
    parser.add_argument("--output-format", "-of", default="json", choices=["json", "csv"],
                        help="Output file format (default: json)")
    parser.add_argument("--security-only", "-s", action="store_true",
                        help="Extract only security-relevant events")
    parser.add_argument("--analyze", "-a", action="store_true",
                        help="Perform analysis on parsed logs")
    
    args = parser.parse_args()
    
    try:
        # Initialize log parser
        log_parser = LogParser(args.format, args.input, args.output)
        
        # Parse logs
        parsed_logs = log_parser.parse()
        
        # Extract security events if requested
        if args.security_only:
            print(f"{Fore.BLUE}[*] Extracting security-relevant events")
            parsed_logs = extract_security_events(parsed_logs, args.format)
            print(f"{Fore.GREEN}[+] Extracted {len(parsed_logs)} security events")
        
        # Perform analysis if requested
        if args.analyze:
            print(f"{Fore.BLUE}[*] Performing analysis on parsed logs")
            analysis = log_parser.analyze()
            
            # Print analysis results
            print(f"{Fore.GREEN}[+] Analysis Results:")
            print(f"  - Total Entries: {analysis['total_entries']}")
            
            if analysis['time_range']['start'] and analysis['time_range']['end']:
                print(f"  - Time Range: {analysis['time_range']['start']} to {analysis['time_range']['end']}")
            
            print("  - Top Event Types:")
            for event_id, count in sorted(analysis['event_counts'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    - {event_id}: {count}")
            
            print("  - Top Sources:")
            for source, count in sorted(analysis['source_counts'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    - {source}: {count}")
            
            # Save analysis results
            analysis_output = os.path.splitext(args.output)[0] + "_analysis.json"
            with open(analysis_output, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
            print(f"{Fore.GREEN}[+] Analysis results saved to {analysis_output}")
        
        # Save parsed logs
        log_parser.save_results(args.output_format)
        
        print(f"{Fore.GREEN}[+] Log parsing completed successfully")
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()