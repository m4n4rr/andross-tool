import json
import re
from collections import defaultdict


class StringEventProcessor:
    """Process structured string events from Frida hooks"""
    
    # Regex patterns for noise filtering
    NOISE_PATTERNS = [
        r'^/data/user/\d+/',  # Android user data paths
        r'^/system/',          # System paths
        r'^/proc/',            # Proc filesystem
        r'^/dev/',             # Device paths
        r'^/cache/',           # Cache paths
        r'^\s*$',              # Empty/whitespace only
    ]
    
    def __init__(self):
        """Initialize the event processor"""
        # Dictionary to store aggregated strings
        # Key: (type, value, caller)
        # Value: count
        self.aggregated = defaultdict(int)
        self.event_count = 0
    
    def is_noise(self, value):
        """Check if a string is noise that should be filtered
        
        Args:
            value: String value to check
            
        Returns:
            True if string matches noise patterns, False otherwise
        """
        if not value or len(value) == 0:
            return True
        
        for pattern in self.NOISE_PATTERNS:
            if re.match(pattern, value):
                return True
        
        return False
    
    def log_to_console(self, event_type, value, caller):
        """Log a finding to console in real-time
        
        Args:
            event_type: Type of event (bytes, chars, copy, etc.)
            value: The string value found
            caller: The calling class and method
        """
        # ANSI color codes
        CYAN = '\033[36m'
        YELLOW = '\033[33m'
        RESET = '\033[0m'
        
        print(f"{CYAN}[{event_type.upper():12}]{RESET} {value[:100]:<100} {YELLOW}| {caller}{RESET}")
    
    def process_event(self, event):
        """Process a single event from Frida
        
        Args:
            event: Dictionary with keys: type, value, caller
        """
        # Extract event data
        event_type = event.get('type', 'unknown')
        value = event.get('value', '')
        caller = event.get('caller', 'unknown.unknown')
        
        self.event_count += 1
        
        # Skip empty strings
        if not value or len(value) == 0:
            return
        
        # Skip noise
        if self.is_noise(value):
            return
        
        # Log to console in real-time (before aggregation)
        self.log_to_console(event_type, value, caller)
        
        # Create aggregation key
        key = (event_type, value, caller)
        
        # Increment counter
        self.aggregated[key] += 1
    
    def get_aggregated_data(self, app_name):
        """Get aggregated and deduplicated strings
        
        Args:
            app_name: Package name of the target application
            
        Returns:
            Dictionary with app name and strings list in desired format
        """
        strings = []
        
        for (event_type, value, caller), count in self.aggregated.items():
            strings.append({
                "type": event_type,
                "value": value,
                "caller": caller,
                "count": count
            })
        
        # Sort by count descending, then by value
        strings.sort(key=lambda x: (-x['count'], x['value']))
        
        return {
            "app": app_name,
            "strings": strings
        }
    
    def get_statistics(self):
        """Get processing statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_events": self.event_count,
            "unique_combinations": len(self.aggregated),
            "aggregated_count": sum(self.aggregated.values())
        }
