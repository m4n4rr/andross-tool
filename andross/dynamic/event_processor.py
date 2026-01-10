import re
from collections import defaultdict


class StringEventProcessor:    
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
        self.aggregated = defaultdict(int)
        self.event_count = 0
    
    def is_noise(self, value):
        if not value or len(value) == 0:
            return True
        
        for pattern in self.NOISE_PATTERNS:
            if re.match(pattern, value):
                return True
        
        return False
    
    def log_to_console(self, event_type, value, caller):
        # ANSI color codes
        CYAN = '\033[36m'
        YELLOW = '\033[33m'
        RESET = '\033[0m'
        
        print(f"{CYAN}[{event_type.upper():12}]{RESET} {value[:100]:<100} {YELLOW}| {caller}{RESET}")
    
    def process_event(self, event):
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
        return {
            "total_events": self.event_count,
            "unique_combinations": len(self.aggregated),
            "aggregated_count": sum(self.aggregated.values())
        }
