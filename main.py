#!/usr/bin/env python3
"""
ELF Symbol Search GUI Application
Allows loading ELF files and searching for symbols using regex patterns
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import os
import configparser
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False


class SearchMode(Enum):
    """Enumeration for search modes"""
    FUZZY = "fuzzy"
    WILDCARD = "wildcard"
    REGEX = "regex"


@dataclass
class SymbolInfo:
    """Data class to represent symbol information"""
    name: str
    address: int
    size: int
    type: str
    bind: str
    section: int
    
    @property
    def is_function(self) -> bool:
        return self.type in ['STT_FUNC']
    
    @property
    def is_variable(self) -> bool:
        return self.type in ['STT_OBJECT', 'STT_COMMON', 'STT_TLS']


class ConfigManager:
    """Handles configuration file operations"""
    
    def __init__(self, config_file: str = "config.ini"):
        self.config_file = config_file
    
    def save_file_path(self, file_path: str) -> None:
        """Save current file path to config file"""
        config = configparser.ConfigParser()
        config.add_section('FileSettings')
        config.set('FileSettings', 'last_file_path', file_path)
        
        try:
            with open(self.config_file, 'w') as configfile:
                config.write(configfile)
        except Exception as e:
            print(f"Error saving config: {str(e)}")
    
    def load_file_path(self) -> Optional[str]:
        """Load last file path from config file"""
        if not os.path.exists(self.config_file):
            return None
        
        config = configparser.ConfigParser()
        try:
            config.read(self.config_file)
            if config.has_option('FileSettings', 'last_file_path'):
                last_path = config.get('FileSettings', 'last_file_path')
                return last_path if os.path.exists(last_path) else None
        except Exception as e:
            print(f"Error loading config: {str(e)}")
        
        return None


class ELFParser:
    """Handles ELF file parsing and symbol extraction"""
    
    @staticmethod
    def extract_symbols(file_path: str) -> List[SymbolInfo]:
        """Extract symbols from ELF file"""
        symbols = []
        
        with open(file_path, 'rb') as f:
            elffile = ELFFile(f)
            
            for section in elffile.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        if not symbol.name:
                            continue
                        
                        symbol_info = SymbolInfo(
                            name=symbol.name,
                            address=symbol['st_value'],
                            size=symbol['st_size'],
                            type=symbol['st_info']['type'],
                            bind=symbol['st_info']['bind'],
                            section=symbol['st_shndx']
                        )
                        symbols.append(symbol_info)
        
        # Sort symbols by address
        symbols.sort(key=lambda x: x.address)
        return symbols


class SymbolSearchEngine:
    """Handles symbol searching with different modes"""
    
    @staticmethod
    def fuzzy_match(pattern: str, text: str) -> bool:
        """Fuzzy matching - checks if all characters in pattern appear in text in order"""
        if not pattern:
            return True
        
        pattern = pattern.lower()
        text = text.lower()
        
        pattern_idx = 0
        for char in text:
            if pattern_idx < len(pattern) and char == pattern[pattern_idx]:
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return True
        
        return pattern_idx == len(pattern)
    
    @staticmethod
    def convert_wildcards_to_regex(pattern: str) -> str:
        """Convert simple wildcards (*) to regex patterns (.*)"""
        if not pattern:
            return pattern
        
        # Escape special regex characters except *
        placeholder = "___WILDCARD___"
        pattern = pattern.replace("*", placeholder)
        pattern = re.escape(pattern)
        pattern = pattern.replace(placeholder, ".*")
        
        return pattern
    
    @classmethod
    def create_search_function(cls, pattern: str, mode: SearchMode) -> Optional[Callable[[str], bool]]:
        """Create a search function based on the mode"""
        if not pattern:
            return None
        
        if mode == SearchMode.FUZZY:
            return lambda symbol_name: cls.fuzzy_match(pattern, symbol_name)
        elif mode == SearchMode.WILDCARD:
            regex_pattern = cls.convert_wildcards_to_regex(pattern)
            regex = re.compile(regex_pattern, re.IGNORECASE)
            return lambda symbol_name: regex.search(symbol_name) is not None
        elif mode == SearchMode.REGEX:
            regex = re.compile(pattern, re.IGNORECASE)
            return lambda symbol_name: regex.search(symbol_name) is not None
        
        return None
    
    @classmethod
    def filter_symbols(cls, symbols: List[SymbolInfo], pattern: str, 
                      mode: SearchMode, show_functions: bool, show_variables: bool) -> List[SymbolInfo]:
        """Filter symbols based on search criteria"""
        search_function = cls.create_search_function(pattern, mode)
        
        matching_symbols = []
        for symbol in symbols:
            # Apply search filter
            if search_function is not None and not search_function(symbol.name):
                continue
            
            # Apply type filter if any checkbox is checked
            if show_functions or show_variables:
                if not ((show_functions and symbol.is_function) or 
                       (show_variables and symbol.is_variable)):
                    continue
            
            matching_symbols.append(symbol)
        
        return matching_symbols


class ELFSymbolSearchGUI:
    """Main GUI application class"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config_manager = ConfigManager()
        self.search_engine = SymbolSearchEngine()
        
        # Application state
        self.current_elf_file: Optional[str] = None
        self.symbols: List[SymbolInfo] = []
        self.search_timer: Optional[str] = None
        
        # Initialize GUI
        self._setup_window()
        self._setup_ui()
        self._check_dependencies()
        self._load_last_file()
    
    def _setup_window(self) -> None:
        """Setup main window properties"""
        self.root.title("ELF Symbol Search")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _setup_ui(self) -> None:
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Setup UI sections
        self._setup_file_section(main_frame)
        self._setup_search_section(main_frame)
        self._setup_filter_section(main_frame)
        self._setup_results_section(main_frame)
        self._setup_status_bar(main_frame)
        
        # Initially disable search functionality
        self._toggle_search_controls(False)
    
    def _setup_file_section(self, parent: ttk.Frame) -> None:
        """Setup file selection section"""
        ttk.Label(parent, text="ELF File:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        file_frame = ttk.Frame(parent)
        file_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 5))
        file_frame.columnconfigure(0, weight=1)
        
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, state="readonly")
        self.file_path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.load_button = ttk.Button(file_frame, text="Load ELF File", command=self._load_elf_file)
        self.load_button.grid(row=0, column=1)
    
    def _setup_search_section(self, parent: ttk.Frame) -> None:
        """Setup search pattern section"""
        ttk.Label(parent, text="Search Pattern:").grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        
        search_frame = ttk.Frame(parent)
        search_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(10, 5))
        search_frame.columnconfigure(0, weight=1)
        
        self.search_pattern_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_pattern_var)
        self.search_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.search_entry.bind('<KeyRelease>', self._on_search_change)
        
        # Search mode selection
        self.search_mode_var = tk.StringVar(value=SearchMode.FUZZY.value)
        mode_frame = ttk.Frame(search_frame)
        mode_frame.grid(row=0, column=1, padx=(5, 0))
        
        ttk.Radiobutton(mode_frame, text="Fuzzy", variable=self.search_mode_var, 
                       value=SearchMode.FUZZY.value, command=self._on_search_mode_change).grid(row=0, column=0, padx=(0, 5))
        ttk.Radiobutton(mode_frame, text="Wildcard", variable=self.search_mode_var, 
                       value=SearchMode.WILDCARD.value, command=self._on_search_mode_change).grid(row=0, column=1, padx=(0, 5))
        ttk.Radiobutton(mode_frame, text="Regex", variable=self.search_mode_var, 
                       value=SearchMode.REGEX.value, command=self._on_search_mode_change).grid(row=0, column=2)
    
    def _setup_filter_section(self, parent: ttk.Frame) -> None:
        """Setup filter options section"""
        ttk.Label(parent, text="Filter by Type:").grid(row=2, column=0, sticky=tk.W, pady=(10, 5))
        
        filter_frame = ttk.Frame(parent)
        filter_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(10, 5))
        
        self.show_functions_var = tk.BooleanVar(value=False)
        self.show_variables_var = tk.BooleanVar(value=False)
        
        self.functions_checkbox = ttk.Checkbutton(
            filter_frame, text="Functions", variable=self.show_functions_var,
            command=self._on_filter_change
        )
        self.functions_checkbox.grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        
        self.variables_checkbox = ttk.Checkbutton(
            filter_frame, text="Variables", variable=self.show_variables_var,
            command=self._on_filter_change
        )
        self.variables_checkbox.grid(row=0, column=1, sticky=tk.W)
    
    def _setup_results_section(self, parent: ttk.Frame) -> None:
        """Setup results display section"""
        ttk.Label(parent, text="Search Results:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        
        self.results_text = scrolledtext.ScrolledText(
            parent, height=20, width=80, font=('Courier', 10), wrap=tk.NONE
        )
        self.results_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
    
    def _setup_status_bar(self, parent: ttk.Frame) -> None:
        """Setup status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Load an ELF file to begin")
        status_bar = ttk.Label(parent, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
    
    def _check_dependencies(self) -> None:
        """Check if required dependencies are available"""
        if not ELFTOOLS_AVAILABLE:
            messagebox.showerror(
                "Missing Dependency", 
                "pyelftools library is required but not installed.\n"
                "Install it with: pip install pyelftools"
            )
    
    def _load_last_file(self) -> None:
        """Load the last used file if available"""
        last_path = self.config_manager.load_file_path()
        if last_path:
            self._load_file(last_path)
    
    def _toggle_search_controls(self, enabled: bool) -> None:
        """Enable or disable search controls"""
        state = "normal" if enabled else "disabled"
        self.search_entry.config(state=state)
        self.functions_checkbox.config(state=state)
        self.variables_checkbox.config(state=state)
    
    def _load_elf_file(self) -> None:
        """Load an ELF file through file dialog"""
        if not ELFTOOLS_AVAILABLE:
            messagebox.showerror("Error", "pyelftools library is not available")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select ELF File",
            filetypes=[
                ("ELF files", "*.elf *.so *.o"),
                ("Executable files", "*"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self._load_file(file_path)
    
    def _load_file(self, file_path: str) -> None:
        """Load and parse an ELF file"""
        try:
            self.status_var.set("Loading ELF file...")
            self.root.update()
            
            # Extract symbols
            self.symbols = ELFParser.extract_symbols(file_path)
            
            # Update UI state
            self.current_elf_file = file_path
            self.file_path_var.set(file_path)
            self._toggle_search_controls(True)
            
            # Display initial results
            self._display_file_info(file_path)
            self._display_symbols(self.symbols)
            
            self.status_var.set(f"Loaded {len(self.symbols)} symbols from {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load ELF file:\n{str(e)}")
            self.status_var.set("Error loading file")
    
    def _display_file_info(self, file_path: str) -> None:
        """Display file information in results area"""
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Loaded ELF file: {os.path.basename(file_path)}\n")
        self.results_text.insert(tk.END, f"Total symbols found: {len(self.symbols)}\n")
        self.results_text.insert(tk.END, "=" * 60 + "\n\n")
    
    def _display_symbols(self, symbols: List[SymbolInfo]) -> None:
        """Display symbols in the results text area"""
        if not symbols:
            self.results_text.insert(tk.END, "No symbols found.\n")
            return
        
        # Header with 32-bit address column
        header = f"{'Address':<10} {'Size':<10} {'Type':<10} {'Bind':<10} {'Symbol Name'}\n"
        self.results_text.insert(tk.END, header)
        self.results_text.insert(tk.END, "-" * 80 + "\n")
        
        # Symbol entries with 32-bit address formatting
        for symbol in symbols:
            # Format address as 32-bit (8 hex digits) instead of 64-bit
            address_str = f"0x{symbol.address:08x}" if symbol.address != 0 else "0x0"
            size_str = str(symbol.size) if symbol.size != 0 else "0"
            
            line = f"{address_str:<10} {size_str:<10} {symbol.type:<10} {symbol.bind:<10} {symbol.name}\n"
            self.results_text.insert(tk.END, line)
    
    def _search_symbols(self) -> None:
        """Search symbols using current criteria"""
        if not self.symbols:
            return
        
        pattern = self.search_pattern_var.get().strip()
        show_functions = self.show_functions_var.get()
        show_variables = self.show_variables_var.get()
        search_mode = SearchMode(self.search_mode_var.get())
        
        try:
            matching_symbols = self.search_engine.filter_symbols(
                self.symbols, pattern, search_mode, show_functions, show_variables
            )
            
            # Display results
            self._display_search_results(pattern, search_mode, show_functions, show_variables, matching_symbols)
            
        except re.error as e:
            messagebox.showerror("Search Error", f"Invalid search pattern:\n{str(e)}")
            self.status_var.set("Invalid search pattern")
    
    def _display_search_results(self, pattern: str, search_mode: SearchMode, 
                               show_functions: bool, show_variables: bool, 
                               matching_symbols: List[SymbolInfo]) -> None:
        """Display search results with criteria information"""
        self.results_text.delete(1.0, tk.END)
        
        # Show search criteria
        filter_info = []
        if show_functions:
            filter_info.append("Functions")
        if show_variables:
            filter_info.append("Variables")
        
        if pattern:
            mode_name = search_mode.value.capitalize()
            self.results_text.insert(tk.END, f"Search pattern: {pattern} ({mode_name} mode)\n")
        
        if filter_info:
            self.results_text.insert(tk.END, f"Filtered by type: {', '.join(filter_info)}\n")
        else:
            self.results_text.insert(tk.END, "Showing all symbol types\n")
        
        self.results_text.insert(tk.END, f"Matching symbols: {len(matching_symbols)}\n")
        self.results_text.insert(tk.END, "=" * 60 + "\n\n")
        
        self._display_symbols(matching_symbols)
        
        # Update status
        mode_name = search_mode.value.capitalize()
        if filter_info:
            self.status_var.set(f"Found {len(matching_symbols)} symbols ({mode_name}, {', '.join(filter_info)})")
        else:
            self.status_var.set(f"Found {len(matching_symbols)} symbols ({mode_name} mode)")
    
    def _on_search_change(self, event: tk.Event) -> None:
        """Handle search pattern change with debouncing"""
        if self.search_timer:
            self.root.after_cancel(self.search_timer)
        
        self.search_timer = self.root.after(300, self._search_symbols)
    
    def _on_search_mode_change(self) -> None:
        """Handle search mode change"""
        self._search_symbols()
    
    def _on_filter_change(self) -> None:
        """Handle filter checkbox changes"""
        self._search_symbols()
    
    def _on_closing(self) -> None:
        """Handle window close event"""
        if self.current_elf_file:
            self.config_manager.save_file_path(self.current_elf_file)
        self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = ELFSymbolSearchGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()