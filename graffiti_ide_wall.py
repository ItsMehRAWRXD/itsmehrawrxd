#!/usr/bin/env python3
"""
Graffiti IDE Wall - Transparent panels floating over spray-painted code background
Inspired by old-school hack forums and IRC channels
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import math
import time
from typing import List, Dict, Tuple
import threading

class GraffitiCodeWall:
    """Spray-painted code wall background"""
    
    def __init__(self, canvas, width, height):
        self.canvas = canvas
        self.width = width
        self.height = height
        self.graffiti_items = []
        self.animation_running = False
        
        # Real code snippets for graffiti
        self.code_spray_patterns = [
            # Assembly graffiti
            ("mov eax, 0x12345678", "#00ff00", 12, "Consolas"),
            ("push ebp\nmov ebp, esp", "#ff0040", 10, "Courier New"),
            ("int 0x80\nret", "#ffff00", 14, "Consolas"),
            ("xor eax, eax\ninc eax", "#ff6600", 11, "Courier New"),
            
            # C++ memory hacking
            ("DWORD dwAddr = 0x401000;", "#00aaff", 10, "Consolas"),
            ("VirtualAlloc(NULL, 4096, MEM_COMMIT);", "#ff4444", 9, "Verdana"),
            ("HMODULE hMod = LoadLibraryA();", "#ffaa00", 11, "Consolas"),
            ("CONTEXT ctx;\nGetThreadContext();", "#ff66ff", 8, "Courier New"),
            
            # Python exploitation
            ("import ctypes\nkernel32 = ctypes.windll.kernel32", "#00ff41", 9, "Consolas"),
            ("def inject_shellcode(pid, shellcode):", "#ff8800", 12, "Verdana"),
            ("class MemoryScanner:", "#88ff00", 10, "Consolas"),
            ("def find_pattern(process, pattern):", "#ff0088", 11, "Courier New"),
            
            # JavaScript obfuscation
            ("var _0x1234=['\\x68\\x65\\x6c\\x6c\\x6f'];", "#00ffff", 8, "Consolas"),
            ("eval(atob('dmFyIGEgPSAiSGVsbG8iOw=='));", "#ff00ff", 9, "Verdana"),
            ("window['\\x65\\x76\\x61\\x6c']('alert');", "#ffff00", 10, "Consolas"),
            ("new Function('return ' + 'alert')();", "#00ff88", 11, "Courier New"),
            
            # PHP backdoors
            ("<?php eval($_POST['cmd']); ?>", "#ff4400", 13, "Consolas"),
            ("<?php system($_GET['x']); ?>", "#ff0044", 12, "Verdana"),
            ("<?php passthru($_REQUEST['c']); ?>", "#ff4400", 10, "Consolas"),
            
            # Batch scripts
            ("@echo off\nnet user admin /add", "#00ff44", 14, "Consolas"),
            ("reg add HKLM\\SOFTWARE /v Malware", "#ff4400", 9, "Courier New"),
            ("wmic process delete", "#ff0044", 15, "Consolas"),
            
            # Lua game hacks
            ("function hack()\n    SetHealth(999)\nend", "#ff8800", 10, "Consolas"),
            ("hook.Add(\"Think\", \"GodMode\");", "#00ff88", 12, "Verdana"),
            ("local target = GetClosestPlayer();", "#ff0088", 11, "Consolas"),
            
            # Ruby exploits
            ("require 'socket'\nTCPSocket.new();", "#ff4400", 9, "Consolas"),
            ("def exploit\n    payload = \"A\" * 1000\nend", "#00ff44", 13, "Verdana"),
            ("system(\"nc -l -p 4444 -e /bin/sh\")", "#ff0044", 8, "Courier New"),
            
            # Go shellcode injection
            ("package main\nimport \"syscall\"", "#ff8800", 10, "Consolas"),
            ("func injectShellcode(sc []byte) {", "#00ff88", 12, "Verdana"),
            ("syscall.Exec(\"/bin/sh\", []string{\"sh\"}, nil)", "#ff0088", 9, "Consolas"),
            
            # Classic hack signatures
            ("HACKED BY ELITE", "#ff0000", 20, "Arial Black"),
            ("PWNED", "#ff6600", 25, "Impact"),
            ("ROOTED", "#00ff00", 22, "Arial Black"),
            ("CRACKED", "#ff00ff", 18, "Impact"),
            ("EXPLOITED", "#00ffff", 16, "Arial Black"),
            ("0WN3D", "#ffff00", 24, "Impact"),
            ("1337", "#ff0066", 30, "Arial Black"),
            ("H4CK3R", "#00ff66", 20, "Impact"),
            
            # Forum signatures
            ("UnknownCheats.me", "#58a6ff", 14, "Verdana"),
            ("HackForums.net", "#ff6b35", 13, "Arial"),
            ("Game-Deception", "#00ff00", 12, "Consolas"),
            ("OGC Elite", "#ff6600", 16, "Arial Black"),
            ("iC JAPS", "#00aaff", 15, "Tahoma"),
            ("Death Elf", "#ff4444", 14, "Times New Roman"),
            
            # IRC commands
            ("/msg #hackers hello", "#ffff00", 11, "Consolas"),
            ("/join #exploits", "#00ffff", 12, "Courier New"),
            ("/kick user1337", "#ff00ff", 10, "Consolas"),
            ("/mode +o elite", "#00ff00", 13, "Courier New"),
            
            # Error messages (graffiti style)
            ("ACCESS DENIED", "#ff0000", 18, "Arial Black"),
            ("SEGMENTATION FAULT", "#ff4400", 16, "Consolas"),
            ("BUFFER OVERFLOW", "#ff0044", 15, "Courier New"),
            ("STACK SMASHING", "#ff4400", 14, "Consolas"),
            ("HEAP CORRUPTION", "#ff0044", 13, "Courier New"),
            
            # Assembly instructions scattered
            ("JMP", "#00ff00", 16, "Consolas"),
            ("CALL", "#ff6600", 15, "Consolas"),
            ("PUSH", "#00ff66", 14, "Consolas"),
            ("POP", "#ff0066", 13, "Consolas"),
            ("MOV", "#6600ff", 12, "Consolas"),
            ("XOR", "#ff6600", 11, "Consolas"),
            ("ADD", "#00ff00", 10, "Consolas"),
            ("SUB", "#ff0066", 9, "Consolas"),
            
            # Memory addresses
            ("0x401000", "#00aaff", 10, "Consolas"),
            ("0x7FFFFFFF", "#ffaa00", 9, "Consolas"),
            ("0xDEADBEEF", "#ff00aa", 11, "Consolas"),
            ("0xCAFEBABE", "#aaff00", 10, "Consolas"),
            ("0x1337BABE", "#ffaa00", 9, "Consolas"),
            
            # Classic virus signatures
            ("I LOVE YOU", "#ff0000", 12, "Arial"),
            ("MELISSA", "#ff4400", 14, "Arial Black"),
            ("ILOVEYOU", "#ff0044", 13, "Impact"),
            ("SASSER", "#ff4400", 15, "Arial Black"),
            
            # Network protocols
            ("TCP/IP", "#00ff00", 11, "Consolas"),
            ("UDP", "#ff6600", 12, "Consolas"),
            ("HTTP", "#00ff66", 10, "Consolas"),
            ("FTP", "#ff0066", 11, "Consolas"),
            ("SSH", "#6600ff", 9, "Consolas"),
            ("TELNET", "#ff6600", 10, "Consolas"),
            
            # File extensions
            (".exe", "#ff0000", 14, "Consolas"),
            (".dll", "#ff4400", 13, "Consolas"),
            (".sys", "#ff0044", 12, "Consolas"),
            (".bat", "#ff4400", 11, "Consolas"),
            (".com", "#ff0044", 10, "Consolas"),
            
            # Registry paths (spray painted)
            ("HKLM\\SOFTWARE", "#00aaff", 9, "Consolas"),
            ("HKEY_LOCAL_MACHINE", "#ffaa00", 7, "Courier New"),
            ("HKCR\\exefile", "#ff00aa", 10, "Consolas"),
            ("HKCU\\Software", "#aaff00", 8, "Courier New"),
        ]
        
        self.create_graffiti_wall()
    
    def create_graffiti_wall(self):
        """Create the spray-painted code wall"""
        # Clear existing graffiti
        self.canvas.delete("graffiti")
        
        # Create subtle brick wall texture
        self.create_brick_wall()
        
        # Add subtle graffiti (less prominent)
        self.spray_subtle_graffiti()
        
        # Add some animated elements
        self.start_animation()
    
    def create_brick_wall(self):
        """Create brick wall background"""
        brick_width = 80
        brick_height = 30
        brick_color = "#2d2d2d"
        mortar_color = "#1a1a1a"
        
        # Draw bricks
        for y in range(0, self.height, brick_height):
            offset = (brick_width // 2) if (y // brick_height) % 2 else 0
            for x in range(offset - brick_width, self.width + brick_width, brick_width):
                # Brick
                self.canvas.create_rectangle(
                    x, y, x + brick_width, y + brick_height,
                    fill=brick_color, outline=mortar_color, width=1,
                    tags="graffiti"
                )
        
        # Add some wall texture (random spots)
        for _ in range(50):
            x = random.randint(0, self.width)
            y = random.randint(0, self.height)
            size = random.randint(2, 8)
            color = random.choice(["#333333", "#444444", "#555555"])
            self.canvas.create_oval(
                x, y, x + size, y + size,
                fill=color, outline="", tags="graffiti"
            )
    
    def spray_subtle_graffiti(self):
        """Spray subtle, recessed graffiti on the wall"""
        num_graffiti = random.randint(8, 15)  # Much fewer graffiti
        
        for _ in range(num_graffiti):
            # Select random code snippet
            text, color, size, font = random.choice(self.code_spray_patterns)
            
            # Random position (more spread out)
            x = random.randint(50, self.width - 300)
            y = random.randint(50, self.height - 100)
            
            # Random rotation (less dramatic)
            angle = random.uniform(-8, 8)
            
            # Much more subtle colors and opacity
            alpha = random.uniform(0.15, 0.35)  # Much more transparent
            subtle_color = self.darken_color(color, 0.7)  # Darker, more muted
            
            # Create subtle graffiti text
            self.create_subtle_spray_text(x, y, text, subtle_color, size, font, angle, alpha)
    
    def spray_code_graffiti(self):
        """Original spray paint code snippets (kept for compatibility)"""
        num_graffiti = random.randint(20, 40)
        
        for _ in range(num_graffiti):
            # Select random code snippet
            text, color, size, font = random.choice(self.code_spray_patterns)
            
            # Random position
            x = random.randint(10, self.width - 200)
            y = random.randint(10, self.height - 50)
            
            # Random rotation
            angle = random.uniform(-15, 15)
            
            # Random opacity (spray paint effect)
            alpha = random.uniform(0.3, 0.8)
            
            # Create graffiti text with spray effect
            self.create_spray_text(x, y, text, color, size, font, angle, alpha)
    
    def create_spray_text(self, x, y, text, color, size, font, angle, alpha):
        """Create spray-painted text effect"""
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            if line.strip():
                # Add some spray effect (multiple slightly offset copies)
                for offset in range(3):
                    offset_x = x + random.randint(-2, 2)
                    offset_y = y + i * (size + 2) + random.randint(-1, 1)
                    
                    # Create text with spray paint effect
                    text_id = self.canvas.create_text(
                        offset_x, offset_y,
                        text=line,
                        fill=color,
                        font=(font, size),
                        angle=angle,
                        tags="graffiti"
                    )
                    
                    # Add some random "drips" below the text
                    if random.random() < 0.3:
                        for drip in range(random.randint(1, 3)):
                            drip_x = offset_x + random.randint(-5, 5)
                            drip_y = offset_y + (drip + 1) * 5
                            drip_size = random.randint(1, 3)
                            self.canvas.create_oval(
                                drip_x, drip_y, drip_x + drip_size, drip_y + drip_size,
                                fill=color, outline="", tags="graffiti"
                            )
    
    def start_animation(self):
        """Start animated graffiti effects"""
        if not self.animation_running:
            self.animation_running = True
            self.animate_graffiti()
    
    def animate_graffiti(self):
        """Animate graffiti elements"""
        if self.animation_running:
            # Make some graffiti "glow" or "flicker"
            for item in self.canvas.find_withtag("graffiti"):
                if random.random() < 0.01:  # 1% chance to flicker
                    current_fill = self.canvas.itemcget(item, "fill")
                    if current_fill:
                        # Slightly brighten the color
                        brightened = self.brighten_color(current_fill)
                        self.canvas.itemconfig(item, fill=brightened)
            
            # Schedule next animation frame
            self.canvas.after(100, self.animate_graffiti)
    
    def brighten_color(self, color):
        """Brighten a hex color"""
        try:
            # Remove # if present
            color = color.lstrip('#')
            # Convert to RGB
            rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
            # Brighten by 20%
            bright_rgb = tuple(min(255, int(c * 1.2)) for c in rgb)
            # Convert back to hex
            return f"#{bright_rgb[0]:02x}{bright_rgb[1]:02x}{bright_rgb[2]:02x}"
        except:
            return color
    
    def stop_animation(self):
        """Stop graffiti animation"""
        self.animation_running = False

class TransparentPanel:
    """Transparent floating panel"""
    
    def __init__(self, parent, title, x, y, width, height, graffiti_wall):
        self.parent = parent
        self.graffiti_wall = graffiti_wall
        
        # Create main frame
        self.frame = tk.Frame(parent, bg='black', relief='raised', bd=2)
        self.frame.place(x=x, y=y, width=width, height=height)
        
        # Create title bar
        self.title_frame = tk.Frame(self.frame, bg='#333333', height=25)
        self.title_frame.pack(fill='x')
        self.title_frame.pack_propagate(False)
        
        # Title label
        self.title_label = tk.Label(
            self.title_frame, 
            text=title, 
            bg='#333333', 
            fg='#00ff00',
            font=('Consolas', 10, 'bold')
        )
        self.title_label.pack(side='left', padx=5, pady=2)
        
        # Close button
        self.close_btn = tk.Button(
            self.title_frame,
            text='×',
            bg='#ff4444',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=3,
            command=self.close_panel
        )
        self.close_btn.pack(side='right', padx=2, pady=2)
        
        # Content area
        self.content_frame = tk.Frame(self.frame, bg='black')
        self.content_frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Make panel semi-transparent
        self.set_transparency(0.7)
        
        # Make draggable
        self.make_draggable()
        
        # Store reference for graffiti wall
        self.graffiti_wall.transparent_panels.append(self)
    
    def set_transparency(self, alpha):
        """Set panel transparency"""
        self.alpha = alpha
        # This is a simplified transparency - in a real implementation,
        # you'd use platform-specific methods for true transparency
    
    def make_draggable(self):
        """Make panel draggable"""
        self.title_frame.bind('<Button-1>', self.start_drag)
        self.title_frame.bind('<B1-Motion>', self.drag)
        self.title_label.bind('<Button-1>', self.start_drag)
        self.title_label.bind('<B1-Motion>', self.drag)
    
    def start_drag(self, event):
        """Start dragging the panel"""
        self.drag_start_x = event.x_root - self.frame.winfo_rootx()
        self.drag_start_y = event.y_root - self.frame.winfo_rooty()
    
    def drag(self, event):
        """Drag the panel"""
        x = event.x_root - self.drag_start_x
        y = event.y_root - self.drag_start_y
        self.frame.place(x=x, y=y)
    
    def close_panel(self):
        """Close the panel"""
        self.frame.destroy()
        if hasattr(self.graffiti_wall, 'transparent_panels'):
            self.graffiti_wall.transparent_panels.remove(self)

class GraffitiIDE:
    """Main Graffiti IDE with transparent panels over code wall"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔥 GRAFFITI IDE - HACK THE MATRIX 🔥")
        self.root.geometry("1400x900")
        self.root.configure(bg='black')
        
        # Make window fullscreen-capable
        self.root.state('zoomed')  # Windows fullscreen
        
        # Create main canvas for graffiti wall
        self.canvas = tk.Canvas(
            self.root, 
            bg='#1a1a1a',
            highlightthickness=0
        )
        self.canvas.pack(fill='both', expand=True)
        
        # Create graffiti wall
        self.graffiti_wall = GraffitiCodeWall(
            self.canvas, 
            self.root.winfo_screenwidth(), 
            self.root.winfo_screenheight()
        )
        self.graffiti_wall.transparent_panels = []
        
        # Create floating panels
        self.create_floating_panels()
        
        # Create main menu
        self.create_graffiti_menu()
        
        # Bind window events
        self.root.bind('<Configure>', self.on_window_resize)
        
        print("🔥 GRAFFITI IDE LOADED - HACK THE MATRIX! 🔥")
        print("🎨 Transparent panels floating over spray-painted code wall")
        print("💀 Real code graffiti from legendary hack forums")
        print("🚀 Ready to code like a true elite hacker!")
    
    def create_graffiti_menu(self):
        """Create graffiti-style menu bar"""
        menubar = tk.Menu(self.root, bg='#333333', fg='#00ff00', font=('Consolas', 9))
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='#222222', fg='#00ff00')
        menubar.add_cascade(label="📁 FILE", menu=file_menu)
        file_menu.add_command(label="🔥 New Hack", command=self.new_hack)
        file_menu.add_command(label="💀 Open Exploit", command=self.open_exploit)
        file_menu.add_command(label="💾 Save Shellcode", command=self.save_shellcode)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Exit Matrix", command=self.root.quit)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0, bg='#222222', fg='#00ff00')
        menubar.add_cascade(label="⚡ EDIT", menu=edit_menu)
        edit_menu.add_command(label="🔪 Cut Code", command=self.cut_code)
        edit_menu.add_command(label="📋 Copy Hack", command=self.copy_hack)
        edit_menu.add_command(label="📌 Paste Exploit", command=self.paste_exploit)
        edit_menu.add_separator()
        edit_menu.add_command(label="🔍 Find Pattern", command=self.find_pattern)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='#222222', fg='#00ff00')
        menubar.add_cascade(label="👁️ VIEW", menu=view_menu)
        view_menu.add_command(label="🎨 New Graffiti", command=self.new_graffiti)
        view_menu.add_command(label="🧹 Clear Wall", command=self.clear_wall)
        view_menu.add_command(label="🎭 Random Spray", command=self.random_spray)
        view_menu.add_separator()
        view_menu.add_command(label="🔧 Toggle Panels", command=self.toggle_panels)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg='#222222', fg='#00ff00')
        menubar.add_cascade(label="🔧 TOOLS", menu=tools_menu)
        tools_menu.add_command(label="💉 Memory Scanner", command=self.memory_scanner)
        tools_menu.add_command(label="🎯 Process Hacker", command=self.process_hacker)
        tools_menu.add_command(label="🌐 Network Sniffer", command=self.network_sniffer)
        tools_menu.add_command(label="🔓 Password Cracker", command=self.password_cracker)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='#222222', fg='#00ff00')
        menubar.add_cascade(label="❓ HELP", menu=help_menu)
        help_menu.add_command(label="📚 Hack Manual", command=self.hack_manual)
        help_menu.add_command(label="💀 Elite Status", command=self.elite_status)
        help_menu.add_command(label="🔥 About Graffiti IDE", command=self.about_graffiti)
    
    def create_floating_panels(self):
        """Create transparent floating panels"""
        # Code Editor Panel
        self.code_panel = TransparentPanel(
            self.root, "💀 CODE EDITOR", 50, 100, 600, 400, self.graffiti_wall
        )
        self.create_code_editor(self.code_panel.content_frame)
        
        # Memory Viewer Panel
        self.memory_panel = TransparentPanel(
            self.root, "🧠 MEMORY VIEWER", 700, 100, 400, 300, self.graffiti_wall
        )
        self.create_memory_viewer(self.memory_panel.content_frame)
        
        # Process List Panel
        self.process_panel = TransparentPanel(
            self.root, "⚡ PROCESS LIST", 1150, 100, 300, 250, self.graffiti_wall
        )
        self.create_process_list(self.process_panel.content_frame)
        
        # Console Panel
        self.console_panel = TransparentPanel(
            self.root, "🔥 HACK CONSOLE", 50, 550, 800, 200, self.graffiti_wall
        )
        self.create_hack_console(self.console_panel.content_frame)
        
        # Network Monitor Panel
        self.network_panel = TransparentPanel(
            self.root, "🌐 NETWORK MONITOR", 900, 450, 400, 200, self.graffiti_wall
        )
        self.create_network_monitor(self.network_panel.content_frame)
        
        # AI Copilot Panel
        self.ai_panel = TransparentPanel(
            self.root, "🤖 AI COPILOT", 1150, 400, 300, 300, self.graffiti_wall
        )
        self.create_ai_copilot(self.ai_panel.content_frame)
    
    def create_code_editor(self, parent):
        """Create code editor with graffiti styling"""
        # Line numbers
        line_frame = tk.Frame(parent, bg='black', width=50)
        line_frame.pack(side='left', fill='y')
        
        line_numbers = tk.Text(
            line_frame, 
            bg='#1a1a1a', 
            fg='#666666', 
            font=('Consolas', 10),
            width=4,
            state='disabled'
        )
        line_numbers.pack(fill='both', expand=True)
        
        # Main editor
        editor_frame = tk.Frame(parent, bg='black')
        editor_frame.pack(side='right', fill='both', expand=True)
        
        self.code_editor = tk.Text(
            editor_frame,
            bg='black',
            fg='#00ff00',
            font=('Consolas', 11),
            insertbackground='#00ff00',
            selectbackground='#333333',
            selectforeground='#ffffff'
        )
        self.code_editor.pack(fill='both', expand=True)
        
        # Add some default graffiti code
        default_code = """// 🔥 ELITE HACKER CODE 🔥
#include <windows.h>
#include <stdio.h>

int main() {
    printf("💀 HACKING THE MATRIX... 💀\\n");
    
    // Memory manipulation
    DWORD dwAddress = 0x401000;
    BYTE* pBytes = (BYTE*)dwAddress;
    *pBytes = 0x90; // NOP instruction
    
    // Process injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1337);
    if (hProcess) {
        printf("🎯 Process opened! Ready to inject...\\n");
        // Shellcode injection would go here
    }
    
    return 0;
}"""
        
        self.code_editor.insert('1.0', default_code)
    
    def create_memory_viewer(self, parent):
        """Create memory viewer with hex dump"""
        memory_text = tk.Text(
            parent,
            bg='black',
            fg='#00ff41',
            font=('Consolas', 9),
            height=15
        )
        memory_text.pack(fill='both', expand=True)
        
        # Add sample hex dump
        hex_dump = """0x401000: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
0x401010: 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00
0x401020: 8B 45 08 83 C0 01 C3 90 90 90 90 90 90 90 90 90
0x401030: 55 8B EC 83 EC 10 8B 45 08 89 45 FC 8B 45 FC C9
0x401040: C3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
0x401050: FF 25 00 20 40 00 90 90 90 90 90 90 90 90 90 90
0x401060: 68 00 20 40 00 E8 00 00 00 00 83 C4 04 C3 90 90
0x401070: 8B 45 08 3D E8 03 00 00 75 0A B8 E7 03 00 00 EB
0x401080: 08 8B 45 08 40 89 45 08 8B 45 08 C3 90 90 90 90"""
        
        memory_text.insert('1.0', hex_dump)
        memory_text.config(state='disabled')
    
    def create_process_list(self, parent):
        """Create process list viewer"""
        process_list = tk.Listbox(
            parent,
            bg='black',
            fg='#ff6600',
            font=('Consolas', 9),
            selectbackground='#333333'
        )
        process_list.pack(fill='both', expand=True)
        
        # Add sample processes
        processes = [
            "explorer.exe (PID: 1234)",
            "notepad.exe (PID: 5678)",
            "chrome.exe (PID: 9012)",
            "steam.exe (PID: 3456)",
            "csgo.exe (PID: 7890)",
            "discord.exe (PID: 2468)",
            "spotify.exe (PID: 1357)",
            "vlc.exe (PID: 9753)"
        ]
        
        for process in processes:
            process_list.insert(tk.END, process)
    
    def create_hack_console(self, parent):
        """Create hack console with graffiti styling"""
        console = tk.Text(
            parent,
            bg='black',
            fg='#00ff00',
            font=('Consolas', 10),
            height=8
        )
        console.pack(fill='both', expand=True)
        
        # Add sample console output
        console_output = """🔥 GRAFFITI IDE CONSOLE 🔥
💀 Initializing hack modules...
🎯 Memory scanner loaded
🌐 Network sniffer active
🔓 Password cracker ready
⚡ Process hacker online
🧠 AI copilot connected
🎨 Graffiti wall rendered
💉 Shellcode injector primed
🔥 READY TO HACK THE MATRIX! 🔥

> """
        
        console.insert('1.0', console_output)
    
    def create_network_monitor(self, parent):
        """Create network monitor"""
        network_text = tk.Text(
            parent,
            bg='black',
            fg='#ff0040',
            font=('Consolas', 8),
            height=10
        )
        network_text.pack(fill='both', expand=True)
        
        # Add sample network traffic
        network_data = """🌐 NETWORK TRAFFIC MONITOR 🌐
192.168.1.100 -> 8.8.8.8:53 (DNS)
192.168.1.100 -> 142.250.191.14:443 (HTTPS)
192.168.1.100 -> 151.101.65.140:443 (HTTPS)
192.168.1.100 -> 52.84.145.78:443 (HTTPS)
192.168.1.100 -> 31.13.77.35:443 (HTTPS)
192.168.1.100 -> 104.16.85.20:443 (HTTPS)
192.168.1.100 -> 157.240.3.35:443 (HTTPS)
192.168.1.100 -> 172.217.164.110:443 (HTTPS)"""
        
        network_text.insert('1.0', network_data)
        network_text.config(state='disabled')
    
    def create_ai_copilot(self, parent):
        """Create AI copilot panel"""
        ai_text = tk.Text(
            parent,
            bg='black',
            fg='#ffaa00',
            font=('Consolas', 9),
            height=12
        )
        ai_text.pack(fill='both', expand=True)
        
        # Add AI copilot interface
        ai_interface = """🤖 AI COPILOT ACTIVE 🤖
Model: CodeLlama-7B
Status: ✅ Connected

💡 SUGGESTIONS:
- Try: VirtualAlloc for memory
- Consider: Process injection
- Use: XOR encryption
- Check: Buffer overflow

🔥 PROMPT:
Write a keylogger in C++

⚡ RESPONSE:
#include <windows.h>
#include <iostream>

HHOOK hHook = NULL;
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Keylogger code here
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}"""
        
        ai_text.insert('1.0', ai_interface)
        ai_text.config(state='disabled')
    
    def on_window_resize(self, event):
        """Handle window resize"""
        if event.widget == self.root:
            self.graffiti_wall.width = event.width
            self.graffiti_wall.height = event.height
            self.graffiti_wall.create_graffiti_wall()
    
    # Menu command methods
    def new_hack(self):
        messagebox.showinfo("🔥 NEW HACK", "💀 Creating new elite hack project...")
    
    def open_exploit(self):
        messagebox.showinfo("💀 OPEN EXPLOIT", "🎯 Loading exploit from database...")
    
    def save_shellcode(self):
        messagebox.showinfo("💾 SAVE SHELLCODE", "💉 Shellcode saved to matrix...")
    
    def cut_code(self):
        messagebox.showinfo("🔪 CUT CODE", "⚡ Code cut and ready for injection...")
    
    def copy_hack(self):
        messagebox.showinfo("📋 COPY HACK", "🎯 Hack copied to clipboard...")
    
    def paste_exploit(self):
        messagebox.showinfo("📌 PASTE EXPLOIT", "💀 Exploit pasted and ready...")
    
    def find_pattern(self):
        messagebox.showinfo("🔍 FIND PATTERN", "🧠 Scanning memory for patterns...")
    
    def new_graffiti(self):
        self.graffiti_wall.spray_code_graffiti()
        messagebox.showinfo("🎨 NEW GRAFFITI", "🔥 Fresh code graffiti sprayed!")
    
    def clear_wall(self):
        self.graffiti_wall.create_graffiti_wall()
        messagebox.showinfo("🧹 CLEAR WALL", "💀 Wall cleared and re-sprayed!")
    
    def random_spray(self):
        self.graffiti_wall.spray_code_graffiti()
        messagebox.showinfo("🎭 RANDOM SPRAY", "🎨 Random code graffiti applied!")
    
    def toggle_panels(self):
        messagebox.showinfo("🔧 TOGGLE PANELS", "⚡ Panel visibility toggled!")
    
    def memory_scanner(self):
        messagebox.showinfo("💉 MEMORY SCANNER", "🧠 Scanning process memory...")
    
    def process_hacker(self):
        messagebox.showinfo("🎯 PROCESS HACKER", "⚡ Analyzing running processes...")
    
    def network_sniffer(self):
        messagebox.showinfo("🌐 NETWORK SNIFFER", "🔍 Monitoring network traffic...")
    
    def password_cracker(self):
        messagebox.showinfo("🔓 PASSWORD CRACKER", "💀 Attempting password brute force...")
    
    def hack_manual(self):
        messagebox.showinfo("📚 HACK MANUAL", "🔥 Elite hacker documentation loaded...")
    
    def elite_status(self):
        messagebox.showinfo("💀 ELITE STATUS", "🎯 Status: ELITE HACKER\n🔥 Level: 1337\n💀 Reputation: LEGENDARY")
    
    def about_graffiti(self):
        messagebox.showinfo("🔥 ABOUT GRAFFITI IDE", 
                          "🔥 GRAFFITI IDE 🔥\n"
                          "💀 The ultimate hacker's IDE\n"
                          "🎨 Transparent panels over code graffiti\n"
                          "🚀 Inspired by legendary hack forums\n"
                          "⚡ Built for elite hackers only\n"
                          "🎯 Version: 1.0.0 ALPHA")

def main():
    """Launch the Graffiti IDE"""
    print("🔥 Initializing GRAFFITI IDE...")
    print("💀 Loading spray-painted code wall...")
    print("🎨 Creating transparent panels...")
    print("🚀 Connecting to the matrix...")
    
    app = GraffitiIDE()
    app.root.mainloop()

if __name__ == "__main__":
    main()
