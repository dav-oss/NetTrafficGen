import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import math
import time
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from ttkbootstrap import Style


class TrafficGenerator:
    def __init__(self, app):
        self.app = app
        self.max_speed = 1000
        self.center_x = 150
        self.center_y = 150
        self.radius = 100
        self.initial_value = 0
        self.analysis_result = ""
        self.traffic_thread = None

    def update_speedometer(self, value):
        angle = (value / self.max_speed) * 180
        self.app.canvas_speedometer.delete("needle")
        self.app.canvas_speedometer.create_line(
            self.center_x,
            self.center_y,
            self.center_x + self.radius * math.sin(math.radians(angle)),
            self.center_y - self.radius * math.cos(math.radians(angle)),
            width=3,
            fill="red",
            tags="needle",
        )

    def generate_traffic(self):
        packet_size = int(self.app.packet_size_entry.get())
        selected_protocol = self.app.protocol_var.get()
        rate = int(self.app.rate_entry.get())
        destination = self.app.destination_entry.get()

        self.analysis_result = f"Traffic Analysis for Destination: {destination}\n"
        self.analysis_result += f"Packet Size: {packet_size} bytes, Protocol: {selected_protocol}, Rate: {rate} packets/second\n"

        for i in range(1, 6):
            self.update_speedometer(i * 200)
            packet = Ether() / IP(dst=destination) / TCP(dport=80)
            self.analysis_result += f"Packet {i} sent to {destination}\n"
            self.app.result_text.insert(tk.END, self.analysis_result)
            self.app.result_text.see(tk.END)
            self.app.update()
            send(packet, verbose=0)  # Send the packet using Scapy
            time.sleep(1)

            self.app.after(
                1000, self.update_speedometer, i * 200
            )  # Animate the speedometer needle

    def start_traffic_generation(self):
        self.analysis_result = ""
        self.app.result_text.delete(1.0, tk.END)  # Clear previous analysis results
        self.traffic_thread = threading.Thread(target=self.generate_traffic)
        self.traffic_thread.start()


class TrafficGeneratorApp:
    def __init__(self, app):
        self.app = app
        self.app.title("Network Traffic Generator")
        self.style = Style(theme="light")  # Set the initial theme to "light"

        # Create a frame using the ttkbootstrap style
        self.frame = self.style.Frame(self.app, text="Traffic Configuration")
        self.frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Packet Size
        packet_size_label = ttk.Label(self.frame, text="Packet Size:")
        packet_size_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.packet_size_entry = ttk.Entry(self.frame)
        self.packet_size_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Protocol
        protocol_label = ttk.Label(self.frame, text="Protocol:")
        protocol_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        common_protocols = ["TCP", "UDP", "HTTP", "FTP", "VoIP", "Custom"]
        self.protocol_var = tk.StringVar()
        protocol_dropdown = self.style.Combobox(
            self.frame, textvariable=self.protocol_var, values=common_protocols
        )
        protocol_dropdown.set("TCP")
        protocol_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        custom_protocol_label = ttk.Label(self.frame, text="Custom Protocol:")
        custom_protocol_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        custom_protocol_entry = ttk.Entry(self.frame, state=tk.DISABLED)
        custom_protocol_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # Rate
        rate_label = ttk.Label(self.frame, text="Rate:")
        rate_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.rate_entry = ttk.Entry(self.frame)
        self.rate_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # Destination
        destination_label = ttk.Label(self.frame, text="Destination:")
        destination_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.destination_entry = ttk.Entry(self.frame)
        self.destination_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        # Result Text
        self.result_text = ScrolledText(self.app, width=40, height=10)
        self.result_text.grid(
            row=1, column=0, columnspan=2, padx=10, pady=10, sticky="w"
        )

        # Speedometer
        self.radius = 100
        self.center_x = 300
        self.center_y = 150
        self.canvas_speedometer = self.style.Canvas(self.app, width=300, height=300)
        self.canvas_speedometer.grid(
            row=0, column=2, rowspan=5, padx=10, pady=10, sticky="e"
        )

        # Start Button
        start_button = self.style.Button(
            self.app,
            text="Start Traffic Generation",
            command=self.traffic_generator.start_traffic_generation,
        )
        start_button.grid(row=6, column=0, padx=10, pady=10, sticky="w")

        # Theme Toggle Button
        self.theme_toggle_button = self.style.Button(
            self.app, text="Toggle Theme", command=self.toggle_theme
        )
        self.theme_toggle_button.grid(row=6, column=1, padx=10, pady=10, sticky="e")

        self.traffic_generator = TrafficGenerator(self)

        # Initialize the speedometer with an initial value
        self.traffic_generator.update_speedometer(self.traffic_generator.initial_value)

    def toggle_theme(self):
        # Toggle between light and dark themes
        current_theme = self.style.get_theme()
        if current_theme == "litera":
            self.style.set_theme("darkly")
        else:
            self.style.set_theme("light")


if __name__ == "__main__":
    app = tk.Tk()
    traffic_app = TrafficGeneratorApp(app)
    app.mainloop()
