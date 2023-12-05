import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import math
import time
import threading
from tkinter.ttk import Frame, Combobox, Button
import logging
import speedtest

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP
from functools import partial


def process_arp_packet(packet, devices):
    if ARP in packet and packet[ARP].op in (1, 2):  # who-has or is-at
        devices.append(packet.sprintf("%ARP.psrc% - %Ether.src%"))


class TrafficGenerator:
    def __init__(self, app, analysis_tab):
        self.app = app
        self.analysis_tab = analysis_tab
        self.max_speed = 1000
        self.center_x = 150
        self.center_y = 150
        self.radius = 100
        self.initial_value = 0
        self.analysis_result = ""
        self.traffic_thread = None
        self.target_devices = []  # The list of devices
        self.speed_test = speedtest.Speedtest()

        # Create a logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        # Create a file handler and set the level to DEBUG
        file_handler = logging.FileHandler("traffic_generator.log")
        file_handler.setLevel(logging.DEBUG)

        # Create a formatter and add it to the file handler
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)

        # Add the file handler to the logger
        self.logger.addHandler(file_handler)

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

    def get_internet_speed(self):
        download_speed = self.speed_test.download()
        return download_speed / 1_000_000

    def discover_devices(self):
        # Clear the existing analysis results
        self.analysis_tab.clear_analysis()
        # Use ARP to discover devices on the network
        devices = []
        sniff(
            filter="arp",
            timeout=2,
            prn=partial(process_arp_packet, devices=devices),
            store=0,
        )
        self.analysis_tab.update_arp_messages(devices)  # Display ARP messages
        return devices

    def redirect_traffic(self):
        devices = self.discover_devices()
        self.target_devices = devices

        # Clear the existing items in the ListBox
        self.app.device_listbox.delete(0, tk.END)

        # Add the discovered devices to the ListBox
        for device in self.target_devices:
            self.app.device_listbox.insert(tk.END, device)

    def generate_traffic(self):
        try:
            if not self.target_devices:
                self.redirect_traffic()  # Discover devices and select a target device

            if self.target_devices:
                # Generate traffic directed to the target device
                packet_size = int(self.app.packet_size_entry.get())
                selected_protocol = self.app.protocol_var.get()
                rate = int(self.app.rate_entry.get())

                for i in range(1, 6):
                    internet_speed = self.get_internet_speed()
                    self.update_speedometer(internet_speed)
                    if self.app.send_to_all_var.get():
                        # Send traffic to all devices in the target list
                        for device in self.target_devices:
                            self.send_packet(
                                device.split(" - ")[1],
                                packet_size,
                                selected_protocol,
                                rate,
                            )
                    else:
                        # Send traffic to the selected device in the target list
                        selected_device = self.app.device_listbox.get(tk.ACTIVE)
                        if selected_device:
                            self.send_packet(
                                selected_device.split(" - ")[1],
                                packet_size,
                                selected_protocol,
                                rate,
                            )
                        else:
                            self.analysis_result += (
                                "No device selected. Traffic not sent.\n"
                            )
                            break

                    self.app.result_text.insert(tk.END, self.analysis_result)
                    self.app.result_text.see(tk.END)
                    self.app.analysis_tab.update_analysis(
                        self.analysis_result
                    )  # Update analysis tab
                    self.app.update()
                    time.sleep(1)

                    self.app.after(
                        100, self.update_speedometer, internet_speed
                    )  # Animate the speedometer needle
        except Exception as e:
            error_message = f"Traffic generation error: {str(e)}"
            self.analysis_tab.update_analysis(error_message)
            self.logger.error(error_message)

    def send_packet(self, destination, packet_size, selected_protocol, rate):
        packet = Ether() / IP(dst=destination) / TCP(dport=80)
        self.analysis_result += (
            f"Packet sent to {destination} "
            f"with size {packet_size} bytes, "
            f"protocol {selected_protocol}, "
            f"rate {rate} packets per second\n"
        )
        send(packet, verbose=0)

    def start_traffic_generation(self):
        self.analysis_result = ""
        self.result_text.delete(1.0, tk.END)  # Clear previous analysis results
        self.traffic_thread = threading.Thread(target=self.generate_traffic)
        self.traffic_thread.start()


class AnalysisTab:
    def __init__(self, app):
        self.app = app
        self.tab = ttk.Frame(self.app.app)
        self.app.notebook.add(self.tab, text="Analysis")

        self.analysis_text = ScrolledText(self.tab, wrap=tk.WORD)
        self.analysis_text.grid(
            row=0, column=0, padx=10, pady=10, columnspan=2, rowspan=2
        )

    def update_analysis(self, analysis_result):
        self.analysis_text.insert(tk.END, analysis_result)
        self.analysis_text.see(tk.END)

    def update_arp_messages(self, arp_messages):
        self.analysis_text.delete(1.0, tk.END)  # Clear previous ARP messages
        self.analysis_text.insert(tk.END, "\n".join(arp_messages) + "\n")
        self.analysis_text.see(tk.END)

    def clear_analysis(self):
        self.analysis_text.delete(1.0, tk.END)


class TrafficGeneratorApp:
    def __init__(self, app):
        self.app = app
        self.app.title("Network Traffic Generator")

        self.notebook = ttk.Notebook(app)
        self.analysis_tab = AnalysisTab(self)

        # Traffic Configuration Tab
        self.frame_config = ttk.Frame(self.notebook)
        self.notebook.add(self.frame_config, text="Traffic Configuration")

        row_counter = 0

        # Rest of the UI elements
        self.packet_size_label = ttk.Label(self.frame_config, text="Packet Size:")
        self.packet_size_label.grid(
            row=row_counter, column=0, padx=5, pady=5, sticky="w"
        )
        self.packet_size_entry = ttk.Entry(self.frame_config)
        self.packet_size_entry.grid(
            row=row_counter, column=1, padx=5, pady=5, sticky="w"
        )
        row_counter += 1

        self.protocol_label = ttk.Label(self.frame_config, text="Protocol:")
        self.protocol_label.grid(
            row=row_counter, column=0, padx=10, pady=10, sticky="w"
        )
        self.protocol_var = tk.StringVar(value="TCP")
        self.protocol_dropdown = ttk.Combobox(
            self.frame_config,
            textvariable=self.protocol_var,
            values=["TCP", "UDP", "ICMP"],
        )
        self.protocol_dropdown.grid(
            row=row_counter, column=1, padx=10, pady=10, sticky="w"
        )
        row_counter += 1

        self.rate_label = ttk.Label(self.frame_config, text="Rate:")
        self.rate_label.grid(row=row_counter, column=0, padx=5, pady=5, sticky="w")
        self.rate_entry = ttk.Entry(self.frame_config)
        self.rate_entry.grid(row=row_counter, column=1, padx=5, pady=5, sticky="w")
        row_counter += 1

        # Checkbutton to send traffic to all devices
        self.send_to_all_var = tk.BooleanVar()
        send_to_all_checkbutton = ttk.Checkbutton(
            self.frame_config, text="Send to All Devices", variable=self.send_to_all_var
        )
        send_to_all_checkbutton.grid(
            row=row_counter, column=1, padx=10, pady=10, sticky="w"
        )

        # ListBox to display discovered devices
        self.device_listbox = tk.Listbox(
            self.frame_config, selectmode=tk.SINGLE, exportselection=False
        )
        self.device_listbox.grid(row=row_counter, column=1, padx=5, pady=5, sticky="w")
        row_counter += 1

        self.result_text = ScrolledText(self.app, width=40, height=10, wrap=tk.WORD)
        self.result_text.grid(
            row=8, column=0, columnspan=2, padx=10, pady=10, sticky="w"
        )

        self.canvas_speedometer = tk.Canvas(self.app, width=300, height=300, bg="white")
        self.canvas_speedometer.grid(
            row=row_counter, column=2, rowspan=5, padx=10, pady=10, sticky="w"
        )

        self.traffic_generator = TrafficGenerator(self.app, self.analysis_tab)
        self.start_button = ttk.Button(
            self.app,
            text="Start Traffic Generation",
            command=self.traffic_generator.start_traffic_generation,
        )
        self.start_button.grid(
            row=row_counter, column=0, columnspan=2, padx=5, pady=5, sticky="w"
        )

        # Analysis Tab

        self.notebook.grid(row=0, column=0, sticky="nsew")  # Adjust as needed

        # Make the grid resizable
        self.app.grid_rowconfigure(0, weight=1)
        self.app.grid_columnconfigure(0, weight=1)

        self.traffic_generator = TrafficGenerator(self.app, self.analysis_tab)

    def toggle_theme(self):
        # Toggle between light and dark themes
        current_theme = self.app.tk_setPalette()
        if current_theme == "light":
            self.app.tk_setPalette("dark")
        else:
            self.app.tk_setPalette("light")


if __name__ == "__main__":
    app = tk.Tk()
    traffic_app = TrafficGeneratorApp(app)
    app.mainloop()
