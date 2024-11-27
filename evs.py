import tkinter as tk
from tkinter import messagebox

class ElectricVehicleSystem:
    def __init__(self, battery_capacity, battery_health, current_charge):
        self.battery_capacity = battery_capacity  # kWh
        self.battery_health = battery_health      # Percentage (0-100)
        self.current_charge = current_charge      # Current charge level in kWh

    # Method to calculate the remaining range of the EV
    def calculate_range(self):
        energy_per_mile = 0.2  # Assume the vehicle consumes 0.2 kWh per mile
        effective_capacity = self.battery_capacity * (self.battery_health / 100)
        remaining_range = self.current_charge / energy_per_mile
        return round(remaining_range, 2)

    # Method to simulate charging the battery
    def charge_battery(self, amount):
        if self.current_charge + amount <= self.battery_capacity:
            self.current_charge += amount
        else:
            self.current_charge = self.battery_capacity

    # Method to simulate driving, which reduces the charge
    def drive(self, miles):
        energy_needed = miles * 0.2  # 0.2 kWh per mile
        if energy_needed <= self.current_charge:
            self.current_charge -= energy_needed
            return True
        else:
            return False

# Create the main GUI application
class EVSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Electric Vehicle System (EVS)")

        # Initialize the EV system with a 75 kWh battery, 90% battery health, and 50 kWh current charge
        self.evs = ElectricVehicleSystem(battery_capacity=75, battery_health=90, current_charge=50)

        # Create and display the current battery status
        self.status_label = tk.Label(root, text=self.get_battery_status(), font=("Arial", 12))
        self.status_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Entry field for charging the battery
        tk.Label(root, text="Charge Amount (kWh):").grid(row=1, column=0)
        self.charge_entry = tk.Entry(root)
        self.charge_entry.grid(row=1, column=1)

        # Charge button
        self.charge_button = tk.Button(root, text="Charge Battery", command=self.charge_battery)
        self.charge_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Entry field for driving miles
        tk.Label(root, text="Drive Distance (miles):").grid(row=3, column=0)
        self.drive_entry = tk.Entry(root)
        self.drive_entry.grid(row=3, column=1)

        # Drive button
        self.drive_button = tk.Button(root, text="Drive", command=self.drive)
        self.drive_button.grid(row=4, column=0, columnspan=2, pady=5)

    # Method to update the battery status label
    def get_battery_status(self):
        range_remaining = self.evs.calculate_range()
        status = (f"Battery Capacity: {self.evs.battery_capacity} kWh\n"
                  f"Battery Health: {self.evs.battery_health}%\n"
                  f"Current Charge: {self.evs.current_charge:.2f} kWh\n"
                  f"Estimated Range: {range_remaining} miles")
        return status

    # Method to handle charging the battery
    def charge_battery(self):
        try:
            amount = float(self.charge_entry.get())
            if amount < 0:
                raise ValueError
            self.evs.charge_battery(amount)
            self.update_status()
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid charge amount.")

    # Method to handle driving the EV
    def drive(self):
        try:
            miles = float(self.drive_entry.get())
            if miles < 0:
                raise ValueError
            if self.evs.drive(miles):
                self.update_status()
            else:
                messagebox.showwarning("Warning", "Not enough charge to complete the trip!")
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid distance.")

    # Method to update the displayed battery status
    def update_status(self):
        self.status_label.config(text=self.get_battery_status())

# Create the Tkinter window
root = tk.Tk()
app = EVSApp(root)
root.mainloop()
