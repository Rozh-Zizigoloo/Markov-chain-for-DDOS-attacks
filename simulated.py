import numpy as np
import random

# 1. Definition of devices in the network
devices = {
    "device_1": 1,
    "device_2": 2,
    "device_2": 3,
    "device_2": 4,
    "device_2": 5,
    "device_2": 6,
    "device_2": 7,
    "device_2": 8,
    "device_2": 9,
    "device_2": 10,
    
}

# 2. Definition of thresholds
thresholds = {
    "read": {
        "safe": 10,
        "suspicious_benign": 20,
        "suspicious_malicious": 30,
        "malicious_benign": 40,
        "malicious_dangerous": 50,
    },
    "update": {
        "safe": 5,
        "suspicious_benign": 10,
        "suspicious_malicious": 15,
        "malicious_benign": 20,
        "malicious_dangerous": 25,
    },
    "delete": {
        "safe": 3,
        "suspicious_benign": 6,
        "suspicious_malicious": 9,
        "malicious_benign": 12,
        "malicious_dangerous": 15,
    },
}

# 3. Define the report function
def generate_report(device_id, activity, subactivity, number_of_activities):
    return {
        "report_id": random.randint(1, 1000),
        "number_of_activities": number_of_activities,
        "activity": activity,
        "subactivity": subactivity,
        "device_id": device_id,
    }

# 4. Simulation function
def simulate():
    # reports
    reports = []

    # Current status of devices
    device_states = {device_id: "safe" for device_id in devices}

    # Simulation for 100 reports
    for _ in range(100):
        # Get the report
        report = generate_report(
            random.choice(list(devices.keys())),
            random.choice(["read", "update", "delete"]),
            random.choice(["safe", "suspicious", "malicious"]),
            random.randint(1, 50),
        )
        reports.append(report)

        # Checking the current status of the device
        device_id = report["device_id"]
        activity = report["activity"]
        subactivity = report["subactivity"]
        number_of_activities = report["number_of_activities"]

        current_state = device_states[device_id]

        # 4.1. Compare activities and thresholds
        if activity == "read":
            if number_of_activities <= thresholds["read"]["safe"]:
                # 4.1.1. در حالت ایمن
                pass
            elif number_of_activities <= thresholds["read"]["suspicious"]:
                # 4.1.2. در حالت مشکوک
                if device_id in devices:
                    device_states[device_id] = "suspicious_benign"
                else:
                    device_states[device_id] = "suspicious_malicious"
            else:
                # 4.1.3. در حالت مخرب
                if device_id in devices:
                    device_states[device_id] = "malicious_benign"
                else:
                    device_states[device_id] = "malicious_dangerous"
        elif activity == "update":
            # ... (similar logic for "update" activity)
        elif activity == "delete":
            # ... (similar logic for "delete" activity)

        # 4.2. بررسی حالت مشکوک
        if current_state in ["suspicious_benign", "suspicious_malicious"]:
            # 4.2.1. ورود به حالت مشاهده
            observation_start_time = time.time()
            observed_activities = []
            while time.time() - observation_start_time <= 60:
                # دریافت گزارش های جدید
                new_reports = [
                    report for report in reports if report["device_id"] == device_id
                ]
                for new_report in new_reports:
                    observed_activities.append(new_report["number_of_activities"])
            average_activity = np.mean(observed_activities)
            
            if average_activity > thresholds["read"]["suspicious"] / 2:
                # 4.2.2. ورود به حالت توقف
                device_states[device_id] = "stopped"
                del devices[device_id]
            else:
                # 4.2.3. بازگشت به حالت ایمن
                device_states[device_id] = "safe"
        # ... (similar logic for "update" and "delete" activities)

        # 4.3. بررسی حالت مخرب
        if current_state in ["malicious_benign", "malicious_dangerous"]:
            # 4.3.1. ورود به حالت توقف
            device_states[device_id] = "stopped"
            del devices[device_id]

    # چاپ وضعیت نهایی دستگاه ها
    print(device_states)


# 5. اجرای شبیه سازی
simulate()

