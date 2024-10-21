import socket
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime, timedelta
import re
import dateparser
import os
from PySide6.QtWidgets import QApplication, QMessageBox, QDialog, QVBoxLayout, QLabel, QPushButton

# Replace 'credentials.json' with your own credentials file.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/calendar']


# Authenticates using the OAuth2 credentials and returns service objects for Gmail and Google Calendar.
def authenticate_gmail_and_calendar(app):
    """
    Authenticate with Gmail and Google Calendar APIs using OAuth2 credentials.
    Returns the service objects for interacting with Gmail and Calendar.
    """
    if check_internet(app):
        creds = None
        creds = service_account.Credentials.from_service_account_file(
            'credentials.json', scopes=SCOPES)

        # Build the service objects for Gmail and Calendar.
        gmail_service = build('gmail', 'v1', credentials=creds)
        calendar_service = build('calendar', 'v3', credentials=creds)
        return gmail_service, calendar_service

    return "", ""


def check_internet_connection(app):
    # List of reliable servers to check for connectivity
    servers = [
        "8.8.8.8",  # Google DNS
        "1.1.1.1",  # Cloudflare DNS
        "208.67.222.222"  # OpenDNS
    ]

    for server in servers:
        try:
            # Try to connect to the server on port 53 (DNS) first
            socket.create_connection((server, 53), timeout=2)
            return True
        except OSError:
            continue  # Try the next server

    # If DNS fails, attempt an HTTP connection as a fallback
    for server in servers:
        try:
            # Try to connect to the server on port 80 (HTTP)
            socket.create_connection((server, 80), timeout=2)
            return True
        except OSError:
            continue  # Try the next server

    return False  # No connection could be established


def check_internet_and_data_transfer(app, servers=None, port=80, timeout=2):
    if servers is None:
        # List of reliable servers to check for connectivity
        servers = [
            '8.8.8.8',  # Google DNS
            '1.1.1.1',  # Cloudflare DNS
            '208.67.222.222'  # OpenDNS
        ]

    for server in servers:
        try:
            # Create a socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                # Try to connect to the server
                sock.connect((server, port))

                # Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode('utf-8'))

                # Receive the response
                response = sock.recv(4096)  # Adjust buffer size as needed

                # Check if we received any data
                if response:
                    return True
                else:
                    show_critical_message(app, f"No data received from {server}.")
        except Exception as e:
            show_critical_message(app, f"Error connecting to {server}: {e}")

    return False  # No successful connection or data transfer


def check_internet(app):
    # Check internet connection
    if check_internet_connection(app):
        # Check internet data transfer
        if check_internet_and_data_transfer(app):
            return True
        else:
            show_critical_message(app, "חיבור האינטרנט אינו תקין. יש לבדוק את החיבור ולנסות שוב.")
            return False

    else:
        show_critical_message(app, "אין חיבור לאינטרנט. יש לבדוק את החיבור ולנסות שוב.")
        return False


# Uses the Gmail API to fetch emails from the last month, filtering by the specified sender.
def get_last_month_emails(service):
    """
    Retrieves emails from the last month from a specified sender.
    Uses a Gmail API query to filter messages by sender and time.
    """
    # Define time range for last month.
    last_month = (datetime.now() - timedelta(days=30)).isoformat() + 'Z'  # 'Z' indicates UTC time.

    # Search for emails from the specific sender in the last month.
    query = f'from:כיוונים נוספים after:{last_month}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages


# Extracts the client’s name and appointment details using regular expressions from the email body.
def extract_appointment_details(service, message_id):
    """
    Extracts the client's name and appointment details from a given email message.
    Uses regex to find the client name and appointment time.
    """
    # Get the message content using the message ID.
    message = service.users().messages().get(userId='me', id=message_id).execute()
    msg_parts = message.get('payload').get('parts', [])
    email_body = ""

    # Extract the plain text part of the email body.
    for part in msg_parts:
        if part['mimeType'] == 'text/plain':
            email_body = part['body']['data']
            break

    # Decode the email body from base64 encoding.
    import base64
    email_body = base64.urlsafe_b64decode(email_body).decode('utf-8')

    # Extract client name using regex.
    name_match = re.search(r'שלום\s+(\S+)', email_body)
    client_name = name_match.group(1) if name_match else "Unknown"

    # Extract appointment date and time using regex.
    appointment_match = re.search(
        r'ליום\s+(\S+)\s+ה(\d{2}/\d{2})\s+בין השעות\s+(\d{2}:\d{2})-(\d{2}:\d{2})',
        email_body
    )
    if appointment_match:
        # Extracted components of the appointment.
        day_of_week, date_str, start_time, end_time = appointment_match.groups()

        # Combine the date and time into datetime objects.
        start_datetime = dateparser.parse(f"{date_str} {start_time}")
        end_datetime = dateparser.parse(f"{date_str} {end_time}")
    else:
        # If no match is found, set to None.
        start_datetime = end_datetime = None

    return client_name, start_datetime, end_datetime


# Creates a new Google Calendar event based on the parsed appointment details.
def create_calendar_event(calendar_service, client_name, start_datetime, end_datetime):
    """
    Creates a Google Calendar event for a given client appointment,
    but first checks if an event with the same details already exists.
    """
    # Define the time range for checking existing events.
    start_time = start_datetime.isoformat()
    end_time = end_datetime.isoformat()

    # Use the Google Calendar API to list events between the start and end times.
    events_result = calendar_service.events().list(
        calendarId='primary',
        timeMin=start_time,
        timeMax=end_time,
        q=client_name,  # Query by client name to narrow the search.
        singleEvents=True
    ).execute()
    existing_events = events_result.get('items', [])

    # Check if any existing event matches the start time, end time, and summary.
    for event in existing_events:
        event_summary = event.get('summary', '')
        event_start = event.get('start', {}).get('dateTime', '')
        event_end = event.get('end', {}).get('dateTime', '')

        # If the details match, print a message and skip creating a new event.
        if (event_summary == f'Appointment with {client_name}' and
            event_start == start_time and
            event_end == end_time):
            print(f"Event already exists: {event.get('htmlLink')}")
            return

    # Define the event details if no matching event was found.
    event = {
        'summary': f'Appointment with {client_name}',
        'description': 'Scheduled via email from כיוונים נוספים.',
        'start': {
            'dateTime': start_time,
            'timeZone': 'Asia/Jerusalem',
        },
        'end': {
            'dateTime': end_time,
            'timeZone': 'Asia/Jerusalem',
        },
    }

    # Insert the event into the calendar.
    event_result = calendar_service.events().insert(calendarId='primary', body=event).execute()
    print(f"Event created: {event_result.get('htmlLink')}")


# Coordinates the entire process, from retrieving emails to creating events in the calendar.
def main():
    """
    Main function to authenticate, retrieve emails, parse appointment details, and create calendar events.
    """
    # Initialize the Qt application for message box handling.
    app = QApplication([])

    # Check or create the "DirectionsEvents" directory.
    directory_path = check_or_create_directory(app)
    if not directory_path:
        print("Failed to access or create the required directory. Exiting.")
        exit(1)

    print(f"Using directory: {directory_path}")

    # Authenticate with Gmail and Calendar.
    gmail_service, calendar_service = authenticate_gmail_and_calendar(app)

    if gmail_service and calendar_service:
        # Get emails from the last month.
        messages = get_last_month_emails(gmail_service)

        # Collect appointment details to summarize for the user.
        appointments = []
        for message in messages:
            message_id = message['id']
            client_name, start_datetime, end_datetime = extract_appointment_details(gmail_service, message_id)

            # If the appointment details were successfully parsed, add to appointments list.
            if start_datetime and end_datetime:
                appointments.append((client_name, start_datetime, end_datetime))
            else:
                print(f"Could not parse appointment details for message ID: {message_id}")

        # Summarize appointments and get user approval.
        if appointments:
            if get_user_approval(app, appointments):
                for client_name, start_datetime, end_datetime in appointments:
                    create_calendar_event(calendar_service, client_name, start_datetime, end_datetime)
            else:
                print("User declined to create calendar events.")
        else:
            print("No valid appointments found.")

        # Exit the application when done.
        app.quit()


# Handles app directory
def check_or_create_directory(app):
    """
    Checks if the 'DirectionsEvents' directory exists in 'AppData' or 'Documents'.
    If it doesn't, attempts to create it, handling permission issues.
    """
    # Define paths for "AppData" and "Documents" locations.
    app_data_path = r"C:\Users\USER\AppData\DirectionsEvents"
    documents_path = r"C:\Users\USER\Documents\DirectionsEvents"

    # Check if the directory exists in either location.
    if os.path.exists(app_data_path):
        if not os.access(app_data_path, os.W_OK | os.R_OK):
            show_critical_message(app, f"No read/write permissions for directory: {app_data_path}")
        return app_data_path
    elif os.path.exists(documents_path):
        if not os.access(documents_path, os.W_OK | os.R_OK):
            show_critical_message(app, f"No read/write permissions for directory: {documents_path}")
        return documents_path

    # Try to create the directory in AppData.
    try:
        os.makedirs(app_data_path, exist_ok=True)
        if not os.access(app_data_path, os.W_OK | os.R_OK):
            show_critical_message(app, f"No read/write permissions for created directory: {app_data_path}.")
        return app_data_path
    except PermissionError:
        # If creation fails due to permissions, try in Documents.
        try:
            os.makedirs(documents_path, exist_ok=True)
            if not os.access(documents_path, os.W_OK | os.R_OK):
                show_critical_message(app, f"No read/write permissions for created directory: {documents_path}.")
            return documents_path
        except PermissionError:
            show_critical_message(app, "Could not create 'DirectionsEvents' in either AppData or Documents due to insufficient permissions.")
    except Exception as e:
        show_critical_message(app, f"Could not create 'DirectionsEvents' in either AppData or Documents due to error: {e}.")


# Shows critical error messages
def show_critical_message(app, message):
    """
    Displays a critical error message using a QMessageBox.
    """
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("Permission Error")
    msg_box.setText(message)
    msg_box.exec_()


# Handles user approval for founded appointments
def get_user_approval(app, appointments):
    """
    Displays a summary of the found appointments and asks for user approval to create calendar events.
    Returns True if the user approves, otherwise False.
    """
    # Create a dialog to summarize the appointments.
    dialog = QDialog()
    dialog.setWindowTitle("Appointment Summary")
    layout = QVBoxLayout()

    # Summarize appointments in the dialog.
    summary_text = "Found the following appointments:\n\n"
    for client_name, start, end in appointments:
        summary_text += f"Client: {client_name}\nStart: {start}\nEnd: {end}\n\n"

    label = QLabel(summary_text)
    layout.addWidget(label)

    # Add approval buttons.
    approve_button = QPushButton("Approve")
    decline_button = QPushButton("Decline")

    layout.addWidget(approve_button)
    layout.addWidget(decline_button)

    dialog.setLayout(layout)

    # Connect buttons to dialog actions.
    approve_button.clicked.connect(dialog.accept)
    decline_button.clicked.connect(dialog.reject)

    # Show the dialog and wait for user input.
    if dialog.exec_() == QDialog.Accepted:
        return True
    return False


# Run the main function when the script is executed.
if __name__ == '__main__':
    main()

