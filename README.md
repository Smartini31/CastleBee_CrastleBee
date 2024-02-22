## CRAstleBee App
The CRAstleBee App is a web-based calendar and event management system built using the Flask framework. This application provides a user-friendly interface for users to manage their events, request time off, and perform administrative tasks. It's designed with simplicity and functionality in mind, making it suitable for various use cases, from personal scheduling to team coordination.

## Features
User Registration and Authentication: Users can register for an account and log in securely. Passwords are hashed for security.

User Roles: The app supports two user roles: regular users and administrators. Administrators have additional privileges.

Dashboard: Each user has a personalized dashboard where they can view and manage their events.

Event Management: Users can create, view, edit, and delete events. Events can include titles, descriptions, start and end times, and types.

Request Time Off: Users can request time off, and administrators can review and approve or reject these requests.

Administrator Tools: Administrators have access to an admin dashboard where they can manage events, user roles, and approvals.

Calendar View: Events are displayed in a calendar view for easy visualization.

## Installation and Usage
To run the CRAstleBee App on your local machine, follow these steps:

Clone this repository to your local environment.

Create a virtual environment and activate it:

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

Install the required dependencies:
```bash
pip install -r requirements.txt
```
Set up the SQLite database by running the following commands:
```bash
Copy code
flask db init
flask db migrate
flask db upgrade
```
Start the Flask development server:
```bash
flask run
```

Access the app in your web browser at http://localhost:5000.