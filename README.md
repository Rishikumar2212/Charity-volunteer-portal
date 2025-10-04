# Charity-volunteer-portal

1. Project Overview :
   
This web application connects volunteers with organizations needing help.
Built using Node.js and Express.js for backend.
Uses HTML, CSS, and JavaScript for frontend.
Volunteers can view, apply for, and track volunteer activities.
Organizations can post opportunities, approve volunteers, and manage activities.
The system efficiently manages all volunteer-related data in a SQLite database.

3. Technology Stack :
   
Frontend:
HTML – structure of pages
CSS – styling and layout
JavaScript – dynamic interactions (form validation, DOM updates)

Backend:
Node.js – server environment
Express.js – handles API endpoints and routing
SQLite – database to store users, announcements, and volunteer activities

Other Tools:
bcrypt – for password hashing
REST APIs – for communication between frontend and backend

3. Database Structure :
   
Tables:
users – stores volunteers and organizations
announcements – stores volunteering opportunities
volunteer_activities – stores which volunteer applied to which activity and its status

Relationships:
users ↔ announcements (organization creates announcements)
users ↔ volunteer_activities (volunteers apply for activities)
announcements ↔ volunteer_activities (tracks volunteer participation)

4. Workflow (Step-by-Step) :
   
Step 1: User Registration & Login
Users register as volunteer or organization.
Passwords are hashed before storing.
Users log in to access their dashboard.

Step 2: Organization Creates Announcement
Organization fills a form (title, date, location, description).
Data is saved in announcements table in the database.
Announcement becomes visible to volunteers.

Step 3: Volunteer Browses & Applies
Volunteers see a list of available announcements.
They can click “Apply” for a particular activity.
Application is recorded in volunteer_activities table with status = "applied".

Step 4: Organization Manages Volunteers
Organization reviews applications.
Updates status to completed or cancelled based on volunteer participation.

Step 5: Tracking & Reporting
Volunteers can see hours contributed and status of applications.
Organizations can see list of volunteers and manage ongoing activities.

5. Frontend & Backend Integration :
   
Frontend sends HTTP requests (GET, POST, PUT) to backend API endpoints.
Backend uses Express.js routes to handle requests and interact with the SQLite database.
Backend returns data in JSON format.
Frontend dynamically updates UI using JavaScript based on API responses.

Example : Volunteer clicks “Apply” → JS sends POST /apply → Express adds record in DB → Returns success → JS updates UI.

6. Full Overview in Workflow Diagram (Conceptually) :
   
Volunteer → Browses → Applies → Backend → DB → Status Updated → Volunteer & Organization Dashboard
Organization → Creates Announcement → Backend → DB → Volunteer Sees → Manages Applications → Status Updated

8. Applications :
   
For Volunteers: Find, apply, and track volunteering activities with ease.
For Organizations: Post events, manage volunteer applications, and monitor participation.
Community Impact: Increases volunteer engagement and streamlines event management.
Educational & Professional Use: Demonstrates full-stack skills and database management experience.
