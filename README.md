# Nyxon's Node.js Dashboard Project

---

## Project Overview
This project is a **Node.js** web application designed and developed by **Nyxon**. It features a **login system**, **user management**, **role-based access control**, and **logging functionality**. The application is built using **Express.js** and includes a **dashboard** for admin users to manage users, view logs, and update system messages.

---

## Key Features

1. **User Authentication**:
   - Secure login and logout functionality.
   - Session management with **express-session**.
   - Password hashing using **bcrypt**.

2. **Role-Based Access Control**:
   - **Admin** users can register new users, delete users, block/unblock users, and update system messages.
   - **Regular** users have access to a profile page but cannot access the admin dashboard.

3. **Logging**:
   - Logs user actions (e.g., login attempts, user registration, user deletion) using **Winston**.
   - Logs are stored in `logs.json` and displayed in the admin dashboard with **color-coded levels** (info, warn, error).

4. **Dashboard**:
   - **Admin Dashboard**: View and manage users, update system messages, and view recent logs.
   - **Profile Page**: Regular users can view their profile and log out.

5. **Styling**:
   - Modern, dark-themed UI with **CSS**.
   - Logs in the dashboard are color-coded for better readability.

---

## File Structure
```
Nyxon-Dash/
├── logs/
│ ├── combined.log
│ ├── error.log
│ └── logs.json
├── node_modules/
├── public/
│ ├── dashboard.css
│ ├── dashboard.html
│ ├── login.html
│ └── profile.html
├── .env
├── .gitignore
├── messages.json
├── package-lock.json
├── package.json
├── README.md
├── server.js
└── users.json
```
---

## Installation

1. **Install Node.js and Required Packages**:
   Run the following command to install Node.js and all required dependencies:

   ```bash
   curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt-get install -y nodejs && npm install express body-parser express-session bcrypt uuid date-fns express-rate-limit express-validator winston chalk dotenv
   ```
This command will:

- Download and install **Node.js**.
- Install all required npm packages for the project.

2. **Start the Server:**
After installing the dependencies, start the server with:
```bash
   node server.js
   ```
The server will run at `http://localhost:3000`.

---

## Code Highlights
1. **Winston Logger:**

- Logs are color-coded in the console and stored in logs.json with timestamps and log levels.

```javascript
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => {
            const timestamp = chalk.gray(`[${info.timestamp}]`);
            const level = info.level === 'info' ? chalk.green.bold(`[${info.level.toUpperCase()}]`) :
                          info.level === 'warn' ? chalk.yellow.bold(`[${info.level.toUpperCase()}]`) :
                          chalk.red.bold(`[${info.level.toUpperCase()}]`);
            const message = info.message;
            return `${timestamp} ${level} ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' })
    ]
});
```
2. **Dashboard Logs:**

- Logs in the dashboard are dynamically colored based on their level.

```javascript
async function fetchLogs() {
    const response = await fetch('/logs');
    const logs = await response.json();
    const logList = document.getElementById('logList');
    logList.innerHTML = '';

    logs.slice(-5).forEach(log => {
        const logItem = document.createElement('div');
        logItem.className = 'log-item';

        let logColor;
        if (log.level === 'info') logColor = 'green';
        else if (log.level === 'warn') logColor = 'orange';
        else if (log.level === 'error') logColor = 'red';
        else logColor = 'white';

        logItem.innerHTML = `
            <span><strong style="color: ${logColor};">[${log.timestamp}]</strong> <span style="color: ${logColor};">${log.message}</span></span>
        `;

        logList.appendChild(logItem);
    });
}
```
---
## Future Enhancements
1. **Database Integration:**

- Replace JSON files with a database (e.g., MongoDB or PostgreSQL) for better scalability.

2. **Email Notifications:**

- Send email notifications for critical events (e.g., account blocked).

3. **Two-Factor Authentication:**

- Add an extra layer of security with 2FA.

4. **Responsive Design:**

- Make the application fully responsive for mobile and tablet devices.
---
**Created by Nyxon**
**GitHub:** [Nyxon's GitHub](https://github.com/ScytheMediaTheDev)
**Contact:** [nyx@elcipse.space](mailto:nyx@elcipse.space)
---

## **Run the following command to install Node.js and all dependencies, and start the project:**
```bash
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt-get install -y nodejs && npm install express body-parser express-session bcrypt uuid date-fns express-rate-limit express-validator winston chalk dotenv && node server.js
```
---
**Enjoy! 🚀**
