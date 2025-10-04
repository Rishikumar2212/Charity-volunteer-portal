// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'your_secret_key_here'; // Replace with a secure key in production

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend'))); // Updated path

// Initialize SQLite database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize database tables
function initializeDatabase() {
    // Users table (for both organizations and volunteers)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('organization', 'volunteer')),
        name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Announcements table
    db.run(`CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        date DATE NOT NULL,
        location TEXT NOT NULL,
        description TEXT NOT NULL,
        organization_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (organization_id) REFERENCES users(id)
    )`);

    // Volunteer activities table
    db.run(`CREATE TABLE IF NOT EXISTS volunteer_activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        volunteer_id INTEGER NOT NULL,
        announcement_id INTEGER NOT NULL,
        hours INTEGER DEFAULT 0,
        status TEXT DEFAULT 'applied' CHECK(status IN ('applied', 'completed', 'cancelled')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (volunteer_id) REFERENCES users(id),
        FOREIGN KEY (announcement_id) REFERENCES announcements(id)
    )`);

    // Create default admin user if not exists
    const adminEmail = 'admin@example.com';
    db.get('SELECT * FROM users WHERE email = ?', [adminEmail], (err, row) => {
        if (!row) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                if (err) throw err;
                db.run(
                    'INSERT INTO users (email, password, type, name) VALUES (?, ?, ?, ?)',
                    [adminEmail, hash, 'organization', 'Admin Organization']
                );
            });
        }
    });
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Routes
// Auth routes
app.post('/api/auth/register', async (req, res) => {
    const { email, password, type, name } = req.body;

    if (!email || !password || !type || !name) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (email, password, type, name) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, type, name],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(409).json({ message: 'Email already in use' });
                    }
                    return res.status(500).json({ message: 'Server error' });
                }

                const token = jwt.sign(
                    { id: this.lastID, email, type, name },
                    SECRET_KEY,
                    { expiresIn: '24h' }
                );

                res.status(201).json({
                    message: 'User registered successfully',
                    token,
                    user: { id: this.lastID, email, type, name }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Server error' });
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { id: user.id, email: user.email, type: user.type, name: user.name },
                SECRET_KEY,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Login successful',
                token,
                user: { id: user.id, email: user.email, type: user.type, name: user.name }
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    });
});

// Announcement routes
app.get('/api/announcements', (req, res) => {
    db.all(
        `SELECT a.*, u.name as organization_name
         FROM announcements a
         JOIN users u ON a.organization_id = u.id
         ORDER BY a.created_at DESC`,
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            res.json(rows);
        }
    );
});

app.get('/api/announcements/:id', (req, res) => {
    const { id } = req.params;

    db.get(
        `SELECT a.*, u.name as organization_name
         FROM announcements a
         JOIN users u ON a.organization_id = u.id
         WHERE a.id = ?`,
        [id],
        (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            if (!row) {
                return res.status(404).json({ message: 'Announcement not found' });
            }
            res.json(row);
        }
    );
});

app.post('/api/announcements', authenticateToken, (req, res) => {
    if (req.user.type !== 'organization') {
        return res.status(403).json({ message: 'Only organizations can create announcements' });
    }

    const { title, date, location, description } = req.body;

    if (!title || !date || !location || !description) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    db.run(
        'INSERT INTO announcements (title, date, location, description, organization_id) VALUES (?, ?, ?, ?, ?)',
        [title, date, location, description, req.user.id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }

            res.status(201).json({
                message: 'Announcement created successfully',
                announcement: { id: this.lastID, title, date, location, description }
            });
        }
    );
});

app.put('/api/announcements/:id', authenticateToken, (req, res) => {
    if (req.user.type !== 'organization') {
        return res.status(403).json({ message: 'Only organizations can update announcements' });
    }

    const { id } = req.params;
    const { title, date, location, description } = req.body;

    db.get(
        'SELECT * FROM announcements WHERE id = ? AND organization_id = ?',
        [id, req.user.id],
        (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            if (!row) {
                return res.status(404).json({ message: 'Announcement not found or not authorized' });
            }

            db.run(
                'UPDATE announcements SET title = ?, date = ?, location = ?, description = ? WHERE id = ?',
                [title, date, location, description, id],
                function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Server error' });
                    }

                    res.json({
                        message: 'Announcement updated successfully',
                        announcement: { id, title, date, location, description }
                    });
                }
            );
        }
    );
});

app.delete('/api/announcements/:id', authenticateToken, (req, res) => {
    if (req.user.type !== 'organization') {
        return res.status(403).json({ message: 'Only organizations can delete announcements' });
    }

    const { id } = req.params;

    db.get(
        'SELECT * FROM announcements WHERE id = ? AND organization_id = ?',
        [id, req.user.id],
        (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            if (!row) {
                return res.status(404).json({ message: 'Announcement not found or not authorized' });
            }

            db.run('DELETE FROM announcements WHERE id = ?', [id], function(err) {
                if (err) {
                    return res.status(500).json({ message: 'Server error' });
                }

                res.json({ message: 'Announcement deleted successfully' });
            });
        }
    );
});

// Volunteer activity routes
app.post('/api/activities', authenticateToken, (req, res) => {
    if (req.user.type !== 'volunteer') {
        return res.status(403).json({ message: 'Only volunteers can apply for opportunities' });
    }

    const { announcement_id } = req.body;

    if (!announcement_id) {
        return res.status(400).json({ message: 'Announcement ID is required' });
    }

    // Check if announcement exists
    db.get('SELECT * FROM announcements WHERE id = ?', [announcement_id], (err, announcement) => {
        if (err) {
            return res.status(500).json({ message: 'Server error' });
        }
        if (!announcement) {
            return res.status(404).json({ message: 'Announcement not found' });
        }

        // Check if already applied
        db.get(
            'SELECT * FROM volunteer_activities WHERE volunteer_id = ? AND announcement_id = ?',
            [req.user.id, announcement_id],
            (err, activity) => {
                if (err) {
                    return res.status(500).json({ message: 'Server error' });
                }
                if (activity) {
                    return res.status(409).json({ message: 'Already applied for this opportunity' });
                }

                // Create activity
                db.run(
                    'INSERT INTO volunteer_activities (volunteer_id, announcement_id) VALUES (?, ?)',
                    [req.user.id, announcement_id],
                    function(err) {
                        if (err) {
                            return res.status(500).json({ message: 'Server error' });
                        }

                        res.status(201).json({
                            message: 'Applied successfully',
                            activity: { id: this.lastID, volunteer_id: req.user.id, announcement_id }
                        });
                    }
                );
            }
        );
    });
});

app.get('/api/activities', authenticateToken, (req, res) => {
    if (req.user.type !== 'volunteer') {
        return res.status(403).json({ message: 'Only volunteers can view their activities' });
    }

    db.all(
        `SELECT va.*, a.title, a.date, a.location, a.description, u.name as organization_name
         FROM volunteer_activities va
         JOIN announcements a ON va.announcement_id = a.id
         JOIN users u ON a.organization_id = u.id
         WHERE va.volunteer_id = ?
         ORDER BY va.created_at DESC`,
        [req.user.id],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            res.json(rows);
        }
    );
});

app.put('/api/activities/:id', authenticateToken, (req, res) => {
    if (req.user.type !== 'volunteer') {
        return res.status(403).json({ message: 'Only volunteers can update their activities' });
    }

    const { id } = req.params;
    const { hours, status } = req.body;

    db.get(
        'SELECT * FROM volunteer_activities WHERE id = ? AND volunteer_id = ?',
        [id, req.user.id],
        (err, activity) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }
            if (!activity) {
                return res.status(404).json({ message: 'Activity not found or not authorized' });
            }

            db.run(
                'UPDATE volunteer_activities SET hours = ?, status = ? WHERE id = ?',
                [hours, status, id],
                function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Server error' });
                    }

                    res.json({
                        message: 'Activity updated successfully',
                        activity: { id, hours, status }
                    });
                }
            );
        }
    );
});

// Leaderboard route
app.get('/api/leaderboard', (req, res) => {
    db.all(
        `SELECT
            u.id,
            u.name,
            SUM(va.hours) as total_hours,
            COUNT(va.id) as total_activities
         FROM users u
         JOIN volunteer_activities va ON u.id = va.volunteer_id
         WHERE va.status = 'completed'
         GROUP BY u.id
         ORDER BY total_hours DESC
         LIMIT 10`,
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Server error' });
            }

            // Add rank badges based on hours
            const leaderboard = rows.map((volunteer, index) => {
                let rank = 'Pro';
                if (volunteer.total_hours >= 40) rank = 'Champion';
                else if (volunteer.total_hours >= 35) rank = 'Elite';
                else if (volunteer.total_hours >= 30) rank = 'Expert';

                return {
                    ...volunteer,
                    rank,
                    position: index + 1
                };
            });

            res.json(leaderboard);
        }
    );
});

// Dashboard stats for organizations
app.get('/api/dashboard/organization', authenticateToken, (req, res) => {
    if (req.user.type !== 'organization') {
        return res.status(403).json({ message: 'Only organizations can access this endpoint' });
    }

    const orgId = req.user.id;

    // Get announcement count
    db.get('SELECT COUNT(*) as count FROM announcements WHERE organization_id = ?', [orgId], (err, row) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        const announcementCount = row.count;

        // Get active volunteers count
        db.get(
            `SELECT COUNT(DISTINCT va.volunteer_id) as count
             FROM volunteer_activities va
             JOIN announcements a ON va.announcement_id = a.id
             WHERE a.organization_id = ? AND va.status = 'applied'`,
            [orgId],
            (err, row) => {
                if (err) return res.status(500).json({ message: 'Server error' });

                const activeVolunteers = row.count;

                // Get completed events count
                db.get(
                    `SELECT COUNT(*) as count
                     FROM volunteer_activities va
                     JOIN announcements a ON va.announcement_id = a.id
                     WHERE a.organization_id = ? AND va.status = 'completed'`,
                    [orgId],
                    (err, row) => {
                        if (err) return res.status(500).json({ message: 'Server error' });

                        const completedEvents = row.count;

                        // Get total volunteer hours
                        db.get(
                            `SELECT SUM(va.hours) as total
                             FROM volunteer_activities va
                             JOIN announcements a ON va.announcement_id = a.id
                             WHERE a.organization_id = ? AND va.status = 'completed'`,
                            [orgId],
                            (err, row) => {
                                if (err) return res.status(500).json({ message: 'Server error' });

                                const totalHours = row.total || 0;

                                res.json({
                                    announcements: announcementCount,
                                    activeVolunteers,
                                    completedEvents,
                                    totalHours
                                });
                            }
                        );
                    }
                );
            }
        );
    });
});

// Dashboard stats for volunteers
app.get('/api/dashboard/volunteer', authenticateToken, (req, res) => {
    if (req.user.type !== 'volunteer') {
        return res.status(403).json({ message: 'Only volunteers can access this endpoint' });
    }

    const volunteerId = req.user.id;

    // Get applications count
    db.get(
        'SELECT COUNT(*) as count FROM volunteer_activities WHERE volunteer_id = ?',
        [volunteerId],
        (err, row) => {
            if (err) return res.status(500).json({ message: 'Server error' });

            const applications = row.count;

            // Get completed events count
            db.get(
                'SELECT COUNT(*) as count FROM volunteer_activities WHERE volunteer_id = ? AND status = "completed"',
                [volunteerId],
                (err, row) => {
                    if (err) return res.status(500).json({ message: 'Server error' });

                    const completedEvents = row.count;

                    // Get total hours
                    db.get(
                        'SELECT SUM(hours) as total FROM volunteer_activities WHERE volunteer_id = ? AND status = "completed"',
                        [volunteerId],
                        (err, row) => {
                            if (err) return res.status(500).json({ message: 'Server error' });

                            const totalHours = row.total || 0;

                            // Get rank
                            let rank = 'Pro';
                            if (totalHours >= 40) rank = 'Champion';
                            else if (totalHours >= 35) rank = 'Elite';
                            else if (totalHours >= 30) rank = 'Expert';

                            // Get position in leaderboard
                            db.get(
                                `SELECT COUNT(*) as position
                                 FROM (
                                     SELECT volunteer_id, SUM(hours) as total_hours
                                     FROM volunteer_activities
                                     WHERE status = 'completed'
                                     GROUP BY volunteer_id
                                     HAVING total_hours > ?
                                 )`,
                                [totalHours],
                                (err, row) => {
                                    if (err) return res.status(500).json({ message: 'Server error' });

                                    const position = (row ? row.position : 0) + 1;

                                    res.json({
                                        applications,
                                        completedEvents,
                                        totalHours,
                                        rank,
                                        position
                                    });
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

// Serve frontend for any other routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// Handle 404 for all other routes
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
