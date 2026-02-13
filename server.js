// Katutransporte Backend Server
// Node.js + Express + SQLite

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'katutransporte_secret_key_2024';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database Setup
const db = new sqlite3.Database('./katutransporte.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('✅ Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize Database Tables
function initializeDatabase() {
    // Users Table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('parent', 'driver', 'admin')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Error creating users table:', err);
        else console.log('✅ Users table ready');
    });

    // Children Table
    db.run(`
        CREATE TABLE IF NOT EXISTS children (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            school TEXT NOT NULL,
            address TEXT NOT NULL,
            emergency_contact TEXT NOT NULL,
            medical_info TEXT,
            status TEXT DEFAULT 'waiting' CHECK(status IN ('waiting', 'picked', 'transit', 'delivered')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES users(id)
        )
    `);

    // Routes Table
    db.run(`
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            driver_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            period TEXT NOT NULL CHECK(period IN ('morning', 'afternoon')),
            group_number INTEGER NOT NULL,
            start_time TEXT,
            end_time TEXT,
            active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (driver_id) REFERENCES users(id)
        )
    `);

    // Route Children (Many-to-Many relationship)
    db.run(`
        CREATE TABLE IF NOT EXISTS route_children (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            route_id INTEGER NOT NULL,
            child_id INTEGER NOT NULL,
            pickup_order INTEGER NOT NULL,
            pickup_time TEXT,
            delivery_time TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (route_id) REFERENCES routes(id),
            FOREIGN KEY (child_id) REFERENCES children(id)
        )
    `);

    // Trips Table
    db.run(`
        CREATE TABLE IF NOT EXISTS trips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            route_id INTEGER NOT NULL,
            driver_id INTEGER NOT NULL,
            date DATE NOT NULL,
            start_time DATETIME,
            end_time DATETIME,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'active', 'completed', 'cancelled')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (route_id) REFERENCES routes(id),
            FOREIGN KEY (driver_id) REFERENCES users(id)
        )
    `);

    // Trip Events (Track pickup/delivery)
    db.run(`
        CREATE TABLE IF NOT EXISTS trip_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trip_id INTEGER NOT NULL,
            child_id INTEGER NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('pickup', 'delivery')),
            event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            latitude REAL,
            longitude REAL,
            notes TEXT,
            FOREIGN KEY (trip_id) REFERENCES trips(id),
            FOREIGN KEY (child_id) REFERENCES children(id)
        )
    `);

    // Notifications Table
    db.run(`
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('info', 'warning', 'success', 'danger')),
            read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Payments Table
    db.run(`
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'paid', 'cancelled')),
            due_date DATE,
            paid_date DATE,
            payment_method TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Authorized Persons Table
    db.run(`
        CREATE TABLE IF NOT EXISTS authorized_persons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            child_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            relationship TEXT NOT NULL,
            pin_code TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (child_id) REFERENCES children(id)
        )
    `);

    // Create admin user if doesn't exist
    const adminEmail = 'admin@katutransporte.com';
    const adminPassword = bcrypt.hashSync('admin123', 10);
    
    db.get('SELECT id FROM users WHERE email = ?', [adminEmail], (err, row) => {
        if (!row) {
            db.run(`
                INSERT INTO users (name, email, phone, password, role)
                VALUES (?, ?, ?, ?, ?)
            `, ['Administrador', adminEmail, '+244900000000', adminPassword, 'admin'], (err) => {
                if (err) console.error('Error creating admin:', err);
                else console.log('✅ Admin user created (email: admin@katutransporte.com, password: admin123)');
            });
        }
    });
}

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
}

// Role-based Authorization Middleware
function authorizeRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        next();
    };
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, phone, password, role } = req.body;

    // Validate input
    if (!name || !email || !phone || !password || !role) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
    }

    // Check if user exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        
        if (row) {
            return res.status(400).json({ error: 'Email já registado' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        db.run(`
            INSERT INTO users (name, email, phone, password, role)
            VALUES (?, ?, ?, ?, ?)
        `, [name, email, phone, hashedPassword, role], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Erro ao criar conta' });
            }

            res.status(201).json({
                message: 'Conta criada com sucesso',
                userId: this.lastID
            });
        });
    });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login realizado com sucesso',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    });
});

// Get Current User
app.get('/api/user', authenticateToken, (req, res) => {
    db.get('SELECT id, name, email, phone, role, created_at FROM users WHERE id = ?', 
        [req.user.id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        if (!user) {
            return res.status(404).json({ error: 'Utilizador não encontrado' });
        }
        res.json(user);
    });
});

// ==================== CHILDREN ROUTES ====================

// Get all children for a parent
app.get('/api/children', authenticateToken, (req, res) => {
    let query = 'SELECT * FROM children';
    let params = [];

    if (req.user.role === 'parent') {
        query += ' WHERE parent_id = ?';
        params = [req.user.id];
    }

    query += ' ORDER BY created_at DESC';

    db.all(query, params, (err, children) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar crianças' });
        }
        res.json(children);
    });
});

// Get single child
app.get('/api/children/:id', authenticateToken, (req, res) => {
    db.get('SELECT * FROM children WHERE id = ?', [req.params.id], (err, child) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        if (!child) {
            return res.status(404).json({ error: 'Criança não encontrada' });
        }
        
        // Check authorization
        if (req.user.role === 'parent' && child.parent_id !== req.user.id) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        res.json(child);
    });
});

// Add new child
app.post('/api/children', authenticateToken, authorizeRole('parent', 'admin'), (req, res) => {
    const { name, age, gender, school, address, emergency_contact, medical_info } = req.body;
    const parent_id = req.user.role === 'parent' ? req.user.id : req.body.parent_id;

    if (!name || !age || !gender || !school || !address || !emergency_contact) {
        return res.status(400).json({ error: 'Todos os campos obrigatórios devem ser preenchidos' });
    }

    db.run(`
        INSERT INTO children (parent_id, name, age, gender, school, address, emergency_contact, medical_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [parent_id, name, age, gender, school, address, emergency_contact, medical_info], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao adicionar criança' });
        }

        // Create notification
        createNotification(parent_id, `${name} foi adicionado(a) com sucesso!`, 'success');

        res.status(201).json({
            message: 'Criança adicionada com sucesso',
            childId: this.lastID
        });
    });
});

// Update child status
app.put('/api/children/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    const validStatuses = ['waiting', 'picked', 'transit', 'delivered'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Status inválido' });
    }

    db.get('SELECT * FROM children WHERE id = ?', [req.params.id], (err, child) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        if (!child) {
            return res.status(404).json({ error: 'Criança não encontrada' });
        }

        db.run('UPDATE children SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [status, req.params.id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao atualizar status' });
            }

            // Create notification for parent
            const messages = {
                'picked': `${child.name} foi recolhido(a)!`,
                'transit': `${child.name} está a caminho!`,
                'delivered': `${child.name} foi entregue com segurança!`
            };

            if (messages[status]) {
                createNotification(child.parent_id, messages[status], 'info');
            }

            res.json({ message: 'Status atualizado com sucesso' });
        });
    });
});

// Delete child
app.delete('/api/children/:id', authenticateToken, (req, res) => {
    db.get('SELECT * FROM children WHERE id = ?', [req.params.id], (err, child) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }
        if (!child) {
            return res.status(404).json({ error: 'Criança não encontrada' });
        }

        // Check authorization
        if (req.user.role === 'parent' && child.parent_id !== req.user.id) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        db.run('DELETE FROM children WHERE id = ?', [req.params.id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao remover criança' });
            }
            res.json({ message: 'Criança removida com sucesso' });
        });
    });
});

// ==================== NOTIFICATIONS ROUTES ====================

// Get notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
    db.all(`
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    `, [req.user.id], (err, notifications) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar notificações' });
        }
        res.json(notifications);
    });
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, (req, res) => {
    db.run(`
        UPDATE notifications 
        SET read = 1 
        WHERE id = ? AND user_id = ?
    `, [req.params.id, req.user.id], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao atualizar notificação' });
        }
        res.json({ message: 'Notificação marcada como lida' });
    });
});

// Helper function to create notifications
function createNotification(userId, message, type = 'info') {
    db.run(`
        INSERT INTO notifications (user_id, message, type)
        VALUES (?, ?, ?)
    `, [userId, message, type], (err) => {
        if (err) console.error('Error creating notification:', err);
    });
}

// ==================== PAYMENTS ROUTES ====================

// Get payments
app.get('/api/payments', authenticateToken, (req, res) => {
    let query = 'SELECT * FROM payments';
    let params = [];

    if (req.user.role === 'parent') {
        query += ' WHERE user_id = ?';
        params = [req.user.id];
    }

    query += ' ORDER BY created_at DESC';

    db.all(query, params, (err, payments) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar pagamentos' });
        }
        res.json(payments);
    });
});

// Create payment
app.post('/api/payments', authenticateToken, authorizeRole('admin'), (req, res) => {
    const { user_id, amount, description, due_date } = req.body;

    if (!user_id || !amount || !description) {
        return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }

    db.run(`
        INSERT INTO payments (user_id, amount, description, due_date)
        VALUES (?, ?, ?, ?)
    `, [user_id, amount, description, due_date], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao criar pagamento' });
        }

        // Notify user
        createNotification(user_id, `Nova mensalidade de ${amount} Kz criada`, 'info');

        res.status(201).json({
            message: 'Pagamento criado com sucesso',
            paymentId: this.lastID
        });
    });
});

// Update payment status
app.put('/api/payments/:id/status', authenticateToken, (req, res) => {
    const { status, payment_method } = req.body;

    if (!['pending', 'paid', 'cancelled'].includes(status)) {
        return res.status(400).json({ error: 'Status inválido' });
    }

    const paid_date = status === 'paid' ? new Date().toISOString().split('T')[0] : null;

    db.run(`
        UPDATE payments 
        SET status = ?, paid_date = ?, payment_method = ?
        WHERE id = ?
    `, [status, paid_date, payment_method, req.params.id], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao atualizar pagamento' });
        }

        if (status === 'paid') {
            db.get('SELECT user_id FROM payments WHERE id = ?', [req.params.id], (err, payment) => {
                if (payment) {
                    createNotification(payment.user_id, 'Pagamento confirmado com sucesso!', 'success');
                }
            });
        }

        res.json({ message: 'Pagamento atualizado com sucesso' });
    });
});

// ==================== ROUTES MANAGEMENT ====================

// Get all routes
app.get('/api/routes', authenticateToken, (req, res) => {
    db.all(`
        SELECT r.*, u.name as driver_name,
        (SELECT COUNT(*) FROM route_children WHERE route_id = r.id) as children_count
        FROM routes r
        LEFT JOIN users u ON r.driver_id = u.id
        WHERE r.active = 1
        ORDER BY r.period, r.group_number
    `, (err, routes) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar rotas' });
        }
        res.json(routes);
    });
});

// Get driver route
app.get('/api/driver/route', authenticateToken, authorizeRole('driver'), (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    const currentHour = new Date().getHours();
    const period = currentHour < 12 ? 'morning' : 'afternoon';

    db.all(`
        SELECT c.*, rc.pickup_order, rc.pickup_time
        FROM children c
        JOIN route_children rc ON c.id = rc.child_id
        JOIN routes r ON rc.route_id = r.id
        WHERE r.driver_id = ? AND r.period = ? AND r.active = 1
        ORDER BY rc.pickup_order
    `, [req.user.id, period], (err, children) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar rota' });
        }
        res.json(children);
    });
});

// Create route
app.post('/api/routes', authenticateToken, authorizeRole('admin'), (req, res) => {
    const { driver_id, name, period, group_number, start_time, end_time } = req.body;

    if (!driver_id || !name || !period || !group_number) {
        return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }

    db.run(`
        INSERT INTO routes (driver_id, name, period, group_number, start_time, end_time)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [driver_id, name, period, group_number, start_time, end_time], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao criar rota' });
        }

        res.status(201).json({
            message: 'Rota criada com sucesso',
            routeId: this.lastID
        });
    });
});

// Assign child to route
app.post('/api/routes/:routeId/children', authenticateToken, authorizeRole('admin'), (req, res) => {
    const { child_id, pickup_order, pickup_time } = req.body;

    if (!child_id || !pickup_order) {
        return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }

    db.run(`
        INSERT INTO route_children (route_id, child_id, pickup_order, pickup_time)
        VALUES (?, ?, ?, ?)
    `, [req.params.routeId, child_id, pickup_order, pickup_time], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao atribuir criança à rota' });
        }

        res.status(201).json({ message: 'Criança atribuída à rota com sucesso' });
    });
});

// ==================== TRIPS ROUTES ====================

// Create trip
app.post('/api/trips', authenticateToken, authorizeRole('driver', 'admin'), (req, res) => {
    const { route_id } = req.body;
    const driver_id = req.user.role === 'driver' ? req.user.id : req.body.driver_id;
    const date = new Date().toISOString().split('T')[0];

    db.run(`
        INSERT INTO trips (route_id, driver_id, date, status, start_time)
        VALUES (?, ?, ?, 'active', CURRENT_TIMESTAMP)
    `, [route_id, driver_id, date], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao criar viagem' });
        }

        res.status(201).json({
            message: 'Viagem iniciada com sucesso',
            tripId: this.lastID
        });
    });
});

// Log trip event (pickup/delivery)
app.post('/api/trips/:tripId/events', authenticateToken, authorizeRole('driver'), (req, res) => {
    const { child_id, event_type, latitude, longitude, notes } = req.body;

    if (!child_id || !event_type) {
        return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }

    db.run(`
        INSERT INTO trip_events (trip_id, child_id, event_type, latitude, longitude, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [req.params.tripId, child_id, event_type, latitude, longitude, notes], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao registar evento' });
        }

        res.status(201).json({ message: 'Evento registado com sucesso' });
    });
});

// ==================== STATISTICS ROUTES ====================

// Get dashboard statistics
app.get('/api/statistics/dashboard', authenticateToken, (req, res) => {
    const queries = {
        totalChildren: 'SELECT COUNT(*) as count FROM children',
        totalParents: "SELECT COUNT(*) as count FROM users WHERE role = 'parent'",
        totalDrivers: "SELECT COUNT(*) as count FROM users WHERE role = 'driver'",
        activeTrips: "SELECT COUNT(*) as count FROM trips WHERE status = 'active'",
        completedTrips: "SELECT COUNT(*) as count FROM trips WHERE status = 'completed'",
        pendingPayments: "SELECT SUM(amount) as total FROM payments WHERE status = 'pending'",
        paidPayments: "SELECT SUM(amount) as total FROM payments WHERE status = 'paid'"
    };

    const stats = {};
    let completed = 0;
    const total = Object.keys(queries).length;

    for (const [key, query] of Object.entries(queries)) {
        db.get(query, (err, row) => {
            if (!err) {
                stats[key] = row.count || row.total || 0;
            }
            completed++;
            
            if (completed === total) {
                res.json(stats);
            }
        });
    }
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Algo deu errado!' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════╗
║     🚌 KATUTRANSPORTE SERVER 🚌          ║
╠════════════════════════════════════════════╣
║  Status: ✅ Running                        ║
║  Port: ${PORT}                              ║
║  Database: SQLite                          ║
║  API: http://localhost:${PORT}/api         ║
╠════════════════════════════════════════════╣
║  Endpoints disponíveis:                    ║
║  • POST /api/register                      ║
║  • POST /api/login                         ║
║  • GET  /api/user                          ║
║  • GET  /api/children                      ║
║  • POST /api/children                      ║
║  • GET  /api/notifications                 ║
║  • GET  /api/payments                      ║
║  • GET  /api/routes                        ║
║  • GET  /api/driver/route                  ║
║  • GET  /api/statistics/dashboard          ║
╠════════════════════════════════════════════╣
║  Admin Login:                              ║
║  Email: admin@katutransporte.com           ║
║  Password: admin123                        ║
╚════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});

module.exports = app;
